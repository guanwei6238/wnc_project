#!/bin/bash
# 方案 B：外部產生流量的多 queue 量測，Pi 端（bridge）
#   筆電 USB 網卡 ── Pi eth0（LAN）[wgw: br0] Pi eth1.20（WAN，VLAN 20）── 筆電 eno2.20
#   eth0 和 eth1.20 移進 wgw netns；eth1 本身（沒有 VLAN 標籤）照常是 SSH 管理線，不動
# 前置：pi_lab_mode.sh up 1000、系統的 suricata 服務已停、sh make_configs.sh；wnc-gw 放在 $GW
# 用法: sudo bash planb_pi.sh up|down
#       sudo bash planb_pi.sh start <empty|full> <queues> <0|1 全部信任>
#       sudo bash planb_pi.sh stop
#       sudo bash planb_pi.sh counters   印 rx/tx 封包數和各種丟包計數（一行 key=value）
#   IMPL=nflog（start、stop）：不經過 wnc-gw，直接跑 suricata --nflog（ids 候選 B），看到 "Engine started" 才裝 table inet sq：
#     信任的 ct mark 先 accept（和 wnc-gw 一樣用到 conntrack），其餘 log group 10..（多個 group 用 symhash 分）
#     BUF（預設 1048576）是每個 group 的 netlink buffer；K（預設 none）是 Suricata 的 -k，K=all 會檢查 checksum
#     stop 時印 Suricata 每個 group 收到的封包數、tcp.invalid_checksum、detect.alert
#   PROTECTION=ips|ids（start，預設 ips）：wnc-gw 的 protection；ids 時 <queues> 是 group 數（10 起）
#   counters 另外印 eth0 送出、收到的 PAUSE（pause_tx0、pause_rx0）
#   MODE=routed（up、start）：eth0（10.99.1.1/24）、eth1.20（10.99.2.1/24）不接 bridge，Pi 做 IP 轉送；下一跳是假的 MAC
#     （02:00:00:99:0x:02，筆電的網卡不收，轉送出去的封包不會被筆電再轉到別的網路），pcap 的 LAN 網段（192.168.100.0/24、
#     192.168.1.0/24、10.0.1.0/24）經 eth0，其餘走 eth1.20；送進來的封包目的 MAC 要先改成 Pi 的（planb_run.sh routed_pcap）。
#     start 寫 mode = "routed"
#   COPIES=N（start，ids）：另外一個 table inet wnc_copy（forward priority 10，在 wnc-gw 之後）對每個封包多送 N 份 NFLOG 複本
#     （group 20..），每份由一個 tcpdump -i nflog:<group> -w /dev/null（只讀不做事，buffer 1 MiB，和 Suricata 的 group 一樣）接收；
#     SNAPLEN=n 時每份只複製前 n bytes。stop 時印每個讀取端的收到／丟掉數
#   FANOUT=N（start，ids）：wnc_copy 只送一份（group 20），由 ~/cpu_alloc/fanout 在 user space 分給 N 個讀取端（執行緒＋環狀緩衝）；
#     統計在 /dev/shm/fanout.stats；SNAPLEN 一樣適用
#   counters 的 nfl_log／nfl_drop 只算 Suricata 的 group（< 20），nfl_xlog／nfl_xdrop 是 wnc_copy 的複本和讀取端丟掉的
GW=${GW:-/tmp/wncgw/wnc-gw}; M=${M:-/tmp/wncgw/m}; L=/tmp/wncgw/planb; CT=${CT:-/home/wnc/ctbench/root/usr/sbin/conntrack}
LOG=/var/log/wnc-gw/suricata
W="ip netns exec wgw"
case "$1" in
up)
  ip netns add wgw
  $W sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  ip -n wgw link set lo up
  ip link add link eth1 name eth1.20 type vlan id 20
  ip link set eth1.20 netns wgw
  ip link set eth0 netns wgw
  if [ "${MODE:-bridge}" = routed ]; then
    ip -n wgw addr add 10.99.1.1/24 dev eth0
    ip -n wgw addr add 10.99.2.1/24 dev eth1.20
    for l in eth0 eth1.20; do ip -n wgw link set $l up; done
    $W sysctl -q -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
      net.ipv4.conf.eth0.rp_filter=0 net.ipv4.conf.eth1/20.rp_filter=0 \
      net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.eth0.send_redirects=0 net.ipv4.conf.eth1/20.send_redirects=0
    ip -n wgw neigh replace 10.99.1.2 lladdr 02:00:00:99:01:02 dev eth0 nud permanent
    ip -n wgw neigh replace 10.99.2.2 lladdr 02:00:00:99:02:02 dev eth1.20 nud permanent
    for n in 192.168.100.0/24 192.168.1.0/24 10.0.1.0/24; do ip -n wgw route add $n via 10.99.1.2 dev eth0; done
    ip -n wgw route add default via 10.99.2.2 dev eth1.20
  else
    modprobe br_netfilter
    ip -n wgw link add br0 type bridge
    for l in eth0 eth1.20; do ip -n wgw link set $l master br0; ip -n wgw link set $l up; done
    ip -n wgw link set br0 up
  fi
  mkdir -p $LOG $L
  mountpoint -q $LOG || mount -t tmpfs -o size=1g,mode=0750 wncgw-suricata-log $LOG
  ;;
down)
  pkill -INT -x wnc-gw; pkill -INT -x tcpdump; pkill -x fanout; sleep 2
  ip netns del wgw
  mountpoint -q $LOG && umount $LOG
  ;;
start)
  rs=$2; q=$3; trusted=$4
  mkdir -p $L
  if [ "${IMPL:-wncgw}" = nflog ]; then
    BUF=${BUF:-1048576}
    { awk '/^nflog:/{skip = 1; next} skip && /^[a-z#]/{skip = 0} !skip' $M/suricata-$rs.yaml
      echo "nflog:"; for i in $(seq 0 $((q - 1))); do printf '  - group: %d\n    buffer-size: %d\n' $((10 + i)) $BUF; done
      printf '  - group: default\n    qthreshold: 1\n    qtimeout: 100\n    max-size: %d\n' $((4 * BUF)); } > $L/suricata-nflog.yaml
    rm -f $LOG/*
    $W suricata -c $L/suricata-nflog.yaml --nflog -k ${K:-none} -l $LOG --set unix-command.enabled=no --set coredump.max-dump=0 > $L/run.log 2>&1 &
    echo $! > $L/suricata.pid
    for i in $(seq 1 300); do grep -q "Engine started" $L/run.log && break; sleep 1; done
    grep -q "Engine started" $L/run.log || { echo "not ready"; tail -5 $L/run.log; exit 1; }
    if [ "$q" -gt 1 ]; then
      vm=$(for i in $(seq 0 $((q - 1))); do printf '%d : jump g%d, ' $i $i; done)
      body="symhash mod $q vmap { ${vm%, } }"
      chains=$(for i in $(seq 0 $((q - 1))); do printf 'chain g%d { counter log group %d; }; ' $i $((10 + i)); done)
    else body="counter log group 10"; chains=; fi
    echo "table inet sq { chain f { type filter hook forward priority 0; policy accept; ct mark & 0x80000000 == 0x80000000 counter accept; $body; }; $chains}" | $W nft -f - || exit 1
    echo "ready impl=nflog rules=$rs groups=$q k=${K:-none} buf=$BUF"
    exit 0
  fi
  P=${PROTECTION:-ips}
  { printf 'mode = "%s"\nxdp = "off"\nprotection = "%s"\n\n[ports]\nlan = "eth0"\nwan = "eth1.20"\n\n[suricata]\nconfig = "%s"\nwhen_unavailable = "drop"\n' ${MODE:-bridge} $P "$M/suricata-$rs.yaml"
    if [ "$q" -gt 1 ]; then
      if [ $P = ids ]; then printf 'group = "10-%d"\n' $((9 + q)); else printf 'queue = "0-%d"\n' $((q - 1)); fi
    fi; } > $L/setting.toml
  rm -f $LOG/*
  $W $GW -c $L/setting.toml run > $L/run.out 2> $L/run.log &
  for i in $(seq 1 300); do grep -q "traffic is inspected" $L/run.log && break; sleep 1; done
  grep -q "traffic is inspected" $L/run.log || { echo "not ready"; tail -5 $L/run.log; exit 1; }
  if [ "$trusted" = 1 ]; then
    $W nft add table inet tmark
    $W nft add chain inet tmark pre '{ type filter hook prerouting priority 0; policy accept; }'
    $W nft add rule inet tmark pre ct mark set ct mark or 0x80000000
  fi
  # 上一次的讀取端沒結束的話 group 20.. 還被佔著，新的 tcpdump／fanout 綁不上
  if [ "${COPIES:-0}" -gt 0 ] || [ "${FANOUT:-0}" -gt 0 ]; then
    pgrep -a -x 'tcpdump|fanout' && { echo "error: leftover reader"; exit 1; }
  fi
  if [ "${COPIES:-0}" -gt 0 ]; then
    sl=; [ "${SNAPLEN:-0}" -gt 0 ] && sl="snaplen $SNAPLEN"
    rules=
    for i in $(seq 0 $((COPIES - 1))); do
      g=$((20 + i))
      # 截短交給規則的 snaplen；tcpdump 用 -s 128 時 libpcap 的接收緩衝只有約 256 bytes，kernel 一批送來的會被截掉（丟或結束）
      $W tcpdump -n -q -i nflog:$g -B 1024 -s 0 -w /dev/null > $L/reader$g.out 2>&1 < /dev/null &
      rules="$rules counter log group $g $sl;"
    done
    sleep 2
    [ "$(pgrep -x tcpdump | wc -l)" = "$COPIES" ] || { echo "reader did not start: $(cat $L/reader*.out | tr '\n' ' ')"; exit 1; }
    echo "table inet wnc_copy { chain f { type filter hook forward priority 10; policy accept;$rules }; }" | $W nft -f - || exit 1
  fi
  if [ "${FANOUT:-0}" -gt 0 ]; then
    sl=; [ "${SNAPLEN:-0}" -gt 0 ] && sl="snaplen $SNAPLEN"
    rm -f /dev/shm/fanout.stats
    $W /home/wnc/cpu_alloc/fanout 20 $FANOUT ${SNAPLEN:-0} > $L/fanout.out 2>&1 < /dev/null &
    sleep 2
    kill -0 $! 2> /dev/null || { echo "fanout did not start: $(cat $L/fanout.out)"; exit 1; }
    echo "table inet wnc_copy { chain f { type filter hook forward priority 10; policy accept; counter log group 20 $sl; }; }" | $W nft -f - || exit 1
  fi
  echo "ready mode=${MODE:-bridge} protection=$P rules=$rs queues=$q trusted=$trusted copies=${COPIES:-0} fanout=${FANOUT:-0} snaplen=${SNAPLEN:-0}"
  ;;
stop)
  if [ -e $L/suricata.pid ]; then
    $W nft delete table inet sq 2>/dev/null
    sleep 9   # stats.log 每 8 秒寫一次，等最後一段
    sp=$(cat $L/suricata.pid); rm -f $L/suricata.pid
    kill -TERM $sp; for i in $(seq 1 60); do kill -0 $sp 2>/dev/null || break; sleep 1; done
    $W $CT -F 2>/dev/null || true
    grep -h -o "(W#[0-9-]*) Pkts [0-9]*" $L/run.log | tr '\n' ' '
    for c in tcp.invalid_checksum detect.alert; do printf '%s=%s ' $c "$(grep "^$c " $LOG/stats.log | tail -1 | awk '{print $NF}')"; done; echo
    exit 0
  fi
  $W nft delete table inet wnc_copy 2> /dev/null
  if pgrep -x tcpdump > /dev/null; then
    pkill -INT -x tcpdump; sleep 1
    for f in $L/reader*.out; do printf '%s: %s\n' "$(basename $f .out)" "$(grep -E 'captured|received|dropped' $f | tr '\n' ' ')"; done
    rm -f $L/reader*.out
  fi
  if pgrep -x fanout > /dev/null; then
    echo "reader fanout: $(cat /dev/shm/fanout.stats 2> /dev/null)"
    # 背景啟動的程式會忽略 SIGINT（bash 沒有 job control 時），fanout 沒有自己處理，所以用 SIGTERM
    pkill -x fanout; for i in $(seq 1 20); do pgrep -x fanout > /dev/null || break; sleep 0.5; done
    rm -f /dev/shm/fanout.stats
  fi
  pkill -INT -x wnc-gw
  for i in $(seq 1 60); do pgrep -x wnc-gw > /dev/null || break; sleep 1; done
  $W nft delete table inet tmark 2>/dev/null
  $W $CT -F 2>/dev/null || true
  grep -h "Verdict" $L/run.log | sed 's/.*Verdict: //; s/ source=.*//'
  ;;
counters)
  s() { $W cat /sys/class/net/$1/statistics/$2; }
  qd=$($W cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null | awk '{d += $6 + $7} END{print d + 0}')
  ct=$($W $CT -S 2>/dev/null | awk '{for (i = 2; i <= NF; i++) { split($i, a, "="); s[a[1]] += a[2] }} END{printf "ct_insert_failed=%d ct_drop=%d", s["insert_failed"], s["drop"]}')
  # NFLOG：log 規則送出的複本（table inet sq，或 wnc-gw ids 模式的 table inet wnc_gw）、收複本的 netlink socket 的 Drops（都不在時是 0）
  logged() { awk '/log group/{for (i = 1; i <= NF; i++) if ($i == "packets") s += $(i + 1)} END{print s + 0}'; }
  nl=$({ $W nft list table inet sq; $W nft list table inet wnc_gw; } 2>/dev/null | logged)
  xl=$($W nft list table inet wnc_copy 2>/dev/null | logged)
  ids=$($W cat /proc/net/netfilter/nfnetlink_log 2>/dev/null | awk '$1 < 20 {print $2}' | tr '\n' ' ')
  xids=$($W cat /proc/net/netfilter/nfnetlink_log 2>/dev/null | awk '$1 >= 20 {print $2}' | tr '\n' ' ')
  drops() { $W awk -v ids=" $1" '$2 == 12 && index(ids, " " $3 " ") {d += $9} END{print d + 0}' /proc/net/netlink; }
  nd=$(drops "$ids"); xd=$(drops "$xids")
  pause=$($W ethtool -S eth0 | awk '/ tx_pause:/{t = $2} / rx_pause:/{r = $2} END{printf "pause_tx0=%d pause_rx0=%d", t, r}')
  echo "rx0=$(s eth0 rx_packets) tx0=$(s eth0 tx_packets) rx1=$(s eth1.20 rx_packets) tx1=$(s eth1.20 tx_packets) miss0=$(s eth0 rx_missed_errors) drop0=$(s eth0 rx_dropped) drop1=$(s eth1.20 rx_dropped) nfq_drop=$qd $ct nfl_log=$nl nfl_drop=$nd nfl_xlog=$xl nfl_xdrop=$xd $pause"
  ;;
*) sed -n '2,21p' "$0"; exit 2 ;;
esac
