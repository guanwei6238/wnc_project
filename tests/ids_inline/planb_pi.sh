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
GW=${GW:-/tmp/wncgw/wnc-gw}; M=${M:-/tmp/wncgw/m}; L=/tmp/wncgw/planb; CT=${CT:-/home/wnc/ctbench/root/usr/sbin/conntrack}
LOG=/var/log/wnc-gw/suricata
W="ip netns exec wgw"
case "$1" in
up)
  modprobe br_netfilter
  ip netns add wgw
  $W sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  ip -n wgw link set lo up
  ip link add link eth1 name eth1.20 type vlan id 20
  ip link set eth1.20 netns wgw
  ip link set eth0 netns wgw
  ip -n wgw link add br0 type bridge
  for l in eth0 eth1.20; do ip -n wgw link set $l master br0; ip -n wgw link set $l up; done
  ip -n wgw link set br0 up
  mkdir -p $LOG $L
  mountpoint -q $LOG || mount -t tmpfs -o size=1g,mode=0750 wncgw-suricata-log $LOG
  ;;
down)
  pkill -INT -x wnc-gw; sleep 2
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
  { printf 'mode = "bridge"\nxdp = "off"\n\n[ports]\nlan = "eth0"\nwan = "eth1.20"\n\n[suricata]\nconfig = "%s"\nwhen_unavailable = "drop"\n' "$M/suricata-$rs.yaml"
    [ "$q" -gt 1 ] && printf 'queue = "0-%d"\n' $((q - 1)); } > $L/setting.toml
  rm -f $LOG/*
  $W $GW -c $L/setting.toml run > $L/run.out 2> $L/run.log &
  for i in $(seq 1 300); do grep -q "traffic is inspected" $L/run.log && break; sleep 1; done
  grep -q "traffic is inspected" $L/run.log || { echo "not ready"; tail -5 $L/run.log; exit 1; }
  if [ "$trusted" = 1 ]; then
    $W nft add table inet tmark
    $W nft add chain inet tmark pre '{ type filter hook prerouting priority 0; policy accept; }'
    $W nft add rule inet tmark pre ct mark set ct mark or 0x80000000
  fi
  echo "ready rules=$rs queues=$q trusted=$trusted"
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
  # NFLOG：log 規則送出的複本、收複本的 netlink socket 的 Drops（table inet sq 不在時都是 0）
  nl=$($W nft list table inet sq 2>/dev/null | awk '/log group/{for (i = 1; i <= NF; i++) if ($i == "packets") s += $(i + 1)} END{print s + 0}')
  ids=$($W cat /proc/net/netfilter/nfnetlink_log 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
  nd=$($W awk -v ids=" $ids" '$2 == 12 && index(ids, " " $3 " ") {d += $9} END{print d + 0}' /proc/net/netlink)
  echo "rx0=$(s eth0 rx_packets) tx0=$(s eth0 tx_packets) rx1=$(s eth1.20 rx_packets) tx1=$(s eth1.20 tx_packets) miss0=$(s eth0 rx_missed_errors) drop0=$(s eth0 rx_dropped) drop1=$(s eth1.20 rx_dropped) nfq_drop=$qd $ct nfl_log=$nl nfl_drop=$nd"
  ;;
*) sed -n '2,11p' "$0"; exit 2 ;;
esac
