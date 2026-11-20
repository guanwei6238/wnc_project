#!/bin/bash
# Plan B: multi-queue measurement with externally generated traffic, Pi side (bridge)
#   laptop USB NIC ── Pi eth0 (LAN) [wgw: br0] Pi eth1.20 (WAN, VLAN 20) ── laptop eno2.20
#   eth0 and eth1.20 move into the wgw netns; eth1 itself (untagged) stays the SSH management link, untouched
# Prerequisites: pi_lab_mode.sh up 1000, system suricata service stopped, sh make_configs.sh; wnc-gw at $GW
# Usage: sudo bash planb_pi.sh up|down
#       sudo bash planb_pi.sh start <empty|full> <queues> <0|1 trust all>
#       sudo bash planb_pi.sh stop
#       sudo bash planb_pi.sh counters   print rx/tx packet counts and all drop counters (one line of key=value)
#   IMPL=nflog (start, stop): bypass wnc-gw and run suricata --nflog directly (ids candidate B); install table inet sq once "Engine started" appears:
#     trusted ct marks are accepted first (uses conntrack, same as wnc-gw), the rest go to log group 10.. (multiple groups split by symhash)
#     BUF (default 1048576) is each group's netlink buffer; K (default none) is Suricata's -k, K=all validates checksums
#     stop prints the packets Suricata received per group, tcp.invalid_checksum, detect.alert
#   PROTECTION=ips|ids (start, default ips): wnc-gw's protection; with ids, <queues> is the number of groups (starting at 10)
#   counters also prints PAUSE frames sent and received on eth0 (pause_tx0, pause_rx0)
#   MODE=routed (up, start): eth0 (10.99.1.1/24) and eth1.20 (10.99.2.1/24) are not bridged, the Pi does IP forwarding; the next hop is a fake MAC
#     (02:00:00:99:0x:02, which the laptop NIC does not accept, so forwarded packets are not routed on by the laptop); pcap LAN subnets (IoT-23 192.168.100.0/24,
#     192.168.1.0/24, 10.0.1.0/24, 192.168.2.0/24, CIC-IDS2017 192.168.10.0/24, CIC-DDoS2019 192.168.50.0/24, CICIoT2023
#     192.168.137.0/24) go via eth0, the rest via eth1.20; incoming packets need their destination MAC rewritten to the Pi's first (planb_run.sh routed_pcap).
#     start writes mode = "routed"
#   TRUST_BACKEND=tc|ctmark (start): written to [trust] backend in setting.toml; omitted if unset (wnc-gw defaults to tc)
#   FEATURE=tc-egress|tc-ingress|xdp-generic (start): adds one [[features]] (flows_tc or flows_xdp in /tmp/wncgw/feat/prog.o,
#     flows.json, tests/features/); output in /var/log/wnc-gw/features/f.jsonl (on tmpfs while measuring, not the SD card; experiment 15)
#   COPIES=N (start, ids): a separate table inet wnc_copy (forward priority 10, after wnc-gw) sends N extra NFLOG copies of every packet
#     (group 20..), each received by a tcpdump -i nflog:<group> -w /dev/null (read only, buffer 1 MiB, same as Suricata's groups);
#     with SNAPLEN=n each copy holds only the first n bytes. stop prints received/dropped per reader
#   FANOUT=N (start, ids): wnc_copy sends one copy (group 20), which ~/cpu_alloc/fanout splits to N readers in user space (threads + ring buffers);
#     stats in /dev/shm/fanout.stats; SNAPLEN applies too
#   counters' nfl_log/nfl_drop count only Suricata's groups (< 20); nfl_xlog/nfl_xdrop are wnc_copy's copies and the readers' drops
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
    for n in 192.168.100.0/24 192.168.1.0/24 10.0.1.0/24 192.168.2.0/24 192.168.10.0/24 192.168.50.0/24 192.168.137.0/24; do
      ip -n wgw route add $n via 10.99.1.2 dev eth0
    done
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
  # Keep the previous Suricata stats (incl. ips.drop_reason.*); the log directory below gets cleared
  [ -s $LOG/stats.log ] && cp $LOG/stats.log $L/stats-$(date -u +%Y%m%dT%H%M%S).log
  { printf 'mode = "%s"\nxdp = "off"\nprotection = "%s"\n\n[ports]\nlan = "eth0"\nwan = "eth1.20"\n\n[suricata]\nconfig = "%s"\nwhen_unavailable = "drop"\n' ${MODE:-bridge} $P "$M/suricata-$rs.yaml"
    if [ "$q" -gt 1 ]; then
      if [ $P = ids ]; then printf 'group = "10-%d"\n' $((9 + q)); else printf 'queue = "0-%d"\n' $((q - 1)); fi
    fi
    [ -n "$TRUST_BACKEND" ] && printf '\n[trust]\nbackend = "%s"\n' "$TRUST_BACKEND"
    case "$FEATURE" in
    tc-egress|tc-ingress) printf '\n[[features]]\nname = "f"\nprogram = "/tmp/wncgw/feat/prog.o"\nentry = "flows_tc"\ndefinition = "/tmp/wncgw/feat/flows.json"\nhook = "%s"\n' $FEATURE ;;
    xdp-generic) printf '\n[[features]]\nname = "f"\nprogram = "/tmp/wncgw/feat/prog.o"\nentry = "flows_xdp"\ndefinition = "/tmp/wncgw/feat/flows.json"\nhook = "xdp"\nxdp_mode = "generic"\n' ;;
    esac; } > $L/setting.toml
  rm -f $LOG/*
  if [ -n "$FEATURE" ]; then mkdir -p $LOG/../features; mountpoint -q $LOG/../features || mount -t tmpfs -o size=512m,mode=0750 wncgw-features $LOG/../features; rm -f $LOG/../features/*; fi
  $W $GW -c $L/setting.toml run > $L/run.out 2> $L/run.log &
  for i in $(seq 1 300); do grep -q "traffic is inspected" $L/run.log && break; sleep 1; done
  grep -q "traffic is inspected" $L/run.log || { echo "not ready"; tail -5 $L/run.log; exit 1; }
  if [ "$trusted" = 1 ]; then
    $W nft add table inet tmark
    $W nft add chain inet tmark pre '{ type filter hook prerouting priority 0; policy accept; }'
    $W nft add rule inet tmark pre ct mark set ct mark or 0x80000000
  fi
  # If the previous readers have not exited, group 20.. is still taken and the new tcpdump/fanout cannot bind
  if [ "${COPIES:-0}" -gt 0 ] || [ "${FANOUT:-0}" -gt 0 ]; then
    pgrep -a -x 'tcpdump|fanout' && { echo "error: leftover reader"; exit 1; }
  fi
  if [ "${COPIES:-0}" -gt 0 ]; then
    sl=; [ "${SNAPLEN:-0}" -gt 0 ] && sl="snaplen $SNAPLEN"
    rules=
    for i in $(seq 0 $((COPIES - 1))); do
      g=$((20 + i))
      # Truncation is left to the rule's snaplen; with tcpdump -s 128 libpcap's receive buffer is only about 256 bytes and a batch from the kernel gets truncated (dropped or exits)
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
    sleep 9   # stats.log is written every 8 s; wait for the last interval
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
    # Background processes ignore SIGINT (bash without job control) and fanout does not handle it itself, so use SIGTERM
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
  # NFLOG: copies sent by log rules (table inet sq, or table inet wnc_gw in wnc-gw ids mode) and Drops on the netlink sockets receiving them (0 when absent)
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
