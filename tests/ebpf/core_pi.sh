#!/bin/bash
# 核心 eBPF 程式在 Pi 上的功能驗證；不碰 eth0、eth1
#   bridge（預設）：ecli(c0 10.8.0.1, fd08::1) --veth-- lan0 [egw: br0] wan0 --veth-- s0(esrv 10.8.0.2, fd08::2)
#   ROUTED=1：     ecli(c0 10.9.1.2, fd09:1::2) --veth-- lan0 10.9.1.1 [egw: 轉送] wan0 10.9.2.1 --veth-- s0(esrv 10.9.2.2, fd09:2::2)
#   up、down 和其他子命令要用同一個 ROUTED
# 用法: sudo bash core_pi.sh up|run|show|tcx|fastpath|auto|kill9|down（tcx 要 foreign_tcx.py 放在同一個目錄）
GW=${GW:-/tmp/wncgw/wnc-gw}; D=/tmp/wncgw/ebpf; ROUTED=${ROUTED:-0}
if [ "$ROUTED" = 1 ]; then MODE=routed; CLI4=10.9.1.2; SRV4=10.9.2.2; CLI6=fd09:1::2; SRV6=fd09:2::2
else MODE=bridge; CLI4=10.8.0.1; SRV4=10.8.0.2; CLI6=fd08::1; SRV6=fd08::2; fi
G="ip netns exec egw"; C="ip netns exec ecli"; S="ip netns exec esrv"

setup() {
  mkdir -p $D
  echo 'alert icmp any any -> any any (msg:"core icmp"; sid:1000301; rev:1;)' > $D/test.rules
  printf '%%YAML 1.1\n---\ninclude: /etc/suricata/suricata.yaml\ndefault-rule-path: %s\nrule-files:\n  - test.rules\n' $D > $D/s.yaml
  printf 'mode = "%s"\n\n[ports]\nlan = "lan0"\nwan = "wan0"\n\n[suricata]\nconfig = "%s"\n' $MODE $D/s.yaml > $D/setting.toml
}

start() {
  rm -f $D/run.log $D/exit
  ( $G $GW -c $D/setting.toml run > /dev/null 2> $D/run.log; echo $? > $D/exit ) &
  for i in $(seq 1 150); do
    grep -q "traffic is inspected" $D/run.log 2>/dev/null && return 0
    [ -e $D/exit ] && break; sleep 0.2
  done
  echo "wnc-gw did not start"; tail -5 $D/run.log; return 1
}

SRVPY='import socket, sys
family = socket.AF_INET6 if ":" in sys.argv[2] else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM if sys.argv[1] == "tcp" else socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((sys.argv[2], 5001)); n = 0
if sys.argv[1] == "tcp":
    s.listen(4)
    while True:
        c, _ = s.accept()
        for line in c.makefile(): n += 1
        print("lines", n, flush=True)
else:
    while True:
        s.recv(2048); n += 1; print("datagrams", n, flush=True)'
CLIPY='import socket, sys, time
proto, src, dst, port, secs = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5])
family = socket.AF_INET6 if ":" in src else socket.AF_INET
s = socket.socket(family, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((src, port)); s.connect((dst, 5001))
end = time.time() + secs; n = 0
while time.time() < end:
    s.send(b"line\n"); n += 1; time.sleep(0.1)
s.close(); print("sent", n)'
fwd() { $G nft list chain inet wnc_gw forward | grep -m1 -o "packets [0-9]*" | cut -d" " -f2; }
ids() { $G nft list chain inet wnc_gw ids | grep -m1 -o "packets [0-9]*" | cut -d" " -f2; }
stop_run() { kill -INT $(pgrep -n -x wnc-gw); until [ -e $D/exit ]; do sleep 0.2; done; }

flow() {  # $1 = tcp|udp，$2 = 來源，$3 = 目的：3 秒時信任、9 秒時取消，共 16 秒
  pkill -f "$D/srv.py"; echo "$SRVPY" > $D/srv.py; echo "$CLIPY" > $D/cli.py
  $S python3 $D/srv.py $1 $3 > $D/srv.out 2>&1 & sleep 0.5
  $C python3 $D/cli.py $1 $2 $3 42000 16 > $D/cli.out & cp=$!; sleep 3
  $GW trust add $1 $2 42000 $3 5001 && echo "   trust add: ok"
  f0=$(fwd); sleep 3; f1=$(fwd); echo "   forward chain while trusted: $f0 -> $f1"
  $GW trust list | sed 's/^/   /'
  [ $1 = tcp ] && $S timeout 2 tcpdump -c 3 -n -v -i s0 "tcp port 5001 and src $2" 2>/dev/null | grep -o -E "(ttl|hlim) [0-9]*" | sort | uniq -c | sed 's/^/   tcpdump: /'
  sleep 3; $GW trust del $1 $2 42000 $3 5001 && echo "   trust del: ok"
  f2=$(fwd); sleep 2; f3=$(fwd); echo "   forward chain after del: $f2 -> $f3"
  wait $cp; sleep 1; echo "   client: $(cat $D/cli.out), server: $(tail -1 $D/srv.out)"; pkill -f "$D/srv.py"
}

case "$1" in
up)
  modprobe br_netfilter
  for ns in ecli esrv egw; do
    ip netns add $ns
    ip -n $ns link set lo up
  done
  ip netns exec egw sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  ip link add c0 netns ecli type veth peer name lan0 netns egw
  ip link add s0 netns esrv type veth peer name wan0 netns egw
  if [ "$ROUTED" = 1 ]; then
    $G sysctl -q -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
    $G sysctl -q -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
    ip -n egw addr add 10.9.1.1/24 dev lan0; ip -n egw addr add 10.9.2.1/24 dev wan0
    ip -n egw addr add fd09:1::1/64 dev lan0 nodad; ip -n egw addr add fd09:2::1/64 dev wan0 nodad
    for l in lan0 wan0; do ip -n egw link set $l up; done
    ip -n ecli addr add 10.9.1.2/24 dev c0; ip -n ecli addr add fd09:1::2/64 dev c0 nodad; ip -n ecli link set c0 up
    ip -n esrv addr add 10.9.2.2/24 dev s0; ip -n esrv addr add fd09:2::2/64 dev s0 nodad; ip -n esrv link set s0 up
    ip -n ecli route add default via 10.9.1.1; ip -n ecli -6 route add default via fd09:1::1
    ip -n esrv route add default via 10.9.2.1; ip -n esrv -6 route add default via fd09:2::1
  else
    ip -n egw link add br0 type bridge
    for l in lan0 wan0; do ip -n egw link set $l master br0; ip -n egw link set $l up; done
    ip -n egw link set br0 up
    ip -n ecli addr add 10.8.0.1/24 dev c0; ip -n ecli link set c0 up
    ip -n esrv addr add 10.8.0.2/24 dev s0; ip -n esrv link set s0 up
    ip -n ecli addr add fd08::1/64 dev c0 nodad; ip -n esrv addr add fd08::2/64 dev s0 nodad
  fi
  modprobe nf_conntrack; $G sysctl -q -w net.netfilter.nf_conntrack_acct=1
  $C ping -c 1 -W 2 $SRV4 | grep -o "1 received"
  ;;
run)
  setup; start || exit 1
  $C ping -c 5 -i 0.2 -W 2 $SRV4 | grep -o "[0-9]* received"
  kill -INT $(pgrep -n -x wnc-gw); until [ -e $D/exit ]; do sleep 0.2; done
  echo "wnc-gw exit=$(cat $D/exit)"
  grep -E "core ebpf|D001|ERROR" $D/run.log | cut -c28-
  ;;
show)
  setup; start || exit 1
  $C ping -c 3 -i 0.2 -W 2 $SRV4 | grep -o "[0-9]* received"
  $G bpftool net show | grep tcx
  map=$(bpftool prog show name wnc_gw_ingress | grep -o "map_ids [0-9]*" | cut -d" " -f2)
  bpftool map dump id $map
  kill -INT $(pgrep -n -x wnc-gw); until [ -e $D/exit ]; do sleep 0.2; done
  ;;
tcx)
  setup
  F="$(dirname "$0")/foreign_tcx.py"
  $G python3 $F lan0 last before_run > /dev/null & F0=$!; sleep 1
  echo "--- doctor (root)"; $G $GW -c $D/setting.toml doctor | sed -n '/TCX INGRESS/,/^$/p;/D00/p'
  echo "--- doctor (wnc)"; $G sudo -u wnc $GW -c $D/setting.toml doctor | sed -n '/TCX INGRESS/,/^$/p;/D00/p'
  start || exit 1
  $G bpftool net show dev lan0 | grep tcx
  $G python3 $F lan0 first jumper > /dev/null & F1=$!; sleep 11
  kill $F1; sleep 10
  link=$($G bpftool net show dev lan0 | grep wnc_gw_ingress | grep -o "link_id [0-9]*" | cut -d" " -f2)
  bpftool link detach id $link; sleep 10
  kill -INT $(pgrep -n -x wnc-gw); until [ -e $D/exit ]; do sleep 0.2; done
  kill $F0
  echo "--- run log"; grep -E "D00|core ebpf" $D/run.log | cut -c28-
  ;;
fastpath)
  setup; start || exit 1
  for f in "tcp $CLI4 $SRV4" "udp $CLI4 $SRV4" "tcp $CLI6 $SRV6"; do echo "=== $MODE: $f"; flow $f; done
  stop_run; grep -E "trusted by request|no longer trusted|core ebpf program detached|ERROR|WARN" $D/run.log | cut -c28-220
  ;;
auto)
  setup; printf '\n[trust]\nauto = true\nmin_packets = 5\nmin_age = 2\nttl = 10\ncheck_interval = 1\n' >> $D/setting.toml
  echo 'alert tcp any any -> any 5001 (msg:"core fin"; flow:to_server; flags:F+; sid:1000302; rev:1;)' >> $D/test.rules
  start || exit 1
  pkill -f "$D/srv.py"; echo "$SRVPY" > $D/srv.py; echo "$CLIPY" > $D/cli.py
  $S python3 $D/srv.py tcp $SRV4 > $D/srv.out 2>&1 & sleep 0.5
  $C python3 $D/cli.py tcp $CLI4 $SRV4 42001 25 > $D/cli.out & cp=$!
  sleep 1; c1=$(ids); sleep 4; c2=$(ids); sleep 3; c3=$(ids)
  echo "   ids chain at 1 s, 5 s, 8 s: $c1 $c2 $c3 (trusted from about 3 s)"
  wait $cp; sleep 2; echo "   client: $(cat $D/cli.out), server: $(tail -1 $D/srv.out)"; pkill -f "$D/srv.py"
  stop_run; grep -E "automatic trust|connection trusted|trust expired|trust revoked|core ebpf program detached|ERROR" $D/run.log | cut -c28-220
  ;;
kill9)
  setup; start || exit 1
  $G bpftool net show dev lan0 2>/dev/null | grep tcx
  kill -9 $(pgrep -n -x wnc-gw); sleep 1
  echo "tcx programs on lan0 after kill -9: $($G bpftool net show dev lan0 2>/dev/null | grep -c tcx)"
  $G nft delete table inet wnc_gw 2>/dev/null; true
  ;;
down)
  for ns in ecli esrv egw; do ip netns del $ns 2>/dev/null; done; true
  ;;
*) echo "usage: sudo bash core_pi.sh up|run|show|tcx|fastpath|auto|kill9|down"; exit 2 ;;
esac
