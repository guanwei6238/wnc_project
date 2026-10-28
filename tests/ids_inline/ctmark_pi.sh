#!/bin/bash
# 3a 功能驗證（Pi，bridge）：sudo bash ctmark_pi.sh <nol2|l2>
# fcli(10.9.0.1) --veth-- [fgw: br0] --veth-- fsrv(10.9.0.2)；Suricata 直接跑 NFQ 在 fgw；conntrack -U 在 fgw 改 mark
v=$1; CT=/home/wnc/ctbench/root/usr/sbin/conntrack; T=/tmp/wncgw/t3a
for ns in fgw fcli fsrv; do ip netns add $ns; ip netns exec $ns sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1; ip -n $ns link set lo up; done
ip link add c-lan netns fcli type veth peer name f-lan netns fgw
ip link add s-wan netns fsrv type veth peer name f-wan netns fgw
ip -n fgw link add br0 type bridge; ip -n fgw link set f-lan master br0; ip -n fgw link set f-wan master br0
for l in br0 f-lan f-wan; do ip -n fgw link set $l up; done
ip -n fcli addr add 10.9.0.1/24 dev c-lan; ip -n fcli link set c-lan up
ip -n fsrv addr add 10.9.0.2/24 dev s-wan; ip -n fsrv link set s-wan up
mkdir -p $T/rules; rm -f $T/fast.log $T/stats.log
echo 'alert tcp any any -> any 5001 (msg:"wnc midstream mark"; content:"WNC-MARK"; sid:1000002; rev:1;)' > $T/rules/mid.rules
sed -e "s|^default-rule-path: .*|default-rule-path: $T/rules|" -e "s|^  - suricata.rules\$|  - mid.rules|" /etc/suricata/suricata.yaml > $T/s.yaml
ip netns exec fgw suricata -c $T/s.yaml -q 0 -l $T --set unix-command.enabled=no --set coredump.max-dump=0 --set stream.midstream=true --set stream.midstream-policy=ignore > $T/out.txt 2>&1 &
sp=$!
until grep -q "Engine started" $T/out.txt; do sleep 0.2; done
l2=""; [ "$v" = l2 ] && l2='meta l4proto tcp tcp flags & (fin | syn | rst) != 0 counter name "l2" queue num 0'
ip netns exec fgw nft -f - <<NFT
table inet t3a {
  counter trusted {}
  counter queued {}
  counter l2 {}
  chain forward {
    type filter hook forward priority 0; policy accept;
    $l2
    ct mark & 0x1 == 0x1 counter name "trusted" accept
    counter name "queued" queue num 0
  }
}
NFT
ip netns exec fsrv python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 5001)); s.listen(1)
c, _ = s.accept(); f = c.makefile(); out = open("/tmp/wncgw/t3a/srv.log", "w")
for line in f:
    out.write(line); out.flush()
' &
sleep 0.5
ip netns exec fcli bash -c 'exec 3<>/dev/tcp/10.9.0.2/5001; for i in $(seq 100); do echo "line $i WNC-MARK" >&3 || exit 1; sleep 0.2; done; exec 3>&-' &
mark() { ip netns exec fgw $CT -U -p tcp --orig-src 10.9.0.1 --orig-dst 10.9.0.2 --orig-port-dst 5001 --mark $1 2>&1 | grep -o "mark=[0-9]*\|updated" | head -1; }
cnt() { ip netns exec fgw nft list counters table inet t3a | awk '/counter /{n=$2} /packets/{printf "%s=%s ", n, $2}'; }
echo "== pi $v"
for t in $(seq 1 24); do
  sleep 1
  case $t in
  4) echo "   -- t=4 set mark 1: $(mark 1)";;
  10) [ "$v" = nol2 ] && echo "   -- t=10 set mark 0: $(mark 0)";;
  esac
  printf "t=%-3s %s alerts=%s srv_lines=%s\n" $t "$(cnt)" "$(grep -c 1000002 $T/fast.log 2>/dev/null || echo 0)" "$(wc -l < $T/srv.log 2>/dev/null || echo 0)"
done
kill -INT $sp; wait $sp
grep -E "Treated|Verdict" $T/out.txt | sed "s/^.*nfq: //"
for ns in fgw fcli fsrv; do ip netns del $ns; done
rm -rf $T
