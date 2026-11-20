#!/bin/bash
# 3b when the connection table is full (Pi, bridge): are trusted connections affected (wgw/wtest already set up, run as root)
#   fcli(10.9.0.1) --veth-- x-lan [wgw: br0] x-wan --veth-- fsrv(10.9.0.2): a TCP connection sending a line every 0.2 s; at t=2 conntrack -U sets the trust bit
#   from t=4 wtest sends 39-1 (IRCBot scan) through the same br0 with tcpreplay; prints the conntrack count, this connection's entry, early_drop and other counters every second
#   PROTO=udp: the trusted flow becomes one-way UDP (fcli:40001 sends one to fsrv:5001 every 0.2 s, fsrv only receives → the entry stays UNREPLIED, never assured)
# Prerequisites: sudo sh env.sh up; sh make_configs.sh; system suricata service stopped; wnc-gw at $GW; nf_conntrack_netlink loaded
# Usage: sudo [PROTO=udp] bash ctfull_pi.sh <pps|x1> <scan seconds>
#   x1 = original timing. The 39-1 scan is only in the last 78 s of the pcap, so cut it out first (frame 17234 is the first packet ≥ 505 s):
#     editcap -F pcap -r S_m39.pcap S_m39_scan.pcap 17234-200000; tcpprep --mac=78:8a:20:43:93:d5 --pcap=S_m39_scan.pcap --cachefile=S_m39_scan.cache
#     then pass PCAP=…/S_m39_scan.pcap CACHE=…/S_m39_scan.cache
CT=${CT:-/home/wnc/ctbench/root/usr/sbin/conntrack}; GW=${GW:-/tmp/wncgw/wnc-gw}; M=${M:-/tmp/wncgw/m}; L=/tmp/wncgw/ctfull
PCAP=${PCAP:-/home/wnc/ids_throughput/data/pcaps/S_m39.pcap}; CACHE=${CACHE:-$M/cache/S_m39.cache}; PROTO=${PROTO:-tcp}
rate=${1:?usage: ctfull_pi.sh <pps|x1> <scan seconds>}; secs=${2:?usage: ctfull_pi.sh <pps|x1> <scan seconds>}
rm -rf $L; mkdir -p $L
for ns in fcli fsrv; do ip netns add $ns; ip netns exec $ns sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1; ip -n $ns link set lo up; done
ip link add c-lan netns fcli type veth peer name x-lan netns wgw
ip link add s-wan netns fsrv type veth peer name x-wan netns wgw
for l in x-lan x-wan; do ip -n wgw link set $l master br0; ip -n wgw link set $l up; done
ip -n fcli addr add 10.9.0.1/24 dev c-lan; ip -n fcli link set c-lan up
ip -n fsrv addr add 10.9.0.2/24 dev s-wan; ip -n fsrv link set s-wan up
ip netns exec wgw $CT -F 2>/dev/null
ip netns exec wgw nft -f - <<'NFT'
table inet obs {
  counter pkts {}
  counter untrusted {}
  chain f {
    type filter hook forward priority -10; policy accept;
    ip saddr 10.9.0.0/24 ip daddr 10.9.0.0/24 counter name "pkts"
    ip saddr 10.9.0.0/24 ip daddr 10.9.0.0/24 ct mark & 0x80000000 == 0 counter name "untrusted"
  }
}
NFT
taskset -c 2,3 ip netns exec wgw $GW -c $M/setting-empty.toml run > $L/run.log 2>&1 &
gp=$!
until grep -q "traffic is inspected" $L/run.log; do sleep 0.2; kill -0 $gp 2>/dev/null || { cat $L/run.log; exit 1; }; done
ctstats() { ip netns exec wgw $CT -S | awk '{for (i = 2; i <= NF; i++) { split($i, a, "="); s[a[1]] += a[2] }} END{print s["invalid"]+0, s["insert_failed"]+0, s["drop"]+0, s["early_drop"]+0}'; }
read -r i0 f0 d0 e0 < <(ctstats)
nfqdrop() { ip netns exec wgw cat /proc/net/netfilter/nfnetlink_queue | awk '{s += $6 + $7} END{print s + 0}'; }
qd0=$(nfqdrop)
obs() { ip netns exec wgw nft list counters table inet obs | awk '/counter /{n=$2} /packets/{printf "%s=%s ", n, $2}'; }
if [ $PROTO = udp ]; then
ip netns exec fsrv python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("", 5001)); out = open("/tmp/wncgw/ctfull/srv.log", "w")
while True:
    out.write(s.recv(100).decode()); out.flush()
' &
else
ip netns exec fsrv python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 5001)); s.listen(1)
c, _ = s.accept(); out = open("/tmp/wncgw/ctfull/srv.log", "w")
for line in c.makefile():
    out.write(line); out.flush()
' &
fi
sleep 0.5
total=$(( (secs + 12) * 5 ))
if [ $PROTO = udp ]; then
ip netns exec fcli python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('', 40001))
for i in range($total):
    s.sendto(f'line {i}\\n'.encode(), ('10.9.0.2', 5001)); time.sleep(0.2)
" &
else
ip netns exec fcli bash -c "exec 3<>/dev/tcp/10.9.0.2/5001 || exit 1; for i in \$(seq $total); do echo \"line \$i\" >&3 || { echo \"write failed at \$i\" > $L/cli.err; exit 1; }; sleep 0.2; done; exec 3>&-" &
fi
cp=$!
sp=
getudp() { ip netns exec wgw $CT -G -p udp -s 10.9.0.1 -d 10.9.0.2 --sport 40001 --dport 5001 2>/dev/null | awk '{m = "mark=0"; for (i = 1; i <= NF; i++) if ($i ~ /^mark=/) m = $i; printf "timeout=%s %s %s", $3, ($0 ~ /UNREPLIED/ ? "unreplied" : ($0 ~ /ASSURED/ ? "assured" : "-")), m}'; }
get() { ip netns exec wgw $CT -G -p tcp -s 10.9.0.1 -d 10.9.0.2 --sport $sp --dport 5001 2>/dev/null | awk '{m = "mark=0"; for (i = 1; i <= NF; i++) if ($i ~ /^mark=/) m = $i; printf "%s %s %s", $4, ($0 ~ /ASSURED/ ? "assured" : "-"), m}'; }
echo "== ctfull proto=$PROTO rate=$rate scan=${secs}s max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
for t in $(seq 1 $((secs + 10))); do
  sleep 1
  case $t in
  2) sp=$(ip netns exec wgw $CT -L -p $PROTO --orig-dst 10.9.0.2 --dport 5001 2>/dev/null | grep -o 'sport=[0-9]*' | head -1 | cut -d= -f2)
     echo "   -- t=2 trust $PROTO sport=$sp: $(ip netns exec wgw $CT -U -p $PROTO --orig-src 10.9.0.1 --orig-dst 10.9.0.2 --orig-port-dst 5001 --mark 0x80000000/0x80000000 2>&1 | tail -1)" ;;
  4) if [ $rate = x1 ]; then opt=--multiplier=1; else opt="--pps=$rate"; fi
     ip netns exec wtest timeout -s INT $secs taskset -c 1 tcpreplay -T nano -i t-wan -I t-lan -c $CACHE $opt $PCAP > $L/tcpreplay.txt 2>&1 &
     echo "   -- t=4 scan started ($opt)" ;;
  esac
  read -r i1 f1 d1 e1 < <(ctstats)
  printf "t=%-3s count=%-6s entry=[%s] %s invalid=%s insert_failed=%s drop=%s early_drop=%s nfq_drop=%s srv=%s\n" $t \
    "$(ip netns exec wgw cat /proc/sys/net/netfilter/nf_conntrack_count)" "$([ -n "$sp" ] && { [ $PROTO = udp ] && getudp || get; })" "$(obs)" \
    $((i1 - i0)) $((f1 - f0)) $((d1 - d0)) $((e1 - e0)) $(( $(nfqdrop) - qd0 )) "$(wc -l < $L/srv.log 2>/dev/null || echo 0)"
done
wait $cp; echo "client exit=$? sent=$total received=$(wc -l < $L/srv.log)"; cat $L/cli.err 2>/dev/null
grep -E "Actual|Rated|Failed" $L/tcpreplay.txt
kill -INT $gp; wait $gp; echo "wnc-gw exit=$?"
grep -E "Treated|Verdict" $L/run.log | sed "s/^.*nfq: //"
dmesg | grep -c "nf_conntrack: table full" | sed 's/^/dmesg "table full" lines: /'
ip netns exec wgw nft delete table inet obs
for ns in fcli fsrv; do ip netns del $ns; done
pkill -f "ctfull/srv.log" 2>/dev/null
