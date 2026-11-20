#!/bin/bash
# wnc-gw's own CPU: after trusting all 8,360 connections of I23_Benign_Final, two phases (no traffic / 20 kpps), bridge and routed
# Prerequisites same as trust_run.sh; results printed to stdout
D=$(cd "$(dirname "$0")" && pwd); O=/home/sixsquare/datasets/throughput/cpu_alloc
LAN=enx9c69d3241bd9; WAN=eno2; PI=wnc@10.254.254.2; G="docker exec wnc-gen"; P="sudo bash ~/cpu_alloc/alloc_pi.sh"; s=I23_Benign_Final
gwns() { ssh $PI 'p=$(pgrep -x wnc-gw); for t in /proc/$p/task/*; do printf "%s " "$(cat $t/comm)"; cut -d" " -f1 $t/schedstat; done' | awk '{a[$1] += $2; s += $2} END{printf "total=%d", s; for (k in a) printf " %s=%d", k, a[k]}'; }
phase() {  # phase <name> <seconds> [pps]: CPU used by each wnc-gw thread during this phase (ms/s)
  local a=$(gwns) t0=$(date +%s.%N)
  if [ -n "$3" ]; then $G tcpreplay -i $LAN -I $WAN.20 -c $c --pps=$3 --loop=$(( $3 * $2 / n + 1 )) --duration=$2 $f > /dev/null 2>&1; else sleep $2; fi
  local b=$(gwns) t1=$(date +%s.%N)
  python3 -I -c "
import sys
a = dict(x.split('=') for x in sys.argv[1].split()); b = dict(x.split('=') for x in sys.argv[2].split()); dt = float(sys.argv[4]) - float(sys.argv[3])
print(sys.argv[5], f'{dt:.1f}s', ' '.join(f'{k}={(int(b[k]) - int(a.get(k, 0))) / 1e6 / dt:.1f}ms/s' for k in b))" "$a" "$b" $t0 $t1 "$m $1"
}
for m in routed bridge; do
  bash $D/alloc_run.sh mode $m > /dev/null
  b=/out/trust/$s.fp; [ $m = routed ] && b=$b.rt; f=$b.pcap; c=$b.cache
  n=$($G tcpprep --print-stats=$c 2>/dev/null | awk '/Total packets/{print $3}')
  ssh $PI "sudo MODE=$m PROTECTION=ips bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1
  $G sh -c "tcpreplay -i $LAN -I $WAN.20 -c $c --pps=10000 --loop=0 $f > /dev/null 2>&1" & sleep $(( n / 10000 + 3 ))
  hops=; [ $m = routed ] && hops=hops
  ssh $PI "$P trust_flows /home/wnc/cpu_alloc/trust/$s.fp.flows $hops"
  $G pkill -x tcpreplay; wait 2> /dev/null
  phase after-trust-0-30s 30
  sleep 30
  phase idle-60-90s 30
  phase traffic-20k 20 20000
  phase idle-after-traffic 30
  ssh $PI "sudo bash ~/ids_inline/planb_pi.sh stop" > /dev/null
done
bash $D/alloc_run.sh mode bridge > /dev/null
echo "PROBE2 DONE"
