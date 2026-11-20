#!/bin/bash
# How many packets really take the fast path with T (TC trust) during measurement: core program COUNTERS (packets, redirects) diffed before/after 10 s at 20 kpps
# Prerequisites same as trust_run.sh; the Pi needs /tmp/wncgw/core_counters.sh (core_counters.sh from this directory). Results go to $O/probe4.kvl
D=$(cd "$(dirname "$0")" && pwd); O=/home/sixsquare/datasets/throughput/cpu_alloc
LAN=enx9c69d3241bd9; WAN=eno2; PI=wnc@10.254.254.2; G="docker exec wnc-gen"; P="sudo bash ~/cpu_alloc/alloc_pi.sh"
counters() { ssh $PI "sudo bash /tmp/wncgw/core_counters.sh"; }
for m in routed bridge; do
  bash $D/alloc_run.sh mode $m > /dev/null
  for s in I23_Benign_Final D12_Benign; do
    b=/out/trust/$s.fp; [ $m = routed ] && b=$b.rt; f=$b.pcap; c=$b.cache
    n=$($G tcpprep --print-stats=$c 2>/dev/null | awk '/Total packets/{print $3}')
    ssh $PI "sudo MODE=$m PROTECTION=ips bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1
    $G sh -c "tcpreplay -i $LAN -I $WAN.20 -c $c --pps=10000 --loop=0 $f > /dev/null 2>&1" & sleep $(( n / 10000 + 3 ))
    hops=; [ $m = routed ] && hops=hops
    ssh $PI "$P trust_flows /home/wnc/cpu_alloc/trust/$s.fp.flows $hops"
    $G pkill -x tcpreplay; wait 2> /dev/null
    ssh $PI "$P place I1" > /dev/null; sleep 5
    read -r p0 r0 <<< "$(counters)"; s0=$(ssh $PI "$P snap")
    [ -n "$r0" ] || { echo "error: cannot read the core program counters"; ssh $PI "sudo bash ~/ids_inline/planb_pi.sh stop" > /dev/null; exit 1; }
    $G tcpreplay -i $LAN -I $WAN.20 -c $c --pps=20000 --loop=3 --duration=10 $f > $O/tcpreplay.txt 2>&1
    sleep 2
    read -r p1 r1 <<< "$(counters)"; s1=$(ssh $PI "$P snap")
    line=$(python3 -I $D/alloc.py diff "$s0" "$s1" $O/tcpreplay.txt probe=4 mode=$m slice=$s)
    echo "$line core_packets=$((p1 - p0)) core_redirected=$((r1 - r0))" >> $O/probe4.kvl
    echo "$m $s: core_packets=$((p1 - p0)) redirected=$((r1 - r0)) $(echo "$line" | grep -o -E '(sent|pi_in|us_per_pkt|sur_w_us_per_pkt|util[0-3])=[^ ]*' | tr '\n' ' ')"
    ssh $PI "sudo bash ~/ids_inline/planb_pi.sh stop; $P place A0" > /dev/null
  done
done
bash $D/alloc_run.sh mode bridge > /dev/null
echo "PROBE4 DONE"
