#!/bin/bash
# cost_pi.sh — step A3: CPU cost of attaching one program to TCX ingress on each port
#   V0 no program; V1 empty program (returns NEXT); V2 per-CPU counter (= current wnc-gw program); V3 V2 + header parsing + one 5-tuple hash map lookup (miss)
#   topology: tests/ids_inline/env.sh (wtest's tcpreplay sends from t-wan, t-lan into wgw's br0, ports g-lan, g-wan); no nft, no Suricata
#   cpu: increase in per-CPU rq_cpu_time from /proc/schedstat ÷ packets sent (same method as trust_cost.sh); bpf_stats off
#   stats: kernel.bpf_stats_enabled=1, read each program's run_cnt, run_time_ns (ns per run of the program itself; bpf_stats has its own cost, so it runs separately from cpu)
#   tcpreplay uses -T nano pinned to CPU 1: the default gtod busy-waits and would hide the kernel cost on CPU 1
# Prerequisites: pi_lab_mode.sh up 1000, system suricata service stopped; ebpf-bench in the same directory as this script
# Usage: sudo bash cost_pi.sh cpu|stats
cd "$(dirname "$0")" || exit 1
MODE=$1; RATE=${RATE:-10000}; PC=${PC:-C17_Benign}; TAG=${TAG:-a3}
ENV=${ENV:-/home/wnc/ids_inline/env.sh}; PCAPS=${PCAPS:-/home/wnc/ids_throughput/data/pcaps}
W=/tmp/wncgw/ebpf; OUT=${OUT:-/home/wnc/ebpf/results}; CACHE=$W/$PC.auto.cache
case $MODE in
cpu) VARS="v0 v1 v2 v3"; ROUNDS=${ROUNDS:-5}; STATS=0 ;;
stats) VARS="v1 v2 v3"; ROUNDS=${ROUNDS:-3}; STATS=1 ;;
*) echo "usage: sudo bash cost_pi.sh cpu|stats"; exit 2 ;;
esac
mkdir -p $W $OUT
pgrep -x Suricata-Main > /dev/null && { echo "a suricata is running; stop it first"; exit 1; }
[ -f $CACHE ] || tcpprep --auto=bridge --pcap=$PCAPS/$PC.pcap --cachefile=$CACHE || exit 1

busy() { awk '/^cpu[0-9]/{s += $8} END{printf "%d", s / 1000}' /proc/schedstat; }
throttled() { vcgencmd get_throttled | cut -d= -f2; }
mhz() { echo $(( $(vcgencmd measure_clock arm | cut -d= -f2) / 1000000 )); }

sysctl -q -w kernel.bpf_stats_enabled=$STATS
sh $ENV down; sh $ENV up
seq=0
for r in $(seq $ROUNDS); do
  for v in $(printf '%s\n' $VARS | shuf); do
    seq=$((seq + 1)); bp=; id=0
    if [ $v != v0 ]; then
      ip netns exec wgw ./ebpf-bench $v g-lan g-wan > $W/bench.out 2>&1 & bp=$!
      until grep -q "prog_id=" $W/bench.out; do kill -0 $bp 2>/dev/null || { cat $W/bench.out; exit 1; }; sleep 0.1; done
      id=$(grep -o "prog_id=[0-9]*" $W/bench.out | cut -d= -f2)
    fi
    sleep 1
    th0=$(throttled); f0=$(mhz); b0=$(busy); t0=${EPOCHREALTIME/./}
    ip netns exec wtest taskset -c 1 tcpreplay -T nano -i t-wan -I t-lan -c $CACHE --pps=$RATE $PCAPS/$PC.pcap > $W/replay.txt 2>&1
    t1=${EPOCHREALTIME/./}; b1=$(busy); th1=$(throttled)
    cnt=0; ns=0
    if [ -n "$bp" ]; then
      [ $STATS = 1 ] && read -r cnt ns < <(bpftool -j prog show id $id | python3 -c 'import json,sys; p=json.load(sys.stdin); print(p.get("run_cnt", 0), p.get("run_time_ns", 0))')
      kill -INT $bp; wait $bp
    fi
    pk=$(grep -o "packets=[0-9]*" $W/bench.out 2>/dev/null | cut -d= -f2); [ $v = v0 ] && pk=0
    sent=$(grep -o "Actual: [0-9]* packets" $W/replay.txt | cut -d" " -f2)
    awk -v tag=$TAG -v mode=$MODE -v round=$r -v seq=$seq -v v=$v -v pc=$PC -v rate=$RATE -v sent=$sent -v pk=${pk:-0} \
        -v b=$((b1 - b0)) -v dt=$((t1 - t0)) -v cnt=$cnt -v ns=$ns -v th0=$th0 -v th1=$th1 -v f0=$f0 'BEGIN{
      printf "tag=%s mode=%s round=%d seq=%d variant=%s pcap=%s rate=%d sent=%d prog_packets=%d busy_us=%d wall_us=%d cpu_us_per_pkt=%.3f run_cnt=%d run_ns=%d ns_per_run=%.1f throttled=%s,%s mhz=%d\n",
        tag, mode, round, seq, v, pc, rate, sent, pk, b, dt, (sent > 0 ? b / sent : 0), cnt, ns, (cnt > 0 ? ns / cnt : 0), th0, th1, f0 }' | tee -a $OUT/cost.kvl
  done
done
sysctl -q -w kernel.bpf_stats_enabled=0
sh $ENV down
