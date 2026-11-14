#!/bin/bash
# cost_pi.sh — 步驟 A3：每個 port 的 TCX ingress 掛一支程式要多少 CPU
#   V0 沒有程式；V1 空程式（回傳 NEXT）；V2 per-CPU 計數（= wnc-gw 現在的程式）；V3 V2＋解析 header＋五元組查一次 hash map（查不到）
#   拓樸：tests/ids_inline/env.sh（wtest 的 tcpreplay 從 t-wan、t-lan 送進 wgw 的 br0，port 是 g-lan、g-wan）；沒有 nft、沒有 Suricata
#   cpu：/proc/schedstat 各 CPU 的 rq_cpu_time 增加量 ÷ 送出的封包（和 trust_cost.sh 同一套）；bpf_stats 關
#   stats：kernel.bpf_stats_enabled=1，讀每支程式的 run_cnt、run_time_ns（程式本身每次執行幾 ns；bpf_stats 自己有成本，所以和 cpu 分開跑）
#   tcpreplay 用 -T nano 綁 CPU 1：預設的 gtod 會忙等，kernel 在 CPU 1 上的成本就看不出來
# 前置：pi_lab_mode.sh up 1000、系統的 suricata 服務已停；ebpf-bench 和這個腳本放在同一個目錄
# 用法: sudo bash cost_pi.sh cpu|stats
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
