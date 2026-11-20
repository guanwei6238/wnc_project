#!/bin/bash
# alloc_run.sh — laptop side of the CPU allocation experiments (traffic generator reuses the wnc-gen container and tcpprep cache from tests/ids_inline/planb_run.sh)
# Prerequisites: on the Pi, planb_pi.sh up and alloc_pi.sh pause off; on the laptop, bash tests/ids_inline/planb_run.sh setup S_m17 S_m1 S_m60
# Usage:
#   bash alloc_run.sh sweep <B0|B1|B2|B3> <placement> <pcap> <round> <pps...>   exp 1: rate sweep for one placement and one workload
#   bash alloc_run.sh exp1 <round>        all of exp 1: B0/B1/B2 × A0 R1 R123 I1 T1 (order randomized each round)
#   bash alloc_run.sh ai <strategy> <cpu|mem|mlp|none> <pps> <round> [threads]   one point of exp 2 (including its "AI only" baseline)
#   bash alloc_run.sh exp2 <round>        all of exp 2: α β γ × none cpu mem, plus mem with 1 thread for γ
# Workloads: B0 bridge only; B1 wnc-gw ips full 2 queues; B2 wnc-gw ips full 1 queue, all trusted; B3 wnc-gw ids (NFLOG) full 2 groups; B4, B5 ips full 3, 4 queues;
#           B6, B7, B8 ids full 1, 3, 4 groups; B9 ips full 1 queue;
#           K0 = B6 (ids 1 group); K1/K2 add 1/2 full NFLOG copies for read-only readers; K2h adds 2 copies of only the first 128 bytes;
#           U2 = K0 plus 1 kernel copy, split to 2 readers by a user-space fanout; K0g3, K2g3, U2g3 are the 3-group versions
#           F2 = B2 plus TC fast path (ebpf-bench v4, trusting all 5-tuples of S_m60): trusted packets are redirected at TC, skipping bridge and netfilter
#           F5n, F5h, F5f = U1 plus ebpf-bench v5 (trusting S_m60): bpf_redirect_neigh without params, with next hop, bpf_fib_lookup+bpf_redirect
#           U1 = wnc-gw ips full 1 queue, no trust (everything inspected); T1 = after U1 starts, send the whole pcap once (20 kpps), then wnc-gw trust add all its
#           flows (S_m60); T1k = same as T1, with X_udp1000, 1,000 synthetic UDP flows (tests/ebpf/make_flows_pcap.py)
# Strategies: alpha = IRQs on CPU0, Suricata pinned to 1,2, AI 1 thread pinned to 3; beta = RPS→CPU1, Suricata pinned to 2,3, AI 2 threads on 2,3 with SCHED_IDLE;
#       gamma = nothing pinned, AI 3 threads; delta = IRQ 29 moved to CPU1, Suricata pinned to 2,3, AI 1 thread pinned to CPU0
#   bash alloc_run.sh exp1b <round>       extension: B4 (3 queues), B5 (4 queues) × A0 I1 T1
#   bash alloc_run.sh exp2b <round>       extension: delta × none cpu mem mlp, alpha × mlp, alpha × mem at 25/50% duty (env var DUTY)
#   bash alloc_run.sh exp1c <round>       extension: ids (B6 B3 B7 B8 = 1–4 groups) × A0 I1 R123, plus inspection capacity (missed copies ≤ 0.1%)
#   bash alloc_run.sh exp3 <round>        per-packet cost of conntrack accounting (nf_conntrack_acct 0/1): B2@40k, B1@40k, B3@30k, A0
#   bash alloc_run.sh exp1d <round>       extension: S_m1 with ips 1–4 queues, ids 1–4 groups × A0 I1 R123; S_m17 adds ips 1 queue × all three, 3, 4 queues × R123
#   bash alloc_run.sh mode <bridge|routed>  switch the Pi topology to this mode (planb_pi.sh down, MODE=… up, PAUSE off)
#   bash alloc_run.sh exp4 <round>        routed vs bridge: B0 B2 B1 B7 × A0 R123, both modes (order swapped each round); routed sends the MAC-rewritten pcap from planb_run.sh routed_pcap
#   bash alloc_run.sh exp5 <round>        multiple ids copies (bridge): K0 K1 K2 K2h × A0 R123 × S_m17, bulk_fixed
#   bash alloc_run.sh night1104           exp5 1 → exp4 1 → exp4 2 → exp5 2, then topology back to bridge, PAUSE on
#   bash alloc_run.sh exp6 <round>        (c) user-space distribution of multiple copies: U2 × A0 R123; R123+3 groups: K0g3 K2g3 U2g3; S_m17, bulk_fixed
#   bash alloc_run.sh night1104b          validate U2 on one point first, then exp6 1, exp6 2
#   bash alloc_run.sh exp7 <round>        rerun of exp5's K2h (reader tcpdump now -s 0, truncation left to the rule's snaplen)
#   bash alloc_run.sh night1104c          exp7 1, exp7 2
#   bash alloc_run.sh exp8 <round>        rerun of exp6's K0g3, K2g3 (during exp6 the fanout never exited and held group 20)
#   bash alloc_run.sh night1104d          exp7 1, exp8 1, exp7 2, exp8 2
#   bash alloc_run.sh exp9 <round>        TC fast path vs ct mark trust (E1 of step C): B0 B2 F2 × A0 I1, all on S_m60 (prereq: ebpf-bench, S_m60.flows in ~/cpu_alloc on the Pi)
#   bash alloc_run.sh exp10 <round>       wnc-gw's own TC fast path, bridge vs routed (C3): B0 U1 T1 T1k × I1, both modes (order swapped each round)
#   bash alloc_run.sh exp12 <round>       rerun of exp10's T1, T1k (routed now with next hop): both modes (order swapped each round)
#   bash alloc_run.sh exp11 <round>       three routed forwarding methods (ebpf-bench v5): F5n F5h F5f T1 × I1 (topology must be routed first: alloc_run.sh mode routed)
#                                         prereq: S_m60.flows, X_udp1000.flows in ~/cpu_alloc on the Pi; on the laptop planb_run.sh setup/routed_pcap S_m60 X_udp1000
# MODE=routed: sweep uses the routed pcap and results get mode=; EXP: exp= in results (default 1)
# Results go one line per point into $OUT/$KVL (default alloc.kvl); stop after two consecutive rates with cap_loss > 1%
LAN=${LAN:-enx9c69d3241bd9}; WAN=${WAN:-eno2}; PI=${PI:-wnc@10.254.254.2}
OUT=${OUT:-/home/sixsquare/datasets/throughput/cpu_alloc}; KVL=${KVL:-alloc.kvl}
HERE=$(cd "$(dirname "$0")" && pwd)
G="docker exec wnc-gen"
SSH="ssh -o ConnectTimeout=20 -o ServerAliveInterval=5 -o ServerAliveCountMax=6 $PI"
P="sudo bash ~/cpu_alloc/alloc_pi.sh"
mkdir -p $OUT

snap() { for i in 1 2 3; do s=$($SSH "$P snap" 2>/dev/null) && [ -n "$s" ] && { echo "$s"; return 0; }; sleep 3; done; return 1; }
cool() {
  for i in $(seq 1 30); do
    t=$($SSH "vcgencmd measure_temp" | tr -dc '0-9.'); awk -v t="$t" 'BEGIN{exit !(t > 70)}' || return 0
    echo "  cooling (temp $t)"; sleep 20
  done
}
pi_start() {
  E="MODE=${MODE:-bridge}"
  case $1 in
  B0) $SSH "sudo pkill -INT -x wnc-gw; echo bridge only" ;;
  B1) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 2 0" | tail -1) ;;
  B2) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 1 1" | tail -1) ;;
  U1) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  F5n|F5h|F5f) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1)
      case $1 in F5n) via=neigh ;; F5h) via=nexthop ;; F5f) via=fib ;; esac
      echo "  $($SSH "$P fastpath_start /home/wnc/cpu_alloc/S_m60.flows v5 --via $via --nexthop eth1.20 10.99.2.2 --nexthop eth0 10.99.1.2" | tail -1)" ;;
  T1|T1k) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1)
      case "$r" in ready*) ;; *) echo "  $r"; return 1 ;; esac
      if [ "${MODE:-bridge}" = routed ]; then f=/out/$WARM_PC.rt.pcap; c=/out/$WARM_PC.rt.cache; else f=/pcaps/$WARM_PC.pcap; c=/out/$WARM_PC.cache; fi
      $G tcpreplay -i $WAN.20 -I $LAN -c $c --pps=20000 $f > /dev/null 2>&1
      hops=; [ "${MODE:-bridge}" = routed ] && hops=hops
      echo "  warm-up sent; $($SSH "$P trust_flows /home/wnc/cpu_alloc/$WARM_PC.flows $hops")" ;;
  F2) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 1 1" | tail -1)
      echo "  $($SSH "$P fastpath_start /home/wnc/cpu_alloc/S_m60.flows" | tail -1)" ;;
  B3) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 2 0" | tail -1) ;;
  B4) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 3 0" | tail -1) ;;
  B5) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 4 0" | tail -1) ;;
  B6) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  B7) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 3 0" | tail -1) ;;
  B8) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 4 0" | tail -1) ;;
  B9) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K0) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K1) r=$($SSH "sudo $E PROTECTION=ids COPIES=1 bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K2) r=$($SSH "sudo $E PROTECTION=ids COPIES=2 bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K2h) r=$($SSH "sudo $E PROTECTION=ids COPIES=2 SNAPLEN=128 bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  U2) r=$($SSH "sudo $E PROTECTION=ids FANOUT=2 bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K0g3) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 3 0" | tail -1) ;;
  K2g3) r=$($SSH "sudo $E PROTECTION=ids COPIES=2 bash ~/ids_inline/planb_pi.sh start full 3 0" | tail -1) ;;
  U2g3) r=$($SSH "sudo $E PROTECTION=ids FANOUT=2 bash ~/ids_inline/planb_pi.sh start full 3 0" | tail -1) ;;
  esac
  [ "$1" = B0 ] && return 0
  echo "  $r"; case "$r" in ready*) return 0 ;; *) return 1 ;; esac
}
pi_stop() {
  case $1 in F2|F5n|F5h|F5f) echo "  fast path: $($SSH "$P fastpath_stop")" ;; esac
  [ "$1" = B0 ] || $SSH "sudo bash ~/ids_inline/planb_pi.sh stop" | grep reader | sed 's/^/  /'
}
# point <pcap> <pps> <loop> k=v...: send traffic once, snap before and after, write one line
point() {
  pc=$1; rate=$2; loop=$3; shift 3
  cool
  s0=$(snap) || { echo "$* pps=$rate invalid=snap0" >> $OUT/$KVL; return 1; }
  lo=""; [ "$loop" -gt 1 ] && lo="--loop=$loop"
  if [ "${MODE:-bridge}" = routed ]; then f=/out/$pc.rt.pcap; c=/out/$pc.rt.cache; else f=/pcaps/$pc.pcap; c=/out/$pc.cache; fi
  $G tcpreplay -i $WAN.20 -I $LAN -c $c --pps=$rate $lo $f > $OUT/tcpreplay.txt 2>&1
  sleep 2
  s1=$(snap) || { echo "$* pps=$rate invalid=snap1" >> $OUT/$KVL; return 1; }
  line=$(python3 -I $HERE/alloc.py diff "$s0" "$s1" $OUT/tcpreplay.txt "$@" pcap=$pc pps=$rate loop=$loop)
  echo "$line" >> $OUT/$KVL
  echo "  $(echo "$line" | grep -o -E ' (actual_pps|cap_loss_pct|copy_loss_pct|xcopy_loss_pct|loss_pct|us_per_pkt|cpu0_us_per_pkt|reader_us_per_pkt|util0|util1|util2|util3|ai_ops_per_s|temp)=[^ ]*' | tr '\n' ' ')"
}
# ai_only k=v...: no traffic, measure only AI and background (6 seconds)
ai_only() {
  s0=$(snap) || return 1; sleep 6; s1=$(snap) || return 1
  line=$(python3 -I $HERE/alloc.py diff "$s0" "$s1" - "$@")
  echo "$line" >> $OUT/$KVL
  echo "  $(echo "$line" | grep -o -E '(ai_ops_per_s|ai_cpu_s_per_s|util0|util1|util2|util3)=[^ ]*' | tr '\n' ' ')"
}

case "$1" in
sweep)
  wl=$2; pl=$3; pc=$4; round=$5; shift 5
  echo "$(date -u +%T) sweep $wl $pl $pc round=$round mode=${MODE:-bridge}"
  WARM_PC=$pc pi_start $wl || { echo "$(date -u +%T) start failed" ; $SSH "sudo bash ~/ids_inline/planb_pi.sh stop" > /dev/null; exit 1; }
  $SSH "$P place $pl"
  fails=0
  for rate in "$@"; do
    n=200000; [ $pc = bulk_fixed ] && n=31433
    loop=1; case $wl in B0|B2|F2|T1|T1k|F5n|F5h|F5f) loop=$(( (5 * rate + n - 1) / n )) ;; esac
    [ $pc = bulk_fixed ] && loop=$(( (5 * rate + n - 1) / n ))
    point $pc $rate $loop exp=${EXP:-1} mode=${MODE:-bridge} workload=$wl placement=$pl round=$round || continue
    l=$(tail -1 $OUT/$KVL | grep -o 'cap_loss_pct=[^ ]*' | cut -d= -f2)
    if awk -v l="$l" 'BEGIN{exit !(l > 1)}'; then fails=$((fails + 1)); [ $fails -ge 2 ] && break; else fails=0; fi
  done
  pi_stop $wl
  $SSH "$P place A0" > /dev/null
  ;;
exp1)
  round=$2
  for wl in B0 B1 B2; do
    case $wl in
    B0) pc=S_m17; rates="50000 100000 150000 200000 250000 300000 350000 400000" ;;
    B1) pc=S_m17; rates="20000 30000 40000 45000 50000 55000 60000 70000 80000 100000" ;;
    B2) pc=S_m60; rates="50000 80000 100000 120000 150000 180000 220000 260000 300000" ;;
    esac
    for pl in $(printf '%s\n' A0 R1 R123 I1 T1 | shuf); do bash "$0" sweep $wl $pl $pc $round $rates; done
  done
  echo "EXP1 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp12)
  round=$2; modes="bridge routed"; [ $((round % 2)) = 0 ] && modes="routed bridge"
  for m in $modes; do
    bash "$0" mode $m
    for wl in $(printf '%s\n' T1 T1k | shuf); do
      pc=S_m60; [ $wl = T1k ] && pc=X_udp1000
      EXP=12 MODE=$m bash "$0" sweep $wl I1 $pc $round 50000 80000 100000 120000 150000 180000 220000 260000 300000 350000 400000
    done
  done
  echo "EXP12 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp11)
  round=$2
  for wl in $(printf '%s\n' F5n F5h F5f T1 | shuf); do
    EXP=11 MODE=routed bash "$0" sweep $wl I1 S_m60 $round 50000 80000 100000 120000 150000 180000 220000 260000 300000 350000 400000
  done
  echo "EXP11 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp10)
  round=$2; modes="bridge routed"; [ $((round % 2)) = 0 ] && modes="routed bridge"
  for m in $modes; do
    bash "$0" mode $m
    for wl in $(printf '%s\n' B0 U1 T1 T1k | shuf); do
      case $wl in
      B0) pc=S_m60; rates="50000 80000 100000 120000 150000 180000 220000 260000 300000 350000 400000" ;;
      U1) pc=S_m60; rates="10000 20000 30000 40000 50000 60000 80000" ;;
      T1) pc=S_m60; rates="50000 80000 100000 120000 150000 180000 220000 260000 300000 350000 400000" ;;
      T1k) pc=X_udp1000; rates="50000 80000 100000 120000 150000 180000 220000 260000 300000 350000 400000" ;;
      esac
      EXP=10 MODE=$m bash "$0" sweep $wl I1 $pc $round $rates
    done
  done
  echo "EXP10 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp9)
  round=$2
  for pt in $(printf '%s\n' B0:A0 B0:I1 B2:A0 B2:I1 F2:A0 F2:I1 | shuf); do
    EXP=9 bash "$0" sweep ${pt%:*} ${pt#*:} S_m60 $round 50000 80000 100000 120000 150000 180000 220000 260000 300000 350000 400000
  done
  echo "EXP9 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
ai)
  st=$2; ai=$3; rate=$4; round=$5; th=$6; duty=${DUTY:-100}
  case $st in
  alpha) pl=A0; pin=1,2; th=${th:-1}; cpus=3; pol=normal ;;
  delta) pl=I1; pin=2,3; th=${th:-1}; cpus=0; pol=normal ;;
  beta) pl=R1; pin=2,3; th=${th:-2}; cpus=2,3; pol=idle ;;
  gamma) pl=A0; pin=none; th=${th:-3}; cpus=any; pol=normal ;;
  esac
  echo "$(date -u +%T) ai strategy=$st ai=$ai threads=$th pps=$rate round=$round"
  pi_start B1 || { echo "  start failed"; $SSH "sudo bash ~/ids_inline/planb_pi.sh stop" > /dev/null; exit 1; }
  $SSH "$P place $pl" > /dev/null
  echo "  pin: $($SSH "$P pin_suricata $pin")"
  [ $ai = none ] || echo "  $($SSH "$P burner_start $ai $th $cpus $pol $duty")"
  m="exp=2 strategy=$st ai=$ai threads=$th round=$round placement=$pl duty=$duty"
  point S_m17 $rate 1 $m traffic=S_m17
  ai_only $m traffic=none pps=0
  [ $ai = none ] || $SSH "$P burner_stop" > /dev/null
  pi_stop B1
  $SSH "$P place A0" > /dev/null
  ;;
exp2)
  round=$2; rate=${3:-40000}
  for pt in $(printf '%s\n' alpha:none alpha:cpu alpha:mem beta:none beta:cpu beta:mem gamma:none gamma:cpu gamma:mem | shuf); do
    bash "$0" ai ${pt%%:*} ${pt##*:} $rate $round
  done
  [ "$round" = 1 ] && bash "$0" ai gamma mem $rate $round 1
  echo "EXP2 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp1b)
  # extension: with IRQs moved off CPU 0, can 3 or 4 queues push inspection capacity past the 55–60 kpps of 2 queues
  round=$2; rates="40000 50000 55000 60000 65000 70000 80000 90000 100000"
  for wl in B4 B5; do
    for pl in $(printf '%s\n' A0 I1 T1 | shuf); do bash "$0" sweep $wl $pl S_m17 $round $rates; done
  done
  echo "EXP1B ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp1c)
  # extension: with ids (NFLOG), forwarding doesn't wait for Suricata; do more groups and moving packet receive off CPU0 raise forwarding and inspection capacity
  round=$2; rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000 250000 300000"
  for wl in B6 B3 B7 B8; do
    for pl in $(printf '%s\n' A0 I1 R123 | shuf); do bash "$0" sweep $wl $pl S_m17 $round $rates; done
  done
  echo "EXP1C ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
acctpt)
  v=$2; wl=$3; pc=$4; rate=$5; round=$6
  echo "$(date -u +%T) acct=$v $wl $pc $rate round=$round"
  $SSH "$P acct $v"
  pi_start $wl || { echo "  start failed"; $SSH "sudo bash ~/ids_inline/planb_pi.sh stop" > /dev/null; exit 1; }
  $SSH "$P place A0" > /dev/null
  loop=1; [ $wl = B2 ] && loop=$(( (5 * rate + 199999) / 200000 ))
  point $pc $rate $loop exp=3 workload=$wl placement=A0 acct=$v round=$round
  pi_stop $wl
  ;;
exp3)
  # 3d needs per-connection packet and byte counts: forwarding cost of enabling nf_conntrack_acct (dump cost is in tests/ctnetlink/bench)
  round=$2
  for pt in $(printf '%s\n' 0:B2:S_m60:40000 1:B2:S_m60:40000 0:B1:S_m17:40000 1:B1:S_m17:40000 0:B3:S_m17:30000 1:B3:S_m17:30000 | shuf); do
    IFS=: read -r v wl pc rate <<< "$pt"; bash "$0" acctpt $v $wl $pc $rate $round
  done
  $SSH "$P acct 0" > /dev/null
  echo "EXP3 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp1d)
  # extension: S_m1, many connections but not all scans (49% bare SYN); measure 1–4 queues/groups for both ips and ids
  round=$2; rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000 250000 300000"
  for pt in $(printf '%s\n' B9:A0 B9:I1 B9:R123 B4:R123 B5:R123 | shuf); do bash "$0" sweep ${pt%%:*} ${pt##*:} S_m17 $round $rates; done
  for wl in B9 B1 B4 B5 B6 B3 B7 B8; do
    for pl in $(printf '%s\n' A0 I1 R123 | shuf); do bash "$0" sweep $wl $pl S_m1 $round $rates; done
  done
  echo "EXP1D ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp2b)
  # extension: delta (IRQ 29 moved to CPU1, Suricata pinned to 2,3, AI pinned to CPU0); alpha with mlp; alpha with mem at lower duty
  round=$2; rate=${3:-40000}
  for pt in $(printf '%s\n' delta:none delta:cpu delta:mem delta:mlp alpha:mlp | shuf); do
    bash "$0" ai ${pt%%:*} ${pt##*:} $rate $round
  done
  for d in 25 50; do DUTY=$d bash "$0" ai alpha mem $rate $round; done
  echo "EXP2B ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
mode)
  m=$2
  echo "$(date -u +%T) topology -> $m"
  $SSH "sudo bash ~/ids_inline/planb_pi.sh down; sudo MODE=$m bash ~/ids_inline/planb_pi.sh up && sudo ip netns exec wgw ip -br addr"
  $SSH "$P pause off" | sed 's/^/  /'
  ;;
exp4)
  # routed vs bridge (todo: developer 2026-11-04 "routed is faster, should routed be the default?")
  round=$2; modes="bridge routed"; [ $((round % 2)) = 0 ] && modes="routed bridge"
  for m in $modes; do
    bash "$0" mode $m
    for pt in $(printf '%s\n' B0:A0 B0:R123 B2:A0 B2:R123 B1:A0 B1:R123 B7:A0 B7:R123 | shuf); do
      wl=${pt%%:*}; pl=${pt##*:}
      case $wl in
      B0) pc=S_m17; rates="50000 100000 150000 200000 250000 300000 350000 400000" ;;
      B2) pc=S_m60; rates="50000 80000 100000 120000 150000 180000 220000 260000 300000" ;;
      B1) pc=S_m17; rates="20000 30000 40000 45000 50000 55000 60000 70000 80000 100000" ;;
      B7) pc=S_m17; rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000 250000" ;;
      esac
      EXP=4 MODE=$m bash "$0" sweep $wl $pl $pc $round $rates
    done
  done
  echo "EXP4 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp5)
  # limit of 2–3 ids copies (advisor's 2026-11-04 concern: one each for Suricata, edge AI, cloud features): all packets, full packets, plus header-only copies
  round=$2
  for pc in S_m17 bulk_fixed; do
    case $pc in
    S_m17) rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000" ;;
    bulk_fixed) rates="10000 20000 30000 40000 50000 60000 70000 80000 90000" ;;
    esac
    for pt in $(printf '%s\n' K0:A0 K0:R123 K1:A0 K1:R123 K2:A0 K2:R123 K2h:A0 K2h:R123 | shuf); do
      EXP=5 MODE=bridge bash "$0" sweep ${pt%%:*} ${pt##*:} $pc $round $rates
    done
  done
  echo "EXP5 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp6)
  round=$2
  for pc in S_m17 bulk_fixed; do
    case $pc in
    S_m17) rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000" ;;
    bulk_fixed) rates="10000 20000 30000 40000 50000 60000 70000 80000 90000" ;;
    esac
    for pt in $(printf '%s\n' U2:A0 U2:R123 K0g3:R123 K2g3:R123 U2g3:R123 | shuf); do
      EXP=6 MODE=bridge bash "$0" sweep ${pt%%:*} ${pt##*:} $pc $round $rates
    done
  done
  echo "EXP6 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp7)
  # rerun of exp5's K2h: exp5's reader tcpdump used -s 128 and the libpcap receive buffer was too small, so copies were lost (S_m17 got only ~10%, the bulk reader exited); data discarded
  round=$2
  for pc in S_m17 bulk_fixed; do
    case $pc in
    S_m17) rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000" ;;
    bulk_fixed) rates="10000 20000 30000 40000 50000 60000 70000 80000 90000" ;;
    esac
    for pt in $(printf '%s\n' K2h:A0 K2h:R123 | shuf); do
      EXP=7 MODE=bridge bash "$0" sweep ${pt%%:*} ${pt##*:} $pc $round $rates
    done
  done
  echo "EXP7 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp8)
  # rerun of exp6's K0g3, K2g3: in exp6 the first fanout never exited and kept holding group 20, so K2g3's first copy went into the fanout and K0g3 got extra CPU from the idle fanout spinning
  round=$2
  for pc in S_m17 bulk_fixed; do
    case $pc in
    S_m17) rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000" ;;
    bulk_fixed) rates="10000 20000 30000 40000 50000 60000 70000 80000 90000" ;;
    esac
    for pt in $(printf '%s\n' K0g3:R123 K2g3:R123 | shuf); do
      EXP=8 MODE=bridge bash "$0" sweep ${pt%%:*} ${pt##*:} $pc $round $rates
    done
  done
  echo "EXP8 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
night1104d)
  bash "$0" mode bridge
  bash "$0" exp7 1
  bash "$0" exp8 1
  bash "$0" exp7 2
  bash "$0" exp8 2
  $SSH "$P pause on" | sed 's/^/  /'
  echo "NIGHT1104D DONE $(date -u +%FT%TZ)"
  ;;
night1104c)
  bash "$0" mode bridge
  bash "$0" exp7 1
  bash "$0" exp7 2
  $SSH "$P pause on" | sed 's/^/  /'
  echo "NIGHT1104C DONE $(date -u +%FT%TZ)"
  ;;
night1104b)
  bash "$0" mode bridge
  KVL=validate.kvl EXP=6 MODE=bridge bash "$0" sweep U2 A0 S_m17 0 20000
  if tail -1 $OUT/validate.kvl | grep -q 'workload=U2 .*xcopy_loss_pct='; then
    bash "$0" exp6 1
    bash "$0" exp6 2
  else
    echo "U2 validation failed; exp6 skipped"
  fi
  $SSH "$P pause on" | sed 's/^/  /'
  echo "NIGHT1104B DONE $(date -u +%FT%TZ)"
  ;;
night1104)
  bash "$0" mode bridge
  bash "$0" exp5 1
  bash "$0" exp4 1
  bash "$0" exp4 2
  bash "$0" mode bridge
  bash "$0" exp5 2
  $SSH "$P pause on" | sed 's/^/  /'
  echo "NIGHT1104 DONE $(date -u +%FT%TZ)"
  ;;
*) sed -n '2,29p' "$0"; exit 2 ;;
esac
