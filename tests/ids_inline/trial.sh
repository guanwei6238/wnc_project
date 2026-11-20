#!/bin/bash
# trial.sh — one inline measurement
#   IMPL=wncgw (default)  wnc-gw starts Suricata (NFQ) and installs the queue rules itself once ready
#   IMPL=nfq            baseline: run Suricata -q 0 directly, install a minimal queue rule after "Engine started"
#   IMPL=afpacket       baseline: Suricata af-packet IPS mode; g-lan, g-wan temporarily leave br0 and Suricata moves packets between them
#   IMPL=nflog          ids candidate: Suricata --nflog, install log group rules after "Engine started"; the kernel forwards as usual and sends only copies
#                       with QUEUES=N, symhash splits across groups 10..10+N-1; NFLOG_BUF (default 1048576, max-size is 4x it), NFLOG_QT (qthreshold, default 1)
#   QUEUES=N (default 1): use queues 0..N-1, Suricata runs N workers (wncgw uses setting-<rules>-qN.toml; nfq uses -q 0:N-1)
#   SURI_CPUS (default 2,3): CPUs Suricata is pinned to
#   QHASH=symhash (nfq only): use queue to symhash mod N (symmetric hash including ports); default is queue num 0-(N-1) (kernel hashes addresses only)
#   RUNMODE=workers|autofp (not for afpacket): set runmode in the yaml; default keeps the yaml's (make_configs.sh sets workers)
#   All three are pinned to $SURI_CPUS; 2 s after ready, tcpreplay (in wtest, pinned to CPU 1, -T nano) sends the whole pcap, waits until processed, reads counters and RSS, then stops
# Usage: sudo [IMPL=...] bash trial.sh <empty|full|gw_corp> <pcap name, e.g. S_m39> <pps number|top|cache> <output dir>
#   cache: only build the tcpprep cache and exit
# Output: <output dir>/result.kv (one line of key=value), run.log, tcpreplay.txt
#
# Split: the IoT-23 router is on the WAN side; packets whose source MAC is the router's are sent from t-wan, the rest from t-lan
# Counters:
#   NFQ (wncgw, nfq): summed over queues in /proc/net/netfilter/nfnetlink_queue; per_queue is packets handed to Suricata per queue. to_queue = reached the queue rule; queue_drop = dropped by the kernel on a full queue; processed = handed to Suricata for a verdict
#   afpacket: processed = packets received on the tester's t-lan, t-wan (sent out by Suricata); to_queue = packets received on the gateway's g-lan, g-wan
#   nflog: to_queue = counter before the log rule; queue_drop = Drops on the netlink socket receiving copies (/proc/net/netlink); processed = the difference
#   cpu_us_per_pkt: increase of rq_cpu_time over all CPUs (/proc/schedstat) ÷ packets sent, incl. tcpreplay and kernel forwarding; NFQ's post-verdict forwarding counts in the worker, NFLOG's does not, so compare the two with this
#     /proc/stat is tick-sampled; a fixed 10,000 pps interval aligned with ticks counts double or zero; tcpreplay's default gtod busy-waits and saturates CPU 1, hiding the forwarding on CPU 1
#     nonidle_cpu_s: cross-check, CPU count × elapsed time − idle from /proc/stat (idle is exact under NO_HZ)
# CPU: schedstat run time (ns) of Suricata worker threads (W-NFQ#0 for NFQ; one W#… per NIC for af-packet), summed, after processing minus before sending
#   us_per_pkt = worker CPU ÷ processed; cpu_kpps = 1000 ÷ us_per_pkt (matches offline's "packets ÷ engine processing time")
#   autofp workers are W#01…, with separate RX threads receiving packets (RX-NFQ#… for NFQ, RX#… for NFLOG) and TX#… sending NFQ verdicts: io_cpu_s is RX + TX
#   path_us_per_pkt = (worker + RX + TX) CPU ÷ processed; use this to compare runmodes
#   proc_kpps = processed ÷ wall-clock time (start of sending → done processing)
set -u
rs=$1; pc=$2; rate=$3; out=$4
IMPL=${IMPL:-wncgw}; QUEUES=${QUEUES:-1}; SURI_CPUS=${SURI_CPUS:-2,3}; RUNMODE=${RUNMODE:-}
if [ "$QUEUES" -gt 1 ]; then qspec=0-$((QUEUES - 1)); qarg=0:$((QUEUES - 1)); qsuffix=-q$QUEUES; else qspec=0; qarg=0; qsuffix=; fi
M=${M:-/tmp/wncgw/m}; GW=${GW:-/tmp/wncgw/wnc-gw}; PCAPS=${PCAPS:-/home/wnc/ids_throughput/data/pcaps}
LOG=/var/log/wnc-gw/suricata
PCAP=$PCAPS/$pc.pcap; CACHE=$M/cache/$pc.cache
mkdir -p "$out"
case $pc in S_h5) router=82:e6:50:12:14:64 ;; S_m3) router=a6:d1:8c:1f:ce:64 ;; *) router=78:8a:20:43:93:d5 ;; esac
[ -f "$CACHE" ] || tcpprep --mac=$router --pcap="$PCAP" --cachefile="$CACHE" || exit 1
[ "$rate" = cache ] && exit 0
Y=$M/suricata-$rs.yaml; S=$M/setting-$rs$qsuffix.toml
if [ -n "$RUNMODE" ]; then
  [ $IMPL = afpacket ] && { echo "RUNMODE is not supported with IMPL=afpacket"; exit 2; }
  sed "s/^runmode: .*/runmode: $RUNMODE/" $M/suricata-$rs.yaml > $out/suricata-base.yaml; Y=$out/suricata-base.yaml
  sed "s|^config = .*|config = \"$Y\"|" $M/setting-$rs$qsuffix.toml > $out/setting.toml; S=$out/setting.toml
fi
runmode=$(awk '/^runmode:/{print $2}' $Y)
nfq() { ip netns exec wgw cat /proc/net/netfilter/nfnetlink_queue; }
nflsock() {  # netlink sockets receiving copies: <sum of Rmem> <sum of Drops>
  local ids; ids=$(ip netns exec wgw cat /proc/net/netfilter/nfnetlink_log | awk '{print $2}' | tr '\n' ' ')
  ip netns exec wgw awk -v ids=" $ids" '$2 == 12 && index(ids, " " $3 " ") {r += $5; d += $9} END{print r + 0, d + 0}' /proc/net/netlink
}
busy() { awk '/^cpu[0-9]/{s += $8} END{printf "%d", s / 1000}' /proc/schedstat; }
idle() { awk '/^cpu /{print $5 + $6}' /proc/stat; }
rx() { local s=0 n; for l in "$@"; do n=$(ip netns exec ${l%%:*} cat /sys/class/net/${l#*:}/statistics/rx_packets); s=$((s + n)); done; echo $s; }
ts() { echo "${EPOCHREALTIME/./}"; }
thr() { vcgencmd get_throttled | cut -d= -f2; }
wait_log() { until grep -q "$1" "$out/run.log" 2>/dev/null; do sleep 0.1; [ -e "$out/exited" ] && { echo "exited before \"$1\": $out"; exit 1; }; done; }

thr0=$(thr)
tstart=$(ts)
case $IMPL in
wncgw)
  setsid bash -c "taskset -c $SURI_CPUS ip netns exec wgw $GW -c $S run > $out/run.log 2>&1 & echo \$! > $out/run.pid; wait \$!; echo exit=\$? >> $out/run.log; touch $out/exited" < /dev/null > /dev/null 2>&1 &
  wait_log "traffic is inspected"
  sp=$(grep -o "suricata started pid=[0-9]*" "$out/run.log" | tail -1 | cut -d= -f2)
  startup=$(grep -o "startup_ms=[0-9]*" "$out/run.log" | head -1 | cut -d= -f2) ;;
nfq|afpacket|nflog)
  if [ $IMPL = nfq ]; then args=(-c $Y -q $qarg)
  elif [ $IMPL = nflog ]; then
    { awk '/^nflog:/{skip = 1; next} skip && /^[a-z#]/{skip = 0} !skip' $Y
      echo "nflog:"; for i in $(seq 0 $((QUEUES - 1))); do printf '  - group: %d\n    buffer-size: %d\n' $((10 + i)) ${NFLOG_BUF:-1048576}; done
      printf '  - group: default\n    qthreshold: %d\n    qtimeout: 100\n    max-size: %d\n' ${NFLOG_QT:-1} $((4 * ${NFLOG_BUF:-1048576})); } > $out/suricata.yaml
    args=(-c $out/suricata.yaml --nflog)
  else
    args=(-c $M/suricata-$rs-afp.yaml --af-packet); ip -n wgw link set g-lan nomaster; ip -n wgw link set g-wan nomaster; fi
  setsid bash -c "taskset -c $SURI_CPUS ip netns exec wgw suricata ${args[*]} -l $LOG --set unix-command.enabled=no --set coredump.max-dump=0 > $out/run.log 2>&1 & echo \$! > $out/run.pid; wait \$!; echo exit=\$? >> $out/run.log; touch $out/exited" < /dev/null > /dev/null 2>&1 &
  wait_log "Engine started"
  startup=$(( ($(ts) - tstart) / 1000 ))
  sp=$(cat $out/run.pid)
  if [ "${QHASH:-}" = symhash ]; then qstmt="queue to symhash mod $QUEUES"; else qstmt="queue num $qspec"; fi
  [ $IMPL = nfq ] && echo "table inet sq { chain f { type filter hook forward priority 0; policy accept; $qstmt; }; }" | ip netns exec wgw nft -f -
  if [ $IMPL = nflog ]; then
    if [ "$QUEUES" -gt 1 ]; then
      vm=$(for i in $(seq 0 $((QUEUES - 1))); do printf '%d : jump g%d, ' $i $i; done)
      body="symhash mod $QUEUES vmap { ${vm%, } }"
      chains=$(for i in $(seq 0 $((QUEUES - 1))); do printf 'chain g%d { counter log group %d; }; ' $i $((10 + i)); done)
    else body="counter log group 10"; chains=; fi
    echo "table inet sq { chain f { type filter hook forward priority 0; policy accept; $body; }; $chains}" | ip netns exec wgw nft -f - || exit 1
  fi ;;
*) echo "unknown IMPL $IMPL"; exit 2 ;;
esac
sleep 2
workers=$(for t in /proc/$sp/task/*; do case "$(cat $t/comm)" in W-NFQ*|W#*) echo "$(cat $t/comm) ${t##*/}" ;; esac; done | sort | cut -d" " -f2)
[ -n "$workers" ] || { echo "no worker thread in $sp"; exit 1; }
ios=$(for t in /proc/$sp/task/*; do case "$(cat $t/comm)" in RX*|TX*) echo ${t##*/} ;; esac; done)
wcpu() { local s=0 n; for t in $workers; do n=$(cut -d" " -f1 /proc/$sp/task/$t/schedstat); s=$((s + n)); done; echo $s; }
iocpu() { local s=0 n; for t in $ios; do n=$(cut -d" " -f1 /proc/$sp/task/$t/schedstat); s=$((s + n)); done; echo $s; }
weach() { for t in $workers; do cut -d" " -f1 /proc/$sp/task/$t/schedstat; done | tr '\n' ' '; }
pq() {
  [ $IMPL = afpacket ] && return
  if [ $IMPL = nflog ]; then ip netns exec wgw nft list table inet sq | awk '/log group/{for (i = 1; i <= NF; i++) if ($i == "packets") printf "%d ", $(i + 1)}'; return; fi
  nfq | awk '{printf "%d ", $8 - $7}'
}
acpu() { cat /proc/$sp/task/*/schedstat | awk '{s+=$1} END{print s}'; }
counters() {  # print to_queue queue_drop processed (cumulative)
  if [ $IMPL = afpacket ]; then echo "$(rx wgw:g-lan wgw:g-wan) 0 $(rx wtest:t-lan wtest:t-wan)"
  elif [ $IMPL = nflog ]; then
    local q d; q=$(ip netns exec wgw nft list table inet sq | awk '/log group/{for (i = 1; i <= NF; i++) if ($i == "packets") s += $(i + 1)} END{print s + 0}')
    read -r _ d < <(nflsock); echo "$q $d $((q - d))"
  else nfq | awk '{q += $8 + $6; d += $6; p += $8 - $7} END{print q, d, p}'; fi
}

read -r q0 qd0 p0 < <(counters); w0=$(wcpu); io0=$(iocpu); a0=$(acpu); we0=($(weach)); pq0=($(pq)); m0=$(busy); i0=$(idle); mt0=$(ts)
if [ "$rate" = top ]; then opt=--topspeed; else opt=--pps=$rate; fi
t0=$(ts)
ip netns exec wtest taskset -c 1 tcpreplay -T nano -i t-wan -I t-lan -c "$CACHE" $opt "$PCAP" > "$out/tcpreplay.txt" 2>&1
t1=$(ts)
if [ $IMPL = afpacket ]; then
  last=-1; while :; do cur=$(rx wtest:t-lan wtest:t-wan); [ "$cur" = "$last" ] && break; last=$cur; t2=$(ts); sleep 0.2; done
elif [ $IMPL = nflog ]; then
  until read -r rmem _ < <(nflsock) && [ "$rmem" = 0 ]; do sleep 0.01; done; t2=$(ts)
else
  until [ "$(nfq | awk '{s += $3} END{print s}')" = 0 ]; do sleep 0.01; done; t2=$(ts)
fi
read -r q1 qd1 p1 < <(counters); w1=$(wcpu); io1=$(iocpu); a1=$(acpu); we1=($(weach)); pq1=($(pq)); m1=$(busy); i1=$(idle); mt1=$(ts)
each=; for i in "${!we1[@]}"; do each+=$(awk -v d=$((we1[i] - we0[i])) 'BEGIN{printf "%.3f", d / 1e9}')/; done
perq=; for i in "${!pq1[@]}"; do perq+=$((pq1[i] - pq0[i]))/; done
hwm=$(awk '/VmHWM/{print $2}' /proc/$sp/status); rss=$(awk '/VmRSS/{print $2}' /proc/$sp/status)
temp=$(vcgencmd measure_temp | sed "s/temp=//; s/'C//"); thr1=$(thr)
case $IMPL in
wncgw) kill -INT "$(cat $out/run.pid)" ;;
nfq|nflog) ip netns exec wgw nft delete table inet sq; kill -TERM "$sp" ;;
afpacket) kill -TERM "$sp" ;;
esac
until [ -e "$out/exited" ]; do sleep 0.2; done
if [ $IMPL = afpacket ]; then ip -n wgw link set g-lan master br0; ip -n wgw link set g-wan master br0; fi

sent=$(grep -o "Actual: [0-9]* packets" "$out/tcpreplay.txt" | cut -d" " -f2)
stopexit=$(grep -o 'suricata stopped pid=[0-9]* exit="[^"]*"' "$out/run.log" | sed 's/.*exit="//; s/"//; s/ /_/g')
[ -n "$stopexit" ] || stopexit=$(grep -o "^exit=[0-9]*" "$out/run.log" | cut -d= -f2)
awk -v impl=$IMPL -v rs=$rs -v pc=$pc -v rate=$rate -v sent=${sent:-0} -v q=$((q1 - q0)) -v qd=$((qd1 - qd0)) -v p=$((p1 - p0)) -v nw=$(echo $workers | wc -w) \
    -v t0=$t0 -v t1=$t1 -v t2=$t2 -v w=$((w1 - w0)) -v io=$((io1 - io0)) -v nio=$(echo $ios | wc -w) -v rm=${runmode:-default} -v a=$((a1 - a0)) -v st=${startup:-0} -v hwm=$hwm -v rss=$rss \
    -v temp=$temp -v thr0=$thr0 -v thr1=$thr1 -v stopexit=${stopexit:-unknown} -v qh=${QHASH:-addr} -v nq=$QUEUES -v cpus=$SURI_CPUS -v each=${each%/} -v perq=${perq%/} -v m=$((m1 - m0)) -v idle=$((i1 - i0)) -v mwall=$((mt1 - mt0)) -v ncpu=$(getconf _NPROCESSORS_ONLN) -v hz=$(getconf CLK_TCK) 'BEGIN{
  busy = (t2 - t0) / 1e6; us = (p > 0 ? w / 1e3 / p : 0)
  printf "impl=%s qhash=%s queues=%d cpus=%s rules=%s pcap=%s rate=%s sent=%d to_queue=%d queue_drop=%d processed=%d workers=%d send_s=%.3f busy_s=%.3f ", impl, qh, nq, cpus, rs, pc, rate, sent, q, qd, p, nw, (t1 - t0) / 1e6, busy
  printf "runmode=%s io_threads=%d io_cpu_s=%.4f path_us_per_pkt=%.2f ", rm, nio, io / 1e9, (p > 0 ? (w + io) / 1e3 / p : 0)
  printf "worker_cpu_s=%.4f all_cpu_s=%.4f us_per_pkt=%.2f cpu_kpps=%.2f proc_kpps=%.2f loss_pct=%.3f ", w / 1e9, a / 1e9, us, (us > 0 ? 1000 / us : 0), p / busy / 1000, (q > 0 ? 100 * (q - p) / q : 0)
  printf "per_queue=%s worker_cpu_each_s=%s ", (perq == "" ? "-" : perq), each
  printf "cpu_s=%.2f cpu_us_per_pkt=%.2f nonidle_cpu_s=%.2f ", m / 1e6, (sent > 0 ? m / sent : 0), ncpu * mwall / 1e6 - idle / hz
  printf "startup_s=%.2f hwm_mb=%.1f rss_mb=%.1f temp_c=%s throttled_before=%s throttled_after=%s suricata_stop=%s\n", st / 1000, hwm / 1024, rss / 1024, temp, thr0, thr1, stopexit
}' > "$out/result.kv"
cat "$out/result.kv"
