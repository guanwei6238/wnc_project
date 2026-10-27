#!/bin/bash
# trial.sh — 一次 inline 量測
#   IMPL=wncgw（預設）  wnc-gw 啟動 Suricata（NFQ），就緒後 wnc-gw 自己裝 queue 規則
#   IMPL=nfq            對照組：直接執行 Suricata -q 0，看到 "Engine started" 後裝一條最簡單的 queue 規則
#   IMPL=afpacket       對照組：Suricata af-packet IPS 模式，g-lan、g-wan 暫時離開 br0，由 Suricata 在兩者之間搬封包
#   QUEUES=N（預設 1）：用 queue 0..N-1，Suricata 開 N 個 worker（wncgw 用 setting-<rules>-qN.toml；nfq 用 -q 0:N-1）
#   SURI_CPUS（預設 2,3）：Suricata 綁的 CPU
#   QHASH=symhash（只有 nfq）：用 queue to symhash mod N（含 port 的對稱 hash），預設是 queue num 0-(N-1)（kernel 只用位址做 hash）
#   三者都綁 $SURI_CPUS；就緒後等 2 秒，tcpreplay（wtest 裡、綁 CPU 1）送整個 pcap，等處理完，讀計數器與 RSS，再停止
# 用法: sudo [IMPL=...] bash trial.sh <empty|full|gw_corp> <pcap 名稱，例如 S_m39> <pps 數字|top|cache> <輸出目錄>
#   cache：只建 tcpprep 的 cache 就結束
# 輸出: <輸出目錄>/result.kv（一行 key=value），run.log，tcpreplay.txt
#
# 分流：IoT-23 的路由器在 WAN 端，來源 MAC 是路由器的封包從 t-wan 送，其餘從 t-lan
# 計數：
#   NFQ（wncgw、nfq）：/proc/net/netfilter/nfnetlink_queue 各 queue 加總；per_queue 是每個 queue 交給 Suricata 的封包數。to_queue = 進到 queue 規則；queue_drop = queue 滿被 kernel 丟掉；processed = 交給 Suricata 判決
#   afpacket：processed = 測試端 t-lan、t-wan 收到的封包（Suricata 送出去的）；to_queue = gateway 端 g-lan、g-wan 收到的封包
# CPU：Suricata worker 執行緒（NFQ 是 W-NFQ#0；af-packet 是每張網卡一個 W#…）的 schedstat 執行時間（ns）加總，送之前和處理完之後相減
#   us_per_pkt = worker CPU ÷ processed；cpu_kpps = 1000 ÷ us_per_pkt（對應 offline 的「packets ÷ engine 處理時間」）
#   proc_kpps = processed ÷（開始送 → 處理完）的牆鐘時間
set -u
rs=$1; pc=$2; rate=$3; out=$4
IMPL=${IMPL:-wncgw}; QUEUES=${QUEUES:-1}; SURI_CPUS=${SURI_CPUS:-2,3}
if [ "$QUEUES" -gt 1 ]; then qspec=0-$((QUEUES - 1)); qarg=0:$((QUEUES - 1)); qsuffix=-q$QUEUES; else qspec=0; qarg=0; qsuffix=; fi
M=${M:-/tmp/wncgw/m}; GW=${GW:-/tmp/wncgw/wnc-gw}; PCAPS=${PCAPS:-/home/wnc/ids_throughput/data/pcaps}
LOG=/var/log/wnc-gw/suricata
PCAP=$PCAPS/$pc.pcap; CACHE=$M/cache/$pc.cache
mkdir -p "$out"
case $pc in S_h5) router=82:e6:50:12:14:64 ;; S_m3) router=a6:d1:8c:1f:ce:64 ;; *) router=78:8a:20:43:93:d5 ;; esac
[ -f "$CACHE" ] || tcpprep --mac=$router --pcap="$PCAP" --cachefile="$CACHE" || exit 1
[ "$rate" = cache ] && exit 0
nfq() { ip netns exec wgw cat /proc/net/netfilter/nfnetlink_queue; }
rx() { local s=0 n; for l in "$@"; do n=$(ip netns exec ${l%%:*} cat /sys/class/net/${l#*:}/statistics/rx_packets); s=$((s + n)); done; echo $s; }
ts() { echo "${EPOCHREALTIME/./}"; }
thr() { vcgencmd get_throttled | cut -d= -f2; }
wait_log() { until grep -q "$1" "$out/run.log" 2>/dev/null; do sleep 0.1; [ -e "$out/exited" ] && { echo "exited before \"$1\": $out"; exit 1; }; done; }

thr0=$(thr)
tstart=$(ts)
case $IMPL in
wncgw)
  setsid bash -c "taskset -c $SURI_CPUS ip netns exec wgw $GW -c $M/setting-$rs$qsuffix.toml run > $out/run.log 2>&1 & echo \$! > $out/run.pid; wait \$!; echo exit=\$? >> $out/run.log; touch $out/exited" < /dev/null > /dev/null 2>&1 &
  wait_log "traffic is inspected"
  sp=$(grep -o "suricata started pid=[0-9]*" "$out/run.log" | tail -1 | cut -d= -f2)
  startup=$(grep -o "startup_ms=[0-9]*" "$out/run.log" | head -1 | cut -d= -f2) ;;
nfq|afpacket)
  if [ $IMPL = nfq ]; then args=(-c $M/suricata-$rs.yaml -q $qarg); else
    args=(-c $M/suricata-$rs-afp.yaml --af-packet); ip -n wgw link set g-lan nomaster; ip -n wgw link set g-wan nomaster; fi
  setsid bash -c "taskset -c $SURI_CPUS ip netns exec wgw suricata ${args[*]} -l $LOG --set unix-command.enabled=no --set coredump.max-dump=0 > $out/run.log 2>&1 & echo \$! > $out/run.pid; wait \$!; echo exit=\$? >> $out/run.log; touch $out/exited" < /dev/null > /dev/null 2>&1 &
  wait_log "Engine started"
  startup=$(( ($(ts) - tstart) / 1000 ))
  sp=$(cat $out/run.pid)
  if [ "${QHASH:-}" = symhash ]; then qstmt="queue to symhash mod $QUEUES"; else qstmt="queue num $qspec"; fi
  [ $IMPL = nfq ] && echo "table inet sq { chain f { type filter hook forward priority 0; policy accept; $qstmt; }; }" | ip netns exec wgw nft -f - ;;
*) echo "unknown IMPL $IMPL"; exit 2 ;;
esac
sleep 2
workers=$(for t in /proc/$sp/task/*; do case "$(cat $t/comm)" in W-NFQ*|W#*) echo "$(cat $t/comm) ${t##*/}" ;; esac; done | sort | cut -d" " -f2)
[ -n "$workers" ] || { echo "no worker thread in $sp"; exit 1; }
wcpu() { local s=0 n; for t in $workers; do n=$(cut -d" " -f1 /proc/$sp/task/$t/schedstat); s=$((s + n)); done; echo $s; }
weach() { for t in $workers; do cut -d" " -f1 /proc/$sp/task/$t/schedstat; done | tr '\n' ' '; }
pq() { [ $IMPL = afpacket ] && return; nfq | awk '{printf "%d ", $8 - $7}'; }
acpu() { cat /proc/$sp/task/*/schedstat | awk '{s+=$1} END{print s}'; }
counters() {  # 印出 to_queue queue_drop processed（累計值）
  if [ $IMPL = afpacket ]; then echo "$(rx wgw:g-lan wgw:g-wan) 0 $(rx wtest:t-lan wtest:t-wan)"
  else nfq | awk '{q += $8 + $6; d += $6; p += $8 - $7} END{print q, d, p}'; fi
}

read -r q0 qd0 p0 < <(counters); w0=$(wcpu); a0=$(acpu); we0=($(weach)); pq0=($(pq))
if [ "$rate" = top ]; then opt=--topspeed; else opt=--pps=$rate; fi
t0=$(ts)
ip netns exec wtest taskset -c 1 tcpreplay -i t-wan -I t-lan -c "$CACHE" $opt "$PCAP" > "$out/tcpreplay.txt" 2>&1
t1=$(ts)
if [ $IMPL = afpacket ]; then
  last=-1; while :; do cur=$(rx wtest:t-lan wtest:t-wan); [ "$cur" = "$last" ] && break; last=$cur; t2=$(ts); sleep 0.2; done
else
  until [ "$(nfq | awk '{s += $3} END{print s}')" = 0 ]; do sleep 0.01; done; t2=$(ts)
fi
read -r q1 qd1 p1 < <(counters); w1=$(wcpu); a1=$(acpu); we1=($(weach)); pq1=($(pq))
each=; for i in "${!we1[@]}"; do each+=$(awk -v d=$((we1[i] - we0[i])) 'BEGIN{printf "%.3f", d / 1e9}')/; done
perq=; for i in "${!pq1[@]}"; do perq+=$((pq1[i] - pq0[i]))/; done
hwm=$(awk '/VmHWM/{print $2}' /proc/$sp/status); rss=$(awk '/VmRSS/{print $2}' /proc/$sp/status)
temp=$(vcgencmd measure_temp | sed "s/temp=//; s/'C//"); thr1=$(thr)
case $IMPL in
wncgw) kill -INT "$(cat $out/run.pid)" ;;
nfq) ip netns exec wgw nft delete table inet sq; kill -TERM "$sp" ;;
afpacket) kill -TERM "$sp" ;;
esac
until [ -e "$out/exited" ]; do sleep 0.2; done
if [ $IMPL = afpacket ]; then ip -n wgw link set g-lan master br0; ip -n wgw link set g-wan master br0; fi

sent=$(grep -o "Actual: [0-9]* packets" "$out/tcpreplay.txt" | cut -d" " -f2)
stopexit=$(grep -o 'suricata stopped pid=[0-9]* exit="[^"]*"' "$out/run.log" | sed 's/.*exit="//; s/"//; s/ /_/g')
[ -n "$stopexit" ] || stopexit=$(grep -o "^exit=[0-9]*" "$out/run.log" | cut -d= -f2)
awk -v impl=$IMPL -v rs=$rs -v pc=$pc -v rate=$rate -v sent=${sent:-0} -v q=$((q1 - q0)) -v qd=$((qd1 - qd0)) -v p=$((p1 - p0)) -v nw=$(echo $workers | wc -w) \
    -v t0=$t0 -v t1=$t1 -v t2=$t2 -v w=$((w1 - w0)) -v a=$((a1 - a0)) -v st=${startup:-0} -v hwm=$hwm -v rss=$rss \
    -v temp=$temp -v thr0=$thr0 -v thr1=$thr1 -v stopexit=${stopexit:-unknown} -v qh=${QHASH:-addr} -v nq=$QUEUES -v cpus=$SURI_CPUS -v each=${each%/} -v perq=${perq%/} 'BEGIN{
  busy = (t2 - t0) / 1e6; us = (p > 0 ? w / 1e3 / p : 0)
  printf "impl=%s qhash=%s queues=%d cpus=%s rules=%s pcap=%s rate=%s sent=%d to_queue=%d queue_drop=%d processed=%d workers=%d send_s=%.3f busy_s=%.3f ", impl, qh, nq, cpus, rs, pc, rate, sent, q, qd, p, nw, (t1 - t0) / 1e6, busy
  printf "worker_cpu_s=%.4f all_cpu_s=%.4f us_per_pkt=%.2f cpu_kpps=%.2f proc_kpps=%.2f loss_pct=%.3f ", w / 1e9, a / 1e9, us, (us > 0 ? 1000 / us : 0), p / busy / 1000, (q > 0 ? 100 * (q - p) / q : 0)
  printf "per_queue=%s worker_cpu_each_s=%s ", (perq == "" ? "-" : perq), each
  printf "startup_s=%.2f hwm_mb=%.1f rss_mb=%.1f temp_c=%s throttled_before=%s throttled_after=%s suricata_stop=%s\n", st / 1000, hwm / 1024, rss / 1024, temp, thr0, thr1, stopexit
}' > "$out/result.kv"
cat "$out/result.kv"
