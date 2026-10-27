#!/bin/bash
# run_mq.sh — 多 queue：同一個 pcap、rule set 全速送，比較 1／2／3 個 queue（= Suricata worker 數）
#   Suricata 一律綁 $SURI_CPUS（預設 0,2,3）；tcpreplay 在 CPU 1，所以 4 個 queue 不量
#   每個 scenario 內 N 的順序打亂
# 前置同 run_pi.sh
# 用法: sudo nohup bash run_mq.sh > /home/wnc/ids_inline/mq.log 2>&1 < /dev/null &
#   QS：要比較的 queue 數（預設 "1 2 3"）；IMPL、QHASH 會傳給 trial.sh
#   mq1   = 預設（wnc-gw，位址 hash）
#   sym1  = TAG=sym1 IMPL=nfq QHASH=symhash QS="2 3" PCS="S_m60 S_somfy02 S_m42 S_m39"
#   addr1 = TAG=addr1 IMPL=nfq QS="2 3" PCS="S_m60 S_somfy02 S_m42 S_m39"
# 結果：$OUT/$TAG.kvl
cd "$(dirname "$0")" || exit 1
TAG=${TAG:-mq1}; RATE=${RATE:-top}; RULESET=${RULESET:-full}; export SURI_CPUS=${SURI_CPUS:-0,2,3}
OUT=${OUT:-/home/wnc/ids_inline/results}; RUNS=${RUNS:-/home/wnc/ids_inline/runs}
LOG=/var/log/wnc-gw/suricata
PCS=${PCS:-"S_m60 S_somfy02 S_m39 S_m42 S_m17"}
mkdir -p "$OUT" "$RUNS/$TAG"
pgrep -x Suricata-Main > /dev/null && { echo "another suricata is running"; exit 1; }
seq=0
for pc in $PCS; do
  for n in $(echo ${QS:-1 2 3} | tr ' ' '\n' | shuf); do
    seq=$((seq + 1)); d=$RUNS/$TAG/$(printf %03d $seq)-q$n-$RULESET-$pc-$RATE
    echo "$(date -u +%T) #$seq queues=$n $RULESET $pc $RATE"
    if QUEUES=$n bash trial.sh "$RULESET" "$pc" "$RATE" "$d" > /dev/null; then
      echo "tag=$TAG seq=$seq $(cat $d/result.kv)" >> "$OUT/$TAG.kvl"
      grep -o -E "proc_kpps=[^ ]*|loss_pct=[^ ]*|per_queue=[^ ]*|worker_cpu_each_s=[^ ]*" $d/result.kv | tr '\n' ' '; echo
    else
      echo "  FAILED: $d"
    fi
    rm -f $LOG/*
  done
done
echo "ALL DONE $(date -u +%FT%TZ)"
