#!/bin/bash
# run_compare.sh — comparison: same pcap, rule set and rate; compares wnc-gw / Suricata running NFQ directly / Suricata af-packet IPS
#   within each (scenario, rule set) the three variants run in shuffled, interleaved order
# Prerequisites same as run_pi.sh
# Usage: sudo nohup bash run_compare.sh > /home/wnc/ids_inline/compare.log 2>&1 < /dev/null &
# Results: $OUT/$TAG.kvl
cd "$(dirname "$0")" || exit 1
TAG=${TAG:-compare1}; RATE=${RATE:-10000}
OUT=${OUT:-/home/wnc/ids_inline/results}; RUNS=${RUNS:-/home/wnc/ids_inline/runs}
LOG=/var/log/wnc-gw/suricata
PCS=${PCS:-"S_m60 S_somfy02 S_m39 S_m42 S_m17"}; RSS=${RSS:-"empty full"}
mkdir -p "$OUT" "$RUNS/$TAG"
pgrep -x Suricata-Main > /dev/null && { echo "another suricata is running"; exit 1; }
seq=0
for pc in $PCS; do bash trial.sh empty "$pc" cache /tmp/x || exit 1; done
for pc in $PCS; do
  for rs in $RSS; do
    for impl in $(printf 'wncgw\nnfq\nafpacket\n' | shuf); do
      seq=$((seq + 1)); d=$RUNS/$TAG/$(printf %03d $seq)-$impl-$rs-$pc
      echo "$(date -u +%T) #$seq $impl $rs $pc"
      if IMPL=$impl bash trial.sh "$rs" "$pc" "$RATE" "$d" > /dev/null; then
        echo "tag=$TAG seq=$seq $(cat $d/result.kv)" >> "$OUT/$TAG.kvl"
        grep -o -E "processed=[^ ]*|us_per_pkt=[^ ]*|loss_pct=[^ ]*" $d/result.kv | tr '\n' ' '; echo
      else
        echo "  FAILED: $d"
      fi
      rm -f $LOG/*
    done
  done
done
echo "ALL DONE $(date -u +%FT%TZ)"
