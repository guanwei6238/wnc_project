#!/bin/bash
# ids 候選 A（NFQ，判決一律放行）對 B（NFLOG 複本）：10,000 pps、1 個 queue／group，2 輪，結果在 results/$TAG.kvl
#   RUNMODES：要比的 Suricata runmode，用空白分開（預設 workers）
# 用法: sudo TAG=nflog1 [RUNMODES="workers autofp"] bash run_nflog.sh
TAG=${TAG:-nflog1}; RUNMODES=${RUNMODES:-workers}; R=/home/wnc/ids_inline/results/$TAG.kvl; RUNS=/tmp/wncgw/runs/$TAG
cd /home/wnc/ids_inline; mkdir -p $RUNS
for round in 1 2; do
  for pc in S_m60 S_m1 S_m17; do
    for rs in empty full; do
      for rm in $RUNMODES; do
        for impl in nfq nflog; do
          out=$RUNS/$round-$pc-$rs-$rm-$impl; rm -rf $out
          echo "$(date -u +%T) round=$round $pc $rs $rm $impl"
          line=$(IMPL=$impl RUNMODE=$rm bash trial.sh $rs $pc 10000 $out 2>&1 | tail -1)
          case "$line" in impl=*) echo "round=$round $line" >> $R ;; *) echo "  FAILED: $line" ;; esac
        done
      done
    done
  done
done
echo "NFLOG DONE $(date -u +%FT%TZ)"
