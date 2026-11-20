#!/bin/bash
# ids candidate A (NFQ, verdict always accept) vs B (NFLOG copies): 10,000 pps, 1 queue/group, 2 rounds, results in results/$TAG.kvl
#   RUNMODES: Suricata runmodes to compare, space-separated (default workers)
# Usage: sudo TAG=nflog1 [RUNMODES="workers autofp"] bash run_nflog.sh
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
