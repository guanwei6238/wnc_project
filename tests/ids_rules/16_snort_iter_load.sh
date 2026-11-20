#!/bin/bash
# Load the snort2lua-converted rules with Snort 3 -T; on ERROR remove the bad rules and reload, iterating until it passes.
# Each round's log is in $RUNS/snort_iter/round_N/; sids removed per round and why accumulate in $RUNS/snort_iter/removed.tsv (round, sid, reason).
# Final passing rules file = $WORK/snort_pack/snort_accepted.rules (the snort_full.rules used by tests/ids_throughput).
# Prerequisite: 15_snort_convert.sh
source "$(dirname "$0")/lib.sh"
I=$RUNS/snort_iter; rm -rf "$I"; mkdir -p "$I"
P=$WORK/snort_pack; rm -rf "$P/iter"; mkdir -p "$P/iter"
cp "$P/snort3_converted.rules" "$P/iter/round_1.rules"
echo -e "round\tsid\treason" > "$I/removed.tsv"
for r in $(seq 1 10); do
  dk -- /scripts/ids.sh snort-T /out/snort_iter/round_$r /rules/snort_pack/iter/round_$r.rules
  rc=$?
  loaded=$(grep 'total rules loaded' "$I/round_$r/out.log" | awk '{print $NF}')
  echo "round $r: snort exit=$rc, 'total rules loaded'=$loaded"
  python3 -I "$HERE/16b_drop_bad_rules.py" "$P/iter/round_$r.rules" "$I/round_$r/out.log" "$P/iter/round_$((r+1)).rules" "$I/removed.tsv" $r
  d=$?
  if [ $d -eq 0 ]; then
    [ $rc -eq 0 ] || { echo "round $r: 無 ERROR 但 snort exit=$rc，需人工檢查"; exit 3; }
    cp "$P/iter/round_$r.rules" "$P/snort_accepted.rules"
    echo "通過。最終規則檔: $P/snort_accepted.rules  (活躍規則行: $(grep -cE '^(alert|drop|reject|pass) ' "$P/snort_accepted.rules"))"
    exit 0
  elif [ $d -eq 2 ]; then exit 2; fi
done
echo "迭代 10 輪仍未通過"; exit 4
