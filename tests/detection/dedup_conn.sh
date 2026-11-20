#!/bin/bash
# Remove duplicate rows from conn.log.labeled: of rows with the same 5-tuple, ts, duration, orig_pkts and resp_pkts, keep only the first (original order kept).
# The official CIC-DDoS2019 03-11 CSV has 482,799 such groups (2 rows each, identical in every field except uid).
# Usage: dedup_conn.sh <input> <output> [temp dir]; low memory use (sort uses disk); dropped line numbers go to <output>.dropped
set -euo pipefail
in=$1; out=$2; tmp=${3:-$(dirname "$out")}
LC_ALL=C awk -F'\t' -v OFS='\t' '$1!~/^#/{print $3,$4,$5,$6,$7,$1,$9,$17,$19,NR}' "$in" \
  | LC_ALL=C sort -S 800M -T "$tmp" -t$'\t' -k1,9 -k10,10n \
  | LC_ALL=C awk -F'\t' '{k=$1 FS $2 FS $3 FS $4 FS $5 FS $6 FS $7 FS $8 FS $9; if(k==pk) print $10; pk=k}' \
  | LC_ALL=C sort -S 200M -T "$tmp" -n > "$out.dropped"
LC_ALL=C awk 'NR==FNR{d[$1]=1; next} !(FNR in d)' "$out.dropped" "$in" > "$out"
echo "$(wc -l < "$out.dropped") rows dropped -> $out"
