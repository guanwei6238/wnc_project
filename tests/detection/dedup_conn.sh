#!/bin/bash
# conn.log.labeled 去掉重複列：5-tuple、ts、duration、orig_pkts、resp_pkts 都相同的列只留第一次出現的（保留原本的順序）。
# CIC-DDoS2019 03-11 的官方 CSV 有 482,799 組這種列（每組 2 列，除了 uid 以外每個欄位都相同）。
# 用法: dedup_conn.sh <輸入> <輸出> [暫存目錄]；記憶體用量小（sort 用磁碟），刪掉的列號寫到 <輸出>.dropped
set -euo pipefail
in=$1; out=$2; tmp=${3:-$(dirname "$out")}
LC_ALL=C awk -F'\t' -v OFS='\t' '$1!~/^#/{print $3,$4,$5,$6,$7,$1,$9,$17,$19,NR}' "$in" \
  | LC_ALL=C sort -S 800M -T "$tmp" -t$'\t' -k1,9 -k10,10n \
  | LC_ALL=C awk -F'\t' '{k=$1 FS $2 FS $3 FS $4 FS $5 FS $6 FS $7 FS $8 FS $9; if(k==pk) print $10; pk=k}' \
  | LC_ALL=C sort -S 200M -T "$tmp" -n > "$out.dropped"
LC_ALL=C awk 'NR==FNR{d[$1]=1; next} !(FNR in d)' "$out.dropped" "$in" > "$out"
echo "$(wc -l < "$out.dropped") rows dropped -> $out"
