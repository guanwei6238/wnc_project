#!/bin/bash
# CIC-DDoS2019 全部 flow 的對齊（不抽樣），算出 flow alignment 和 packet coverage。
#   03-11：直接讀 pcap/0311.pcap，一批放得下全部 2,036 萬條 flow
#   01-12：zip 邊解壓邊用 pipe 送進 align_stream.py（不先存成 160 GB 的 pcap）；pipe 只能讀一次，
#          所以每次只載入一份 flow（--part i/K），K 份依序各讀一次，最後用 merge_align.py 相加
# 用法: align_cicddos2019_full.sh [K，預設 1]
# 前提：zip 已從 NAS 複製到 ~/datasets/cicddos2019/zips/；conn/0112/*.conn.log.labeled 已由 run_cicddos2019_0112_full.sh 產生。
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
A=$HERE/../iot23/align_stream.py
D=/home/sixsquare/datasets/cicddos2019
K=${1:-1}

# 03-11 的官方 CSV 有 482,799 組重複列，用去重後的（dedup_conn.sh）；01-12 沒有重複列
[ -f "$D/conn/0311.dedup.conn.log.labeled" ] || "$HERE/dedup_conn.sh" "$D/conn/0311.conn.log.labeled" "$D/conn/0311.dedup.conn.log.labeled"
[ -f "$D/align/0311_dedup.json" ] || python3 -I "$A" "$D/conn/0311.dedup.conn.log.labeled" "$D/pcap/0311.pcap" \
    --cic --max-flows 25000000 --json "$D/align/0311_dedup.json"

c=$D/conn/0112.conn.log.labeled
[ -f "$c" ] || cat "$D"/conn/0112/*.conn.log.labeled > "$c"
parts=()
for ((i = 0; i < K; i++)); do
    p=$D/align/0112.part${i}of$K.json
    [ -f "$p" ] || python3 -I "$HERE/zip_pcap_concat.py" /dev/stdout "$D"/zips/PCAP-01-12_*.zip 2>> "$D/align/0112.concat.log" \
        | python3 -I "$A" "$c" /dev/stdin --cic --part "$i/$K" --max-flows 60000000 --json "$p"
    parts+=("$p")
done
python3 -I "$HERE/merge_align.py" "$D/align/0112.json" "${parts[@]}"
