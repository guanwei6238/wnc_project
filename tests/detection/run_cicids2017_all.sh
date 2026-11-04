#!/bin/bash
# 依序處理 CIC-IDS2017 的其他天：等該天的 pcap 下載完（鏡像 sha256 核對過才有 .ok）再跑 run_cicids2017.sh。
# 用法: run_cicids2017_all.sh <day>...
HERE=$(cd "$(dirname "$0")" && pwd)
C=/home/sixsquare/datasets/cicids2017
declare -A FILE=([monday]=Monday-WorkingHours [tuesday]=Tuesday-WorkingHours [wednesday]=Wednesday-workingHours
                 [thursday]=Thursday-WorkingHours [friday]=Friday-WorkingHours)
for day in "$@"; do
    f=$C/pcaps/${FILE[$day]}.pcap
    until [ -f "$f.ok" ] || [ -f "$C/pcap/$day.pcap.ok" ]; do sleep 30; done
    "$HERE/run_cicids2017.sh" "$day" > "$C/run_$day.log" 2>&1
    echo "$day rc=$?"
done
