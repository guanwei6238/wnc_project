#!/bin/bash
# 比對「原版 02_align.py」與「串流版 align_stream.py」在兩個小樣本上的輸出是否逐字一致。
# 另外用 --max-flows 1000 強制分批，確認分批與不分批結果相同。
HERE="$(cd "$(dirname "$0")" && pwd)"
S="$HERE/../dataset/data/小樣本資料"
T="${TMPDIR:-/tmp}"
for d in Hakai-8-1 Somfy-01; do
  L="$S/$d/conn.log.labeled"; P=$(ls "$S/$d"/*.pcap)
  # 原版輸出到「涵蓋」那行為止（後面是說明文字，串流版不印）
  python3 -I "$HERE/../dataset/02_align.py" "$L" "$P" | sed '/^其餘為/,$d' > "$T/orig.txt"
  python3 -I "$HERE/align_stream.py" "$L" "$P" --text > "$T/new.txt"
  python3 -I "$HERE/align_stream.py" "$L" "$P" --text --max-flows 1000 > "$T/shard.txt"
  echo "== $d"
  diff "$T/orig.txt" "$T/new.txt" > /dev/null && echo "  原版 vs 串流版：完全一致" || { echo "  原版 vs 串流版：有差異"; diff "$T/orig.txt" "$T/new.txt"; }
  diff "$T/new.txt" "$T/shard.txt" > /dev/null && echo "  不分批 vs 分批：完全一致" || echo "  不分批 vs 分批：有差異"
done
