#!/bin/bash
# Check that the original 02_align.py and the streaming align_stream.py give identical output on two small samples.
# Also force sharding with --max-flows 1000 to confirm sharded and unsharded results match.
HERE="$(cd "$(dirname "$0")" && pwd)"
S="$HERE/../dataset/data/小樣本資料"
T="${TMPDIR:-/tmp}"
for d in Hakai-8-1 Somfy-01; do
  L="$S/$d/conn.log.labeled"; P=$(ls "$S/$d"/*.pcap)
  # Original output up to the coverage line (the rest is explanatory text the streaming version doesn't print)
  python3 -I "$HERE/../dataset/02_align.py" "$L" "$P" | sed '/^其餘為/,$d' > "$T/orig.txt"
  python3 -I "$HERE/align_stream.py" "$L" "$P" --text > "$T/new.txt"
  python3 -I "$HERE/align_stream.py" "$L" "$P" --text --max-flows 1000 > "$T/shard.txt"
  echo "== $d"
  diff "$T/orig.txt" "$T/new.txt" > /dev/null && echo "  原版 vs 串流版：完全一致" || { echo "  原版 vs 串流版：有差異"; diff "$T/orig.txt" "$T/new.txt"; }
  diff "$T/new.txt" "$T/shard.txt" > /dev/null && echo "  不分批 vs 分批：完全一致" || echo "  不分批 vs 分批：有差異"
done
