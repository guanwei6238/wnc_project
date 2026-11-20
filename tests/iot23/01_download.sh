#!/bin/bash
# Download the full IoT-23 dataset (Zenodo 4743746), resumable, verifying md5 when done.
# Zenodo throttles each single connection (measured about 0.3~0.4 MB/s, 10+ hours for 21.5 GB),
# so the file is split into N ranges (HTTP Range) fetched over N parallel connections, then joined with cat.
# Safe to rerun: the downloaded part of each range is kept and resumed from where it stopped.
# Usage: ./01_download.sh <download dir>      (use a directory set aside for this download)
set -u
DIR="${1:?用法: $0 <下載目錄>}"
URL="https://zenodo.org/api/records/4743746/files/iot_23_datasets_full.tar.gz/content"
SIZE=21510801277
MD5_EXPECT=7132e603f9750b8580b6cebdbcd43e9c
N=6
SEG=$(( (SIZE + N - 1) / N ))
cd "$DIR" || exit 1

fetch_part() {   # $1 = part number
  local i=$1 start=$(( $1 * SEG )) end=$(( ($1 + 1) * SEG - 1 ))
  [ $end -ge $SIZE ] && end=$(( SIZE - 1 ))
  local want=$(( end - start + 1 ))
  while :; do
    local have=0; [ -f part$i ] && have=$(stat -c%s part$i)
    [ $have -ge $want ] && break
    nice -n 10 ionice -c3 curl -sS -L -r $(( start + have ))-$end "$URL" >> part$i || sleep 10
  done
}

for i in $(seq 0 $(( N - 1 ))); do fetch_part $i & done
wait

# Join only if every part has the right size
for i in $(seq 0 $(( N - 1 ))); do
  s=$(( i * SEG )); e=$(( (i + 1) * SEG - 1 )); [ $e -ge $SIZE ] && e=$(( SIZE - 1 ))
  [ "$(stat -c%s part$i)" = "$(( e - s + 1 ))" ] || { echo "part$i 大小不對"; exit 1; }
done
cat $(for i in $(seq 0 $(( N - 1 ))); do echo part$i; done) > iot_23_datasets_full.tar.gz
echo "合併大小: $(stat -c%s iot_23_datasets_full.tar.gz)（預期 $SIZE）"
MD5=$(nice -n 10 ionice -c3 md5sum iot_23_datasets_full.tar.gz | cut -d' ' -f1)
echo "md5 自己算: $MD5"
echo "md5 Zenodo: $MD5_EXPECT"
if [ "$MD5" = "$MD5_EXPECT" ]; then echo "MD5 OK"; rm -f part[0-9]*; else echo "MD5 不符！"; exit 2; fi
