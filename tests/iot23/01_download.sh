#!/bin/bash
# 下載 IoT-23 完整資料集（Zenodo 4743746），可續傳，下載完驗證 md5。
# Zenodo 對「單一連線」限速（實測約 0.3~0.4 MB/s，21.5 GB 要十幾小時），
# 所以把檔案切成 N 段（HTTP Range），同時開 N 條連線，最後用 cat 接起來。
# 可重複執行：每段已下載的部分會被保留，從斷點接著抓。
# 用法：./01_download.sh <下載目錄>      （目錄要是你專為這次下載準備的目錄）
set -u
DIR="${1:?用法: $0 <下載目錄>}"
URL="https://zenodo.org/api/records/4743746/files/iot_23_datasets_full.tar.gz/content"
SIZE=21510801277
MD5_EXPECT=7132e603f9750b8580b6cebdbcd43e9c
N=6
SEG=$(( (SIZE + N - 1) / N ))
cd "$DIR" || exit 1

fetch_part() {   # $1 = 第幾段
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

# 每段大小都對才接起來
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
