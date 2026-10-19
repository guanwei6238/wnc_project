#!/bin/bash
# 在「容器內」執行的單一入口，包住 /usr/bin/time -v，讓每次量測格式一致。
# 用法: ids.sh <mode> <outdir> <rules> [pcap]
#   mode = suri-T | suri-r | snort-T | snort-r
#     -T : 只測試設定(載入規則、建好偵測引擎後就結束)   -r : 真的讀 pcap 跑一遍(完整初始化)
#   環境變數  MPM=ac-ks|hs|ac  SPM=bm|hs (Suricata; SPM 是單一 pattern 比對, 預設 bm 以便 Pi 上等價; hs 組要設 SPM=hs)   SEARCH=ac_bnfa|hyperscan|ac_full (Snort 3)  EVENT_FILTER_LUA=<.lua 路徑> (Snort 3, 選用)
# 產生: <outdir>/out.log (引擎 stdout+stderr)  <outdir>/time.txt (/usr/bin/time -v)
mode=$1; outdir=$2; rules=$3; pcap=${4:-}
mkdir -p "$outdir"
cd "$outdir" || exit 99      # 引擎產生的檔案(fast.log, eve.json…)都落在這裡

# Snort 3 預設 HOME_NET='any'，ET 規則裡的 !$HOME_NET 會變成 "!any is not allowed" 而被拒絕，
# 這是設定問題不是規則問題。這裡把 HOME_NET/EXTERNAL_NET 設成與 Suricata 預設相同(RFC1918 三段)，
# 兩個引擎才在同一個前提下比較。做法：複製官方 snort.lua，只改這兩行。
SNORT_ETC=/opt/snort/etc/snort
sed -e "s|^HOME_NET = 'any'|HOME_NET = '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]'|" \
    -e "s|^EXTERNAL_NET = 'any'|EXTERNAL_NET = '!\$HOME_NET'|" $SNORT_ETC/snort.lua > "$outdir/snort.lua"
SNORT_CONF=(-c "$outdir/snort.lua" --include-path $SNORT_ETC)

# EVENT_FILTER_LUA(選用): snort2lua 產生的 .lua，裡面是 rule 內 threshold 被改寫成的 event_filter 設定。
# 只用 -R 載規則時這些 threshold 不會生效；要載入就設這個環境變數(容器內路徑)。預設不載入。
EVF=""; [ -n "$EVENT_FILTER_LUA" ] && EVF="; include '$EVENT_FILTER_LUA'"

case $mode in
  suri-T)  cmd=(suricata -T -v -c /etc/suricata/suricata.yaml -S "$rules" -l "$outdir" --set mpm-algo=${MPM:-ac-ks} --set spm-algo=${SPM:-bm}) ;;
  suri-r)  cmd=(suricata -v -c /etc/suricata/suricata.yaml -S "$rules" -l "$outdir" --set mpm-algo=${MPM:-ac-ks} --set spm-algo=${SPM:-bm} -k none -r "$pcap") ;;
  snort-T) cmd=(snort -T "${SNORT_CONF[@]}" -R "$rules" --lua "search_engine = { search_method = '${SEARCH:-ac_bnfa}' } $EVF") ;;
  snort-r) cmd=(snort "${SNORT_CONF[@]}" -R "$rules" --lua "search_engine = { search_method = '${SEARCH:-ac_bnfa}' } $EVF" -r "$pcap" -A alert_fast -l "$outdir" -k none) ;;
  *) echo "unknown mode $mode"; exit 98 ;;
esac

# -v: 印出 Maximum resident set size(峰值 RSS) 與 Elapsed(wall clock)
/usr/bin/time -v -o "$outdir/time.txt" "${cmd[@]}" > "$outdir/out.log" 2>&1
rc=$?
echo "exit_code=$rc" >> "$outdir/time.txt"
exit $rc
