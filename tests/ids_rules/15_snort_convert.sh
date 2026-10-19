#!/bin/bash
# 用 snort2lua 把「Snort 版」ET 規則(work/snort_pack/et_all.rules)轉成 Snort 3 語法 -> work/snort_pack/snort3_converted.rules（給 16 載入）。
# snort2lua 會把輸出檔(如 et_all.rules.lua)寫在「來源規則檔旁邊」，而 $WORK 在容器內是唯讀(/rules)，
#   所以先把規則複製到可寫的 $RUNS/snort_s2l/ 再轉。
# 轉不了的規則：整條被 '#' 註解並寫進 snort2lua_err.txt(原因在 '^^^^' 行；18 用它歸因)；
# 注意 snort2lua 也會把部分選項(如 threshold)改寫進 .lua 設定檔(snort3_conv.lua)而不是留在規則裡。
# 前置：02_prep_rules.py 已對 Snort 版包產生 $WORK/snort_pack/et_all.rules。
source "$(dirname "$0")/lib.sh"
D=$RUNS/snort_s2l
rm -rf "$D"; mkdir -p "$D"
cp "$WORK/snort_pack/et_all.rules" "$D/et_all.rules"
printf 'include /out/snort_s2l/et_all.rules\n' > "$D/snort.conf"
dk -w /out/snort_s2l -- snort2lua -c snort.conf -s -r snort3_converted.rules -o snort3_conv.lua -e snort2lua_err.txt > "$D/stdout.txt" 2>&1
tail -12 "$D/stdout.txt"
cp "$D/snort3_converted.rules" "$WORK/snort_pack/snort3_converted.rules"
ls -la "$D"; wc -l "$WORK/snort_pack/snort3_converted.rules"
