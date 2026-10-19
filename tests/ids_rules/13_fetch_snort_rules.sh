#!/bin/bash
# 下載並凍結「Snort 版」ET Open 規則快照（給 Snort 3 用；Suricata 用 00_fetch_rules.sh 的 Suricata 版）。
# 為什麼要另一份：Suricata 版規則有 dns.query/tls.sni… 等 Suricata 專有關鍵字，Snort 3 不能用。ET 另有 Snort 語法的包：
#   open/snort-3.0.0/  與  open/snort-2.9.0/   ("2.9" 是『規則語法世代』；我們跑的引擎仍是 Snort 3.12.2.0，
#   snort2lua 只是 Snort 3 附的規則轉換工具)。兩個包都會下載（2026-10-11 的快照兩包內容完全相同），後續流程用 snort-3.0.0。
# 安全：下載的是不受信任資料 -> 解壓前檢查沒有絕對路徑或 '..'，各自解壓到「新的空目錄」並設唯讀。
# 快照一旦建立就不要重抓覆蓋。用法: 13_fetch_snort_rules.sh [日期標籤，預設今天]
set -e
RULESETS=/home/sixsquare/datasets/rulesets
TAG=${1:-$(date +%F)}
DL=$RULESETS/dl_snort
mkdir -p "$DL"; cd "$RULESETS"
for ver in 3.0.0 2.9.0; do
  name=snort-$ver
  SNAP=snapshot_${name}_$TAG
  [ -e "$SNAP" ] && { echo "$SNAP 已存在，不覆蓋"; exit 1; }
  curl -sS -D "$DL/$name.hdr.txt" -o "$DL/$name.tar.gz" "https://rules.emergingthreats.net/open/$name/emerging.rules.tar.gz"
  date -u +%FT%TZ > "$DL/$name.download_date.txt"
  sha256sum "$DL/$name.tar.gz" | tee "$DL/$name.sha256"
  tar tzf "$DL/$name.tar.gz" > "$DL/$name.tar_list.txt"
  if grep -qE '^/|(^|/)\.\.(/|$)' "$DL/$name.tar_list.txt"; then echo "$name tar 清單含絕對路徑或 ..，中止"; exit 1; fi
  mkdir "$SNAP" && tar xzf "$DL/$name.tar.gz" -C "$SNAP" --no-same-owner
  chmod -R a-w "$SNAP"
  echo "ok -> $RULESETS/$SNAP"
done
