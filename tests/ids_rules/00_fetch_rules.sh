#!/bin/bash
# 下載並凍結 ET Open 規則快照。用法: 00_fetch_rules.sh [快照目錄名，預設 snapshot_<今天>]
# 版本網址用 suricata-7.0.10：ET 以「Suricata 版本」分目錄，這是 Debian trixie suricata 套件的版本。
# 安全：規則包是不受信任資料 -> 解壓前檢查沒有絕對路徑或 '..'，且解壓到「新的空目錄」。
# 注意：快照一旦建立就不要重抓覆蓋(實驗要用同一份)。本次凍結的快照見 rules_manifest.txt。
set -e
RULESETS=/home/sixsquare/datasets/rulesets
SNAP=${1:-snapshot_$(date +%F)}
URL=https://rules.emergingthreats.net/open/suricata-7.0.10/emerging.rules.tar.gz
mkdir -p "$RULESETS/dl"; cd "$RULESETS"
[ -e "$SNAP" ] && { echo "$SNAP 已存在，不覆蓋"; exit 1; }
curl -sS -o dl/emerging.rules.tar.gz "$URL"; date -u +%FT%TZ > dl/download_date.txt
sha256sum dl/emerging.rules.tar.gz
tar tzf dl/emerging.rules.tar.gz > dl/tar_list.txt
if grep -qE '^/|(^|/)\.\.(/|$)' dl/tar_list.txt; then echo "tar 清單含絕對路徑或 ..，中止"; exit 1; fi
mkdir "$SNAP" && tar xzf dl/emerging.rules.tar.gz -C "$SNAP" --no-same-owner
chmod -R a-w "$SNAP"     # 唯讀，避免不小心改到凍結的快照
echo "ok -> $RULESETS/$SNAP/rules"
