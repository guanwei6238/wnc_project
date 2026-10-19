#!/bin/bash
# 解壓前先檢查 tar 清單（資料來源不受信任），沒問題才解壓。
# 檢查：1) 沒有絕對路徑  2) 沒有 ".." 路徑成分  3) 只有一般檔案與目錄（沒有 symlink / hardlink / 裝置檔）
# 用法：./02_extract.sh <tar.gz> <解壓目錄（要是新的空目錄）> <清單輸出檔>
set -eu
TGZ="${1:?}"; DEST="${2:?}"; LIST="${3:?}"
[ -z "$(ls -A "$DEST")" ] || { echo "解壓目錄不是空的: $DEST"; exit 1; }

nice -n 10 ionice -c3 tar -tzvf "$TGZ" > "$LIST"        # 完整清單（含型態、大小）
echo "清單筆數: $(wc -l < "$LIST")"
# 型態是每行第一個字元：- 一般檔案, d 目錄, l symlink, h hardlink ...
if cut -c1 "$LIST" | grep -qv '^[-d]$'; then echo "發現非一般檔案/目錄的項目："; grep -v '^[-d]' "$LIST" | head; exit 1; fi
tar -tzf "$TGZ" > "$LIST.names"   # 純檔名清單（只列出，不解壓）
if grep -qE '^/' "$LIST.names"; then echo "發現絕對路徑"; grep -E '^/' "$LIST.names" | head; exit 1; fi
if grep -qE '(^|/)\.\.(/|$)' "$LIST.names"; then echo "發現 .. 路徑"; grep -E '(^|/)\.\.(/|$)' "$LIST.names" | head; exit 1; fi
echo "清單檢查通過，開始解壓"
nice -n 10 ionice -c3 tar -xzf "$TGZ" -C "$DEST" --no-same-owner --no-same-permissions
echo "解壓完成"
