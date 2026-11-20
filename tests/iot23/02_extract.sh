#!/bin/bash
# Check the tar listing before extracting (the data source is untrusted); extract only if it passes.
# Checks: 1) no absolute paths  2) no ".." path components  3) only regular files and directories (no symlinks / hardlinks / device files)
# Usage: ./02_extract.sh <tar.gz> <extract dir (must be a new empty dir)> <listing output file>
set -eu
TGZ="${1:?}"; DEST="${2:?}"; LIST="${3:?}"
[ -z "$(ls -A "$DEST")" ] || { echo "解壓目錄不是空的: $DEST"; exit 1; }

nice -n 10 ionice -c3 tar -tzvf "$TGZ" > "$LIST"        # full listing (with types and sizes)
echo "清單筆數: $(wc -l < "$LIST")"
# The type is the first character of each line: - regular file, d directory, l symlink, h hardlink ...
if cut -c1 "$LIST" | grep -qv '^[-d]$'; then echo "發現非一般檔案/目錄的項目："; grep -v '^[-d]' "$LIST" | head; exit 1; fi
tar -tzf "$TGZ" > "$LIST.names"   # names only (listed, not extracted)
if grep -qE '^/' "$LIST.names"; then echo "發現絕對路徑"; grep -E '^/' "$LIST.names" | head; exit 1; fi
if grep -qE '(^|/)\.\.(/|$)' "$LIST.names"; then echo "發現 .. 路徑"; grep -E '(^|/)\.\.(/|$)' "$LIST.names" | head; exit 1; fi
echo "清單檢查通過，開始解壓"
nice -n 10 ionice -c3 tar -xzf "$TGZ" -C "$DEST" --no-same-owner --no-same-permissions
echo "解壓完成"
