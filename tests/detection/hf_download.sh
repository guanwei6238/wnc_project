#!/bin/bash
# 從 Hugging Face 的 dataset 鏡像下載檔案，下載完用 Hugging Face 記的 sha256（LFS oid）核對。
# 用法: hf_download.sh <repo，例如 bencorn/CICIDS2017> <目的目錄> <repo 內路徑>...
# 鏡像不是官方來源：和官方的一致性另外核對（CIC-IDS2017 有官方 md5）。
set -euo pipefail
repo=$1; dst=$2; shift 2
mkdir -p "$dst"
tree=$(mktemp)
trap 'rm -f "$tree"' EXIT
curl -sS -m 120 -o "$tree" "https://huggingface.co/api/datasets/$repo/tree/main?recursive=true"
for p in "$@"; do
    # 大檔（LFS）記 sha256；小檔是一般 git 檔，記的是 git blob 的 sha1（"blob <大小>\0" + 內容）
    want=$(python3 -c 'import json,sys; x=next(x for x in json.load(open(sys.argv[1])) if x["path"]==sys.argv[2]); print(x["lfs"]["oid"] if "lfs" in x else "git:" + x["oid"])' "$tree" "$p")
    out=$dst/$(basename "$p")
    if [ -f "$out.ok" ]; then echo "skip $p"; continue; fi
    curl -sS -L --http1.1 -C - --retry 10 --retry-all-errors -o "$out" "https://huggingface.co/datasets/$repo/resolve/main/$p"
    case $want in
        git:*) got=git:$( { printf 'blob %s\0' "$(stat -c %s "$out")"; cat "$out"; } | sha1sum | cut -d' ' -f1) ;;
        *) got=$(sha256sum "$out" | cut -d' ' -f1) ;;
    esac
    if [ "$got" = "$want" ]; then echo "$got" > "$out.ok"; echo "ok $p"; else echo "SHA256 MISMATCH $p got=$got want=$want"; fi
done
