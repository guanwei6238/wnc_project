#!/bin/bash
# Download files from a Hugging Face dataset mirror and verify them against the sha256 Hugging Face records (LFS oid).
# Usage: hf_download.sh <repo, e.g. bencorn/CICIDS2017> <dest dir> <path in repo>...
# The mirror is not the official source: consistency with the official files is checked separately (CIC-IDS2017 has official md5s).
set -euo pipefail
repo=$1; dst=$2; shift 2
mkdir -p "$dst"
tree=$(mktemp)
trap 'rm -f "$tree"' EXIT
curl -sS -m 120 -o "$tree" "https://huggingface.co/api/datasets/$repo/tree/main?recursive=true"
for p in "$@"; do
    # Large files (LFS) record sha256; small files are regular git files and record the git blob sha1 ("blob <size>\0" + content)
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
