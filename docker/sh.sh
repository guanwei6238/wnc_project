#!/usr/bin/env bash
# ./sh.sh <cli|gw|srv> [指令...]   不給指令就開互動 shell
set -euo pipefail
[[ $# -ge 1 ]] || { echo "用法: $0 <cli|gw|srv> [指令...]" >&2; exit 1; }
node="$1"; shift
if [[ $# -eq 0 ]]; then
  exec docker exec -it "wnc-$node" bash
else
  exec docker exec -it "wnc-$node" "$@"
fi
