#!/usr/bin/env bash
# ./sh.sh <cli|gw|srv> [cmd...]   opens an interactive shell if no command is given
set -euo pipefail
[[ $# -ge 1 ]] || { echo "用法: $0 <cli|gw|srv> [指令...]" >&2; exit 1; }
node="$1"; shift
if [[ $# -eq 0 ]]; then
  exec docker exec -it "wnc-$node" bash
else
  exec docker exec -it "wnc-$node" "$@"
fi
