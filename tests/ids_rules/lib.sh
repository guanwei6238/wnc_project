# 各腳本共用：定義路徑與 dk() 函式（用 docker 在容器內跑命令）。用法: source lib.sh
# 為什麼 --network none：執行階段不需要網路，也避免新建/佔用 Docker 網段(曾與 NAS 網段衝突)。
# 為什麼 --user：避免容器以 root 寫出檔案，之後宿主機無法刪除。
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULESETS=/home/sixsquare/datasets/rulesets     # 大檔放 repo 外
WORK=$RULESETS/work                            # et_all.rules / 轉換後規則(容器內唯讀 /rules)
RUNS=$RULESETS/runs                            # 每次執行的 log(容器內 /out)
IMAGE=wnc-ids-lab
mkdir -p "$WORK" "$RUNS"
# dk [額外 docker 參數...] -- 命令...   例: dk --memory=1g --memory-swap=1g -- /scripts/ids.sh ...
dk() {
  local extra=()
  while [ "$1" != "--" ]; do extra+=("$1"); shift; done; shift
  docker run --rm --network none --user "$(id -u):$(id -g)" \
    -v "$HERE":/scripts:ro -v "$WORK":/rules:ro -v "$RUNS":/out \
    "${extra[@]}" $IMAGE "$@"
}
