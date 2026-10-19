#!/bin/bash
# 共用路徑與 dk() 函式（在容器內跑指令）。用法: source lib.sh
# 大檔（切片 pcap、原始 log）放 repo 外的 $BIG；repo 內只放腳本、manifest、小型結果。
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIG=${BIG:-/home/sixsquare/datasets/throughput}
PCAPS=$BIG/pcaps          # 凍結後的切片（唯讀使用）
RULES=$BIG/rules          # 四個規則檔 + SHA256SUMS
RUNS=$BIG/runs            # 每次量測的原始 log
IOT23=/home/sixsquare/datasets/iot23/extracted/run1/opt/Malware-Project/BigDataset/IoTScenarios
IMAGE=${IMAGE:-wnc-ids-lab}
mkdir -p "$PCAPS" "$RULES" "$RUNS"

# dk [額外 docker 參數...] -- 命令...
# 為什麼 --network none: 執行階段不需要網路，也不建立新 Docker 網段（曾與 NAS 的 172.24.8.x 衝突）。
# 為什麼 --user: 避免容器以 root 寫出檔案，之後宿主機無法刪除。
dk() {
  local extra=()
  while [ "$1" != "--" ]; do extra+=("$1"); shift; done; shift
  docker run --rm --network none --user "$(id -u):$(id -g)" "${extra[@]}" "$IMAGE" "$@"
}
