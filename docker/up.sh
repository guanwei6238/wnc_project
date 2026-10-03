#!/usr/bin/env bash
# 建立並啟動 testbed，最後做連通性驗證。
set -euo pipefail
cd "$(dirname "$0")"

echo "==> 建立 image（第一次會比較久）"
docker compose build

echo "==> 啟動容器"
docker compose up -d

echo "==> 等待節點就緒"
for i in $(seq 20); do
  if docker exec wnc-gw test -f /run/wnc-ifaces 2>/dev/null; then break; fi
  sleep 0.5
done

echo "==> 連通性驗證: cli -> srv (要經過 gw 轉發)"
if docker exec wnc-cli ping -c2 -W2 10.0.2.2 >/dev/null 2>&1; then
  echo "    OK"
else
  echo "    失敗。用下面指令看原因:" >&2
  echo "      docker compose logs" >&2
  exit 1
fi

echo "==> 驗證封包真的經過 gw（看 TTL 有沒有被減 1）"
docker exec wnc-cli ping -c1 10.0.2.2 | grep -E 'ttl=' || true

echo
echo "==> 各節點狀態"
docker compose ps
echo
cat <<'MSG'
testbed 就緒。常用指令：

  ./sh.sh gw                      # 進入閘道器 shell（cli / gw / srv）
  docker compose logs gw          # 看該節點開機時印的網路摘要

  # 在閘道器上看封包流過
  docker exec -it wnc-gw tcpdump -ni any -nn icmp

  # 量吞吐量（srv 上的 iperf3 server 已自動啟動）
  docker exec wnc-cli iperf3 -c 10.0.2.2 -t 5

  # 看連線追蹤表（這是防火牆的核心資料結構）
  docker exec wnc-gw conntrack -L

  ./down.sh                       # 全部清掉
MSG
