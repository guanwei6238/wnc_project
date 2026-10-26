#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"
docker compose down -v --remove-orphans
echo "已清除。image 保留（下次啟動比較快）；要連 image 一起刪：docker rmi wnc-lab:latest wnc-lab-gw:latest"
