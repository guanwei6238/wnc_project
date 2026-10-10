#!/usr/bin/env bash
# 第 1 關：拿到的檔案是不是「同一份」、格式是否完整？
# 只讀檔，不送封包。兩支 Python 腳本來自資料集補充包，未修改。
set -euo pipefail
cd "$(dirname "$0")/data"

echo "===== 1-1 雜湊、PCAP record 完整性、封包數、標籤列數 ====="
python3 verify_samples.py

echo
echo "===== 1-2 依記錄的五元組與時間，重新裁切兩個小案例，核對是否逐位元相同 ====="
python3 reproduce_cases.py --output-dir "$(mktemp -d)"
