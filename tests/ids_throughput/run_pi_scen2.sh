#!/bin/bash
# run_pi_scen2.sh — 在 Pi 上跑 14 個 IoT-23 scenario 切片 × empty／full／gw_corp × 兩個 engine，全部在同一次開機內完成，每格 1 暖機 + 3 次。
# 在解壓後的 ids_throughput/ 目錄執行。
#
# 設計：
#   - empty、full、gw_corp 全部在同一次開機內量，條件一致
#   - 同一個 engine 的 full 與 gw_corp 放在同一批交錯執行（run_matrix.py 每一輪打亂順序）
#   - 前後各跑一次錨點，確認這次開機的 Pi 狀態、看整段期間有沒有漂移
#
# 批次（tag 前綴 pi_scen2_）：
#   anchor0  錨點：C_somfy02 × full × 兩引擎
#   E        empty：14 切片（含 .small，Suricata 差分法用）× 兩引擎
#   S        Suricata：full／gw_corp × 14 切片
#   N        Snort 3：full／gw_corp × 14 切片（full 的 9 個 scan／flood 切片每次 4–9 分鐘，這批約 5 小時）
#   anchor1  錨點：同 anchor0，放在最後
#
# 用法： nohup bash run_pi_scen2.sh > ~/pi_scen2_driver.log 2>&1 < /dev/null &
# 前置：量測模式（pi_lab_mode.sh up 1000）、時鐘已校正、系統 suricata 服務已停、
#       data/pcaps 內有 S_*.pcap（含 .small）與 C_somfy02.pcap、data/rules 內有 *_full.rules 與 *_gw_corp.rules。
# 結果：results/pi_scen2_*.csv（每次量測一行）、*.env.json、*.summary.csv。最後一行 log 是 "ALL DONE"。

cd "$(dirname "$0")" || exit 1
export BIG=$PWD/data SNORT_ETC=${SNORT_ETC:-/etc/snort} MODE=native
RUNS=$BIG/runs; mkdir -p "$RUNS"
CPUSET=${CPUSET:-2,3}
ALL="S_m17,S_h5,S_m3,S_somfy02,S_m36,S_m48,S_m39,S_m60,S_m44,S_m1,S_m34,S_m20,S_m42,S_h4"
ALLP=$(echo "$ALL" | sed 's/,/.pcap,/g').pcap

step() {
  local tag=$1; shift
  echo; echo "=================== $(date -u +%FT%TZ)  開始 $tag ==================="
  ./run_matrix.py --tag "$tag" --cpuset "$CPUSET" --runs-dir "$RUNS" --timeout 3600 "$@"
  echo "--- $tag 結束 rc=$?  $(date -u +%FT%TZ)"
}

echo "Pi 狀態: $(vcgencmd get_throttled) $(vcgencmd measure_temp) 時脈 $(( $(vcgencmd measure_clock arm | cut -d= -f2)/1000000 )) MHz"
echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)  上限: $(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq)/1000 )) MHz"
pgrep -x Suricata-Main >/dev/null && echo "⚠ 系統的 suricata 服務還在跑（sudo systemctl stop suricata）"

step pi_scen2_anchor0 --pcaps C_somfy02.pcap --engines suricata,snort --rules full --reps 3 --warmup 1
step pi_scen2_E       --pcaps "$ALL"  --engines suricata,snort --rules empty --reps 3 --warmup 1
step pi_scen2_S       --pcaps "$ALLP" --engines suricata --rules full,gw_corp --reps 3 --warmup 1
step pi_scen2_N       --pcaps "$ALLP" --engines snort --rules full,gw_corp --reps 3 --warmup 1
step pi_scen2_anchor1 --pcaps C_somfy02.pcap --engines suricata,snort --rules full --reps 3 --warmup 1

echo; echo "=== 各批的彙總 ==="
for t in pi_scen2_anchor0 pi_scen2_E pi_scen2_S pi_scen2_N pi_scen2_anchor1; do
  [ -f results/$t.csv ] && python3 -I summarize.py results/$t.csv --out results/$t.summary.csv 2>&1 | head -60
done
echo "ALL DONE $(date -u +%FT%TZ)"
