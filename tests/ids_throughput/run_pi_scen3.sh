#!/bin/bash
# run_pi_scen3.sh — Pi 上的 Suricata 8.0.7 速度：IoT-23 的 14 個 scenario 切片（重量）＋ CIC 三個 dataset 依流量特徵挑的切片，
# × empty／full／gw_corp（2026-10-30 的 ET Open，和偵測測試同一份 rule），全部在同一次開機內，每格 1 warm-up + 3。
# 量法和 run_pi_scen2.sh 相同（measure.sh、run_matrix.py），只換 engine 版本與 rule：Suricata 8.0.7、data/rules_1030/。
#
# 批次（tag 前綴 pi_scen3_）：
#   anchor0  錨點：C_somfy02 × full
#   E        empty：全部切片（含 .small，差分法用）
#   S        full／gw_corp × 全部切片
#   anchor1  錨點：同 anchor0，放在最後
#
# 用法： nohup bash run_pi_scen3.sh > ~/pi_scen3_driver.log 2>&1 < /dev/null &
# 前置：量測模式（pi_lab_mode.sh up 1000）、時鐘已校正、系統 suricata 服務已停、data/pcaps 內有切片（含 .small）、
#       data/rules_1030 內有 suricata_full.rules、suricata_gw_corp.rules、SHA256SUMS；切片清單在 scen3_slices.txt。
# 結果：results/pi_scen3_*.csv、*.env.json、*.summary.csv。最後一行 log 是 "ALL DONE"。

cd "$(dirname "$0")" || exit 1
export BIG=$PWD/data MODE=native
RUNS=$BIG/runs; mkdir -p "$RUNS"
CPUSET=${CPUSET:-2,3}
ALL=$(paste -sd, scen3_slices.txt)
ALLP=$(echo "$ALL" | sed 's/,/.pcap,/g').pcap
M=(--manifest manifest_scen3.json --rules-dir "$BIG/rules_1030")

step() {
  local tag=$1; shift
  echo; echo "=================== $(date -u +%FT%TZ)  開始 $tag ==================="
  ./run_matrix.py --tag "$tag" --cpuset "$CPUSET" --runs-dir "$RUNS" --timeout 3600 "${M[@]}" "$@"
  echo "--- $tag 結束 rc=$?  $(date -u +%FT%TZ)"
}

echo "Pi 狀態: $(vcgencmd get_throttled) $(vcgencmd measure_temp) 時脈 $(( $(vcgencmd measure_clock arm | cut -d= -f2)/1000000 )) MHz"
echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)  上限: $(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq)/1000 )) MHz"
echo "suricata: $(suricata -V)"
pgrep -x Suricata-Main >/dev/null && echo "⚠ 系統的 suricata 服務還在跑（sudo systemctl stop suricata）"

step pi_scen3_anchor0 --pcaps C_somfy02.pcap --engines suricata --rules full --reps 3 --warmup 1
step pi_scen3_E       --pcaps "$ALL"  --engines suricata --rules empty --reps 3 --warmup 1
step pi_scen3_S       --pcaps "$ALLP" --engines suricata --rules full,gw_corp --reps 3 --warmup 1
step pi_scen3_anchor1 --pcaps C_somfy02.pcap --engines suricata --rules full --reps 3 --warmup 1

echo; echo "=== 各批的彙總 ==="
for t in pi_scen3_anchor0 pi_scen3_E pi_scen3_S pi_scen3_anchor1; do
  [ -f results/$t.csv ] && python3 -I summarize.py results/$t.csv --out results/$t.summary.csv 2>&1 | head -80
done
echo "ALL DONE $(date -u +%FT%TZ)"
