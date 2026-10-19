#!/bin/bash
# run_pi_main.sh — 在 Pi 上依序跑主矩陣的五個批次（native 模式）：4 個切片 × empty／common／full／sel × 兩個 engine。
# 在解壓後的 ids_throughput/ 目錄裡執行。
#
# 為什麼分批、次數不同：每次量測都要重新載入約 5 萬條規則（約 30–40 秒），而 Snort 3 掛 common／full 在 A、B2 切片
# 單次就要 12–27 分鐘。全部格子都做 5 次重複會要十幾個小時，所以：
#   - 一般格子：1 次 warm-up + 3 次正式
#   - 慢的格子（Snort 3 掛 common／full 的 A、B2 切片）：0 次 warm-up + 2 次正式
#   - 只有 empty 跑 .small（差分法：Suricata empty 的自報時間不含 EOF 後的 flow 清理，要用差分欄），
#     其他規則集用自報時間，所以只跑大 pcap，省下一半的規則載入時間。
#
# 批次（tag 前綴 pi_）：
#   E     empty：兩引擎 × 4 切片（含 .small）
#   R1    Suricata：common / full / sel × 4 切片
#   R2a1  Snort 3：sel × 4 切片
#   R2a2  Snort 3：common / full × B1、C（快的格子）
#   R2b   Snort 3：common / full × A、B2（慢的格子）
# 規則集：full = 完整 ET Open；sel = full 扣掉 header 逗號 >= 8（帶長 IP 清單）的規則（見 04_make_sel_rules.py），
#   這是依成本挑的，不是依偵測價值挑的；common = 兩個 engine 規則包 sid 的交集。
#
# 用法： nohup bash run_pi_main.sh > ~/pi_main_driver.log 2>&1 < /dev/null &
# 前置：Pi 已在量測模式（pi_lab_mode.sh up 1000）；系統的 suricata 服務已停；/etc/snort 有 Snort 3 設定；
#       data/pcaps 內有 4 個切片與 .small；data/rules 內有 *_common.rules、*_full.rules、*_sel.rules。
# 結果：results/pi_*.csv（每次量測一行）、results/pi_*.env.json、results/pi_*.summary.csv。最後一行 log 是 "ALL DONE"。

cd "$(dirname "$0")" || exit 1
export BIG=$PWD/data SNORT_ETC=${SNORT_ETC:-/etc/snort} MODE=native
RUNS=$BIG/runs; mkdir -p "$RUNS"
CPUSET=${CPUSET:-2,3}
A=A_scan17.pcap; B1=B1_pay5.pcap; B2=B2_mix3.pcap; C=C_somfy02.pcap
ALL4="$A,$B1,$B2,$C"

step() {   # step <標籤> <run_matrix 參數...>
  local tag=$1; shift
  echo; echo "=================== $(date -u +%FT%TZ)  開始 $tag ==================="
  ./run_matrix.py --tag "$tag" --cpuset "$CPUSET" --runs-dir "$RUNS" "$@"
  echo "--- $tag 結束 rc=$?  $(date -u +%FT%TZ)"
}

echo "Pi 狀態: $(vcgencmd get_throttled) $(vcgencmd measure_temp) 時脈 $(( $(vcgencmd measure_clock arm | cut -d= -f2)/1000000 )) MHz"
echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)  上限: $(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq)/1000 )) MHz"
pgrep -x Suricata-Main >/dev/null && echo "⚠ 系統的 suricata 服務還在跑（sudo systemctl disable --now suricata）"

step pi_E    --pcaps A_scan17,B1_pay5,B2_mix3,C_somfy02 --engines suricata,snort --rules empty --reps 3 --warmup 1
step pi_R1   --pcaps "$ALL4" --engines suricata --rules common,full,sel --reps 3 --warmup 1
step pi_R2a1 --pcaps "$ALL4" --engines snort --rules sel --reps 3 --warmup 1
step pi_R2a2 --pcaps "$B1,$C" --engines snort --rules common,full --reps 3 --warmup 1
step pi_R2b  --pcaps "$A,$B2" --engines snort --rules common,full --reps 2 --warmup 0

echo; echo "=== 各批的彙總 ==="
for t in pi_E pi_R1 pi_R2a1 pi_R2a2 pi_R2b; do
  [ -f results/$t.csv ] && python3 -I summarize.py results/$t.csv --out results/$t.summary.csv 2>&1 | tail -n +1 | head -40
done
echo "ALL DONE $(date -u +%FT%TZ)"
