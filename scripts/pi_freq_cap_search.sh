#!/bin/bash
# pi_freq_cap_search.sh — 找出「持續滿載也不降頻」的最高 CPU 時脈上限（在 Pi 上執行，需要 sudo）
#
# 為什麼需要：Pi 4 沒有足夠散熱時，持續滿載會撞到 80°C 溫度牆而降頻，時脈在 600–1700 MHz 之間亂跳，
# 量測結果會隨溫度飄移而不可重現。解法之一是把最高時脈「鎖」在一個固定值：
# 數字穩定、可重現（代價是低於 Pi 4 的實際能力，報告時要明講鎖在多少 MHz）。
#
# 做什麼：由高到低逐一試候選上限。每個候選：
#   1. 鎖頻（寫 scaling_max_freq，只影響這次開機）
#   2. 等閒置降溫到 COOL°C 以下（最多等 MAXWAIT 秒，等不到就照跑並在紀錄註明）
#   3. 跑 pi_power_check.sh SEC 秒滿載
#   4. 第一個 PASS 的就是答案，停止
# 結束時（含被中斷）一定把上限還原成原本的值。
#
# 用法： pi_freq_cap_search.sh [候選MHz ...]       預設 1500 1200 1000
# 環境變數： SEC=240（每個候選滿載秒數）  COOL=60（開始前要降到幾°C）  MAXWAIT=900
#
# 前置：~/pi_power_check.sh 要在同一個目錄（scp 過去）。

CAPS=("$@"); [ ${#CAPS[@]} -eq 0 ] && CAPS=(1500 1200 1000)
SEC=${SEC:-240}; COOL=${COOL:-60}; MAXWAIT=${MAXWAIT:-900}
CHECK="$(dirname "$0")/pi_power_check.sh"
[ -f "$CHECK" ] || { echo "找不到 $CHECK"; exit 2; }

CPUF=/sys/devices/system/cpu/cpu0/cpufreq
ORIG=$(cat $CPUF/scaling_max_freq)         # 單位 kHz
temp() { vcgencmd measure_temp | sed "s/temp=//; s/'C//"; }
set_cap() {                                 # $1 = kHz
  for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq; do echo "$1" | sudo tee "$f" >/dev/null; done
}
restore() { set_cap "$ORIG"; echo "已還原最高時脈上限為 $((ORIG/1000)) MHz"; }
trap restore EXIT

echo "原本的上限: $((ORIG/1000)) MHz   候選: ${CAPS[*]} MHz   每個候選滿載 ${SEC} 秒，開始前降到 < ${COOL}°C"
answer=""
for cap in "${CAPS[@]}"; do
  set_cap $((cap * 1000))
  echo
  echo "=================== 候選上限 ${cap} MHz ==================="
  waited=0
  while awk -v t="$(temp)" -v c="$COOL" 'BEGIN{exit !(t>=c)}'; do
    [ "$waited" -ge "$MAXWAIT" ] && { echo "（等了 ${waited} 秒仍未降到 ${COOL}°C，目前 $(temp)°C，照跑；這會讓結果偏悲觀）"; break; }
    sleep 10; waited=$((waited + 10))
  done
  echo "開始前溫度 $(temp)°C（等待 ${waited} 秒）"
  if bash "$CHECK" "$SEC" 4 10; then answer=$cap; echo ">>> ${cap} MHz：PASS"; break; else echo ">>> ${cap} MHz：FAIL"; fi
done
echo
if [ -n "$answer" ]; then echo "結論：持續滿載 ${SEC} 秒不降頻的最高候選上限是 ${answer} MHz"
else echo "結論：所有候選（${CAPS[*]} MHz）都不及格，需要更低的上限或加強散熱"; fi
