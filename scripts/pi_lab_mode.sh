#!/bin/bash
# pi_lab_mode.sh — 把 Pi 切到「量測模式」/ 還原（在 Pi 上執行；需要 sudo；只影響這次開機，重開機會回到預設）
#
# 為什麼：量測要在固定、可重現的 CPU 狀態下做：
#   - governor 設 performance（避免 ondemand 在負載剛上來時還在升頻）
#   - 最高時脈鎖在一個「持續滿載也不降頻」的值（這台 Pi 4 沒有足夠散熱，1800 MHz 會撞溫度牆；
#     實測 1000 MHz 持續滿載 4 分鐘不降頻，見 pi_freq_cap_search.sh）
# 這個狀態要寫進每份量測結果的 metadata，報告時明講「Pi 4 鎖在 X MHz」。
#
# 用法：
#   pi_lab_mode.sh up [MHz]   進入量測模式（預設 1000 MHz）
#   pi_lab_mode.sh down       還原：governor=ondemand，最高時脈=硬體上限
#   pi_lab_mode.sh status     顯示目前狀態（不需要 sudo）

CPU=/sys/devices/system/cpu
HWMAX=$(cat $CPU/cpu0/cpufreq/cpuinfo_max_freq)
setall() {   # $1=檔名(相對於 cpufreq/)  $2=值
  for f in $CPU/cpu*/cpufreq/$1; do echo "$2" | sudo tee "$f" >/dev/null; done
}
status() {
  echo "機型: $(tr -d '\0' < /proc/device-tree/model)"
  echo "governor: $(sort -u $CPU/cpu*/cpufreq/scaling_governor | tr '\n' ' ')"
  echo "最高時脈上限: $(sort -u $CPU/cpu*/cpufreq/scaling_max_freq | awk '{printf "%d MHz ", $1/1000}')（硬體上限 $((HWMAX/1000)) MHz）"
  echo "目前時脈: $(( $(vcgencmd measure_clock arm | cut -d= -f2) / 1000000 )) MHz   溫度: $(vcgencmd measure_temp | sed 's/temp=//')   throttled=$(vcgencmd get_throttled | cut -d= -f2)"
}
case "${1:-}" in
  up)
    MHZ=${2:-1000}
    [ $((MHZ * 1000)) -le "$HWMAX" ] || { echo "要求的 ${MHZ} MHz 超過硬體上限 $((HWMAX/1000)) MHz"; exit 1; }
    setall scaling_max_freq $((MHZ * 1000))      # 先鎖上限，再設 governor，避免瞬間衝高
    setall scaling_governor performance
    echo "已進入量測模式："; status ;;
  down)
    setall scaling_governor ondemand
    setall scaling_max_freq "$HWMAX"
    echo "已還原："; status ;;
  status) status ;;
  *) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
