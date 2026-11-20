#!/bin/bash
# pi_lab_mode.sh — switch the Pi into measurement mode / restore it (run on the Pi; needs sudo; affects this boot only, reboot returns to defaults)
#
# Why: measurements need a fixed, reproducible CPU state:
#   - governor set to performance (so ondemand is not still ramping up when load arrives)
#   - max clock locked at a value that does not throttle under sustained full load (this Pi 4 lacks cooling and hits the thermal wall at 1800 MHz;
#     1000 MHz measured with no throttling over 4 minutes of full load, see pi_freq_cap_search.sh)
# This state goes into the metadata of every measurement result; reports state "Pi 4 locked at X MHz".
#
# Usage:
#   pi_lab_mode.sh up [MHz]   enter measurement mode (default 1000 MHz)
#   pi_lab_mode.sh down       restore: governor=ondemand, max clock = hardware max
#   pi_lab_mode.sh status     show current state (no sudo needed)

CPU=/sys/devices/system/cpu
HWMAX=$(cat $CPU/cpu0/cpufreq/cpuinfo_max_freq)
setall() {   # $1=file name (relative to cpufreq/)  $2=value
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
    setall scaling_max_freq $((MHZ * 1000))      # lock the cap first, then set the governor, to avoid a momentary spike
    setall scaling_governor performance
    echo "已進入量測模式："; status ;;
  down)
    setall scaling_governor ondemand
    setall scaling_max_freq "$HWMAX"
    echo "已還原："; status ;;
  status) status ;;
  *) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
