#!/bin/bash
# pi_freq_cap_search.sh — find the highest CPU clock cap that does not throttle under sustained full load (run on the Pi, needs sudo)
#
# Why: without enough cooling, a Pi 4 under sustained full load hits the 80°C thermal wall and throttles; the clock jumps around 600–1700 MHz,
# so results drift with temperature and are not reproducible. One fix is to lock the max clock at a fixed value:
# stable, reproducible numbers (at the cost of being below the Pi 4's real capability; reports must state the MHz it was locked at).
#
# What it does: try candidate caps from high to low. For each candidate:
#   1. Lock the clock (write scaling_max_freq; affects this boot only)
#   2. Wait idle until below COOL°C (at most MAXWAIT seconds; if not reached, run anyway and note it in the log)
#   3. Run pi_power_check.sh at full load for SEC seconds
#   4. The first PASS is the answer; stop
# On exit (including interrupts) the cap is always restored to its original value.
#
# Usage: pi_freq_cap_search.sh [candidate MHz ...]       default 1500 1200 1000
# Env: SEC=240 (full-load seconds per candidate)  COOL=60 (°C to cool to before starting)  MAXWAIT=900
#
# Prerequisite: ~/pi_power_check.sh must be in the same directory (scp it over).

CAPS=("$@"); [ ${#CAPS[@]} -eq 0 ] && CAPS=(1500 1200 1000)
SEC=${SEC:-240}; COOL=${COOL:-60}; MAXWAIT=${MAXWAIT:-900}
CHECK="$(dirname "$0")/pi_power_check.sh"
[ -f "$CHECK" ] || { echo "找不到 $CHECK"; exit 2; }

CPUF=/sys/devices/system/cpu/cpu0/cpufreq
ORIG=$(cat $CPUF/scaling_max_freq)         # in kHz
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
