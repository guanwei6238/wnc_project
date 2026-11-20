#!/bin/bash
# pi_power_check.sh — verify the Raspberry Pi's power supply and cooling (run on the Pi)
#
# Why: when the Pi is undervolted or overheating, the CPU is throttled (1800 -> 600 MHz), and the measured throughput
# reflects power/cooling, not the engine. Before measuring, prove this Pi does not throttle under sustained full load.
#
# What it does: run N CPU-bound processes for SEC seconds, sampling every INTERVAL seconds:
#   vcgencmd get_throttled (undervoltage/throttling flags), ARM clock, temperature, load average
# Prints PASS / FAIL with the reason at the end.
#
# Usage: pi_power_check.sh [seconds=600] [procs=4] [interval=10]
#   e.g.  ./pi_power_check.sh 20 4 2      # 20-second quick run
#
# Criteria (FAIL if any fails):
#   1. The "current" throttled bits (bit0 undervoltage, bit1 freq capped, bit2 throttled, bit3 soft temp limit) stay 0 in every sample
#   2. Max temperature < 80°C (Pi 4 starts throttling at 80°C)
#   3. Min clock under full load ≥ 95% of the current cap (scaling_max_freq) (with a locked clock, the locked value)
#   (bits 16–19, "occurred since boot", only clear on reboot, so they are printed for reference, not judged.)
#
# Load: each process repeatedly computes SHA-256 over 1 MB in python3 (uses both CPU and memory bandwidth).
# This is not the most power-hungry load, so PASS is a lower bound; IDS load looks different and still needs watching.

SEC=${1:-600}; N=${2:-4}; INTERVAL=${3:-10}
command -v vcgencmd >/dev/null || { echo "找不到 vcgencmd：這不是 Raspberry Pi（或缺少 libraspberrypi-bin）"; exit 2; }

get_clock() { echo $(( $(vcgencmd measure_clock arm | cut -d= -f2) / 1000000 )); }
get_temp()  { vcgencmd measure_temp | sed "s/temp=//; s/'C//"; }
get_thr()   { vcgencmd get_throttled | cut -d= -f2; }

HWMAX=$(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null || echo 0) / 1000 ))
MAXF=$(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null || echo 0) / 1000 ))   # current cap (may be locked lower by hand)
echo "機型: $(tr -d '\0' < /proc/device-tree/model)"
echo "CPU 硬體上限: ${HWMAX} MHz   目前設定上限: ${MAXF} MHz   governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)   開始前 throttled=$(get_thr) 溫度=$(get_temp)°C"
echo "開始滿載: ${N} 個程序 × ${SEC} 秒，每 ${INTERVAL} 秒取樣"
printf '%-9s %-10s %-9s %-8s %s\n' 經過秒數 throttled ARM_MHz 溫度C load1

PIDS=()
for _ in $(seq "$N"); do
  timeout "$SEC" python3 -c 'import hashlib
b = bytes(1 << 20)
while True:
    hashlib.sha256(b).digest()' &
  PIDS+=($!)
done
trap 'kill "${PIDS[@]}" 2>/dev/null' EXIT

start=$(date +%s); maxT=0; minC=999999; badn=0; bad1=""; badbits=0; n=0
while :; do
  el=$(( $(date +%s) - start ))
  [ "$el" -ge "$SEC" ] && break
  thr=$(get_thr); clk=$(get_clock); tmp=$(get_temp); ld=$(cut -d' ' -f1 /proc/loadavg)
  printf '%-9s %-10s %-9s %-8s %s\n' "$el" "$thr" "$clk" "$tmp" "$ld"
  cur=$(( thr & 0xF ))                       # take the "current" bits bit0–3
  n=$((n+1))
  if [ "$cur" -ne 0 ]; then badn=$((badn+1)); badbits=$(( badbits | cur )); [ -z "$bad1" ] && bad1="${el}s"; fi
  [ "$clk" -lt "$minC" ] && minC=$clk
  maxT=$(awk -v a="$maxT" -v b="$tmp" 'BEGIN{print (b>a)?b:a}')
  sleep "$INTERVAL"
done
wait "${PIDS[@]}" 2>/dev/null

echo
echo "--- 結果 ---"
echo "最高溫度: ${maxT}°C   滿載期間最低時脈: ${minC} MHz（設定上限 ${MAXF} MHz，硬體上限 ${HWMAX} MHz）   結束時 throttled=$(get_thr)（含「開機後曾」位元）"
fail=0
if [ "$badn" -gt 0 ]; then
  why=""; [ $((badbits & 1)) -ne 0 ] && why="$why 欠壓(bit0)"; [ $((badbits & 2)) -ne 0 ] && why="$why 時脈被限制(bit1)"; [ $((badbits & 4)) -ne 0 ] && why="$why 降頻中(bit2)"; [ $((badbits & 8)) -ne 0 ] && why="$why 軟性溫度限制(bit3)"
  echo "FAIL: ${n} 次取樣中有 ${badn} 次 throttled 目前位元非 0，第一次在 ${bad1}；出現過：${why}"; fail=1
fi
if awk -v t="$maxT" 'BEGIN{exit !(t>=80)}'; then echo "FAIL: 最高溫度 ${maxT}°C ≥ 80°C"; fail=1; fi
if [ "$MAXF" -gt 0 ] && [ "$minC" -lt $(( MAXF * 95 / 100 )) ]; then echo "FAIL: 最低時脈 ${minC} MHz < 設定上限 ${MAXF} MHz 的 95%"; fail=1; fi
[ "$fail" -eq 0 ] && echo "PASS: 持續滿載 ${SEC} 秒，無欠壓、無降頻、溫度與時脈正常"
exit "$fail"
