#!/bin/bash
# pi_power_check.sh — 驗收 Raspberry Pi 的供電與散熱（在 Pi 上執行）
#
# 為什麼需要：Pi 欠壓或過熱時，CPU 會被降頻（1800 → 600 MHz），這時量到的吞吐量
# 不是引擎的能力，而是電源／散熱的問題。量測之前要先證明這台 Pi 在持續滿載下不會降頻。
#
# 做什麼：開 N 個吃 CPU 的程序跑 SEC 秒，每 INTERVAL 秒取樣一次：
#   vcgencmd get_throttled（欠壓／降頻旗標）、ARM 時脈、溫度、load average
# 結束後給出 PASS / FAIL 與原因。
#
# 用法： pi_power_check.sh [秒數=600] [程序數=4] [取樣間隔=10]
#   例： ./pi_power_check.sh 20 4 2      # 20 秒快速試跑
#
# 判準（任一不成立就 FAIL）：
#   1. 取樣中 throttled 的「目前」位元（bit0 欠壓、bit1 時脈上限、bit2 降頻、bit3 溫度上限）全程為 0
#   2. 最高溫度 < 80°C（Pi 4 在 80°C 開始降頻）
#   3. 滿載期間最低時脈 ≥ 「目前設定上限」(scaling_max_freq) 的 95%（鎖頻後以鎖定值為準）
#   （bit16–19「開機後曾發生」要重開機才會清，所以只印出來參考，不拿來判定。）
#
# 負載：每個程序在 python3 裡反覆算 1 MB 資料的 SHA-256（同時用到 CPU 與記憶體頻寬）。
# 這不是最耗電的負載，所以「通過」是下限保證；IDS 的負載型態不同，仍需另外觀察。

SEC=${1:-600}; N=${2:-4}; INTERVAL=${3:-10}
command -v vcgencmd >/dev/null || { echo "找不到 vcgencmd：這不是 Raspberry Pi（或缺少 libraspberrypi-bin）"; exit 2; }

get_clock() { echo $(( $(vcgencmd measure_clock arm | cut -d= -f2) / 1000000 )); }
get_temp()  { vcgencmd measure_temp | sed "s/temp=//; s/'C//"; }
get_thr()   { vcgencmd get_throttled | cut -d= -f2; }

HWMAX=$(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null || echo 0) / 1000 ))
MAXF=$(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null || echo 0) / 1000 ))   # 目前設定的上限（可能被人為鎖低）
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
  cur=$(( thr & 0xF ))                       # 取「目前」位元 bit0–3
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
