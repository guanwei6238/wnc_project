#!/bin/bash
# run_pi_mem_scen.sh — 在 Pi 目前的 memory 等級下，用指定的 scenario 量 full／gw_corp 的 RSS 與處理速度。
# 在解壓後的 ids_throughput/ 目錄執行。每個 memory 等級（用 pi_set_total_mem.sh 設定並重開機後）跑一次。
#
# 用法： PCAP=S_m39.pcap nohup bash run_pi_mem_scen.sh <等級標籤，例如 1gb> > ~/pi_mem39_<標籤>.log 2>&1 < /dev/null &
#   環境變數：PCAP（預設 S_m39.pcap）、RULES（預設 full,gw_corp）、TAGP（tag 前綴，預設 pi_mem39）
#
# 做法：
#   - 預設用 39-1 (IRCBot) 的切片 S_m39：Suricata 掛 full／gw_corp 時，它都是 14 個 scenario 裡最慢、RSS 最大；
#     Snort 3 也排在最慢的前幾個；而且它在 11 個 usable scenario 裡
#   - 4 GB 不另外量，直接用 run_pi_scen2.sh（pi_scen2_S／N）的 S_m39；這支只量 2 GB、1 GB
#   - swap 維持系統預設（zram 開）
#   - 每格 1 暖機 + 3 次；Snort 3 full 在 39-1 每次約 8.5 分鐘，逾時設 3600 秒
#   - 開跑前先等 vcgencmd 回報的 ARM 時脈降到 1000 MHz：剛開機的一兩分鐘內，kernel 的 scaling_max_freq
#     已是 1000 MHz，但韌體實際仍跑 1800 MHz（Snort 3 會快約 1.76 倍）
#   - 矩陣前清掉 dmesg，矩陣後把 OOM 相關訊息存到 results/<tag>.dmesg.txt
#   - 最後對 Suricata 的每個 rule set 各跑一次取樣，記錄 VmSwap（被換進 zram 的量）峰值，結果只印在 log：
#     RSS 不含被換出去的 page
#   - SKIP_MATRIX=1：只做 OOM 紀錄與 VmSwap 取樣（補跑用）
#
# 前置：Pi 在量測模式（pi_lab_mode.sh up 1000）、時鐘已校正、系統 suricata 服務已停、data/pcaps 內有 $PCAP、data/rules 內有對應規則。
cd "$(dirname "$0")" || exit 1
LABEL=${1:?用法: $0 <等級標籤，例如 1gb>}
export BIG=$PWD/data SNORT_ETC=${SNORT_ETC:-/etc/snort} MODE=native
RUNS=$BIG/runs; mkdir -p "$RUNS" /dev/shm/ids_tp
PCAP=${PCAP:-S_m39.pcap}; RULES=${RULES:-full,gw_corp}
TAG=${TAGP:-pi_mem39}_$LABEL

memtotal() { awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo; }
snap() {
  echo "MemTotal=$(memtotal) MB  $(free -m | awk 'NR==2{print "available="$7" MB used="$3" MB"}')"
  echo "swap: $(awk 'NR>1{printf "%s %d MB used %d MB; ", $1, $3/1024, $4/1024}' /proc/swaps)"
  echo "throttled=$(vcgencmd get_throttled | cut -d= -f2) $(vcgencmd measure_temp)  governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor) max=$(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq)/1000 )) MHz"
}

echo "===== $TAG  開始 $(date -u +%FT%TZ) ====="
snap
echo "total_mem 設定: $(grep -h '^total_mem=' /boot/firmware/config.txt || echo '(無，使用實際記憶體)')"
pgrep -x Suricata-Main >/dev/null && echo "⚠ 系統的 suricata 服務還在跑"
# 等時脈真的鎖住（最多 5 分鐘）
for i in $(seq 1 60); do
  mhz=$(( $(vcgencmd measure_clock arm | cut -d= -f2) / 1000000 ))
  [ "$mhz" -le 1050 ] && break
  [ "$i" -eq 1 ] && echo "等 ARM 時脈降到 1000 MHz（目前 $mhz MHz）..."
  sleep 5
done
echo "ARM 時脈: $(( $(vcgencmd measure_clock arm | cut -d= -f2) / 1000000 )) MHz"

if [ "${SKIP_MATRIX:-0}" != 1 ]; then
sudo dmesg -C 2>/dev/null

./run_matrix.py --tag "$TAG" --pcaps "$PCAP" --engines suricata,snort --rules "$RULES" \
  --reps 3 --warmup 1 --timeout 3600 --cpuset 2,3 --runs-dir "$RUNS"
echo "rc=$?"
snap
fi
{ echo "=== $TAG  $(date -u +%FT%TZ) ==="; sudo dmesg -T 2>/dev/null | grep -iE "out of memory|oom-kill|killed process" | tail -20; } > "results/$TAG.dmesg.txt"

# VmSwap 取樣（Suricata，每個 rule set 一次）
for RS in ${RULES//,/ }; do
echo "--- VmSwap 取樣（Suricata $RS）---"
pin0=$(awk '/^pswpin/{print $2}' /proc/vmstat); pout0=$(awk '/^pswpout/{print $2}' /proc/vmstat)
OUT=$RUNS/${TAG}_probe_$RS; rm -rf "$OUT"
WORK=/dev/shm/ids_tp RULES_DIR=$PWD/data/rules THREADS=1 CPUSET=2,3 timeout 3600 bash measure.sh suricata "$RS" "data/pcaps/$PCAP" "$OUT" > /dev/null 2>&1 &
MP=$!; mr=0; ma=0; ms=0
while kill -0 $MP 2>/dev/null; do
  pid=$(pgrep -f "suricata -v -c" | tail -1)
  if [ -n "$pid" ] && [ -r /proc/$pid/status ]; then
    read -r r a s < <(awk '/^VmRSS/{r=int($2/1024)} /^RssAnon/{a=int($2/1024)} /^VmSwap/{s=int($2/1024)} END{print r+0, a+0, s+0}' /proc/$pid/status 2>/dev/null)
    [ "${r:-0}" -gt $mr ] && mr=$r; [ "${a:-0}" -gt $ma ] && ma=$a; [ "${s:-0}" -gt $ms ] && ms=$s
  fi
  sleep 0.3
done
wait $MP; rc=$?
echo "probe $RS rc=$rc peak VmRSS=${mr}MB RssAnon=${ma}MB VmSwap=${ms}MB pswpin=$(( $(awk '/^pswpin/{print $2}' /proc/vmstat) - pin0 )) pswpout=$(( $(awk '/^pswpout/{print $2}' /proc/vmstat) - pout0 ))"
grep -E "Maximum resident|Major|System time" "$OUT/time.txt"
done
echo "===== $TAG  結束 $(date -u +%FT%TZ) ====="
echo "MEMSCEN DONE $LABEL"
