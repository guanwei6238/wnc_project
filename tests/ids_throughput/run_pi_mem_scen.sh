#!/bin/bash
# run_pi_mem_scen.sh - at the Pi's current memory level, measure RSS and processing speed of full/gw_corp on a given scenario.
# Run from the unpacked ids_throughput/ dir. Run once per memory level (after setting it with pi_set_total_mem.sh and rebooting).
#
# Usage: PCAP=S_m39.pcap nohup bash run_pi_mem_scen.sh <level label, e.g. 1gb> > ~/pi_mem39_<label>.log 2>&1 < /dev/null &
#   Environment: PCAP (default S_m39.pcap), RULES (default full,gw_corp), TAGP (tag prefix, default pi_mem39)
#
# Method:
#   - Defaults to the 39-1 (IRCBot) slice S_m39: with Suricata on full/gw_corp it is the slowest and largest-RSS of the 14 scenarios;
#     it is also among the slowest for Snort 3, and it is one of the 11 usable scenarios
#   - 4 GB is not measured separately; reuse S_m39 from run_pi_scen2.sh (pi_scen2_S/N). This script only does 2 GB and 1 GB
#   - swap stays at the system default (zram on)
#   - 1 warm-up + 3 runs per cell; Snort 3 full on 39-1 takes about 8.5 min per run, timeout 3600 s
#   - Before starting, wait until vcgencmd reports the ARM clock at 1000 MHz: for a minute or two after boot the kernel's scaling_max_freq
#     is already 1000 MHz but the firmware still runs at 1800 MHz (Snort 3 is about 1.76x faster)
#   - Clear dmesg before the matrix; afterwards save OOM-related messages to results/<tag>.dmesg.txt
#   - Finally run each Suricata rule set once with sampling to record peak VmSwap (amount swapped into zram), printed to the log only:
#     RSS does not include swapped-out pages
#   - SKIP_MATRIX=1: only the OOM record and VmSwap sampling (for re-runs)
#
# Prerequisites: Pi in lab mode (pi_lab_mode.sh up 1000), clock synced, system suricata service stopped, $PCAP in data/pcaps, matching rules in data/rules.
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
# Wait until the clock is actually locked (up to 5 minutes)
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

# VmSwap sampling (Suricata, once per rule set)
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
