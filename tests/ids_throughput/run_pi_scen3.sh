#!/bin/bash
# run_pi_scen3.sh - Suricata 8.0.7 speed on the Pi: the 14 IoT-23 scenario slices (re-measured) + slices picked by traffic features from the three CIC datasets,
# x empty/full/gw_corp (ET Open of 2026-10-30, the same rules as the detection test), all within one boot, 1 warm-up + 3 per cell.
# Same method as run_pi_scen2.sh (measure.sh, run_matrix.py); only the engine version and rules change: Suricata 8.0.7, data/rules_1030/.
#
# Batches (tag prefix pi_scen3_):
#   anchor0  anchor: C_somfy02 x full
#   E        empty: all slices (including .small, for the difference method)
#   S        full/gw_corp x all slices
#   anchor1  anchor: same as anchor0, run last
#
# Usage: nohup bash run_pi_scen3.sh > ~/pi_scen3_driver.log 2>&1 < /dev/null &
# Prerequisites: lab mode (pi_lab_mode.sh up 1000), clock synced, system suricata service stopped, slices (with .small) in data/pcaps,
#       data/rules_1030 has suricata_full.rules, suricata_gw_corp.rules, SHA256SUMS; the slice list is in scen3_slices.txt.
# Results: results/pi_scen3_*.csv, *.env.json, *.summary.csv. The last log line is "ALL DONE".

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
