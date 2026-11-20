#!/bin/bash
# run_pi_scen2.sh - on the Pi, run 14 IoT-23 scenario slices x empty/full/gw_corp x two engines, all within one boot, 1 warm-up + 3 runs per cell.
# Run from the unpacked ids_throughput/ dir.
#
# Design:
#   - empty, full and gw_corp are all measured in the same boot, same conditions
#   - full and gw_corp for the same engine are interleaved in one batch (run_matrix.py shuffles the order each round)
#   - an anchor run at the start and end checks the Pi's state for this boot and any drift over the whole run
#
# Batches (tag prefix pi_scen2_):
#   anchor0  anchor: C_somfy02 x full x both engines
#   E        empty: 14 slices (including .small, for the Suricata difference method) x both engines
#   S        Suricata: full/gw_corp x 14 slices
#   N        Snort 3: full/gw_corp x 14 slices (full on the 9 scan/flood slices takes 4-9 min per run; this batch is about 5 hours)
#   anchor1  anchor: same as anchor0, run last
#
# Usage: nohup bash run_pi_scen2.sh > ~/pi_scen2_driver.log 2>&1 < /dev/null &
# Prerequisites: lab mode (pi_lab_mode.sh up 1000), clock synced, system suricata service stopped,
#       data/pcaps has S_*.pcap (with .small) and C_somfy02.pcap, data/rules has *_full.rules and *_gw_corp.rules.
# Results: results/pi_scen2_*.csv (one row per run), *.env.json, *.summary.csv. The last log line is "ALL DONE".

cd "$(dirname "$0")" || exit 1
export BIG=$PWD/data SNORT_ETC=${SNORT_ETC:-/etc/snort} MODE=native
RUNS=$BIG/runs; mkdir -p "$RUNS"
CPUSET=${CPUSET:-2,3}
ALL="S_m17,S_h5,S_m3,S_somfy02,S_m36,S_m48,S_m39,S_m60,S_m44,S_m1,S_m34,S_m20,S_m42,S_h4"
ALLP=$(echo "$ALL" | sed 's/,/.pcap,/g').pcap

step() {
  local tag=$1; shift
  echo; echo "=================== $(date -u +%FT%TZ)  開始 $tag ==================="
  ./run_matrix.py --tag "$tag" --cpuset "$CPUSET" --runs-dir "$RUNS" --timeout 3600 "$@"
  echo "--- $tag 結束 rc=$?  $(date -u +%FT%TZ)"
}

echo "Pi 狀態: $(vcgencmd get_throttled) $(vcgencmd measure_temp) 時脈 $(( $(vcgencmd measure_clock arm | cut -d= -f2)/1000000 )) MHz"
echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)  上限: $(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq)/1000 )) MHz"
pgrep -x Suricata-Main >/dev/null && echo "⚠ 系統的 suricata 服務還在跑（sudo systemctl stop suricata）"

step pi_scen2_anchor0 --pcaps C_somfy02.pcap --engines suricata,snort --rules full --reps 3 --warmup 1
step pi_scen2_E       --pcaps "$ALL"  --engines suricata,snort --rules empty --reps 3 --warmup 1
step pi_scen2_S       --pcaps "$ALLP" --engines suricata --rules full,gw_corp --reps 3 --warmup 1
step pi_scen2_N       --pcaps "$ALLP" --engines snort --rules full,gw_corp --reps 3 --warmup 1
step pi_scen2_anchor1 --pcaps C_somfy02.pcap --engines suricata,snort --rules full --reps 3 --warmup 1

echo; echo "=== 各批的彙總 ==="
for t in pi_scen2_anchor0 pi_scen2_E pi_scen2_S pi_scen2_N pi_scen2_anchor1; do
  [ -f results/$t.csv ] && python3 -I summarize.py results/$t.csv --out results/$t.summary.csv 2>&1 | head -60
done
echo "ALL DONE $(date -u +%FT%TZ)"
