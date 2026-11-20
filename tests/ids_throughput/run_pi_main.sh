#!/bin/bash
# run_pi_main.sh - run the five batches of the main matrix on the Pi in order (native mode): 4 slices x empty/common/full/sel x two engines.
# Run from the unpacked ids_throughput/ dir.
#
# Why batches with different repeat counts: each run reloads about 50k rules (about 30-40 s), and Snort 3 with common/full on slices A and B2
# takes 12-27 min per run. 5 repeats for every cell would take over ten hours, so:
#   - normal cells: 1 warm-up + 3 counted runs
#   - slow cells (Snort 3 with common/full on slices A, B2): 0 warm-up + 2 counted runs
#   - only empty runs .small (difference method: Suricata's self-reported time for empty excludes flow cleanup after EOF, so the difference column is used),
#     other rule sets use self-reported time, so only the large pcap runs, saving half the rule load time.
#
# Batches (tag prefix pi_):
#   E     empty: both engines x 4 slices (including .small)
#   R1    Suricata: common / full / sel x 4 slices
#   R2a1  Snort 3: sel x 4 slices
#   R2a2  Snort 3: common / full x B1, C (fast cells)
#   R2b   Snort 3: common / full x A, B2 (slow cells)
# Rule sets: full = all of ET Open; sel = full minus rules with >= 8 header commas (long IP lists) (see 04_make_sel_rules.py),
#   chosen by cost, not by detection value; common = intersection of the two engines' rule pack sids.
#
# Usage: nohup bash run_pi_main.sh > ~/pi_main_driver.log 2>&1 < /dev/null &
# Prerequisites: Pi in lab mode (pi_lab_mode.sh up 1000); system suricata service stopped; Snort 3 config in /etc/snort;
#       data/pcaps has the 4 slices and .small; data/rules has *_common.rules, *_full.rules, *_sel.rules.
# Results: results/pi_*.csv (one row per run), results/pi_*.env.json, results/pi_*.summary.csv. The last log line is "ALL DONE".

cd "$(dirname "$0")" || exit 1
export BIG=$PWD/data SNORT_ETC=${SNORT_ETC:-/etc/snort} MODE=native
RUNS=$BIG/runs; mkdir -p "$RUNS"
CPUSET=${CPUSET:-2,3}
A=A_scan17.pcap; B1=B1_pay5.pcap; B2=B2_mix3.pcap; C=C_somfy02.pcap
ALL4="$A,$B1,$B2,$C"

step() {   # step <label> <run_matrix args...>
  local tag=$1; shift
  echo; echo "=================== $(date -u +%FT%TZ)  開始 $tag ==================="
  ./run_matrix.py --tag "$tag" --cpuset "$CPUSET" --runs-dir "$RUNS" "$@"
  echo "--- $tag 結束 rc=$?  $(date -u +%FT%TZ)"
}

echo "Pi 狀態: $(vcgencmd get_throttled) $(vcgencmd measure_temp) 時脈 $(( $(vcgencmd measure_clock arm | cut -d= -f2)/1000000 )) MHz"
echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)  上限: $(( $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq)/1000 )) MHz"
pgrep -x Suricata-Main >/dev/null && echo "⚠ 系統的 suricata 服務還在跑（sudo systemctl disable --now suricata）"

step pi_E    --pcaps A_scan17,B1_pay5,B2_mix3,C_somfy02 --engines suricata,snort --rules empty --reps 3 --warmup 1
step pi_R1   --pcaps "$ALL4" --engines suricata --rules common,full,sel --reps 3 --warmup 1
step pi_R2a1 --pcaps "$ALL4" --engines snort --rules sel --reps 3 --warmup 1
step pi_R2a2 --pcaps "$B1,$C" --engines snort --rules common,full --reps 3 --warmup 1
step pi_R2b  --pcaps "$A,$B2" --engines snort --rules common,full --reps 2 --warmup 0

echo; echo "=== 各批的彙總 ==="
for t in pi_E pi_R1 pi_R2a1 pi_R2a2 pi_R2b; do
  [ -f results/$t.csv ] && python3 -I summarize.py results/$t.csv --out results/$t.summary.csv 2>&1 | tail -n +1 | head -40
done
echo "ALL DONE $(date -u +%FT%TZ)"
