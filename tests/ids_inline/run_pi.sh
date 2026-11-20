#!/bin/bash
# run_pi.sh — inline measurement of 14 scenarios × empty/full/gw_corp (run on the Pi)
#   A: send at $RATE pps (a rate with no packet loss), main numbers us_per_pkt/cpu_kpps; 3 rounds, scenario and rule set order shuffled each round
#   B: one full-speed run, reference numbers proc_kpps and loss_pct
#   one anchor run (S_m39 × full × A) at the start and end, one warm-up at the start (not counted)
# Prerequisites: sudo sh env.sh up; sh make_configs.sh; pi_lab_mode.sh up 1000; system suricata service stopped; wnc-gw at $GW
# Usage: sudo nohup bash run_pi.sh > /home/wnc/ids_inline/driver.log 2>&1 < /dev/null &
# Results: $OUT/$TAG.kvl (one line per measurement, prefixed with tag, round, mode, seq), $OUT/$TAG.meta; per-measurement logs in $RUNS/$TAG/
cd "$(dirname "$0")" || exit 1
TAG=${TAG:-inline1}; RATE=${RATE:-10000}
OUT=${OUT:-/home/wnc/ids_inline/results}; RUNS=${RUNS:-/home/wnc/ids_inline/runs}
LOG=/var/log/wnc-gw/suricata
ALL="S_m17 S_h5 S_m3 S_somfy02 S_m36 S_m48 S_m39 S_m60 S_m44 S_m1 S_m34 S_m20 S_m42 S_h4"
mkdir -p "$OUT" "$RUNS/$TAG"

fail() { echo "preflight: $*"; exit 1; }
[ "$(sort -u /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor)" = performance ] || fail "governor is not performance"
[ "$(sort -u /sys/devices/system/cpu/cpu*/cpufreq/scaling_max_freq)" = 1000000 ] || fail "max freq is not 1000 MHz"
pgrep -x Suricata-Main > /dev/null && fail "another suricata is running"
pgrep -x wnc-gw > /dev/null && fail "another wnc-gw is running"
mountpoint -q $LOG || fail "$LOG is not a tmpfs mount"
ip netns list | grep -q wgw || fail "netns wgw missing"

{
  echo "tag=$TAG rate=$RATE start=$(date -u +%FT%TZ)"
  echo "kernel=$(uname -r) model=$(tr -d '\0' < /proc/device-tree/model)"
  echo "suricata=$(suricata -V 2>&1 | head -1)"
  echo "tcpreplay=$(tcpreplay -V 2>&1 | head -1)"
  echo "wnc_gw_sha256=$(sha256sum ${GW:-/tmp/wncgw/wnc-gw} | cut -c1-64)"
  echo "mem_total_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)"
} > "$OUT/$TAG.meta"
cat "$OUT/$TAG.meta"

seq=0
trial() {  # trial <round> <mode> <rules> <pcap> <rate>
  seq=$((seq + 1))
  local d=$RUNS/$TAG/$(printf %03d $seq)-$2-$3-$4-$5
  echo "$(date -u +%T) #$seq round=$1 mode=$2 $3 $4 $5"
  if bash trial.sh "$3" "$4" "$5" "$d" > /dev/null; then
    echo "tag=$TAG round=$1 mode=$2 seq=$seq $(cat $d/result.kv)" >> "$OUT/$TAG.kvl"
    tail -1 "$OUT/$TAG.kvl" | grep -o -E "us_per_pkt=[^ ]*|proc_kpps=[^ ]*|loss_pct=[^ ]*|hwm_mb=[^ ]*" | tr '\n' ' '; echo
  else
    echo "  FAILED: $d"
  fi
  rm -f $LOG/*
}

for pc in $ALL; do bash trial.sh empty "$pc" cache "$RUNS/$TAG/cache" || fail "tcpprep failed for $pc"; done
trial 0 warmup full S_m39 $RATE
trial 0 anchor full S_m39 $RATE
for round in 1 2 3; do
  for pc in $(echo $ALL | tr ' ' '\n' | shuf); do
    for rs in $(printf 'empty\nfull\ngw_corp\n' | shuf); do trial $round A $rs $pc $RATE; done
  done
done
for pc in $ALL; do for rs in empty full gw_corp; do trial 1 B $rs $pc top; done; done
trial 9 anchor full S_m39 $RATE
echo "ALL DONE $(date -u +%FT%TZ)"
