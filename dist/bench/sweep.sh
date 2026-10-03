#!/usr/bin/env bash
# Outer loop around run.sh.  Usage: sweep.sh [-c sweep.conf] [--find-ndr]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CONF=sweep.conf; FIND_NDR=0
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--config) CONF=${2:?}; shift 2 ;;
    --find-ndr)  FIND_NDR=1; shift ;;
    -h|--help)   echo "Usage: $0 [-c sweep.conf] [--find-ndr]" >&2; exit 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -r "$CONF" ] || { echo "sweep.sh: config not found: $CONF (see sweep.conf.example)" >&2; exit 1; }

# defaults, overridable by the config
ENGINES=(suricata snort3 zeek); PCAPS=(); MODE=offline; IFACE=""; THREADS=(1); RULES=(none)
PPS_RATES=(""); DURATION=30; REPEATS=1; OUT=results.csv; LOGDIR=/run/bench-logs; LABEL=sweep
COOLDOWN=30; TEMP_MAX=55; PPS_MIN=1000; PPS_MAX=40000; RESOLUTION=500; LOSS_TOLERANCE=0.1
# shellcheck disable=SC1090
source "$CONF"
export GEN_CMD
[ "${#PCAPS[@]}" -gt 0 ] || { echo "sweep.sh: PCAPS is empty" >&2; exit 1; }
[ "$FIND_NDR" = 0 ] || [ "$MODE" = live ] || { echo "sweep.sh: --find-ndr needs MODE=live" >&2; exit 1; }
[ "$MODE" = offline ] && PPS_RATES=("")

log() { echo "sweep.sh: $*" >&2; }

cool_down() {
  [ "$MODE" = live ] || return 0
  sleep "$COOLDOWN"
  command -v vcgencmd >/dev/null 2>&1 || return 0
  while :; do
    t=$(vcgencmd measure_temp 2>/dev/null | sed -n "s/temp=\([0-9.]*\).*/\1/p")
    [ -z "$t" ] && return 0
    awk -v t="$t" -v m="$TEMP_MAX" 'BEGIN{exit !(t<m)}' && return 0
    log "SoC at ${t}C, waiting for < ${TEMP_MAX}C"; sleep 5
  done
}

# run_one ENGINE PCAP RULES THREADS PPS LABEL  -> runs run.sh; returns its status
run_one() {
  local e=$1 p=$2 r=$3 t=$4 pps=$5 label=$6
  local args=(--engine "$e" --mode "$MODE" --pcap "$p" --threads "$t" --rules "$r" --label "$label" --out "$OUT" --logdir "$LOGDIR")
  [ "$MODE" = live ] && args+=(--iface "$IFACE" --duration "$DURATION")
  [ -n "$pps" ] && args+=(--pps "$pps")
  "$HERE/run.sh" "${args[@]}" > /dev/null
}

# last CSV row's value for a header name
last_col() {
  awk -F, -v c="$1" 'NR==1{for(i=1;i<=NF;i++) if($i==c) k=i; next} {v=$k} END{print v}' "$OUT"
}

rules_for() { [ "$1" = zeek ] && echo none || printf '%s\n' "${RULES[@]}"; }

if [ "$FIND_NDR" = 0 ]; then
  total=0
  for e in "${ENGINES[@]}"; do for p in "${PCAPS[@]}"; do for r in $(rules_for "$e"); do
  for t in "${THREADS[@]}"; do for pps in "${PPS_RATES[@]}"; do for ((i = 1; i <= REPEATS; i++)); do
    log "run $e $(basename "$p") rules=$r threads=$t pps=${pps:-n/a} rep=$i/$REPEATS"
    run_one "$e" "$p" "$r" "$t" "$pps" "$LABEL" || log "run failed (continuing)"
    total=$((total + 1)); cool_down
  done; done; done; done; done; done
  log "done, $total runs, results in $OUT"
  exit 0
fi

# ---------- --find-ndr: binary search for highest pps with total drop <= tolerance ----------
probe() { # ENGINE PCAP RULES THREADS PPS LABEL -> 0 if within tolerance and generator reached the rate
  run_one "$1" "$2" "$3" "$4" "$5" "$6" || { log "probe run failed"; cool_down; return 1; }
  local d sent rs ok=1
  d=$(last_col total_drop_pct); sent=$(last_col gen_sent_pkts); rs=$(last_col replay_s)
  cool_down
  [ -n "$d" ] || { log "probe pps=$5: no drop figure"; return 1; }
  if [ -n "$sent" ] && [ -n "$rs" ]; then
    awk -v s="$sent" -v r="$rs" -v p="$5" 'BEGIN{exit !(s/r >= 0.95*p)}' || {
      log "probe pps=$5: generator only achieved $(awk -v s="$sent" -v r="$rs" 'BEGIN{printf "%d",s/r}') pps (treated as fail; NDR is generator-limited)"; return 1; }
  fi
  awk -v d="$d" -v t="$LOSS_TOLERANCE" 'BEGIN{exit !(d<=t)}' && { log "probe pps=$5: drop=$d% PASS"; return 0; }
  log "probe pps=$5: drop=$d% FAIL"; return 1
}

for e in "${ENGINES[@]}"; do for p in "${PCAPS[@]}"; do for r in $(rules_for "$e"); do for t in "${THREADS[@]}"; do
  log "NDR search $e $(basename "$p") rules=$r threads=$t in [$PPS_MIN, $PPS_MAX]"
  lo=0; hi=$PPS_MAX
  if probe "$e" "$p" "$r" "$t" "$PPS_MAX" ndr-search; then lo=$PPS_MAX
  elif ! probe "$e" "$p" "$r" "$t" "$PPS_MIN" ndr-search; then
    log "no passing rate at PPS_MIN=$PPS_MIN for $e $(basename "$p"); no ndr-result row written"; continue
  else
    lo=$PPS_MIN
    while [ $((hi - lo)) -gt "$RESOLUTION" ]; do
      mid=$(((lo + hi) / 2))
      if probe "$e" "$p" "$r" "$t" "$mid" ndr-search; then lo=$mid; else hi=$mid; fi
    done
  fi
  log "NDR $e $(basename "$p") rules=$r threads=$t = $lo pps (loss <= $LOSS_TOLERANCE%)"
  run_one "$e" "$p" "$r" "$t" "$lo" ndr-result || log "ndr-result run failed"
  cool_down
done; done; done; done
