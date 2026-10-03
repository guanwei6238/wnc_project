#!/usr/bin/env bash
# Outer loop around inline.sh.  Usage: sweep-inline.sh [-c sweep-inline.conf]
# Order: engines (none first) x rules x threads x tests x repeats, then the optional NDR searches.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PROG=sweep-inline.sh
# shellcheck source=lib.sh
. "$HERE/lib.sh"
CONF=sweep-inline.conf
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--config) CONF=${2:?}; shift 2 ;;
    -h|--help)   echo "Usage: $0 [-c sweep-inline.conf]" >&2; exit 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -r "$CONF" ] || die "config not found: $CONF (see sweep-inline.conf.example)"

ENGINES=(none suricata snort3); RULES=(none full); THREADS=(1); IFA=""; IFB=""; REPEATS=1; LABEL=sweep
TESTS=("latency --duration 10"); NDR_FRAMES=(); NDR_DURATION=10
OUT=inline.csv; LOGDIR=/run/bench-logs; COOLDOWN=30; TEMP_MAX=55
# shellcheck disable=SC1090
source "$CONF"
export TEMP_MAX
[ -n "$IFA" ] && [ -n "$IFB" ] || die "IFA and IFB must be set in $CONF"

cool_down() { sleep "$COOLDOWN"; wait_temp "$TEMP_MAX"; }

run_one() { # ARGS...  (passed to inline.sh)
  "$HERE/inline.sh" --ifa "$IFA" --ifb "$IFB" --out "$OUT" --logdir "$LOGDIR" "$@" > /dev/null
}

# combos: "none" once with no rules/threads; engines over RULES x THREADS
combos() {
  local e r t
  for e in "${ENGINES[@]}"; do
    if [ "$e" = none ]; then echo "none n/a n/a"; continue; fi
    for r in "${RULES[@]}"; do for t in "${THREADS[@]}"; do echo "$e $r $t"; done; done
  done
}

total=0
while read -r e r t; do
  eargs=(--engine "$e"); [ "$e" = none ] || eargs+=(--rules "$r" --threads "$t")
  for spec in "${TESTS[@]}"; do
    read -r -a targs <<< "$spec"
    for ((i = 1; i <= REPEATS; i++)); do
      info "run $e rules=$r threads=$t [$spec] rep=$i/$REPEATS"
      run_one "${eargs[@]}" --test "${targs[0]}" "${targs[@]:1}" --label "$LABEL" || warn "run failed (continuing)"
      total=$((total + 1)); cool_down
    done
  done
  for f in "${NDR_FRAMES[@]:-}"; do
    [ -n "$f" ] || continue
    info "NDR search $e rules=$r threads=$t frame=$f"
    run_one "${eargs[@]}" --test udp --find-ndr --frame "$f" --duration "$NDR_DURATION" || warn "NDR search failed (continuing)"
    total=$((total + 1)); cool_down
  done
done < <(combos)
info "done, $total runs, results in $OUT"
