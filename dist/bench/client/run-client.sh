#!/usr/bin/env bash
# Runs ON THE CLIENT HOST (Debian/Ubuntu): one inline-benchmark test against the server host.
#   run-client.sh TEST SERVER_IP [--duration S] [--streams N] [--conns N] [--reqs N] [--threads N]
#                 [--rate MBPS] [--frame BYTES] [--object NAME] [--count N] [--port P] [--proto udp|tcp]
#                 [cps, RFC 9411 mode: --target-cps N --init-s S --ramp-s S --sustain-s S --slice-s S
#                  --fail-txn-max-pct X --rst-max-pct X --rate-dev-max-pct X]
# TEST: latency | tcp | udp | http | cps | tls | ttfb
# stdout: one `metric=value` per line (parsed by bench/inline.sh). Diagnostics go to stderr.
# Exit status: 0 = test ran and metrics were emitted, non-zero = failure (partial metrics may exist).
set -uo pipefail

usage() { sed -n '2,9p' "$0" >&2; exit 2; }
die()  { echo "run-client.sh: ERROR: $*" >&2; exit 1; }
info() { echo "run-client.sh: $*" >&2; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' not found (run bench/client/setup-client.sh)"; }
emit() { printf '%s=%s\n' "$1" "$2"; }

[ $# -ge 2 ] || usage
TEST=$1; SERVER=$2; shift 2
DURATION="" STREAMS=1 CONNS="" REQS="" THREADS=2 RATE="" FRAME=512 OBJECT="" COUNT="" PORT=11111 PROTO=udp
# cps RFC 9411 mode (enabled by --target-cps). Defaults = the RFC 9411 values; flag > env var > default.
TARGET_CPS=""
INIT_S=${INIT_S:-5} RAMP_S=${RAMP_S:-30} SUSTAIN_S=${SUSTAIN_S:-300} SLICE_S=${SLICE_S:-10}
FAIL_TXN_MAX_PCT=${FAIL_TXN_MAX_PCT:-0.001} RST_MAX_PCT=${RST_MAX_PCT:-0.001} RATE_DEV_MAX_PCT=${RATE_DEV_MAX_PCT:-5}
while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DURATION=${2:?}; shift 2 ;;
    --streams)  STREAMS=${2:?};  shift 2 ;;
    --conns)    CONNS=${2:?};    shift 2 ;;
    --reqs)     REQS=${2:?};     shift 2 ;;
    --threads)  THREADS=${2:?};  shift 2 ;;
    --rate)     RATE=${2:?};     shift 2 ;;
    --frame)    FRAME=${2:?};    shift 2 ;;
    --object)   OBJECT=${2:?};   shift 2 ;;
    --count)    COUNT=${2:?};    shift 2 ;;
    --port)     PORT=${2:?};     shift 2 ;;
    --proto)    PROTO=${2:?};    shift 2 ;;
    --target-cps) TARGET_CPS=${2:?}; shift 2 ;;
    --init-s)   INIT_S=${2:?};   shift 2 ;;
    --ramp-s)   RAMP_S=${2:?};   shift 2 ;;
    --sustain-s) SUSTAIN_S=${2:?}; shift 2 ;;
    --slice-s)  SLICE_S=${2:?};  shift 2 ;;
    --fail-txn-max-pct) FAIL_TXN_MAX_PCT=${2:?}; shift 2 ;;
    --rst-max-pct)      RST_MAX_PCT=${2:?};      shift 2 ;;
    --rate-dev-max-pct) RATE_DEV_MAX_PCT=${2:?}; shift 2 ;;
    -h|--help)  usage ;;
    *) echo "run-client.sh: unknown argument: $1" >&2; usage ;;
  esac
done
for v in STREAMS THREADS FRAME PORT; do [[ "${!v}" =~ ^[0-9]+$ ]] || die "--${v,,} must be an integer"; done
need python3
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
case "$SERVER" in *:*) HOSTPORT="[$SERVER]" ;; *) HOSTPORT=$SERVER ;; esac

# percentile helper: pct FILE P  (file = one number per line; linear interpolation)
pct() { python3 - "$1" "$2" <<'PY'
import sys
v = sorted(float(x) for x in open(sys.argv[1]).read().split())
p = float(sys.argv[2])
if not v: sys.exit(1)
k = (len(v) - 1) * p / 100.0; lo = int(k); hi = min(lo + 1, len(v) - 1)
print("%.4f" % (v[lo] + (v[hi] - v[lo]) * (k - lo)))
PY
}

# iperf3 with retries (the server is briefly busy right after a previous test); JSON to $2
run_iperf3() { # outfile args...
  local out=$1 i err; shift
  for i in 1 2 3 4 5; do
    iperf3 -c "$SERVER" -J "$@" > "$out" 2> "$TMP/iperf3.err"
    err=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("error",""))' "$out" 2>/dev/null || echo "unparseable output")
    [ -z "$err" ] && return 0
    info "iperf3: $err (attempt $i/5)"; sleep 2
  done
  return 1
}

# h2load unit-aware parse. usage: h2load_parse OUTPUT_FILE -> key=value lines
h2load_parse() { python3 - "$1" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
def sec(v, u): return float(v) * {"us": 1e-6, "ms": 1e-3, "s": 1.0}[u]
m = re.search(r"finished in ([\d.]+)(us|ms|s),\s+([\d.]+) req/s", t)
if m: print("finished_s=%.6f" % sec(m.group(1), m.group(2))); print("rps=%s" % m.group(3))
m = re.search(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed, (\d+) errored, (\d+) timeout", t)
if m:
    print("total=%s" % m.group(1)); print("done=%s" % m.group(3)); print("succeeded=%s" % m.group(4))
    print("failed=%d" % (int(m.group(5)) + int(m.group(6)) + int(m.group(7))))
for key, name in (("time for request", "req"), ("time for connect", "connect"), ("time to 1st byte", "ttfb")):
    m = re.search(key + r":\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)", t)
    if m:
        print("%s_min_ms=%.4f" % (name, sec(m.group(1), m.group(2)) * 1e3))
        print("%s_max_ms=%.4f" % (name, sec(m.group(3), m.group(4)) * 1e3))
        print("%s_mean_ms=%.4f" % (name, sec(m.group(5), m.group(6)) * 1e3))
m = re.search(r"TLS Protocol: (\S+)", t)
if m: print("tls_protocol=%s" % m.group(1))
m = re.search(r"Cipher: (\S+)", t)
if m: print("tls_cipher=%s" % m.group(1))
PY
}
kv() { sed -n "s/^$2=//p" "$1" | head -1; }   # kv FILE KEY

# h2load wrapper: run_h2load URL CONNS REQS THREADS [extra args...] ; output -> $TMP/h2.out, log -> $TMP/h2.log
run_h2load() {
  local url=$1 c=$2 n=$3 t=$4; shift 4
  [ "$t" -gt "$c" ] && t=$c
  info "h2load --h1 -c $c -n $n -t $t $* $url"
  h2load --h1 -c "$c" -n "$n" -t "$t" --log-file="$TMP/h2.log" "$@" "$url" > "$TMP/h2.out" 2> "$TMP/h2.err" || {
    cat "$TMP/h2.err" >&2; tail -5 "$TMP/h2.out" >&2; die "h2load failed"; }
  h2load_parse "$TMP/h2.out" > "$TMP/h2.kv"
  [ -n "$(kv "$TMP/h2.kv" rps)" ] || { tail -15 "$TMP/h2.out" >&2; die "could not parse h2load output"; }
}

# ---------- cps, RFC 9411 mode (--target-cps) ----------
# Load: each phase (ramp 25/50/75 % steps, sustain 100 %) is cut into slices of SLICE_S s, one per
#   h2load --h1 -r R --rate-period=Pms -c N -n N -H "Connection: close" --log-file=...
# (-c N -n N: N clients, one request each = N new TCP connections, opened R at a time every P ms).
# h2load's --rps is ignored with --h1 and -r/-D are exclusive, hence the slices. They are started on an ABSOLUTE
# schedule (slice K at t0 + its offset, in the background) so a slow tail overlaps the next slice instead of
# leaving a gap. KPIs come from the merged sustain logs only. Phase/pass-fail/conformance logic is in rfc_report.
sleep_until() { # EPOCH
  local d; d=$(awk -v t="$1" -v n="$(date +%s.%N)" 'BEGIN{d=t-n; if(d>0) printf "%.3f", d}')
  [ -z "$d" ] || sleep "$d"
}
nst_snap() { nstat -az TcpActiveOpens TcpAttemptFails TcpEstabResets TcpOutRsts 2>/dev/null | awk '/^Tcp/{print $1, $2}'; }

# rfc_plan -> $TMP/plan.tsv: idx phase step R P_ms N offset_s dur_s nominal_cps
rfc_plan() { python3 - "$TARGET_CPS" "$RAMP_S" "$SUSTAIN_S" "$SLICE_S" > "$TMP/plan.tsv" <<'PY'
import sys
target, ramp, sustain, slice_s = (float(x) for x in sys.argv[1:5])
def pick(t):
    # (R, P ms) with R/P*1000 ~ t: the largest P <= 10 ms within 0.5 % of t (fewest timer wakeups), else the closest
    # R/P over P = 1..20 ms (smaller P wins ties); below 100/s R = 1 and P = 1000/t
    if t < 100: return 1, max(1, round(1000.0 / t))
    best = None
    for p in range(1, 21):
        r = round(t * p / 1000.0)
        if r < 1: continue
        e = abs(r * 1000.0 / p - t) / t
        if best is None or e < best[0] - 1e-12: best = (e, r, p)
    near = [(p, round(t * p / 1000.0)) for p in range(1, 11) if round(t * p / 1000.0) >= 1
            and abs(round(t * p / 1000.0) * 1000.0 / p - t) / t <= 0.005]
    if near: p, r = max(near); return r, p
    return best[1], best[2]
phases = []
if ramp > 0:
    for j in (1, 2, 3): phases.append(("ramp", j, target * j / 4.0, ramp / 3.0))
phases.append(("sustain", 4, target, sustain))
idx, off = 0, 0.0
for ph, step, rate, dur in phases:
    done = 0.0
    while dur - done > 1e-9:
        d = min(slice_s, dur - done)
        r, p = pick(rate)
        n = r * int(d * 1000 // p)
        if n >= 1:
            idx += 1
            print("%d\t%s\t%d\t%d\t%d\t%d\t%.3f\t%.3f\t%.2f" % (idx, ph, step, r, p, n, off + done, d, r * 1000.0 / p))
        done += d
    off += dur
PY
}

# rfc_report: reads $TMP/plan.tsv, the slice outputs/logs and the nstat snapshots; prints all metrics, #series/#slice
# lines and the verdicts. This is the ONLY place that computes criteria and conformance.
rfc_report() { python3 - "$TMP" "$TS_SUSTAIN" <<'PY'
import math, os, re, sys
tmp, ts = sys.argv[1], float(sys.argv[2])
env = os.environ
f = lambda k: float(env[k])
target = f("TARGET_CPS"); init_s = f("INIT_S"); ramp_s = f("RAMP_S"); sustain_s = f("SUSTAIN_S"); slice_s = f("SLICE_S")
th_fail, th_rst, th_dev = f("FAIL_TXN_MAX_PCT"), f("RST_MAX_PCT"), f("RATE_DEV_MAX_PCT")
g = lambda v: ("%.6g" % v)
out = lambda k, v: print("%s=%s" % (k, v))

def nst(s):
    d = {}
    for ln in s.strip().splitlines():
        k, v = ln.split(); d[k] = int(v)
    return d
n0, n1 = nst(env.get("NS0", "")), nst(env.get("NS1", ""))
dl = lambda k: n1.get(k, 0) - n0.get(k, 0)

slices = []
for ln in open(tmp + "/plan.tsv"):
    i, ph, step, R, P, N, off, dur, nom = ln.split("\t")
    slices.append(dict(i=int(i), ph=ph, step=int(step), R=int(R), P=int(P), N=int(N), dur=float(dur), nom=float(nom)))
for s in slices:
    base = "%s/s%d" % (tmp, s["i"])
    try: s["state"] = open(base + ".state").read().strip()
    except OSError: s["state"] = "skipped"
    recs = []
    try:
        for ln in open(base + ".log"):
            a = ln.split()
            if len(a) == 3: recs.append((int(a[0]), int(a[1]), int(a[2])))
    except OSError: pass
    s["recs"] = recs
    ok_in_log = sum(1 for r in recs if 200 <= r[1] < 400)
    s["total"], s["succ"] = s["N"], 0
    try:
        t = open(base + ".out").read()
        m = re.search(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed", t)
        if m and s["state"] not in ("killed", "skipped"): s["succ"] = int(m.group(4))
        else: s["succ"] = ok_in_log
    except OSError: s["succ"] = ok_in_log
    s["fail"] = s["total"] - s["succ"]

for s in slices:
    print("#slice %d %s step=%d rate=%s R=%d P=%dms N=%d dur=%.2fs state=%s succeeded=%d failed=%d" %
          (s["i"], s["ph"], s["step"], g(s["nom"]), s["R"], s["P"], s["N"], s["dur"], s["state"], s["succ"], s["fail"]))
for st in (1, 2, 3):
    sl = [s for s in slices if s["ph"] == "ramp" and s["step"] == st]
    if sl: print("#ramp step=%d target_cps=%s txn=%d failed=%d (not measured, discarded)" %
                 (st, g(target * st / 4), sum(s["total"] for s in sl), sum(s["fail"] for s in sl)))

sus = [s for s in slices if s["ph"] == "sustain"]
S = int(sustain_s)
cnt = [0] * max(S, 1)
for s in sus:
    for st, code, du in s["recs"]:
        if not 200 <= code < 400: continue
        k = math.floor((st + du) / 1e6 - ts)   # second (relative to sustain start) in which the connection completed
        if 0 <= k < S: cnt[k] += 1
kept = cnt[1:S - 1] if S >= 3 else []
for k, c in enumerate(cnt):
    print("#series sustain_s=%d conn_per_s=%d%s" % (k, c, "" if 1 <= k < S - 1 else " dropped"))
if kept:
    mean = sum(kept) / len(kept)
    devs = [abs(c - mean) / mean * 100 for c in kept] if mean > 0 else [100.0] * len(kept)
    dmax, viol = max(devs), sum(1 for d in devs if d > th_dev)
    cmin, cmax = min(kept), max(kept)
else:
    mean = cmin = cmax = 0.0; dmax, viol = 100.0, 0

tot = sum(s["total"] for s in sus); fail = sum(s["fail"] for s in sus)
fail_pct = 100.0 * fail / tot if tot else 100.0
rst = dl("TcpEstabResets") + dl("TcpAttemptFails"); opens = dl("TcpActiveOpens") or tot
rst_pct = 100.0 * rst / opens if opens else 100.0
nover = sum(1 for s in slices if s["state"] == "killed"); nskip = sum(1 for s in slices if s["state"] == "skipped")
c_fail = fail_pct < th_fail
c_rst = rst_pct < th_rst
c_dev = bool(kept) and dmax < th_dev
yn = lambda b: "pass" if b else "fail"

dev = []
if init_s < 5: dev.append("init=%gs<5s" % init_s)
if ramp_s <= 0: dev.append("ramp=none")
if sustain_s < 300: dev.append("sustain=%gs<300s" % sustain_s)
for n, v, d in (("fail_txn_max_pct", th_fail, 0.001), ("rst_max_pct", th_rst, 0.001), ("rate_dev_max_pct", th_dev, 5)):
    if v > d: dev.append("%s=%g>%g" % (n, v, d))

nom = sus[0]["nom"] if sus else 0
out("cps_target", g(target)); out("cps_nominal", g(nom))
out("cps_pacing", "%d/%dms" % (sus[0]["R"], sus[0]["P"]) if sus else "n/a")
out("cps_sustain_mean", "%.2f" % mean); out("cps_sustain_min", cmin); out("cps_sustain_max", cmax)
out("cps_samples", len(kept))
out("cps_dev_max_pct", "%.3f" % dmax); out("cps_dev_violations", viol)
out("txn_total", tot); out("txn_failed", fail); out("txn_failed_pct", "%.5f" % fail_pct)
out("rst_count", rst); out("rst_pct", "%.5f" % rst_pct)
for k in ("TcpActiveOpens", "TcpAttemptFails", "TcpEstabResets", "TcpOutRsts"): out("nstat_" + k.lower(), dl(k))
out("slices_total", len(slices)); out("slices_overrun", nover); out("slices_skipped", nskip)
out("crit_failed_txn", yn(c_fail)); out("crit_rst", yn(c_rst)); out("crit_rate_dev", yn(c_dev))
out("crit_all", yn(c_fail and c_rst and c_dev))
out("fail_txn_max_pct", g(th_fail)); out("rst_max_pct", g(th_rst)); out("rate_dev_max_pct", g(th_dev))
out("init_s", g(init_s)); out("ramp_s", g(ramp_s)); out("sustain_s", g(sustain_s)); out("slice_s", g(slice_s))
out("rfc9411_conformant", "yes" if not dev else "no"); out("rfc9411_deviations", ";".join(dev) or "none")
PY
}

cps_rfc9411() {
  need nstat
  local v url="http://$HOSTPORT/$OBJECT" grace=${SLICE_GRACE_S:-15} maxalive=${SLICE_MAX_ALIVE:-4} txn_to=${TXN_TIMEOUT_S:-10}
  for v in TARGET_CPS INIT_S RAMP_S SUSTAIN_S SLICE_S FAIL_TXN_MAX_PCT RST_MAX_PCT RATE_DEV_MAX_PCT; do
    [[ "${!v}" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "$v must be a number (got '${!v}')"
  done
  awk -v t="$TARGET_CPS" -v s="$SUSTAIN_S" -v l="$SLICE_S" 'BEGIN{exit !(t>0 && s>=3 && l>=1)}' \
    || die "--target-cps must be > 0, --sustain-s >= 3, --slice-s >= 1"
  [ -z "$CONNS" ] || die "--conns is not used with --target-cps (connections per slice = rate x slice length)"
  ulimit -n "$(ulimit -Hn)" 2>/dev/null || true       # a slow path keeps rate x latency connections open
  rfc_plan; [ -s "$TMP/plan.tsv" ] || die "empty load plan"
  local t0 st idx phase step R P N off dur nom i now_t alive
  t0=$(awk -v n="$(date +%s.%N)" 'BEGIN{printf "%.3f", n + 1}')
  TS_SUSTAIN=$(awk -v t="$t0" -v r="$RAMP_S" 'BEGIN{printf "%.3f", t + r}')
  info "RFC 9411 cps: target=$TARGET_CPS/s ramp=${RAMP_S}s (25/50/75%) sustain=${SUSTAIN_S}s slice=${SLICE_S}s, $(wc -l < "$TMP/plan.tsv") slices"
  declare -A PID=() DL=() ST=()
  NS0="" NS1=""
  reap() { # kill slices that outlived their window + grace; record state of finished ones
    local k n
    n=$(date +%s.%N)
    for k in "${!PID[@]}"; do
      if kill -0 "${PID[$k]}" 2>/dev/null; then
        if awk -v n="$n" -v d="${DL[$k]}" 'BEGIN{exit !(n>d)}'; then
          kill -KILL "${PID[$k]}" 2>/dev/null; wait "${PID[$k]}" 2>/dev/null
          echo killed > "$TMP/s$k.state"; info "slice $k still running ${grace}s after its window: killed (counted as failure signal)"
          unset 'PID[$k]'
        fi
      else
        wait "${PID[$k]}" 2>/dev/null; echo "rc$?" > "$TMP/s$k.state"; unset 'PID[$k]'
      fi
    done
  }
  while IFS=$'\t' read -r idx phase step R P N off dur nom; do
    st=$(awk -v t="$t0" -v o="$off" 'BEGIN{printf "%.3f", t + o}')
    sleep_until "$st"
    if [ "$phase" = sustain ] && [ -z "$NS0" ]; then NS0=$(nst_snap); fi
    reap
    if [ "${#PID[@]}" -ge "$maxalive" ]; then
      echo skipped > "$TMP/s$idx.state"; info "slice $idx skipped: $maxalive h2load processes already alive (counted as failure)"; continue
    fi
    ( exec h2load --h1 -r "$R" --rate-period="${P}ms" -c "$N" -n "$N" -t 1 -T "${txn_to}s" -H "Connection: close" \
        --log-file="$TMP/s$idx.log" "$url" > "$TMP/s$idx.out" 2> "$TMP/s$idx.err" ) &
    PID[$idx]=$!; DL[$idx]=$(awk -v s="$st" -v d="$dur" -v g="$grace" 'BEGIN{printf "%.3f", s + d + g}')
    info "slice $idx $phase step=$step: ${R} conn / ${P} ms (~$nom/s), N=$N, ${dur}s"
  done < "$TMP/plan.tsv"
  sleep_until "$(awk -v t="$TS_SUSTAIN" -v s="$SUSTAIN_S" 'BEGIN{printf "%.3f", t + s}')"
  NS1=$(nst_snap)
  while [ "${#PID[@]}" -gt 0 ]; do reap; sleep 0.5; done
  export NS0 NS1 TARGET_CPS INIT_S RAMP_S SUSTAIN_S SLICE_S FAIL_TXN_MAX_PCT RST_MAX_PCT RATE_DEV_MAX_PCT
  rfc_report
}

case "$TEST" in
latency)
  : "${DURATION:=10}"
  if command -v sockperf >/dev/null 2>&1; then
    flags=(); [ "$PROTO" = tcp ] && flags+=(--tcp)
    info "sockperf ping-pong -i $SERVER -p $PORT -t $DURATION --full-rtt ${flags[*]}"
    sockperf ping-pong -i "$SERVER" -p "$PORT" -t "$DURATION" --full-rtt "${flags[@]}" 2>&1 \
      | sed 's/\x1b\[[0-9;]*m//g' > "$TMP/sp.out" || true
    avg=$(sed -n 's/.*avg-rtt=\([0-9.]*\).*/\1/p' "$TMP/sp.out" | head -1)
    [ -n "$avg" ] || { tail -15 "$TMP/sp.out" >&2; die "sockperf produced no result (is 'sockperf server -p $PORT' running on the server?)"; }
    p() { sed -n "s/.*percentile *$1 *= *\([0-9.]*\).*/\1/p" "$TMP/sp.out" | head -1; }
    emit tool sockperf
    emit rtt_p50_us "$(p 50.000)"; emit rtt_p99_us "$(p 99.000)"; emit rtt_p999_us "$(p 99.900)"
    emit rtt_avg_us "$avg"
    emit rtt_min_us "$(sed -n 's/.*<MIN> observation = *\([0-9.]*\).*/\1/p' "$TMP/sp.out" | head -1)"
    emit rtt_max_us "$(sed -n 's/.*<MAX> observation = *\([0-9.]*\).*/\1/p' "$TMP/sp.out" | head -1)"
    emit rtt_samples "$(sed -n 's/.*Total \([0-9]*\) observations.*/\1/p' "$TMP/sp.out" | head -1)"
    emit rtt_lost "$(sed -n 's/.*# dropped messages = \([0-9]*\).*/\1/p' "$TMP/sp.out" | head -1)"
  else
    need ping
    : "${COUNT:=$((DURATION * 100))}"
    info "sockperf not found; falling back to ping -i 0.01 -c $COUNT (needs root for the 10 ms interval)"
    ping -i 0.01 -c "$COUNT" "$SERVER" 2> "$TMP/ping.err" | sed -n 's/.*time=\([0-9.]*\) ms.*/\1/p' > "$TMP/rtt_ms.txt"
    [ -s "$TMP/rtt_ms.txt" ] || { cat "$TMP/ping.err" >&2; die "ping produced no replies"; }
    awk '{printf "%.3f\n", $1*1000}' "$TMP/rtt_ms.txt" > "$TMP/rtt_us.txt"
    emit tool ping
    emit rtt_p50_us "$(pct "$TMP/rtt_us.txt" 50)"; emit rtt_p99_us "$(pct "$TMP/rtt_us.txt" 99)"
    emit rtt_avg_us "$(awk '{s+=$1} END{printf "%.3f", s/NR}' "$TMP/rtt_us.txt")"
    emit rtt_min_us "$(sort -n "$TMP/rtt_us.txt" | head -1)"; emit rtt_max_us "$(sort -n "$TMP/rtt_us.txt" | tail -1)"
    emit rtt_samples "$(wc -l < "$TMP/rtt_us.txt")"
    emit rtt_lost "$((COUNT - $(wc -l < "$TMP/rtt_us.txt")))"
  fi ;;

tcp)
  need iperf3; : "${DURATION:=10}"
  info "iperf3 -c $SERVER -t $DURATION -P $STREAMS"
  run_iperf3 "$TMP/ip.json" -t "$DURATION" -P "$STREAMS" || die "iperf3 tcp failed: $(cat "$TMP/iperf3.err")"
  python3 - "$TMP/ip.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); e = d["end"]
r = e.get("sum_received") or e.get("sum")
print("tcp_mbps=%.3f" % (r["bits_per_second"] / 1e6))
print("tcp_retransmits=%d" % e["sum_sent"].get("retransmits", 0))
print("tcp_streams=%d" % len(e["streams"]))
PY
  ;;

udp)
  need iperf3; : "${DURATION:=10}"; : "${RATE:=10}"
  [[ "$RATE" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--rate must be a number (Mbit/s)"
  payload=$((FRAME - 42))               # frame = payload + 14 (Ethernet) + 20 (IPv4) + 8 (UDP), no FCS
  [ "$payload" -lt 16 ] && { info "frame $FRAME B needs payload < 16 B; iperf3 minimum is 16, clamping"; payload=16; }
  [ "$payload" -gt 1472 ] && { info "frame $FRAME B exceeds MTU 1500, clamping to 1514"; payload=1472; }
  info "iperf3 -c $SERVER -u -b ${RATE}M -l $payload -t $DURATION"
  run_iperf3 "$TMP/ip.json" -u -b "${RATE}M" -l "$payload" -t "$DURATION" || die "iperf3 udp failed: $(cat "$TMP/iperf3.err")"
  python3 - "$TMP/ip.json" "$RATE" "$payload" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); e = d["end"]
s = e["sum_sent"]; r = e.get("sum_received") or e["sum"]
print("udp_offered_mbps=%s" % sys.argv[2])
print("udp_sent_mbps=%.3f" % (s["bits_per_second"] / 1e6))
print("udp_recv_mbps=%.3f" % (r["bits_per_second"] / 1e6))
print("udp_pps=%.0f" % (s["packets"] / s["seconds"]))
print("udp_loss_pct=%.4f" % r["lost_percent"])
print("udp_jitter_ms=%.4f" % r["jitter_ms"])
print("frame_bytes_actual=%d" % (int(sys.argv[3]) + 42))
PY
  ;;

http)
  need h2load; : "${CONNS:=50}"; : "${REQS:=20000}"; : "${OBJECT:=100k}"
  run_h2load "http://$HOSTPORT/$OBJECT" "$CONNS" "$REQS" "$THREADS"
  emit http_rps "$(kv "$TMP/h2.kv" rps)"
  emit http_succeeded "$(kv "$TMP/h2.kv" succeeded)"
  emit http_failed "$(kv "$TMP/h2.kv" failed)"
  # h2load only prints min/max/mean/sd; percentiles come from --log-file (start_us status request_time_us)
  awk '{print $3/1000}' "$TMP/h2.log" > "$TMP/req_ms.txt"
  [ -s "$TMP/req_ms.txt" ] || die "h2load log file is empty"
  emit http_req_p50_ms "$(pct "$TMP/req_ms.txt" 50)"; emit http_req_p99_ms "$(pct "$TMP/req_ms.txt" 99)"
  emit http_req_mean_ms "$(kv "$TMP/h2.kv" req_mean_ms)"
  emit http_ttfb_mean_ms "$(kv "$TMP/h2.kv" ttfb_mean_ms)" ;;

cps)
  need h2load; : "${OBJECT:=1k}"
  if [ -n "$TARGET_CPS" ]; then cps_rfc9411
  else
  : "${CONNS:=500}"; : "${REQS:=$CONNS}"
  extra=(); [ -n "$RATE" ] && extra+=(-r "$RATE")
  # one request per connection (-n == -c); with --reqs > --conns the server is told to close after each response,
  # so h2load reconnects and every request still costs a new TCP connection
  [ "$REQS" -gt "$CONNS" ] && extra+=(-H "Connection: close")
  run_h2load "http://$HOSTPORT/$OBJECT" "$CONNS" "$REQS" "$THREADS" "${extra[@]}"
  emit cps_achieved "$(kv "$TMP/h2.kv" rps)"
  emit cps_succeeded "$(kv "$TMP/h2.kv" succeeded)"
  emit cps_failed "$(kv "$TMP/h2.kv" failed)"
  emit connect_time_mean_ms "$(kv "$TMP/h2.kv" connect_mean_ms)"
  emit rfc9411_conformant no          # legacy burst: no init/ramp/sustain phases, no acceptance criteria
  emit rfc9411_deviations legacy-burst
  fi ;;

tls)
  need openssl; need h2load; : "${DURATION:=10}"; : "${CONNS:=100}"; : "${REQS:=$CONNS}"; : "${OBJECT:=1k}"
  info "openssl s_time -connect $HOSTPORT:443 -new -time $DURATION"
  t0=$(date +%s.%N)
  openssl s_time -connect "$HOSTPORT:443" -new -time "$DURATION" > "$TMP/st.out" 2> "$TMP/st.err" </dev/null || true
  t1=$(date +%s.%N)
  tot=$(sed -n 's/^\([0-9][0-9]*\) connections in [0-9.]*s;.*/\1/p' "$TMP/st.out" | head -1)
  [ -n "$tot" ] || { cat "$TMP/st.err" >&2; tail -3 "$TMP/st.out" | cut -c1-200 >&2; die "could not parse openssl s_time output (is nginx listening on :443?)"; }
  el=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.3f", b-a}')
  emit tls_handshakes_total "$tot"
  emit tls_handshakes_per_s "$(awk -v n="$tot" -v e="$el" 'BEGIN{printf "%.2f", n/e}')"   # wall-clock based
  emit tls_handshakes_per_user_s "$(sed -n 's/^[0-9]* connections in [0-9.]*s; \([0-9.]*\) connections\/user sec.*/\1/p' "$TMP/st.out" | head -1)"
  extra=(); [ "$REQS" -gt "$CONNS" ] && extra+=(-H "Connection: close")   # new TCP+TLS session per request
  run_h2load "https://$HOSTPORT/$OBJECT" "$CONNS" "$REQS" "$THREADS" "${extra[@]}"
  emit tls_cps "$(kv "$TMP/h2.kv" rps)"
  emit tls_failed "$(kv "$TMP/h2.kv" failed)"
  emit tls_connect_mean_ms "$(kv "$TMP/h2.kv" connect_mean_ms)"
  emit tls_protocol "$(kv "$TMP/h2.kv" tls_protocol)"
  emit tls_cipher "$(kv "$TMP/h2.kv" tls_cipher)" ;;

ttfb)
  need curl; : "${OBJECT:=1m}"; : "${COUNT:=200}"
  info "curl x$COUNT http://$HOSTPORT/$OBJECT"
  : > "$TMP/curl.txt"; fails=0
  for ((i = 0; i < COUNT; i++)); do
    curl -s -o /dev/null -w '%{time_connect} %{time_starttransfer} %{time_total}\n' "http://$HOSTPORT/$OBJECT" >> "$TMP/curl.tmp" 2>/dev/null \
      && tail -1 "$TMP/curl.tmp" >> "$TMP/curl.txt" || fails=$((fails + 1))
  done
  [ -s "$TMP/curl.txt" ] || die "all curl requests failed"
  col() { awk -v c="$1" '{printf "%.4f\n", $c*1000}' "$TMP/curl.txt" > "$TMP/c$1.txt"; }
  col 1; col 2; col 3
  emit ttfb_p50_ms "$(pct "$TMP/c2.txt" 50)"; emit ttfb_p99_ms "$(pct "$TMP/c2.txt" 99)"
  emit ttlb_p50_ms "$(pct "$TMP/c3.txt" 50)"; emit ttlb_p99_ms "$(pct "$TMP/c3.txt" 99)"
  emit connect_p50_ms "$(pct "$TMP/c1.txt" 50)"
  emit ttfb_failed "$fails" ;;

*) echo "run-client.sh: unknown test '$TEST' (latency tcp udp http cps tls ttfb)" >&2; usage ;;
esac
