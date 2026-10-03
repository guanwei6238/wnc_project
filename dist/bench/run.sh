#!/usr/bin/env bash
# Single benchmark run of one engine (suricata | snort3 | zeek); appends one CSV row.
# See bench/README.md for details and the CSV column reference.
set -euo pipefail

usage() {
  cat >&2 <<USAGE
Usage: $0 --engine {suricata|snort3|zeek} --mode {offline|live} --pcap FILE
          [--iface IF] [--pps N] [--duration S] [--threads N] [--rules {full|none}]
          [--label STR] [--out results.csv] [--logdir DIR]

Environment (all optional):
  GEN_CMD        live: shell command run locally to start the replay; \$PPS \$DURATION
                 \$PCAP \$PCAP_BASENAME are substituted. Unset = ask the operator.
  SETTLE/DRAIN   seconds to wait after engine ready / after replay (default 5/5)
  HOME_NET       snort3 HOME_NET (default 192.168.0.0/16)
  SNORT_CONF, SNORT_RULES, SURICATA_CONF, SURICATA_RULES, ZEEK_BIN, ZEEK_SCRIPTS
  GOVERNOR       performance (default: set for the run, restored on exit) | keep (do not touch the CPU governor)
  KEEP_OUTPUTS=1 keep suricata's default fast/eve outputs enabled
  KEEP_RUNS      number of per-run log dirs kept in --logdir (default 30)
USAGE
  exit 2
}
die()  { echo "run.sh: ERROR: $*" >&2; exit 1; }
warn() { echo "run.sh: WARNING: $*" >&2; }
info() { echo "run.sh: $*" >&2; }

ENGINE="" MODE="" PCAP="" IFACE="" PPS="" DURATION="" THREADS=1 RULES=full LABEL="" OUT="results.csv" LOGDIR="/run/bench-logs"
while [ $# -gt 0 ]; do
  case "$1" in
    --engine)   ENGINE=${2:?}; shift 2 ;;
    --mode)     MODE=${2:?}; shift 2 ;;
    --pcap)     PCAP=${2:?}; shift 2 ;;
    --iface)    IFACE=${2:?}; shift 2 ;;
    --pps)      PPS=${2:?}; shift 2 ;;
    --duration) DURATION=${2:?}; shift 2 ;;
    --threads)  THREADS=${2:?}; shift 2 ;;
    --rules)    RULES=${2:?}; shift 2 ;;
    --label)    LABEL=${2:?}; shift 2 ;;
    --out)      OUT=${2:?}; shift 2 ;;
    --logdir)   LOGDIR=${2:?}; shift 2 ;;
    -h|--help)  usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ "$(id -u)" -eq 0 ] || die "must run as root"
case "$ENGINE" in suricata|snort3|zeek) ;; *) usage ;; esac
case "$MODE" in offline|live) ;; *) usage ;; esac
case "$RULES" in full|none) ;; *) usage ;; esac
[ -n "$PCAP" ] || usage
[[ "$THREADS" =~ ^[0-9]+$ ]] && [ "$THREADS" -ge 1 ] || die "--threads must be a positive integer"
if [ "$MODE" = offline ]; then
  [ -r "$PCAP" ] || die "pcap not readable: $PCAP"
  PCAP=$(readlink -f "$PCAP")
else
  [ -n "$IFACE" ] || die "--iface is required for live mode"
  [ -d "/sys/class/net/$IFACE" ] || die "no such interface: $IFACE"
  : "${DURATION:=30}"
  [ -r "$PCAP" ] && PCAP=$(readlink -f "$PCAP") || warn "pcap not readable locally; pcap packet/byte columns will be empty"
fi
[ "$ENGINE" = zeek ] && RULES_COL="n/a" || RULES_COL="$RULES"
PCAP_BASENAME=$(basename "$PCAP")
SETTLE=${SETTLE:-5}; DRAIN=${DRAIN:-5}; KEEP_RUNS=${KEEP_RUNS:-30}
READY_TIMEOUT=${READY_TIMEOUT:-300}
HOME_NET=${HOME_NET:-192.168.0.0/16}
SNORT_CONF=${SNORT_CONF:-/etc/snort/snort.lua}
SNORT_RULES=${SNORT_RULES:-/etc/snort/rules/et-open.rules}
SURICATA_CONF=${SURICATA_CONF:-/etc/suricata/suricata.yaml}
SURICATA_RULES=${SURICATA_RULES:-}
ZEEK_SCRIPTS=${ZEEK_SCRIPTS:-local policy/misc/stats policy/misc/capture-loss}
if [ -z "${ZEEK_BIN:-}" ]; then
  if [ -x /opt/zeek/bin/zeek ]; then ZEEK_BIN=/opt/zeek/bin/zeek; else ZEEK_BIN=$(command -v zeek || true); fi
fi
TIME_BIN=/usr/bin/time
[ -x "$TIME_BIN" ] || die "/usr/bin/time not found (apt install time)"
OUT=$(readlink -m "$OUT")

san() { printf '%s' "$1" | tr ',\n\r"' '    ' | sed 's/^ *//;s/ *$//'; }
calc() { awk "BEGIN{printf \"%.4f\", $1}"; }
now() { date +%s.%N; }
ro() { local f=$1; [ -r "$f" ] && cat "$f" 2>/dev/null || true; }

# ---------- engine binary / version ----------
case "$ENGINE" in
  suricata) BIN=$(command -v suricata || true); [ -n "$BIN" ] || die "suricata not found"
            VERSION=$("$BIN" -V 2>&1 | sed -n 's/.*version \([^ ]*\).*/\1/p' | head -1) ;;
  snort3)   BIN=$(command -v snort || true); [ -n "$BIN" ] || die "snort not found"
            VERSION=$("$BIN" -V 2>&1 | sed -n 's/.*Version \([0-9][0-9.]*\).*/\1/p' | head -1) ;;
  zeek)     BIN=$ZEEK_BIN; [ -n "$BIN" ] && [ -x "$BIN" ] || die "zeek not found (set ZEEK_BIN)"
            VERSION=$("$BIN" --version 2>&1 | awk '{print $NF}' | head -1) ;;
esac

# ---------- pcap stats ----------
PCAP_PKTS="" PCAP_BYTES=""
if [ -r "$PCAP" ]; then
  if command -v capinfos >/dev/null 2>&1; then
    line=$(capinfos -T -r -m -M -c -d "$PCAP" 2>/dev/null | head -1 || true)
    PCAP_PKTS=$(echo "$line" | awk -F, '{print $(NF-1)}'); PCAP_BYTES=$(echo "$line" | awk -F, '{print $NF}')
  fi
  if ! [[ "$PCAP_PKTS" =~ ^[0-9]+$ ]] && command -v python3 >/dev/null 2>&1; then
    read -r PCAP_PKTS PCAP_BYTES < <(python3 - "$PCAP" <<'PY' || true
import struct, sys
f = open(sys.argv[1], 'rb'); n = 0; b = 0
m = f.read(4)
try:
    if m in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        e = '<' if m[0] in (0xd4, 0x4d) else '>'
        f.read(20)
        while True:
            h = f.read(16)
            if len(h) < 16: break
            _, _, incl, orig = struct.unpack(e + 'IIII', h)
            f.seek(incl, 1); n += 1; b += orig
    elif m == b'\x0a\x0d\x0d\x0a':
        f.seek(8); e = '<' if f.read(4) == b'\x4d\x3c\x2b\x1a' else '>'
        f.seek(0)
        while True:
            h = f.read(8)
            if len(h) < 8: break
            t, l = struct.unpack(e + 'II', h)
            body = f.read(l - 8)
            if t == 6: n += 1; b += struct.unpack(e + 'I', body[16:20])[0]
            elif t == 3: n += 1; b += struct.unpack(e + 'I', body[0:4])[0]
            elif t == 2: n += 1; b += struct.unpack(e + 'I', body[8:12])[0]
except Exception:
    pass
print(n, b)
PY
)
  fi
  [[ "$PCAP_PKTS" =~ ^[0-9]+$ ]] || { PCAP_PKTS=""; PCAP_BYTES=""; }
fi

# ---------- environment preparation ----------
HAVE_VC=0; command -v vcgencmd >/dev/null 2>&1 && HAVE_VC=1
vc_temp() { [ $HAVE_VC = 1 ] && vcgencmd measure_temp 2>/dev/null | sed -n "s/temp=\([0-9.]*\).*/\1/p" || true; }
vc_thr()  { [ $HAVE_VC = 1 ] && vcgencmd get_throttled 2>/dev/null | sed -n 's/throttled=//p' || true; }
TEMP0=$(vc_temp); THR0=$(vc_thr)
case "$THR0" in ""|0x0) ;; *) warn "vcgencmd get_throttled=$THR0 at start (undervoltage/throttling has occurred; results may be unreliable)";; esac

# governor: GOVERNOR=performance (default, restored on exit) | keep. CPUFREQ_ROOT is overridable for tests.
CPUFREQ_ROOT=${CPUFREQ_ROOT:-/sys/devices/system/cpu}
GOV_FILES=() GOV_OLD=()
restore_governor() {
  local i done_="" n=${#GOV_FILES[@]}
  for ((i = 0; i < n; i++)); do
    echo "${GOV_OLD[$i]}" > "${GOV_FILES[$i]}" 2>/dev/null \
      && done_="$done_ $(basename "$(dirname "$(dirname "${GOV_FILES[$i]}")")"):${GOV_OLD[$i]}" \
      || warn "could not restore governor in ${GOV_FILES[$i]}"
  done
  GOV_FILES=() GOV_OLD=()
  [ -z "$done_" ] || info "CPU governor restored:$done_"
  return 0
}
trap restore_governor EXIT
trap 'warn "interrupted"; exit 130' INT TERM
gov_changed=""
case "${GOVERNOR:-performance}" in
  performance)
    for g in "$CPUFREQ_ROOT"/cpu[0-9]*/cpufreq/scaling_governor; do
      [ -w "$g" ] || continue
      cur=$(cat "$g")
      [ "$cur" = performance ] || { echo performance > "$g" 2>/dev/null && {
        GOV_FILES+=("$g"); GOV_OLD+=("$cur"); gov_changed="$gov_changed $(basename "$(dirname "$(dirname "$g")")"):$cur"; }; }
    done
    [ -n "$gov_changed" ] && info "CPU governor set to performance (was:$gov_changed; restored on exit)"
    [ "$(ro "$CPUFREQ_ROOT/cpu0/cpufreq/scaling_governor")" = performance ] || \
      [ ! -e "$CPUFREQ_ROOT/cpu0/cpufreq/scaling_governor" ] || warn "CPU governor is not performance" ;;
  keep) info "GOVERNOR=keep: CPU governor left untouched" ;;
  *) die "GOVERNOR must be performance or keep (got '${GOVERNOR}')" ;;
esac

# log dir (tmpfs)
if ! grep -q " $LOGDIR tmpfs " /proc/mounts 2>/dev/null; then
  mkdir -p "$LOGDIR"
  mount -t tmpfs -o size=256M tmpfs "$LOGDIR" 2>/dev/null && info "mounted tmpfs on $LOGDIR" \
    || warn "could not mount tmpfs on $LOGDIR; logs go to the regular filesystem (I/O may skew results)"
fi
TS=$(date +%Y%m%d-%H%M%S)
RUN="$LOGDIR/$TS-$ENGINE-$$"
mkdir -p "$RUN/work"

if [ "$MODE" = live ]; then
  chg=$(ethtool -K "$IFACE" gro off lro off gso off tso off 2>&1 | tr '\n' ';' || true)
  info "ethtool -K $IFACE gro/lro/gso/tso off: ${chg:-no output}"
else
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || warn "could not drop page cache"
fi

# ---------- build engine command ----------
CMD=()
case "$ENGINE" in
  suricata)
    CMD=("$BIN" -c "$SURICATA_CONF" -l "$RUN/work" --set stats.enabled=yes)
    if [ "$RULES" = none ]; then CMD+=(-S /dev/null)
    elif [ -n "$SURICATA_RULES" ]; then CMD+=(-S "$SURICATA_RULES")
    else info "suricata rules=full: using rule-files from $SURICATA_CONF (install ET Open with suricata-update)"; fi
    if [ "${KEEP_OUTPUTS:-0}" != 1 ]; then
      while read -r k; do CMD+=(--set "$k=no"); done < <("$BIN" -c "$SURICATA_CONF" --dump-config 2>/dev/null \
        | sed -n 's/^\(outputs\.[0-9]*\.\(fast\|eve-log\|syslog\|http-log\|tls-log\|lua\|file-store\|tcp-data\|http-body-data\|pcap-log\|alert-debug\|tls-store\)\.enabled\) = yes$/\1/p')
    fi
    if [ "$MODE" = offline ]; then
      CMD+=(-r "$PCAP"); [ "$THREADS" = 1 ] && CMD+=(--runmode single)
    else
      CMD+=(--af-packet --runmode workers --set "af-packet.0.interface=$IFACE" --set "af-packet.0.threads=$THREADS")
    fi
    READY_RE='Engine started' ;;
  snort3)
    {
      echo "include '$SNORT_CONF'"
      echo "HOME_NET = '$HOME_NET'"
      echo "EXTERNAL_NET = '!\$HOME_NET'"
      echo "for k, v in pairs(ips.variables.nets) do if v == 'any' then ips.variables.nets[k] = HOME_NET end end"
      echo "ips.variables.nets.HOME_NET = HOME_NET"
      echo "ips.variables.nets.EXTERNAL_NET = EXTERNAL_NET"
      if [ "$RULES" = full ]; then
        [ -r "$SNORT_RULES" ] || die "snort rules file not found: $SNORT_RULES"
        echo "ips.rules = [[ include $SNORT_RULES ]]"
      else
        echo "ips.rules = nil"
      fi
    } > "$RUN/bench.lua"
    CMD=("$BIN" -c "$RUN/bench.lua" -k none -A none -l "$RUN/work")
    if [ "$MODE" = offline ]; then CMD+=(-r "$PCAP")
    else CMD+=(--daq afpacket -i "$IFACE" -z "$THREADS" --daq-var fanout_type=hash); fi
    READY_RE='Commencing packet processing' ;;
  zeek)
    if [ "$MODE" = offline ]; then CMD=("$BIN" -C -r "$PCAP")
    else
      if "$BIN" -N 2>/dev/null | grep -qi 'AF_Packet'; then CMD=("$BIN" -C -i "af_packet::$IFACE")
      else warn "zeek has no AF_Packet plugin; falling back to libpcap (-i $IFACE)"; CMD=("$BIN" -C -i "$IFACE"); fi
      [ "$THREADS" -gt 1 ] && warn "zeek runs as a single process here; --threads $THREADS is only recorded"
    fi
    # shellcheck disable=SC2206
    CMD+=($ZEEK_SCRIPTS)
    READY_RE='listening on' ;;
esac
info "engine command: ${CMD[*]}"

# ---------- helpers for measurement ----------
cpu_snap() { awk '/^cpu /{idle=$5+$6; t=0; for(i=2;i<=9;i++) t+=$i; print t, idle}' /proc/stat; }
cpu_pct() { # $1 "t i" start, $2 "t i" end
  awk -v a="$1" -v b="$2" 'BEGIN{split(a,x," ");split(b,y," ");dt=y[1]-x[1];di=y[2]-x[2]; if(dt>0) printf "%.2f",(dt-di)*100/dt}'; }
NICS="rx_packets rx_bytes rx_dropped rx_missed_errors rx_fifo_errors"
nic_snap() { local c; for c in $NICS; do f=/sys/class/net/$IFACE/statistics/$c; [ -r "$f" ] && cat "$f" || echo ""; done | tr '\n' ' '; }
subst() {
  local s=$1 v
  for v in PCAP_BASENAME PCAP PPS DURATION; do
    local val=${!v}; s=${s//\$\{$v\}/$val}; s=${s//\$$v/$val}
  done
  printf '%s' "$s"
}
export PPS DURATION PCAP PCAP_BASENAME

# ---------- run ----------
TIMEF="$RUN/time.txt"
LINEBUF=""  # line-buffer stdout so the readiness pattern shows up while the engine runs
[ "$MODE" = live ] && command -v stdbuf >/dev/null 2>&1 && LINEBUF="stdbuf -oL -eL"
CPU_A=$(cpu_snap); T_START=$(now)
( cd "$RUN/work" && exec "$TIME_BIN" -f '%e %U %S %M' -o "$TIMEF" $LINEBUF "${CMD[@]}" ) > "$RUN/engine.out" 2>&1 &
TPID=$!
REPLAY_S="" GEN_SENT="" NIC0="" NIC1="" CPU_C="" CPU_D=""
RC=0
if [ "$MODE" = offline ]; then
  wait "$TPID" || RC=$?
  CPU_B=$(cpu_snap); CPU_UTIL=$(cpu_pct "$CPU_A" "$CPU_B")
else
  # wait until the engine reports readiness (rule loading can take minutes on a Pi)
  waited=0
  until grep -q "$READY_RE" "$RUN/engine.out" 2>/dev/null || ! kill -0 "$TPID" 2>/dev/null; do
    sleep 1; waited=$((waited+1))
    [ "$waited" -ge "$READY_TIMEOUT" ] && { warn "engine not ready after ${READY_TIMEOUT}s, continuing"; break; }
  done
  kill -0 "$TPID" 2>/dev/null || { cat "$RUN/engine.out" >&2; die "engine exited before replay (see $RUN/engine.out)"; }
  info "engine ready after ${waited}s; settling ${SETTLE}s"
  sleep "$SETTLE"
  NIC0=$(nic_snap); CPU_C=$(cpu_snap); T_R0=$(now)
  if [ -n "${GEN_CMD:-}" ]; then
    gc=$(subst "$GEN_CMD"); info "replay: $gc"
    bash -c "$gc" > "$RUN/gen.out" 2>&1 || warn "GEN_CMD exited non-zero (see $RUN/gen.out)"
    GEN_SENT=$(sed -n 's/^Actual: \([0-9]*\) packets.*/\1/p' "$RUN/gen.out" | tail -1)
  else
    echo "Start replay now ($PCAP_BASENAME pps=${PPS:-max} duration=${DURATION}s), press Enter when finished" >&2
    read -r _ || true
  fi
  T_R1=$(now); REPLAY_S=$(calc "$T_R1 - $T_R0")
  CPU_D=$(cpu_snap); CPU_UTIL=$(cpu_pct "$CPU_C" "$CPU_D")
  info "replay finished after ${REPLAY_S}s; draining ${DRAIN}s"
  sleep "$DRAIN"
  NIC1=$(nic_snap)
  pkill -TERM -P "$TPID" 2>/dev/null || kill -TERM "$TPID" 2>/dev/null || true
  for _ in $(seq 1 120); do kill -0 "$TPID" 2>/dev/null || break; sleep 1; done
  if kill -0 "$TPID" 2>/dev/null; then warn "engine did not exit, killing"; pkill -KILL -P "$TPID" 2>/dev/null || true; fi
  wait "$TPID" || RC=$?
fi
T_END=$(now); WALL_FALLBACK=$(calc "$T_END - $T_START")
TEMP1=$(vc_temp); THR1=$(vc_thr)
# engine terminated by our SIGTERM: not an error in live mode
[ "$MODE" = live ] && [ "$RC" = 143 ] && RC=0

read -r WALL USR SYS RSS < <(tail -n 1 "$TIMEF" 2>/dev/null || echo "") || true
WALL=${WALL:-$WALL_FALLBACK}; CPU_S=""
[ -n "${USR:-}" ] && CPU_S=$(calc "$USR + $SYS")

# ---------- engine counters ----------
RX="" PROC="" DROP="" FLOWS="" ALERTS=""
case "$ENGINE" in
  suricata)
    SL="$RUN/work/stats.log"
    if [ -s "$SL" ]; then
      # last "Date:" block; counters have the form "name | Total | value"
      sc() { awk -F'|' -v n="$1" '/^Date:/{delete v; next} {k=$1; gsub(/ /,"",k); t=$2; gsub(/ /,"",t); if(k==n && t=="Total"){x=$3; gsub(/ /,"",x); v[0]=x}} END{if(0 in v) print v[0]}' "$SL"; }
      PROC=$(sc decoder.pkts); RX=$(sc capture.kernel_packets); DROP=$(sc capture.kernel_drops)
      [ -n "$RX" ] || RX=$PROC
      DROP=${DROP:-0}   # zero counters are omitted from stats.log
      FLOWS=$(sc flow.total)
      if [ -z "$FLOWS" ]; then FLOWS=$(( $(sc flow.tcp) + $(sc flow.udp) )); fi
      ALERTS=$(sc detect.alert); ALERTS=${ALERTS:-0}
    else warn "suricata stats.log missing/empty (see $RUN/engine.out)"; fi ;;
  snort3)
    SO="$RUN/engine.out"
    sn() { awk -v s="$1" -v k="$2" '/^[A-Za-z_]/{sec=$1; next} sec==s && $1==k":"{print $2; exit}' "$SO"; }
    RX=$(sn daq received); PROC=$(sn daq analyzed); DROP=$(sn daq dropped)
    [ -n "$DROP" ] || DROP=0
    FLOWS=$(sn stream flows)
    [ -n "$FLOWS" ] || FLOWS=$(( $(sn stream_tcp sessions) + $(sn stream_udp sessions) ))
    ALERTS=$(sn detection total_alerts); [ -n "$ALERTS" ] || ALERTS=$(sn detection alerts); ALERTS=${ALERTS:-0}
    [ -n "$RX" ] || warn "snort summary not found (see $RUN/engine.out)" ;;
  zeek)
    ZD="$RUN/work"
    if [ -s "$ZD/stats.log" ]; then
      # stats.log rows are per-interval deltas; "-" = unset
      read -r PROC DROP < <(awk -F'\t' '/^#fields/{for(i=2;i<=NF;i++){if($i=="pkts_proc")p=i-1; if($i=="pkts_dropped")d=i-1}} /^#/{next} {if($p!="-")sp+=$p; if($d!="-")sd+=$d} END{printf "%d %d\n",sp,sd}' "$ZD/stats.log")
      RX=$((PROC + DROP))
    else warn "zeek stats.log missing (see $RUN/work)"; fi
    zrows() { [ -f "$1" ] && grep -vc '^#' "$1" || echo 0; }
    FLOWS=$(zrows "$ZD/conn.log"); ALERTS=$(zrows "$ZD/notice.log") ;;
esac

# ---------- NIC deltas ----------
nd() { # index into snapshots
  awk -v a="$NIC0" -v b="$NIC1" -v i="$1" 'BEGIN{split(a,x," ");split(b,y," "); if(y[i]!="" && x[i]!="") print y[i]-x[i]}'; }
NIC_RXP="" NIC_RXB="" NIC_DRP="" NIC_MISS="" NIC_FIFO=""
if [ "$MODE" = live ]; then
  NIC_RXP=$(nd 1); NIC_RXB=$(nd 2); NIC_DRP=$(nd 3); NIC_MISS=$(nd 4); NIC_FIFO=$(nd 5)
fi

# ---------- derived ----------
PROC_PPS="" EDROP="" KDROP="" TDROP=""
DENOM=$WALL; [ -n "$REPLAY_S" ] && DENOM=$REPLAY_S
[ -n "$PROC" ] && PROC_PPS=$(awk -v p="$PROC" -v w="$DENOM" 'BEGIN{if(w>0) printf "%.1f", p/w}')
if [[ "$RX" =~ ^[0-9]+$ ]] && [ "$RX" -gt 0 ]; then
  KDROP=$(awk -v d="${DROP:-0}" -v r="$RX" 'BEGIN{printf "%.4f", 100*d/r}')
  EDROP=$(awk -v d="${DROP:-0}" -v r="$RX" -v p="${PROC:-0}" 'BEGIN{x=r-d-p; if(x<0)x=0; printf "%.4f", 100*x/r}')
fi
REF=""
if [ -n "$GEN_SENT" ]; then REF=$GEN_SENT
elif [ "$MODE" = live ] && [ -n "$NIC_RXP" ]; then REF=$((NIC_RXP + ${NIC_MISS:-0} + ${NIC_FIFO:-0}))
elif [ "$MODE" = offline ] && [ -n "$PCAP_PKTS" ]; then REF=$PCAP_PKTS; fi
if [[ "$REF" =~ ^[0-9]+$ ]] && [ "$REF" -gt 0 ] && [ -n "$PROC" ]; then
  TDROP=$(awk -v r="$REF" -v p="$PROC" 'BEGIN{x=100*(r-p)/r; if(x<0)x=0; printf "%.4f", x}')
fi

# ---------- CSV ----------
COLS=(timestamp hostname engine version mode pcap pcap_pkts pcap_bytes pps_req duration_req threads rules label
      wall_s replay_s cpu_s cpu_util_pct peak_rss_kb
      nic_rx_packets nic_rx_bytes nic_rx_dropped nic_rx_missed nic_rx_fifo gen_sent_pkts
      eng_rx_pkts eng_proc_pkts eng_drop_pkts eng_flows eng_alerts
      proc_pps eng_drop_pct kernel_drop_pct total_drop_pct
      temp_start_c temp_end_c throttled_start throttled_end exit_code logdir)
declare -A V=(
  [timestamp]=$(date -u +%Y-%m-%dT%H:%M:%SZ) [hostname]=$(hostname) [engine]=$ENGINE [version]=$VERSION [mode]=$MODE
  [pcap]=$PCAP_BASENAME [pcap_pkts]=$PCAP_PKTS [pcap_bytes]=$PCAP_BYTES [pps_req]=$PPS [duration_req]=$DURATION
  [threads]=$THREADS [rules]=$RULES_COL [label]=$LABEL [wall_s]=$WALL [replay_s]=$REPLAY_S [cpu_s]=$CPU_S
  [cpu_util_pct]=$CPU_UTIL [peak_rss_kb]=${RSS:-} [nic_rx_packets]=$NIC_RXP [nic_rx_bytes]=$NIC_RXB
  [nic_rx_dropped]=$NIC_DRP [nic_rx_missed]=$NIC_MISS [nic_rx_fifo]=$NIC_FIFO [gen_sent_pkts]=$GEN_SENT
  [eng_rx_pkts]=$RX [eng_proc_pkts]=$PROC [eng_drop_pkts]=$DROP [eng_flows]=$FLOWS [eng_alerts]=$ALERTS
  [proc_pps]=$PROC_PPS [eng_drop_pct]=$EDROP [kernel_drop_pct]=$KDROP [total_drop_pct]=$TDROP
  [temp_start_c]=$TEMP0 [temp_end_c]=$TEMP1 [throttled_start]=$THR0 [throttled_end]=$THR1
  [exit_code]=$RC [logdir]=$RUN )
mkdir -p "$(dirname "$OUT")"
if [ ! -s "$OUT" ]; then ( IFS=,; echo "${COLS[*]}" ) > "$OUT"; fi
line=""
for c in "${COLS[@]}"; do line+="$(san "${V[$c]:-}"),"; done
echo "${line%,}" >> "$OUT"
info "row appended to $OUT"
echo "${line%,}"

# ---------- housekeeping: keep tmpfs from filling ----------
find "$RUN" -type f -size +20M -delete 2>/dev/null || true
ls -1dt "$LOGDIR"/*/ 2>/dev/null | tail -n +$((KEEP_RUNS + 1)) | xargs -r rm -rf
[ "$RC" -eq 0 ] || warn "engine exit code $RC (see $RUN/engine.out)"
exit 0
