#!/usr/bin/env bash
# Tier 3: one INLINE run on the Pi (client --(cable)--> IF_A [engine] IF_B --(cable)--> server).
# Orchestrates the engine (or a kernel bridge baseline), triggers the test on the client host and appends
# LONG-format CSV rows (one per metric). See bench/README.md, "Tier 3".
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PROG=inline.sh
# shellcheck source=lib.sh
. "$HERE/lib.sh"

usage() {
  cat >&2 <<USAGE
Usage: $0 --engine {none|suricata|snort3} --test {latency|tcp|udp|http|cps|tls|ttfb}
          [--ifa IF] [--ifb IF] [--threads N] [--rules {full|none}] [--label STR]
          [--out inline.csv] [--logdir DIR] [test args] [--find-ndr --frame SIZE]

Test args (forwarded to bench/client/run-client.sh): --duration S --streams N --conns N --reqs N
  --rate MBPS --frame BYTES --object NAME --count N --port P --proto udp|tcp --client-threads N
  (--client-threads is the load generator's thread count; --threads is the ENGINE's.)
cps, RFC 9411 mode (only with --target-cps N; otherwise the legacy burst): --init-s S (default 5; this IS the
  settle wait) --ramp-s S (30) --sustain-s S (300) --slice-s S (10) --fail-txn-max-pct X (0.001)
  --rst-max-pct X (0.001) --rate-dev-max-pct X (5). Each also has an env var: INIT_S RAMP_S SUSTAIN_S SLICE_S
  FAIL_TXN_MAX_PCT RST_MAX_PCT RATE_DEV_MAX_PCT (flag wins). Emits crit_* and rfc9411_conformant metrics.
--find-ndr (needs --test udp and --frame): binary search of the UDP offered rate for PDR/NDR.

Environment (all optional):
  CLIENT_CMD     shell template run locally to start the test on the client host; \$TEST \$SERVER_IP \$ARGS are
                 substituted. Must print \`metric=value\` lines. Default (if CLIENT_HOST is set):
                   ssh \$CLIENT_HOST bench/client/run-client.sh \$TEST \$SERVER_IP \$ARGS
                 If neither is set the command is printed and metrics are read from stdin until EOF.
  CLIENT_HOST    ssh target for the default CLIENT_CMD
  SERVER_IP      server address as seen by the client (default 10.10.0.3)
  CLIENT_TIMEOUT seconds before a client command is killed (default 900; for cps --target-cps at least
                 ramp+sustain+120)
  SETTLE/DRAIN   seconds after engine ready / after the test (default 5/5; cps --target-cps: INIT_S, else SETTLE)
  READY_TIMEOUT  seconds to wait for engine readiness (default 300)
  BRIDGE         bridge name for --engine none (default br0)
  GOVERNOR       performance (default: set for the run, restored on exit) | keep (do not touch the CPU governor)
  MGMT_NET       in-band management prefix on IF_A (e.g. 192.168.99.0/24). Unset: derived from IF_A's IPv4 address
                 if it has one (management mode), else IF_A stays address-less. See README, "In-band management".
  CLIENT_SSH_OPTS ssh options of the default CLIENT_CMD (default: ControlMaster=auto, ControlPath=/run/bench-ssh/%C,
                 ControlPersist=10m, so consecutive runs reuse one ssh connection)
  HOME_NET, SNORT_CONF, SNORT_RULES, SURICATA_CONF, SURICATA_RULES, KEEP_OUTPUTS=1, KEEP_RUNS
  SURICATA_DEFRAG  af-packet defrag yes|no (default yes)
  PDR_LOSS (0.5) NDR_LOSS (0.01) RATE_MIN (5) RATE_MAX (100) RATE_RES (2)   [--find-ndr; Mbit/s, loss in %]
USAGE
  exit 2
}

ENGINE="" TEST="" IFA="" IFB="" THREADS=1 RULES=full LABEL="" OUT="inline.csv" LOGDIR="/run/bench-logs" FIND_NDR=0
declare -A TA=()          # test args: name (without --) -> value
while [ $# -gt 0 ]; do
  case "$1" in
    --engine)   ENGINE=${2:?}; shift 2 ;;
    --test)     TEST=${2:?}; shift 2 ;;
    --ifa)      IFA=${2:?}; shift 2 ;;
    --ifb)      IFB=${2:?}; shift 2 ;;
    --threads)  THREADS=${2:?}; shift 2 ;;
    --rules)    RULES=${2:?}; shift 2 ;;
    --label)    LABEL=${2:?}; shift 2 ;;
    --out)      OUT=${2:?}; shift 2 ;;
    --logdir)   LOGDIR=${2:?}; shift 2 ;;
    --find-ndr) FIND_NDR=1; shift ;;
    --client-threads) TA[threads]=${2:?}; shift 2 ;;
    --duration|--streams|--conns|--reqs|--rate|--frame|--object|--count|--port|--proto) TA[${1#--}]=${2:?}; shift 2 ;;
    --target-cps|--init-s|--ramp-s|--sustain-s|--slice-s|--fail-txn-max-pct|--rst-max-pct|--rate-dev-max-pct) TA[${1#--}]=${2:?}; shift 2 ;;
    -h|--help)  usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ "$(id -u)" -eq 0 ] || die "must run as root"
case "$ENGINE" in none|suricata|snort3) ;; *) usage ;; esac
case "$TEST" in latency|tcp|udp|http|cps|tls|ttfb) ;; *) usage ;; esac
case "$RULES" in full|none) ;; *) usage ;; esac
[[ "$THREADS" =~ ^[0-9]+$ ]] && [ "$THREADS" -ge 1 ] || die "--threads must be a positive integer"
IFA=${IFA:-${IF_A:-}}; IFB=${IFB:-${IF_B:-}}
[ -n "$IFA" ] && [ -n "$IFB" ] || die "--ifa and --ifb (the two cabled interfaces) are required"
[ "$IFA" != "$IFB" ] || die "--ifa and --ifb must differ"
for i in "$IFA" "$IFB"; do [ -d "/sys/class/net/$i" ] || die "no such interface: $i"; done
if [ "$FIND_NDR" = 1 ]; then
  [ "$TEST" = udp ] || die "--find-ndr requires --test udp"
  [ -n "${TA[frame]:-}" ] || die "--find-ndr requires --frame SIZE"
  [ -n "${CLIENT_CMD:-}${CLIENT_HOST:-}" ] || die "--find-ndr needs CLIENT_CMD or CLIENT_HOST (it cannot be driven by hand)"
fi
if [ "$ENGINE" = none ]; then RULES_COL="n/a"; THREADS_COL="n/a"; else RULES_COL=$RULES; THREADS_COL=$THREADS; fi

SERVER_IP=${SERVER_IP:-10.10.0.3}
SETTLE=${SETTLE:-5}; DRAIN=${DRAIN:-5}; KEEP_RUNS=${KEEP_RUNS:-30}
READY_TIMEOUT=${READY_TIMEOUT:-300}; CT_USER=${CLIENT_TIMEOUT:-}; CLIENT_TIMEOUT=${CLIENT_TIMEOUT:-900}
# cps RFC 9411 mode: every phase/threshold value is flag > env var > RFC default, and is always forwarded to the client
# (ssh does not carry env vars). The Init phase is the settle wait below, so INIT_S replaces SETTLE for this mode.
RFC_CPS=0
if [ "$TEST" = cps ] && [ -n "${TA[target-cps]:-}" ]; then
  RFC_CPS=1
  for kv in init-s:INIT_S:"${SETTLE:-5}" ramp-s:RAMP_S:30 sustain-s:SUSTAIN_S:300 slice-s:SLICE_S:10 \
            fail-txn-max-pct:FAIL_TXN_MAX_PCT:0.001 rst-max-pct:RST_MAX_PCT:0.001 rate-dev-max-pct:RATE_DEV_MAX_PCT:5; do
    IFS=: read -r k e d <<< "$kv"
    [ -n "${TA[$k]:-}" ] || TA[$k]=${!e:-$d}
  done
  SETTLE=${TA[init-s]}
  need_to=$(awk -v i="${TA[init-s]}" -v r="${TA[ramp-s]}" -v s="${TA[sustain-s]}" 'BEGIN{printf "%d", i + r + s + 120}')
  [ -n "$CT_USER" ] || [ "$CLIENT_TIMEOUT" -ge "$need_to" ] || CLIENT_TIMEOUT=$need_to   # default only; an explicit value wins
fi
BRIDGE=${BRIDGE:-br0}
HOME_NET=${HOME_NET:-10.10.0.0/24}
SNORT_CONF=${SNORT_CONF:-/etc/snort/snort.lua}
SNORT_RULES=${SNORT_RULES:-/etc/snort/rules/et-open.rules}
SURICATA_CONF=${SURICATA_CONF:-/etc/suricata/suricata.yaml}
SURICATA_RULES=${SURICATA_RULES:-}
SURICATA_DEFRAG=${SURICATA_DEFRAG:-yes}
PDR_LOSS=${PDR_LOSS:-0.5}; NDR_LOSS=${NDR_LOSS:-0.01}
RATE_MIN=${RATE_MIN:-5}; RATE_MAX=${RATE_MAX:-100}; RATE_RES=${RATE_RES:-2}
if [ -z "${CLIENT_CMD:-}" ] && [ -n "${CLIENT_HOST:-}" ]; then
  CLIENT_SSH_OPTS=${CLIENT_SSH_OPTS:--o ControlMaster=auto -o ControlPath=/run/bench-ssh/%C -o ControlPersist=10m}
  CLIENT_CMD='ssh $CLIENT_SSH_OPTS $CLIENT_HOST bench/client/run-client.sh $TEST $SERVER_IP $ARGS'
  case "$CLIENT_SSH_OPTS" in */run/bench-ssh/*) mkdir -p -m 700 /run/bench-ssh ;; esac
fi
TIME_BIN=/usr/bin/time
[ "$ENGINE" = none ] || [ -x "$TIME_BIN" ] || die "/usr/bin/time not found (apt install time)"
OUT=$(readlink -m "$OUT")

# ---------- in-band management on IF_A (see README, "In-band management") ----------
# IF_A may carry IPv4 address(es) of a management prefix MGMT_NET: the Pi is then reachable from the client over the
# test cable, and the engines/bridge must neither inspect nor forward that traffic. IF_B always stays address-less.
MGMT=0 MGMT_ADDRS=() MGMT_ROUTES=() MGMT_MOVED=0 MGMT_NFT_BR="" MGMT_NFT_CTR=""
mapfile -t MGMT_ADDRS < <(ip -o -4 addr show dev "$IFA" 2>/dev/null | awk '{print $4}')
if [ -n "${MGMT_NET:-}" ]; then
  ip4_valid_cidr "$MGMT_NET" || die "MGMT_NET must look like 192.168.99.0/24 (got '$MGMT_NET')"
  for a in "${MGMT_ADDRS[@]}"; do
    ip4_in_net "$a" "$MGMT_NET" || die "$IFA has address $a outside MGMT_NET=$MGMT_NET"
  done
  MGMT=1; MGMT_NET=$(ip4_net "$MGMT_NET")
  [ "${#MGMT_ADDRS[@]}" -gt 0 ] || warn "MGMT_NET=$MGMT_NET is set but $IFA has no IPv4 address"
elif [ "${#MGMT_ADDRS[@]}" -gt 0 ]; then
  mapfile -t _nets < <(for a in "${MGMT_ADDRS[@]}"; do ip4_net "$a"; done | sort -u)
  [ "${#_nets[@]}" -eq 1 ] || die "$IFA has addresses in several prefixes (${_nets[*]}); set MGMT_NET to the management one"
  MGMT=1; MGMT_NET=${_nets[0]}
  info "management mode: MGMT_NET=$MGMT_NET derived from $IFA address(es) ${MGMT_ADDRS[*]}"
fi
# STUB: Snort 3 + management mode. A later step (once Snort 3 is built and the DAQ afpacket BPF/outgoing-frame
# behaviour is verified) replaces this function with the real BPF/forwarding setup.
mgmt_snort3_stub() { die "in-band management not yet verified for Snort 3 / DAQ afpacket; see README"; }
[ "$MGMT" = 0 ] || [ "$ENGINE" != snort3 ] || mgmt_snort3_stub
[ "$MGMT" = 0 ] || command -v nft >/dev/null 2>&1 || [ "$ENGINE" != none ] || die "management mode with --engine none needs nft (apt install nftables)"

# ---------- engine binary / version ----------
BIN="" VERSION="kernel-bridge"
case "$ENGINE" in
  suricata) BIN=$(command -v suricata || true); [ -n "$BIN" ] || die "suricata not found"
            VERSION=$("$BIN" -V 2>&1 | sed -n 's/.*version \([^ ]*\).*/\1/p' | head -1) ;;
  snort3)   BIN=$(command -v snort || true); [ -n "$BIN" ] || die "snort not found"
            VERSION=$("$BIN" -V 2>&1 | sed -n 's/.*Version \([0-9][0-9.]*\).*/\1/p' | head -1) ;;
  none)     VERSION="kernel-$(uname -r)" ;;
esac

# ---------- environment ----------
TEMP0=$(vc_temp); THR0=$(vc_thr)
case "$THR0" in ""|0x0) ;; *) warn "vcgencmd get_throttled=$THR0 at start (undervoltage/throttling has occurred; results may be unreliable)";; esac
ensure_tmpfs "$LOGDIR"
TS=$(date +%Y%m%d-%H%M%S)
RUN_ID="$TS-inline-$ENGINE-$$"
RUN="$LOGDIR/$RUN_ID"
mkdir -p "$RUN/work"
METRICS="$RUN/metrics.tsv"; : > "$METRICS"
NOTE=""

TPID="" BRIDGE_UP=0 PROMISC_ON=()
# undo everything management mode changed; idempotent, safe to call when nothing (or only part) was done
mgmt_restore() {
  [ -z "$MGMT_NFT_BR" ] || { nft delete table bridge "$MGMT_NFT_BR" 2>/dev/null; MGMT_NFT_BR=""; }
  [ -z "$MGMT_NFT_CTR" ] || { nft delete table netdev "$MGMT_NFT_CTR" 2>/dev/null; MGMT_NFT_CTR=""; }
  if [ "$MGMT_MOVED" = 1 ]; then
    local a r
    for a in "${MGMT_ADDRS[@]}"; do
      ip -4 addr show dev "$IFA" 2>/dev/null | grep -qw "${a%/*}" || ip addr add "$a" brd + dev "$IFA" 2>/dev/null
    done
    for r in "${MGMT_ROUTES[@]}"; do ip route replace $r dev "$IFA" 2>/dev/null; done
    MGMT_MOVED=0; info "management address(es) back on $IFA: ${MGMT_ADDRS[*]}"
  fi
}
cleanup() {
  set +e
  restore_governor
  if [ -n "$TPID" ] && kill -0 "$TPID" 2>/dev/null; then pkill -KILL -P "$TPID" 2>/dev/null; kill -KILL "$TPID" 2>/dev/null; fi
  if [ "$BRIDGE_UP" = 1 ]; then
    ip link set "$IFA" nomaster 2>/dev/null; ip link set "$IFB" nomaster 2>/dev/null
    ip link set "$BRIDGE" down 2>/dev/null; ip link del "$BRIDGE" 2>/dev/null
    info "bridge $BRIDGE deleted"
  fi
  mgmt_restore
  local i; for i in "${PROMISC_ON[@]:-}"; do [ -n "$i" ] && ip link set "$i" promisc off 2>/dev/null; done
}
trap cleanup EXIT
trap 'warn "interrupted"; exit 130' INT TERM
set_governor        # after the traps: every exit path (normal, die, INT, TERM) restores it

# interfaces: transparent L2, no IP, no IPv6 autoconf (RS/MLD chatter would pollute the counters), offloads off
for i in "$IFA" "$IFB"; do
  if [ "$i" = "$IFB" ] && ip -o addr show dev "$i" 2>/dev/null | grep -q 'inet '; then
    die "$i has an IP address; IF_B must be an address-less test interface (IF_A may carry the management address, see MGMT_NET)"
  fi
  sysctl -qw "net.ipv6.conf.$i.disable_ipv6=1" 2>/dev/null || true
  ip link set "$i" up
  chg=$(ethtool -K "$i" gro off lro off gso off tso off 2>&1 | tr '\n' ';' || true)
  info "ethtool -K $i gro/lro/gso/tso off: ${chg:-no output}"
done

# ---------- engine command ----------
CMD=(); READY_RE=""
build_cmd() {
  CMD=()
  case "$ENGINE" in
    none) ;;
    suricata)
      CMD=("$BIN" -c "$SURICATA_CONF" -l "$RUN/work" --set stats.enabled=yes)
      if [ "$RULES" = none ]; then CMD+=(-S /dev/null)
      elif [ -n "$SURICATA_RULES" ]; then CMD+=(-S "$SURICATA_RULES")
      else info "suricata rules=full: using rule-files from $SURICATA_CONF"; fi
      if [ "${KEEP_OUTPUTS:-0}" != 1 ]; then
        while read -r k; do CMD+=(--set "$k=no"); done < <(suricata_outputs_off_keys "$BIN" "$SURICATA_CONF")
      fi
      # IPS copy mode: two af-packet entries, each forwarding to the other. tpacket-v3 MUST be off in copy mode.
      local n=0 a b ids=(98 99) pair=("$IFA:$IFB" "$IFB:$IFA")
      for n in 0 1; do
        a=${pair[$n]%%:*}; b=${pair[$n]##*:}
        CMD+=(--set "af-packet.$n.interface=$a" --set "af-packet.$n.threads=$THREADS"
              --set "af-packet.$n.cluster-id=${ids[$n]}" --set "af-packet.$n.cluster-type=cluster_flow"
              --set "af-packet.$n.copy-mode=ips" --set "af-packet.$n.copy-iface=$b"
              --set "af-packet.$n.tpacket-v3=no" --set "af-packet.$n.use-mmap=yes"
              --set "af-packet.$n.defrag=$SURICATA_DEFRAG")
        # management mode: the engine must not see (so not forward) management frames; `net` also covers their ARP
        [ "$MGMT" = 0 ] || CMD+=(--set "af-packet.$n.bpf-filter=not net $MGMT_NET")
      done
      [ "$MGMT" = 0 ] || info "management mode: suricata bpf-filter 'not net $MGMT_NET' on both af-packet entries" 
      CMD+=(--runmode workers --af-packet)
      READY_RE='Engine started' ;;
    snort3)
      gen_bench_lua "$RUN/bench.lua" "$RULES"
      CMD=("$BIN" -c "$RUN/bench.lua" --daq afpacket -i "$IFA:$IFB" -Q -z "$THREADS" -k none -A none
           --daq-var fanout_type=hash -l "$RUN/work")
      READY_RE='Commencing packet processing' ;;
  esac
}

# ---------- helpers ----------
nic_ctr() { cat "/sys/class/net/$1/statistics/$2" 2>/dev/null || echo 0; }
nic_snap() { echo "$(nic_ctr "$IFA" rx_packets) $(nic_ctr "$IFA" tx_packets) $(nic_ctr "$IFB" rx_packets) $(nic_ctr "$IFB" tx_packets)"; }
nic_delta() { awk -v a="$1" -v b="$2" 'BEGIN{split(a,x," ");split(b,y," ");printf "%d %d %d %d", y[1]-x[1], y[2]-x[2], y[3]-x[3], y[4]-x[4]}'; }
unit_of() {
  case "$1" in
    *_us) echo us ;; *_ms) echo ms ;; *_mbps) echo Mbps ;; *_pct) echo % ;; *_pps) echo pps ;;
    *_per_s|*_per_user_s|*_rps|cps_achieved|tls_cps|cps_target|cps_nominal|cps_sustain_*) echo /s ;; *_bytes*) echo B ;; *_pkts) echo pkts ;;
    init_s|ramp_s|sustain_s|slice_s) echo s ;; *) echo "" ;;
  esac
}
ta_args() { # "--k v ..." (client option names), optionally overriding via associative array name $1
  local k out=""
  for k in $(printf '%s\n' "${!TA[@]}" | sort); do out+=" --$k ${TA[$k]}"; done
  printf '%s' "${out# }"
}
ta_label() { local k out=""; for k in $(printf '%s\n' "${!TA[@]}" | sort); do out+=" $k=${TA[$k]}"; done; printf '%s' "${out# }"; }
subst() {
  local s=$1 v
  for v in SERVER_IP ARGS TEST CLIENT_HOST CLIENT_SSH_OPTS; do
    local val=${!v:-}; s=${s//\$\{$v\}/$val}; s=${s//\$$v/$val}
  done
  printf '%s' "$s"
}

# metrics.tsv rows use the 0x1f separator so that empty fields survive `read`
SEP=$'\x1f'
rowout() { local IFS=$SEP; printf '%s\n' "$*" >> "$METRICS"; }

# measure TEST ARGS LABEL : run the client once; append rows to $METRICS; metric values land in associative array M
declare -A M=()
MEAS=0
measure() {
  local test=$1 args=$2 label=$3 cmd rc=0 n out cpua cpub nic0 nic1 cpu d
  MEAS=$((MEAS + 1)); M=(); out="$RUN/client-$MEAS.out"
  export TEST=$test ARGS=$args SERVER_IP
  nic0=$(nic_snap); cpua=$(cpu_snap)
  if [ -n "${CLIENT_CMD:-}" ]; then
    cmd=$(subst "$CLIENT_CMD"); info "client: $cmd"
    timeout "$CLIENT_TIMEOUT" bash -c "$cmd" > "$out" 2> "$RUN/client-$MEAS.err" || rc=$?
    [ -s "$RUN/client-$MEAS.err" ] && sed "s/^/  client: /" "$RUN/client-$MEAS.err" >&2
  else
    echo "Run on the client host:  bench/client/run-client.sh $test $SERVER_IP $args" >&2
    echo "Paste its stdout (metric=value lines), then Ctrl-D:" >&2
    cat > "$out" || true
  fi
  cpub=$(cpu_snap); nic1=$(nic_snap)
  cpu=$(cpu_pct "$cpua" "$cpub"); d=$(nic_delta "$nic0" "$nic1")
  [ "$rc" = 0 ] || warn "client command exited with $rc (test=$test, see $out)"
  local k v unit
  while IFS='=' read -r k v; do
    [[ "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    M[$k]=$v; unit=$(unit_of "$k")
    rowout "$test" "$(san "$args")" "$label" "$k" "$(san "$v")" "$unit" "$cpu" $d
  done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$out" || true)
  [ "${#M[@]}" -gt 0 ] || warn "no metrics were produced by the client (test=$test)"
  return "$rc"
}

# management mode + kernel bridge: the address(es) must live on the bridge, not on a port; the bridge gets IF_A's MAC and a
# postrouting rule keeps management frames (IPv4 + ARP of MGMT_NET) from being flooded/forwarded out of IF_B.
mgmt_bridge_prepare() {
  ip link set "$BRIDGE" address "$(cat "/sys/class/net/$IFA/address")"
}
mgmt_bridge_finish() {
  local a r
  mapfile -t MGMT_ROUTES < <(ip -4 route show dev "$IFA" | grep -v ' proto kernel' | sed 's/ dev [^ ]*//')
  MGMT_NFT_BR=inline_mgmt_br
  nft delete table bridge "$MGMT_NFT_BR" 2>/dev/null || true
  nft -f - <<NFT || { MGMT_NFT_BR=""; die "could not install the nftables bridge rule (kernel module nf_tables_bridge?)"; }
table bridge $MGMT_NFT_BR {
  chain post {
    type filter hook postrouting priority 100; policy accept;
    oifname "$IFB" ip saddr $MGMT_NET counter drop
    oifname "$IFB" ip daddr $MGMT_NET counter drop
    oifname "$IFB" ether type arp arp saddr ip $MGMT_NET counter drop
    oifname "$IFB" ether type arp arp daddr ip $MGMT_NET counter drop
  }
}
NFT
  MGMT_MOVED=1
  for a in "${MGMT_ADDRS[@]}"; do
    ip addr del "$a" dev "$IFA" 2>/dev/null; ip addr add "$a" brd + dev "$BRIDGE"
  done
  for r in "${MGMT_ROUTES[@]}"; do ip route replace $r dev "$BRIDGE" 2>/dev/null; done
  info "management mode: ${MGMT_ADDRS[*]:-(no address)} moved from $IFA to $BRIDGE (MAC of $IFA); nft bridge table $MGMT_NFT_BR drops $MGMT_NET toward $IFB"
}

# management traffic accounting: a netdev table counting MGMT_NET frames (IPv4 + ARP) at IF_A ingress and egress
mgmt_ctr_start() {
  command -v nft >/dev/null 2>&1 || { warn "nft not found: management counters skipped"; return 0; }
  local T=inline_mgmt_ctr rules="" d dir
  nft delete table netdev "$T" 2>/dev/null || true
  for d in "ingress rx" "egress tx"; do
    set -- $d; dir=$2
    rules+="  chain $1 { type filter hook $1 device \"$IFA\" priority 0; policy accept;
    ip saddr $MGMT_NET counter name $dir accept
    ip daddr $MGMT_NET counter name $dir accept
    ether type arp arp saddr ip $MGMT_NET counter name $dir accept
    ether type arp arp daddr ip $MGMT_NET counter name $dir accept
  }
"
  done
  if nft -f - 2> "$RUN/nft-counters.err" <<NFT
table netdev $T {
  counter rx { }
  counter tx { }
$rules}
NFT
  then MGMT_NFT_CTR=$T; info "management counters: nft netdev table $T on $IFA (ingress+egress)"
  else warn "nft netdev ingress/egress counters unavailable (see $RUN/nft-counters.err): management counters skipped"; fi
}
mgmt_ctr_read() { # -> "rx_pkts rx_bytes tx_pkts tx_bytes" ; empty if unavailable
  [ -n "$MGMT_NFT_CTR" ] || return 0
  local c out=""
  for c in rx tx; do out+="$(nft list counter netdev "$MGMT_NFT_CTR" "$c" 2>/dev/null | awk '/packets/{printf "%d %d", $2, $4}') "; done
  echo "$out"
}

# ---------- start engine / bridge ----------
EXTRA_ENGINE_ARGS=""
start_engine() {
  build_cmd
  info "engine command: ${CMD[*]}"
  local waited=0
  LINEBUF=""; command -v stdbuf >/dev/null 2>&1 && LINEBUF="stdbuf -oL -eL"
  ( cd "$RUN/work" && exec "$TIME_BIN" -f '%e %U %S %M' -o "$RUN/time.txt" $LINEBUF "${CMD[@]}" ) > "$RUN/engine.out" 2>&1 &
  TPID=$!
  until grep -q "$READY_RE" "$RUN/engine.out" 2>/dev/null || ! kill -0 "$TPID" 2>/dev/null; do
    sleep 1; waited=$((waited+1))
    [ "$waited" -ge "$READY_TIMEOUT" ] && { warn "engine not ready after ${READY_TIMEOUT}s, continuing"; break; }
  done
  kill -0 "$TPID" 2>/dev/null || return 1
  info "engine ready after ${waited}s"
  return 0
}

[ "$MGMT" = 0 ] || mgmt_ctr_start
if [ "$ENGINE" = none ]; then
  ip link show "$BRIDGE" >/dev/null 2>&1 && die "bridge $BRIDGE already exists (set BRIDGE=name or remove it)"
  ip link add "$BRIDGE" type bridge
  BRIDGE_UP=1
  sysctl -qw "net.ipv6.conf.$BRIDGE.disable_ipv6=1" 2>/dev/null || true
  [ "$MGMT" = 0 ] || mgmt_bridge_prepare          # br0 takes IF_A's MAC (client ARP cache stays valid)
  ip link set "$IFA" master "$BRIDGE"; ip link set "$IFB" master "$BRIDGE"
  ip link set "$BRIDGE" up
  [ "$MGMT" = 0 ] || mgmt_bridge_finish
  info "baseline: kernel bridge $BRIDGE = {$IFA, $IFB}, no engine (this is the FLOOR; it is not the userspace af_packet path)"
else
  for i in "$IFA" "$IFB"; do ip link set "$i" promisc on && PROMISC_ON+=("$i"); done   # inline capture needs promisc on both
  if ! start_engine; then
    if [ "$ENGINE" = snort3 ] && [ "$THREADS" -gt 1 ]; then
      warn "snort3 inline pair did not start with -z $THREADS (see $RUN/engine.out); falling back to -z 1"
      cp "$RUN/engine.out" "$RUN/engine.failed.out"; NOTE="snort -z $THREADS failed; ran with 1 thread"; THREADS=1; THREADS_COL=1
      start_engine || { cat "$RUN/engine.out" >&2; die "engine exited during start-up (see $RUN/engine.out)"; }
    else cat "$RUN/engine.out" >&2; die "engine exited during start-up (see $RUN/engine.out)"; fi
  fi
fi
info "settling ${SETTLE}s"; sleep "$SETTLE"

# ---------- measurement ----------
CPU_A=$(cpu_snap); T0=$(now); MC0=$(mgmt_ctr_read)
CLIENT_RC=0
if [ "$FIND_NDR" = 0 ]; then
  measure "$TEST" "$(ta_args)" "$LABEL" || CLIENT_RC=$?
else
  declare -A PLOSS=() PSENT=() PPASS=()
  FRAME=${TA[frame]}; DUR=${TA[duration]:-10}
  PAYLOAD_LAST=""
  # probe RATE: sets PLOSS/PSENT; cached
  probe() {
    local r=$1 args rc=0
    [ -n "${PLOSS[$r]:-}" ] && return 0
    TA[rate]=$r; TA[duration]=$DUR; args=$(ta_args)
    wait_temp "${TEMP_MAX:-1000}"
    measure udp "$args" ndr-search || rc=$?
    PLOSS[$r]=${M[udp_loss_pct]:-100}; PSENT[$r]=${M[udp_sent_mbps]:-0}
    [ -n "${M[frame_bytes_actual]:-}" ] && PAYLOAD_LAST=$((M[frame_bytes_actual] - 42))
    [ "$rc" = 0 ] || PLOSS[$r]=100
    sleep "$DRAIN"
  }
  # pass THRESHOLD RATE: 0 if loss <= THRESHOLD and the generator really reached >= 95% of RATE
  pass() {
    local th=$1 r=$2
    probe "$r"
    if ! awk -v s="${PSENT[$r]}" -v r="$r" 'BEGIN{exit !(s >= 0.95*r)}'; then
      warn "probe ${r} Mbps: client only sent ${PSENT[$r]} Mbps (< 95%): generator-limited, counted as fail"; return 1
    fi
    if awk -v l="${PLOSS[$r]}" -v t="$th" 'BEGIN{exit !(l <= t)}'; then info "probe ${r} Mbps: loss=${PLOSS[$r]}% <= $th% PASS"; return 0; fi
    info "probe ${r} Mbps: loss=${PLOSS[$r]}% > $th% FAIL"; return 1
  }
  # search THRESHOLD LO HI -> RESULT (0 = nothing passes at LO)
  search() {
    local th=$1 lo=$2 hi=$3 mid
    RESULT=0
    if pass "$th" "$hi"; then RESULT=$hi; return; fi
    pass "$th" "$lo" || return 0
    while [ $((hi - lo)) -gt "$RATE_RES" ]; do
      mid=$(((lo + hi) / 2))
      if pass "$th" "$mid"; then lo=$mid; else hi=$mid; fi
    done
    RESULT=$lo
  }
  info "NDR/PDR search: frame=$FRAME B, rates [$RATE_MIN, $RATE_MAX] Mbit/s, resolution $RATE_RES, PDR<=$PDR_LOSS% NDR<=$NDR_LOSS%"
  search "$PDR_LOSS" "$RATE_MIN" "$RATE_MAX"; PDR=$RESULT
  if [ "$PDR" -gt 0 ]; then search "$NDR_LOSS" "$RATE_MIN" "$PDR"; NDR=$RESULT; else NDR=0; fi
  PAYLOAD=${PAYLOAD_LAST:-$((FRAME - 42))}; [ "$PAYLOAD" -gt 0 ] || PAYLOAD=1
  pps_of() { awk -v m="$1" -v p="$PAYLOAD" 'BEGIN{printf "%.0f", m*1e6/(8*p)}'; }
  [ "$PDR" -gt 0 ] || warn "no passing rate at RATE_MIN=$RATE_MIN Mbps (result 0)"
  RARGS="frame=$FRAME duration=$DUR pdr_loss=$PDR_LOSS ndr_loss=$NDR_LOSS rate_min=$RATE_MIN rate_max=$RATE_MAX rate_res=$RATE_RES"
  info "RESULT: NDR=$NDR Mbps ($(pps_of "$NDR") pps)  PDR=$PDR Mbps ($(pps_of "$PDR") pps) at $FRAME B frames"
  for kv in "ndr_mbps $NDR Mbps" "pdr_mbps $PDR Mbps" "ndr_pps $(pps_of "$NDR") pps" "pdr_pps $(pps_of "$PDR") pps"; do
    set -- $kv
    rowout udp "$RARGS" ndr-result "$1" "$2" "$3" "" "" "" "" "" 
  done
  [ -n "$LABEL" ] && info "note: --label ignored in --find-ndr mode (rows are labelled ndr-search / ndr-result)"
fi
T1=$(now); CPU_B=$(cpu_snap); MC1=$(mgmt_ctr_read)
if [ -n "$MC0" ] && [ -n "$MC1" ]; then   # management frames seen on IF_A during the measurement phase (delta)
  read -r a1 a2 a3 a4 <<< "$MC0"; read -r b1 b2 b3 b4 <<< "$MC1"
  for kv in "mgmt_ifa_rx_pkts $((b1 - a1))" "mgmt_ifa_rx_bytes $((b2 - a2))" "mgmt_ifa_tx_pkts $((b3 - a3))" "mgmt_ifa_tx_bytes $((b4 - a4))"; do
    set -- $kv; rowout "$TEST" "$(san "$(ta_args)")" "$LABEL" "$1" "$2" "$(unit_of "$1")" "" "" "" "" ""
  done
  info "management frames on $IFA during the measurement: rx $((b1 - a1)) pkts/$((b2 - a2)) B, tx $((b3 - a3)) pkts/$((b4 - a4)) B (nft counts from the IP header)"
fi
CPU_UTIL=$(cpu_pct "$CPU_A" "$CPU_B")
info "test finished after $(calc "$T1 - $T0")s; draining ${DRAIN}s"
sleep "$DRAIN"

# ---------- stop ----------
RC=0
if [ "$ENGINE" != none ]; then
  pkill -TERM -P "$TPID" 2>/dev/null || kill -TERM "$TPID" 2>/dev/null || true
  for _ in $(seq 1 120); do kill -0 "$TPID" 2>/dev/null || break; sleep 1; done
  if kill -0 "$TPID" 2>/dev/null; then warn "engine did not exit, killing"; pkill -KILL -P "$TPID" 2>/dev/null || true; fi
  wait "$TPID" || RC=$?
  [ "$RC" = 143 ] && RC=0
  TPID=""
fi
TEMP1=$(vc_temp); THR1=$(vc_thr)
RSS=""
[ -s "$RUN/time.txt" ] && read -r _ _ _ RSS < <(tail -n 1 "$RUN/time.txt") || true

# ---------- engine counters (same sources as run.sh) ----------
RX="" PROC="" DROP="" FLOWS="" ALERTS=""
case "$ENGINE" in
  suricata)
    SL="$RUN/work/stats.log"
    if [ -s "$SL" ]; then
      sc() { awk -F'|' -v n="$1" '/^Date:/{delete v; next} {k=$1; gsub(/ /,"",k); t=$2; gsub(/ /,"",t); if(k==n && t=="Total"){x=$3; gsub(/ /,"",x); v[0]=x}} END{if(0 in v) print v[0]}' "$SL"; }
      PROC=$(sc decoder.pkts); RX=$(sc capture.kernel_packets); DROP=$(sc capture.kernel_drops)
      [ -n "$RX" ] || RX=$PROC
      DROP=${DROP:-0}
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
esac

# ---------- CSV (long format: one row per metric) ----------
COLS=(run_id timestamp engine engine_version rules threads test test_args label metric value unit
      cpu_util_pct peak_rss_kb eng_rx eng_drop eng_flows eng_alerts ifa_rx ifa_tx ifb_rx ifb_tx
      temp_start temp_end throttled note logdir)
mkdir -p "$(dirname "$OUT")"
[ -s "$OUT" ] || ( IFS=,; echo "${COLS[*]}" ) > "$OUT"
TSTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NROWS=0
while IFS=$SEP read -r test targs label metric value unit cpu a_rx a_tx b_rx b_tx; do
  [ -n "$test" ] || continue
  [ "$FIND_NDR" = 1 ] && [ "$label" = ndr-result ] && cpu="$CPU_UTIL"
  [ -n "$label" ] || label=$LABEL
  fields=("$RUN_ID" "$TSTAMP" "$ENGINE" "$VERSION" "$RULES_COL" "$THREADS_COL" "$test" "$targs" "$label" "$metric" "$value" "$unit"
          "$cpu" "$RSS" "$RX" "$DROP" "$FLOWS" "$ALERTS" "$a_rx" "$a_tx" "$b_rx" "$b_tx"
          "$TEMP0" "$TEMP1" "$THR1" "$NOTE" "$RUN")
  line=""; for f in "${fields[@]}"; do line+="$(san "$f"),"; done
  echo "${line%,}" >> "$OUT"; NROWS=$((NROWS + 1))
done < "$METRICS"
info "$NROWS rows appended to $OUT (run_id $RUN_ID; engine: rx=${RX:-n/a} drop=${DROP:-n/a} flows=${FLOWS:-n/a} alerts=${ALERTS:-n/a} rss_kb=${RSS:-n/a} cpu=${CPU_UTIL}%)"
[ "$NROWS" -gt 0 ] || warn "no rows written: the client produced no metrics"

# ---------- housekeeping ----------
find "$RUN" -type f -size +20M -delete 2>/dev/null || true
ls -1dt "$LOGDIR"/*/ 2>/dev/null | tail -n +$((KEEP_RUNS + 1)) | xargs -r rm -rf
[ "$RC" -eq 0 ] || warn "engine exit code $RC (see $RUN/engine.out)"
[ "$CLIENT_RC" -eq 0 ] && [ "$NROWS" -gt 0 ] || exit 1
exit 0
