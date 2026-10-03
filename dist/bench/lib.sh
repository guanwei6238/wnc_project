# bench/lib.sh -- helpers shared by inline.sh and sweep-inline.sh (sourced, not executed).
# Same conventions as run.sh (which keeps its own copies): set PROG before sourcing for message prefixes.
PROG=${PROG:-bench}
die()  { echo "$PROG: ERROR: $*" >&2; exit 1; }
warn() { echo "$PROG: WARNING: $*" >&2; }
info() { echo "$PROG: $*" >&2; }

san()  { printf '%s' "$1" | tr ',\n\r"' '    ' | sed 's/^ *//;s/ *$//'; }
calc() { awk "BEGIN{printf \"%.4f\", $1}"; }
now()  { date +%s.%N; }
ro()   { local f=$1; [ -r "$f" ] && cat "$f" 2>/dev/null || true; }

HAVE_VC=0; command -v vcgencmd >/dev/null 2>&1 && HAVE_VC=1
vc_temp() { [ $HAVE_VC = 1 ] && vcgencmd measure_temp 2>/dev/null | sed -n "s/temp=\([0-9.]*\).*/\1/p" || true; }
vc_thr()  { [ $HAVE_VC = 1 ] && vcgencmd get_throttled 2>/dev/null | sed -n 's/throttled=//p' || true; }

cpu_snap() { awk '/^cpu /{idle=$5+$6; t=0; for(i=2;i<=9;i++) t+=$i; print t, idle}' /proc/stat; }
cpu_pct()  { # $1 "t i" start, $2 "t i" end
  awk -v a="$1" -v b="$2" 'BEGIN{split(a,x," ");split(b,y," ");dt=y[1]-x[1];di=y[2]-x[2]; if(dt>0) printf "%.2f",(dt-di)*100/dt}'; }

# wait until the SoC is below $1 degC (no-op without vcgencmd)
wait_temp() {
  local max=$1 t
  [ $HAVE_VC = 1 ] || return 0
  while :; do
    t=$(vc_temp); [ -z "$t" ] && return 0
    awk -v t="$t" -v m="$max" 'BEGIN{exit !(t<m)}' && return 0
    info "SoC at ${t}C, waiting for < ${max}C"; sleep 5
  done
}

# CPU governor: GOVERNOR=performance (default) | keep. set_governor saves each core's current governor before
# switching it; restore_governor (call it from the EXIT trap) puts them back. CPUFREQ_ROOT is overridable for tests.
CPUFREQ_ROOT=${CPUFREQ_ROOT:-/sys/devices/system/cpu}
GOV_FILES=() GOV_OLD=()
set_governor() {
  local g cur gov_changed="" gov="${GOVERNOR:-performance}"
  case "$gov" in
    performance) ;;
    keep) info "GOVERNOR=keep: CPU governor left untouched"; return 0 ;;
    *) die "GOVERNOR must be performance or keep (got '$gov')" ;;
  esac
  for g in "$CPUFREQ_ROOT"/cpu[0-9]*/cpufreq/scaling_governor; do
    [ -w "$g" ] || continue
    cur=$(cat "$g")
    [ "$cur" = performance ] || { echo performance > "$g" 2>/dev/null && {
      GOV_FILES+=("$g"); GOV_OLD+=("$cur"); gov_changed="$gov_changed $(basename "$(dirname "$(dirname "$g")")"):$cur"; }; }
  done
  [ -n "$gov_changed" ] && info "CPU governor set to performance (was:$gov_changed; restored on exit)"
  [ "$(ro "$CPUFREQ_ROOT/cpu0/cpufreq/scaling_governor")" = performance ] || \
    [ ! -e "$CPUFREQ_ROOT/cpu0/cpufreq/scaling_governor" ] || warn "CPU governor is not performance"
  return 0
}
restore_governor() {
  local i done_="" n=${#GOV_FILES[@]}
  for ((i = 0; i < n; i++)); do
    echo "${GOV_OLD[$i]}" > "${GOV_FILES[$i]}" 2>/dev/null \
      && done_="$done_ $(basename "$(dirname "$(dirname "${GOV_FILES[$i]}")")"):${GOV_OLD[$i]}" \
      || echo "$PROG: WARNING: could not restore governor in ${GOV_FILES[$i]}" >&2
  done
  GOV_FILES=() GOV_OLD=()
  [ -z "$done_" ] || info "CPU governor restored:$done_"
  return 0
}

# mount tmpfs on $1 unless it already is one
ensure_tmpfs() {
  local d=$1
  if ! grep -q " $d tmpfs " /proc/mounts 2>/dev/null; then
    mkdir -p "$d"
    mount -t tmpfs -o size=256M tmpfs "$d" 2>/dev/null && info "mounted tmpfs on $d" \
      || warn "could not mount tmpfs on $d; logs go to the regular filesystem (I/O may skew results)"
  fi
}

# write a snort3 bench.lua: gen_bench_lua FILE RULES(full|none)  (env HOME_NET SNORT_CONF SNORT_RULES)
gen_bench_lua() {
  local f=$1 rules=$2
  {
    echo "include '$SNORT_CONF'"
    echo "HOME_NET = '$HOME_NET'"
    echo "EXTERNAL_NET = '!\$HOME_NET'"
    echo "for k, v in pairs(ips.variables.nets) do if v == 'any' then ips.variables.nets[k] = HOME_NET end end"
    echo "ips.variables.nets.HOME_NET = HOME_NET"
    echo "ips.variables.nets.EXTERNAL_NET = EXTERNAL_NET"
    if [ "$rules" = full ]; then
      [ -r "$SNORT_RULES" ] || die "snort rules file not found: $SNORT_RULES"
      echo "ips.rules = [[ include $SNORT_RULES ]]"
    else
      echo "ips.rules = nil"
    fi
  } > "$f"
}

# suricata: print the "outputs.N.xxx.enabled" keys that are on in the config, one per line
suricata_outputs_off_keys() { # $1 binary $2 conf
  "$1" -c "$2" --dump-config 2>/dev/null \
    | sed -n 's/^\(outputs\.[0-9]*\.\(fast\|eve-log\|syslog\|http-log\|tls-log\|lua\|file-store\|tcp-data\|http-body-data\|pcap-log\|alert-debug\|tls-store\)\.enabled\) = yes$/\1/p'
}

# ---- IPv4 prefix helpers (pure bash) ----
ip4_to_int() { local IFS=.; set -- $1; echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 )); }
ip4_net() { # a.b.c.d/len -> network/len (host bits cleared)
  local a=${1%/*} l=${1#*/} n m
  n=$(ip4_to_int "$a"); m=$(( l == 0 ? 0 : (0xFFFFFFFF << (32 - l)) & 0xFFFFFFFF )); n=$(( n & m ))
  printf '%d.%d.%d.%d/%d\n' $((n >> 24 & 255)) $((n >> 16 & 255)) $((n >> 8 & 255)) $((n & 255)) "$l"
}
ip4_valid_cidr() { # a.b.c.d/len
  local o IFS=.; [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || return 1
  [ "${1#*/}" -le 32 ] || return 1
  for o in ${1%/*}; do [ "$o" -le 255 ] || return 1; done
}
ip4_in_net() { # ADDR/len NET/len : is ADDR inside NET?
  [ "$(ip4_net "${1%/*}/${2#*/}")" = "$(ip4_net "$2")" ]
}
