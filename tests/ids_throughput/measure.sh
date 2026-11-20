#!/bin/bash
# measure.sh -- one measurement: have one engine read one pcap and keep the raw logs. Both MODE=docker and native run this script (same logic).
#   docker mode: called by run_matrix.py via `docker run ... /scripts/measure.sh` (inside the container it is a native environment)
#   native mode: called directly by run_matrix.py (on the Pi)
#
# Usage: measure.sh <suricata|snort> <empty|rule set name> <pcap path> <output dir>      rule set names e.g. full, sel, gw_corp, common
# Environment variables (all have defaults):
#   WORK          scratch dir for the pcap copy and engine output; must be tmpfs/in-memory (keeps disk I/O out). docker: /work; Pi: /dev/shm/ids_tp
#   RULES_DIR     rules dir (contains <engine>_<rule set>.rules, e.g. suricata_full.rules, snort_gw_corp.rules)
#   THREADS       packet processing threads. Only 1 is supported here (still recorded so the interface need not change later)
#   CPUSET        native mode only: e.g. "2,3" -> taskset -c 2,3. In docker mode --cpuset-cpus does this
#   SNORT_ETC     dir with the official Snort 3 snort.lua; SURICATA_YAML  Suricata config file
# Output (<output dir>): engine.log  time.txt(/usr/bin/time -v)  timing.kv(externally measured wall clock µs, exit code)  stats.log(Suricata)  sids.txt(alert sid counts)

set -u
engine=$1; rset=$2; pcap=$3; out=$4
WORK=${WORK:-/work}
RULES_DIR=${RULES_DIR:-/rules}
THREADS=${THREADS:-1}
SNORT_ETC=${SNORT_ETC:-/opt/snort/etc/snort}
SURICATA_YAML=${SURICATA_YAML:-/etc/suricata/suricata.yaml}

[ "$THREADS" = "1" ] || { echo "THREADS=$THREADS 尚未支援（本步驟固定單一封包處理執行緒）"; exit 97; }
mkdir -p "$out" || exit 99
run=$(mktemp -d "$WORK/run.XXXXXX") || exit 99
trap 'rm -rf "$run"' EXIT

# 1. Rule file. empty = empty-rule baseline (Suricata uses /dev/null per spec; /dev/null also works for Snort, tested)
if [ "$rset" = empty ]; then rf=/dev/null; else rf="$RULES_DIR/${engine}_${rset}.rules"; fi
[ -r "$rf" ] || { echo "找不到規則檔 $rf"; exit 98; }

# 2. Copy the pcap into tmpfs first. Not counted in engine time. (The engine then reads from an in-memory filesystem, not disk)
cp "$pcap" "$run/in.pcap" || exit 99

# 3. Build the command. Common rule: change only the *required* settings, keep each engine's defaults/official config otherwise.
pin=(); [ -n "${CPUSET:-}" ] && pin=(taskset -c "$CPUSET")
case $engine in
  suricata)
    # --runmode single  : one worker thread (capture + decode + detect on the same thread). log prints "Threads created -> W: 1"
    # -k none           : ignore checksums (some IoT-23 packets have bad checksums and would be dropped otherwise)
    # mpm ac-ks / spm bm: the Pi's Debian package has no Hyperscan, so x86 uses the same matchers the Pi can
    # unix-command=no   : disable the unix socket management thread (it fails as non-root anyway; keeps environments consistent)
    # -v                : needed to print "time elapsed" (the engine's own processing time)
    cmd=("${pin[@]}" suricata -v -c "$SURICATA_YAML" -S "$rf" -l "$run" --runmode single
         --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none -r "$run/in.pcap")
    ;;
  snort)
    # Snort 3's default HOME_NET=any makes ET's !$HOME_NET rejected; set it to match Suricata's default (same as tests/ids_rules/ids.sh)
    sed -e "s|^HOME_NET = 'any'|HOME_NET = '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]'|" \
        -e "s|^EXTERNAL_NET = 'any'|EXTERNAL_NET = '!\$HOME_NET'|" "$SNORT_ETC/snort.lua" > "$run/snort.lua"
    # alert_fast.file=true: alerts go to $run/alert_fast.txt (otherwise they flood stdout and the I/O differs from Suricata)
    # -k none: ignore checksums; --max-packet-threads: packet processing threads
    # -s 65535: snaplen. Snort 3 by default only looks at the first 1518 bytes of each packet; larger packets in the pcap would be truncated and not the same data
    cmd=("${pin[@]}" snort -c "$run/snort.lua" --include-path "$SNORT_ETC" -R "$rf"
         --lua "search_engine = { search_method = 'ac_bnfa' } alert_fast = { file = true }"
         -r "$run/in.pcap" -A alert_fast -l "$run" -k none -s 65535 --max-packet-threads "$THREADS")
    ;;
  *) echo "unknown engine $engine"; exit 98 ;;
esac

# 4. Run. External wall clock uses bash's built-in $EPOCHREALTIME (µs), finer than time -v's 10 ms resolution.
#    /usr/bin/time -v gives user/sys CPU and peak RSS (including children).
t0=${EPOCHREALTIME/./}
/usr/bin/time -v -o "$out/time.txt" "${cmd[@]}" > "$out/engine.log" 2>&1
rc=$?
t1=${EPOCHREALTIME/./}
{ echo "wall_us=$((t1 - t0))"; echo "exit_code=$rc"; echo "threads=$THREADS"; echo "cmd=${cmd[*]}"; } > "$out/timing.kv"

# 5. Post-processing (not timed): Suricata's stats.log, alert sid counts
[ -f "$run/stats.log" ] && cp "$run/stats.log" "$out/stats.log"
alertfile="$run/fast.log"; [ "$engine" = snort ] && alertfile="$run/alert_fast.txt"
if [ -f "$alertfile" ]; then
  # both engines' fast format has "[**] [gid:sid:rev]", so one grep extracts the sid
  grep -o '\[\*\*\] \[[0-9]*:[0-9]*:[0-9]*\]' "$alertfile" | cut -d: -f2 | sort | uniq -c | sort -rn > "$out/sids.txt"
else
  : > "$out/sids.txt"
fi
exit $rc
