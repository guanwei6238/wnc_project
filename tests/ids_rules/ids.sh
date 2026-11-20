#!/bin/bash
# Single entry point run inside the container; wraps /usr/bin/time -v so every measurement has the same format.
# Usage: ids.sh <mode> <outdir> <rules> [pcap]
#   mode = suri-T | suri-r | snort-T | snort-r
#     -T : test config only (exit after loading rules and building the detection engine)   -r : actually read the pcap once (full init)
#   env  MPM=ac-ks|hs|ac  SPM=bm|hs (Suricata; SPM is single-pattern matching, default bm to match the Pi; the hs group must set SPM=hs)   SEARCH=ac_bnfa|hyperscan|ac_full (Snort 3)  EVENT_FILTER_LUA=<.lua path> (Snort 3, optional)
# Output: <outdir>/out.log (engine stdout+stderr)  <outdir>/time.txt (/usr/bin/time -v)
mode=$1; outdir=$2; rules=$3; pcap=${4:-}
mkdir -p "$outdir"
cd "$outdir" || exit 99      # files the engine writes (fast.log, eve.json…) all land here

# Snort 3 defaults to HOME_NET='any', so !$HOME_NET in ET rules becomes "!any is not allowed" and gets rejected;
# that is a config issue, not a rule issue. Here HOME_NET/EXTERNAL_NET are set to Suricata's defaults (the three RFC1918 ranges)
# so both engines are compared on the same premise. How: copy the official snort.lua and change only these two lines.
SNORT_ETC=/opt/snort/etc/snort
sed -e "s|^HOME_NET = 'any'|HOME_NET = '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]'|" \
    -e "s|^EXTERNAL_NET = 'any'|EXTERNAL_NET = '!\$HOME_NET'|" $SNORT_ETC/snort.lua > "$outdir/snort.lua"
SNORT_CONF=(-c "$outdir/snort.lua" --include-path $SNORT_ETC)

# EVENT_FILTER_LUA (optional): the .lua from snort2lua, holding the event_filter settings that in-rule thresholds were rewritten into.
# With only -R loading rules these thresholds do not take effect; set this env var (path inside the container) to load it. Not loaded by default.
EVF=""; [ -n "$EVENT_FILTER_LUA" ] && EVF="; include '$EVENT_FILTER_LUA'"

case $mode in
  suri-T)  cmd=(suricata -T -v -c /etc/suricata/suricata.yaml -S "$rules" -l "$outdir" --set mpm-algo=${MPM:-ac-ks} --set spm-algo=${SPM:-bm}) ;;
  suri-r)  cmd=(suricata -v -c /etc/suricata/suricata.yaml -S "$rules" -l "$outdir" --set mpm-algo=${MPM:-ac-ks} --set spm-algo=${SPM:-bm} -k none -r "$pcap") ;;
  snort-T) cmd=(snort -T "${SNORT_CONF[@]}" -R "$rules" --lua "search_engine = { search_method = '${SEARCH:-ac_bnfa}' } $EVF") ;;
  snort-r) cmd=(snort "${SNORT_CONF[@]}" -R "$rules" --lua "search_engine = { search_method = '${SEARCH:-ac_bnfa}' } $EVF" -r "$pcap" -A alert_fast -l "$outdir" -k none) ;;
  *) echo "unknown mode $mode"; exit 98 ;;
esac

# -v: prints Maximum resident set size (peak RSS) and Elapsed (wall clock)
/usr/bin/time -v -o "$outdir/time.txt" "${cmd[@]}" > "$outdir/out.log" 2>&1
rc=$?
echo "exit_code=$rc" >> "$outdir/time.txt"
exit $rc
