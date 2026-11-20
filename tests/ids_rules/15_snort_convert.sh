#!/bin/bash
# Convert the "Snort" ET rules (work/snort_pack/et_all.rules) to Snort 3 syntax with snort2lua -> work/snort_pack/snort3_converted.rules (loaded by 16).
# snort2lua writes its output files (e.g. et_all.rules.lua) next to the source rules file, and $WORK is read-only (/rules) in the container,
#   so copy the rules to the writable $RUNS/snort_s2l/ first, then convert.
# Unconvertible rules: the whole rule is commented out with '#' and written to snort2lua_err.txt (reason on the '^^^^' line; 18 uses it for attribution);
# note that snort2lua also rewrites some options (e.g. threshold) into the .lua config (snort3_conv.lua) instead of keeping them in the rule.
# Prerequisite: 02_prep_rules.py has produced $WORK/snort_pack/et_all.rules for the Snort package.
source "$(dirname "$0")/lib.sh"
D=$RUNS/snort_s2l
rm -rf "$D"; mkdir -p "$D"
cp "$WORK/snort_pack/et_all.rules" "$D/et_all.rules"
printf 'include /out/snort_s2l/et_all.rules\n' > "$D/snort.conf"
dk -w /out/snort_s2l -- snort2lua -c snort.conf -s -r snort3_converted.rules -o snort3_conv.lua -e snort2lua_err.txt > "$D/stdout.txt" 2>&1
tail -12 "$D/stdout.txt"
cp "$D/snort3_converted.rules" "$WORK/snort_pack/snort3_converted.rules"
ls -la "$D"; wc -l "$WORK/snort_pack/snort3_converted.rules"
