#!/bin/bash
# pack.sh -- pack what the Pi needs into one tar.gz + sha256 for you to scp over (this script does not connect or transfer).
# Contents: scripts (measurement: measure.sh run_matrix.py summarize.py pcap_stats.py lib.sh; batches: run_pi_main.sh run_pi_scen2.sh
#       run_pi_mem_scen.sh pi_set_total_mem.sh; 04_make_sel_rules.py; README.md manifest.json)
#       + data/pcaps (the 4 slices and 14 scenario slices in the manifest, plus their .small)
#       + data/rules (common/full/sel/gw_corp rule files for both engines + sel_removed_sids.txt + SHA256SUMS)
#       common is used only by run_pi_main.sh.
# Usage: ./pack.sh            # about 1.3 GB before compression
# Output: $BIG/ids_throughput_pi.tar.gz  and  $BIG/ids_throughput_pi.tar.gz.sha256
source "$(dirname "$0")/lib.sh"
stage=$(mktemp -d "$BIG/pack_stage.XXXXXX"); trap 'rm -rf "$stage"' EXIT
d=$stage/ids_throughput; mkdir -p "$d/data/pcaps" "$d/data/rules" "$d/results"
for f in measure.sh run_matrix.py summarize.py pcap_stats.py README.md manifest.json lib.sh run_pi_main.sh run_pi_scen2.sh run_pi_mem_scen.sh pi_set_total_mem.sh 04_make_sel_rules.py; do cp "$HERE/$f" "$d/"; done
# Slices, scenario slices and small (by manifest kind, synth_* excluded; symlinks plus tar -h to dereference, avoiding another copy of the large files)
python3 -I - "$HERE/manifest.json" > "$stage/files.txt" <<'P'
import json, sys
for m in json.load(open(sys.argv[1])):
    if m["kind"] in ("slice", "scen", "small") and not m["name"].startswith("synth_"):
        print(m["name"])
P
while read -r n; do ln -s "$PCAPS/$n" "$d/data/pcaps/$n"; done < "$stage/files.txt"
for r in suricata_common suricata_full suricata_sel suricata_gw_corp snort_common snort_full snort_sel snort_gw_corp; do ln -s "$RULES/$r.rules" "$d/data/rules/$r.rules"; done
ln -s "$RULES/sel_removed_sids.txt" "$d/data/rules/sel_removed_sids.txt"   # sids removed for the sel rule set (for reproduction)
cp "$RULES/SHA256SUMS" "$d/data/rules/SHA256SUMS"
(cd "$d/data/pcaps" && sha256sum * > ../pcaps.SHA256SUMS)
chmod +x "$d"/*.sh "$d"/*.py
tar -C "$stage" -h -czf "$BIG/ids_throughput_pi.tar.gz" ids_throughput
(cd "$BIG" && sha256sum ids_throughput_pi.tar.gz | tee ids_throughput_pi.tar.gz.sha256)
ls -la "$BIG/ids_throughput_pi.tar.gz"; tar -tzf "$BIG/ids_throughput_pi.tar.gz" | head -40
