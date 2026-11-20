#!/bin/bash
# Run Suricata 8.0.7 (full) on the 36 sampled CICIoT2023 pcaps (1-2 files per attack, 1 Benign).
# Labels are per file only, so also write stats.log (total flows) to compute the share of flows with alerts later.
# The attacker (a Raspberry Pi in the lab network) and the victim devices share one LAN, and the official list has device names but no IPs,
# so HOME_NET and EXTERNAL_NET are both any: no inside/outside, rules in every direction apply (the upper bound of what the rules can detect).
# Usage: run_ciciot2023.sh [parallelism, default 3]; only processes files that are downloaded and sha256-checked (have .ok).
set -euo pipefail
SRC=/mnt/nas/dataset/ciciot2023/pcap_sample
R=/home/sixsquare/datasets/detection
one() {
    f=$1; n=$(basename "$f" .pcap); o=$R/ciciot2023/$n
    [ -f "$o/done.txt" ] && return 0
    mkdir -p "$R/ciciot2023"; exec 9>"$R/ciciot2023/.$n.lock"; flock -n 9 || return 0   # only one process per file
    rm -rf "$o"; mkdir -p "$o"
    docker run --rm --user 1000:1000 -v "$SRC":/pcap:ro -v "$R/rules":/rules:ro -v "$o":/out \
        wnc-suricata8 suricata -v -c /rules/detect_stats.yaml -S /rules/et_all.rules --runmode single \
        --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none \
        --set 'vars.address-groups.HOME_NET=any' --set 'vars.address-groups.EXTERNAL_NET=any' \
        -r "/pcap/$n.pcap" -l /out > "$o/run.log" 2>&1
    echo "rc=$?" > "$o/done.txt"; echo "$n done"
}
export -f one; export SRC R
for ok in "$SRC"/*.pcap.ok; do echo "${ok%.ok}"; done | xargs -P "${1:-3}" -I{} bash -c 'one {}'
