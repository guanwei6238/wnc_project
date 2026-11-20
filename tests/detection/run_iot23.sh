#!/bin/bash
# Run Suricata 8.0.7 (full rules) on the full pcaps of the 11 usable IoT-23 scenarios, keeping eve.json (alerts only).
# Usage: run_iot23.sh [parallelism, default 4]
# The pcap for each scenario follows "pcap" in tests/iot23/results/*.json (the same file used for alignment).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIG=/home/sixsquare/datasets/iot23/extracted/run1/opt/Malware-Project/BigDataset/IoTScenarios
RULES=/home/sixsquare/datasets/detection/rules
OUT=/home/sixsquare/datasets/detection/iot23
SCEN="17-1 43-1 39-1 33-1 35-1 48-1 36-1 7-1 9-1 1-1 42-1"   # large files first
mkdir -p "$OUT"

one() {
    s=$1
    name=CTU-IoT-Malware-Capture-$s
    pcap=$(python3 -c "import json;print(json.load(open('$HERE/../iot23/results/$name.json'))['pcap'])")
    o=$OUT/$s; rm -rf "$o"; mkdir -p "$o"
    t0=$(date +%s.%N)
    docker run --rm --user 1000:1000 -v "$BIG/$name":/pcap:ro -v "$RULES":/rules:ro -v "$o":/out \
        wnc-suricata8 suricata -v -c /rules/detect.yaml -S /rules/et_all.rules --runmode single \
        --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none \
        -r "/pcap/$pcap" -l /out > "$o/run.log" 2>&1
    echo "$s rc=$? sec=$(echo "$(date +%s.%N) - $t0" | bc) pcap=$pcap" | tee "$o/done.txt"
}
export -f one; export HERE BIG RULES OUT
echo $SCEN | tr ' ' '\n' | xargs -P "${1:-4}" -I{} bash -c 'one {}'
