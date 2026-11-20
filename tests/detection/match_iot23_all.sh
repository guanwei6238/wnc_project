#!/bin/bash
# Run match_iot23.py on all 11 usable scenarios; 39-1 has the most alerts (about 14.7 million), so it starts first and is split into 4 shards (not enough memory to load it all at once).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIG=/home/sixsquare/datasets/iot23/extracted/run1/opt/Malware-Project/BigDataset/IoTScenarios
R=/home/sixsquare/datasets/detection
mkdir -p "$R/match"
one() {
    s=$1; t0=$(date +%s)
    python3 -I "$HERE/match_iot23.py" "$BIG/CTU-IoT-Malware-Capture-$s/bro/conn.log.labeled" \
        "$R/iot23/$s/eve.json" "$R/rules/gw_corp_sids.txt" "$R/rules/iplist_sids.txt" "$R/match/$s.json" \
        "$( [ "$s" = 39-1 ] && echo 4 || echo 1 )"
    echo "$s rc=$? sec=$(( $(date +%s) - t0 ))"
}
export -f one; export HERE BIG R
echo 39-1 17-1 43-1 33-1 35-1 7-1 9-1 36-1 48-1 1-1 42-1 | tr ' ' '\n' | xargs -P 4 -I{} bash -c 'one {}'
