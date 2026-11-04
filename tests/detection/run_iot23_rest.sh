#!/bin/bash
# IoT-23 其餘的 scenario（11 個 usable 以外）：12 個有 label 的 + Somfy-02～06（沒有 label，只跑 Suricata、只能數 alert）。
# 1. 從 NAS 的原始壓縮檔一次取出需要的 pcap 與 conn.log.labeled（tar 只讀一遍）
# 2. Suricata 8.0.7（full），設定同 run_iot23.sh
# 3. alert 對 label（match_iot23.py；flow 多或 alert 多的分批）
# 這些 scenario 的對齊有已知問題（../iot23/report.md 第 2 節）：alert 對 flow 只看 5-tuple 與時間、不看 packet 數，
# 所以 34-1、60-1（packet 數對不上）仍對得到；52-1、49-1 的 label 只涵蓋 pcap 前段，之後的 alert 會算成 unmatched。
# 用法: run_iot23_rest.sh [Suricata 平行數，預設 3]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TGZ=/mnt/nas/wnc_data/iot_23_datasets_full.tar.gz
X=/home/sixsquare/datasets/iot23/extracted/run1
BIG=$X/opt/Malware-Project/BigDataset/IoTScenarios
R=/home/sixsquare/datasets/detection
export HERE BIG R
# id | 資料夾（相對 IoTScenarios） | pcap | 有沒有 label
LIST=$(python3 -I - "$HERE/../iot23/results" <<'P'
import glob, json, os, sys
usable = {'1-1', '7-1', '9-1', '17-1', '33-1', '35-1', '36-1', '39-1', '42-1', '43-1', '48-1'}
for f in sorted(glob.glob(os.path.join(sys.argv[1], '*.json'))):
    n = os.path.basename(f)[:-5]; d = json.load(open(f))
    if n.startswith('CTU-IoT-Malware-Capture-'):
        sid = n[len('CTU-IoT-Malware-Capture-'):]; folder = n
    else:
        sid = 'H' + n[len('CTU-Honeypot-Capture-'):].replace('__', '_'); folder = n.replace('__', '/')
    if sid in usable:
        continue
    print('%s|%s|%s|%s' % (sid, folder, d['pcap'], 'yes' if d.get('log') else 'no'))
P
)
echo "$LIST" > "$R/iot23_rest.list"

# 1. 取出（已經取過的跳過）
if [ ! -f "$X/.rest_extracted" ]; then
    mkdir -p "$X"
    pats=()
    while IFS='|' read -r sid folder pcap lab; do
        pats+=("*/IoTScenarios/$folder/$pcap")
        [ "$lab" = yes ] && pats+=("*/IoTScenarios/$folder/bro/conn.log.labeled")
    done <<< "$LIST"
    tar -xzf "$TGZ" -C "$X" --wildcards "${pats[@]}"
    touch "$X/.rest_extracted"
fi
echo "extracted $(date +%T)"

# 2. Suricata
sur() {
    IFS='|' read -r sid folder pcap lab <<< "$1"
    o=$R/iot23/$sid
    [ -f "$o/done.txt" ] && grep -q "rc=0" "$o/done.txt" && return 0
    rm -rf "$o"; mkdir -p "$o"
    t0=$(date +%s)
    set +e
    docker run --rm --memory 4g --user 1000:1000 -v "$BIG/$folder":/pcap:ro -v "$R/rules":/rules:ro -v "$o":/out \
        wnc-suricata8 suricata -v -c /rules/detect.yaml -S /rules/et_all.rules --runmode single \
        --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none \
        -r "/pcap/$pcap" -l /out > "$o/run.log" 2>&1
    echo "$sid rc=$? sec=$(( $(date +%s) - t0 )) pcap=$pcap" | tee "$o/done.txt"
}
export -f sur
echo "$LIST" | xargs -d '\n' -P "${1:-3}" -I{} bash -c 'sur "{}"'
echo "suricata done $(date +%T)"

# 3. alert 對 label（一次一個，避免記憶體疊加）
mkdir -p "$R/match"
while IFS='|' read -r sid folder pcap lab; do
    [ "$lab" = yes ] || continue
    [ -f "$R/match/$sid.json" ] && continue
    n=$(grep -c '"event_type":"alert"' "$R/iot23/$sid/eve.json" || true)
    sh=1; [ "$n" -gt 3000000 ] && sh=$(( n / 3000000 + 1 ))
    t0=$(date +%s)
    python3 -I "$HERE/match_iot23.py" "$BIG/$folder/bro/conn.log.labeled" "$R/iot23/$sid/eve.json" \
        "$R/rules/gw_corp_sids.txt" "$R/rules/iplist_sids.txt" "$R/match/$sid.json" "$sh"
    echo "match $sid alerts=$n shards=$sh sec=$(( $(date +%s) - t0 ))"
done <<< "$LIST"
echo "ALL DONE $(date +%T)"
