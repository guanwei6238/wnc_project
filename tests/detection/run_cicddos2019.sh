#!/bin/bash
# Pipeline for one CIC-DDoS2019 day: Suricata 8.0.7 (full) -> match alerts to labels -> sampled alignment.
# Usage: run_cicddos2019.sh <day, e.g. 0311> [sampling interval, default 20]
# Requires: ~/datasets/cicddos2019/pcap/<day>.pcap (joined by zip_pcap_concat.py), conn/<day>.conn.log.labeled (cic_to_conn.py --tz 3).
# Alignment samples 1 of every N flows: this day has tens of millions of flows, and aligning all of them takes many shards, each rereading the 29 GB pcap.
# Sampling only estimates flow alignment; packet coverage needs all flows, so it isn't computed here.
# HOME_NET is the victim subnet 192.168.50.0/24 (the attacker is 172.16.0.5, which the default HOME_NET treats as an internal host).
set -euo pipefail
day=$1; every=${2:-20}
HERE=$(cd "$(dirname "$0")" && pwd)
D=/home/sixsquare/datasets/cicddos2019
R=/home/sixsquare/datasets/detection
conn=$D/conn/$day.conn.log.labeled
# The official CSV has duplicate rows (03-11 has 482,799 groups of identical rows); dedup before use
[ -f "$D/conn/$day.dedup.conn.log.labeled" ] || "$HERE/dedup_conn.sh" "$conn" "$D/conn/$day.dedup.conn.log.labeled"
conn=$D/conn/$day.dedup.conn.log.labeled

o=$R/cicddos2019/$day
if [ ! -f "$o/done.txt" ]; then
    rm -rf "$o"; mkdir -p "$o"
    docker run --rm --user 1000:1000 -v "$D/pcap":/pcap:ro -v "$R/rules":/rules:ro -v "$o":/out \
        wnc-suricata8 suricata -v -c /rules/detect.yaml -S /rules/et_all.rules --runmode single \
        --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none \
        --set 'vars.address-groups.HOME_NET=[192.168.50.0/24]' \
        -r "/pcap/$day.pcap" -l /out > "$o/run.log" 2>&1
    echo "rc=$?" > "$o/done.txt"
fi

mkdir -p "$R/match_cicddos2019"
python3 -I "$HERE/match_iot23.py" "$conn" "$o/eve.json" "$R/rules/gw_corp_sids.txt" "$R/rules/iplist_sids.txt" \
    "$R/match_cicddos2019/$day.json" 4 --cic

mkdir -p "$D/align"
awk -v n="$every" '/^#/ || (++i % n == 0)' "$conn" > "$D/conn/$day.sample$every.conn.log.labeled"
python3 -I "$HERE/../iot23/align_stream.py" "$D/conn/$day.sample$every.conn.log.labeled" "$D/pcap/$day.pcap" \
    --json "$D/align/$day.sample$every.json"
echo "$day done"
