#!/bin/bash
# CIC-DDoS2019 一天的流程：Suricata 8.0.7（full）→ alert 對 label → 抽樣對齊。
# 用法: run_cicddos2019.sh <day，例如 0311> [抽樣間隔，預設 20]
# 前提：~/datasets/cicddos2019/pcap/<day>.pcap（zip_pcap_concat.py 串好）、conn/<day>.conn.log.labeled（cic_to_conn.py --tz 3）。
# 對齊只抽每 N 條 flow 取 1 條：這天的 flow 有上千萬條，全部對齊要分很多批、每批重讀一次 29 GB 的 pcap。
# 抽樣只估得出 flow alignment；packet coverage 要全部 flow 才算得出來，這裡不算。
# HOME_NET 設成受害端網段 192.168.50.0/24（攻擊者是 172.16.0.5，預設的 HOME_NET 會把它當成內部主機）。
set -euo pipefail
day=$1; every=${2:-20}
HERE=$(cd "$(dirname "$0")" && pwd)
D=/home/sixsquare/datasets/cicddos2019
R=/home/sixsquare/datasets/detection
conn=$D/conn/$day.conn.log.labeled
# 官方 CSV 有重複列（03-11 有 482,799 組完全相同的列），先去重再用
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
