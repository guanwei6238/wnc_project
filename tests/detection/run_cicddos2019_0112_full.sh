#!/bin/bash
# CIC-DDoS2019 01-12 full day (no sampling): extract the zips on the NAS on the fly and pipe them into Suricata, one continuous run, no pcap on disk
# (verified on 03-11: pipe and file input give identical alerts); also record each piece's time range, for aligning by attack window later.
# Each attack's CSV becomes one conn file (local time UTC-4); alerts are matched against all flows.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
D=/home/sixsquare/datasets/cicddos2019
R=/home/sixsquare/datasets/detection
N=/mnt/nas/dataset/cicddos2019
o=$R/cicddos2019/0112
C=$D/conn/0112
mkdir -p "$C" "$R/match_cicddos2019"

# 1. CSV -> conn, running alongside Suricata (WebDDoS is in UDPLag.csv)
(
    for c in DrDoS_NTP DrDoS_DNS DrDoS_LDAP DrDoS_MSSQL DrDoS_NetBIOS DrDoS_SNMP DrDoS_SSDP DrDoS_UDP UDPLag Syn TFTP; do
        [ -f "$C/$c.conn.log.labeled.ok" ] && continue
        unzip -p "$D/dl/CSV-01-12.zip" "01-12/$c.csv" | python3 -I "$HERE/cic_to_conn.py" --tz 4 "$C/$c.conn.log.labeled" /dev/stdin
        touch "$C/$c.conn.log.labeled.ok"
    done
) > "$C/convert.log" 2>&1 &
conv=$!

# 2. Suricata 8.0.7 (full), HOME_NET as in run_cicddos2019.sh
if [ ! -f "$o/done.txt" ]; then
    rm -rf "$o"; mkdir -p "$o"
    set +e
    python3 -I "$HERE/zip_pcap_concat.py" --windows "$D/pcap/0112.windows.tsv" /dev/stdout "$N"/pcaps/PCAP-01-12_*.zip \
        2> "$o/concat.log" \
    | docker run --rm -i --user 1000:1000 -v "$R/rules":/rules:ro -v "$o":/out \
        wnc-suricata8 suricata -v -c /rules/detect.yaml -S /rules/et_all.rules --runmode single \
        --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none \
        --set 'vars.address-groups.HOME_NET=[192.168.50.0/24]' \
        -r /dev/stdin -l /out > "$o/run.log" 2>&1
    st=("${PIPESTATUS[@]}")
    set -e
    echo "rc=${st[*]}" > "$o/done.txt"
    [ "${st[*]}" = "0 0" ] || { echo "concat/suricata failed: ${st[*]}"; exit 1; }
fi
wait $conv

# 3. Match alerts to labels (all 50,063,112 flows)
python3 -I "$HERE/match_iot23.py" <(cat "$C"/*.conn.log.labeled) "$o/eve.json" \
    "$R/rules/gw_corp_sids.txt" "$R/rules/iplist_sids.txt" "$R/match_cicddos2019/0112.json" 1 --cic
echo "0112 done"
