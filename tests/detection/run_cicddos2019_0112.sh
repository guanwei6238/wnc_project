#!/bin/bash
# Time-sample CIC-DDoS2019 01-12 (about 163 GB, 818 pieces): take 1 of every 8 pieces and join them into one pcap,
# keep labels only for flows fully inside those pieces' time windows, then run run_cicddos2019.sh.
# CSV times are local time, UTC-4 in December (03-11 is UTC-3): confirmed by comparing the pcap's first packet with the CSV's first row.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
D=/home/sixsquare/datasets/cicddos2019
N=/mnt/nas/dataset/cicddos2019
for z in 0-0249 0250-0499 0500-0749 0750-0818; do
    until [ -f "$N/pcaps/PCAP-01-12_$z.zip.ok" ]; do sleep 30; done
done
[ -f "$D/pcap/0112s.pcap.ok" ] || {
    python3 -I "$HERE/zip_pcap_concat.py" --every 8 --windows "$D/pcap/0112s.windows.tsv" "$D/pcap/0112s.pcap" \
        "$N"/pcaps/PCAP-01-12_*.zip
    touch "$D/pcap/0112s.pcap.ok"
}
if [ ! -f "$D/conn/0112s.conn.log.labeled" ]; then
    : > "$D/conn/0112.all.conn.log.labeled"
    for c in DrDoS_NTP DrDoS_DNS DrDoS_LDAP DrDoS_MSSQL DrDoS_NetBIOS DrDoS_SNMP DrDoS_SSDP DrDoS_UDP Syn TFTP UDPLag; do
        unzip -p "$N/csvs/CSV-01-12.zip" "01-12/$c.csv" | python3 -I "$HERE/cic_to_conn.py" --tz 4 /dev/stdout /dev/stdin \
            | { [ -s "$D/conn/0112.all.conn.log.labeled" ] && grep -v '^#' || cat; } >> "$D/conn/0112.all.conn.log.labeled"
    done
    python3 -I "$HERE/conn_in_windows.py" "$D/pcap/0112s.windows.tsv" "$D/conn/0112.all.conn.log.labeled" \
        "$D/conn/0112s.conn.log.labeled"
    rm -f "$D/conn/0112.all.conn.log.labeled"
fi
"$HERE/run_cicddos2019.sh" 0112s
