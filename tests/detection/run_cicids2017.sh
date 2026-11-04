#!/bin/bash
# CIC-IDS2017 一天的完整流程：pcapng 轉 pcap → 對齊 → Suricata 8.0.7 → alert 對 label → 原檔存到 NAS。
# 用法: run_cicids2017.sh <day，例如 wednesday>
# 前提：~/datasets/cicids2017/pcaps/<官方檔名> 已從鏡像下載完（hf_download.sh 已核對鏡像的 sha256）；
#       ~/datasets/cicids2017/conn/<day>.conn.log.labeled 已由 cic_to_conn.py 產生。
set -euo pipefail
day=$1
HERE=$(cd "$(dirname "$0")" && pwd)
C=/home/sixsquare/datasets/cicids2017
R=/home/sixsquare/datasets/detection
NAS=/mnt/nas/dataset/cicids2017
declare -A FILE=([monday]=Monday-WorkingHours [tuesday]=Tuesday-WorkingHours [wednesday]=Wednesday-workingHours
                 [thursday]=Thursday-WorkingHours [friday]=Friday-WorkingHours)
f=${FILE[$day]}
src=$C/pcaps/$f.pcap
# 同一天只能有一個流程在跑（可能同時有幾個 run_cicids2017_all.sh）；後到的等前一個做完，已完成的步驟靠標記檔跳過
exec 9>"$C/.lock.$day"; flock 9
want=$(cut -d' ' -f1 "$C/official_md5/$f.md5")
if [ -f "$src" ]; then
    [ -f "$src.ok" ] || { echo "$f 還沒下載完"; exit 1; }
    [ "$(md5sum < "$src" | cut -d' ' -f1)" = "$want" ] || { echo "$f 和官方 md5 不符"; exit 1; }
    echo "official md5 ok: $f"
fi

# 1. 對齊程式只讀 libpcap，官方檔是 pcapng → 轉成 pcap（時間精度沿用原檔）
mkdir -p "$C/pcap"
out=$C/pcap/$day.pcap
if [ ! -f "$out.ok" ]; then
    editcap -F pcap "$src" "$out"
    touch "$out.ok"
fi

# 2. 對齊（定義和 IoT-23 相同）
mkdir -p "$C/align"
[ -f "$C/align/$day.json" ] || python3 -I "$HERE/../iot23/align_stream.py" "$C/conn/$day.conn.log.labeled" "$out" --json "$C/align/$day.json"

# 3. Suricata 8.0.7（full），只留 eve 的 alert。
#    HOME_NET 設成受害端網段 192.168.10.0/24：攻擊者經防火牆 NAT 後是 172.16.0.1，
#    Suricata 預設的 HOME_NET 含 172.16.0.0/12，會把攻擊者當成內部主機，外部打內部的 rule 就不會觸發。
o=$R/cicids2017/$day
if [ ! -f "$o/done.txt" ]; then
    rm -rf "$o"; mkdir -p "$o"
    docker run --rm --user 1000:1000 -v "$C/pcap":/pcap:ro -v "$R/rules":/rules:ro -v "$o":/out \
        wnc-suricata8 suricata -v -c /rules/detect.yaml -S /rules/et_all.rules --runmode single \
        --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none \
        --set 'vars.address-groups.HOME_NET=[192.168.10.0/24]' \
        -r "/pcap/$day.pcap" -l /out > "$o/run.log" 2>&1
    echo "rc=$?" > "$o/done.txt"
fi

# 4. alert 對 label
mkdir -p "$R/match_cicids2017"
python3 -I "$HERE/match_iot23.py" "$C/conn/$day.conn.log.labeled" "$o/eve.json" \
    "$R/rules/gw_corp_sids.txt" "$R/rules/iplist_sids.txt" "$R/match_cicids2017/$day.json"

# 5. 原檔（pcapng）存到 NAS，核對 md5 後才刪本機的原檔（放最後：NAS 走 WiFi，讀寫很慢，不擋分析）
mkdir -p "$NAS/pcaps"
if [ -f "$src" ] && [ ! -f "$NAS/pcaps/$f.pcap.md5ok" ]; then
    [ "$(stat -c %s "$NAS/pcaps/$f.pcap" 2>/dev/null)" = "$(stat -c %s "$src")" ] || cp "$src" "$NAS/pcaps/$f.pcap"
    [ "$(md5sum < "$NAS/pcaps/$f.pcap" | cut -d' ' -f1)" = "$want" ] || { echo "NAS 複本 md5 不符"; exit 1; }
    touch "$NAS/pcaps/$f.pcap.md5ok"
fi
rm -f "$src" "$src.ok"

echo "$day done"
