#!/bin/bash
# 檢查 Suricata 的 flow emergency mode 有沒有影響偵測結果：
# Debian 預設 flow.memcap 128 MiB，flood 時 flow table 會滿（run.log 出現 "Flow emergency mode entered"），
# 這裡把 flow.memcap 調到 4 GiB 重跑同一份 pcap，之後和原本的 eve.json 逐筆比對 alert。
# 03-11 已另外跑過（alert 657 筆相同、每個 label 有 alert 的 flow 數相同）。
# 輸出: ~/datasets/detection/memcap_test/<名稱>/{eve.json,run.log,stats.log}
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
R=/home/sixsquare/datasets/detection
T=$R/memcap_test
NAS=/mnt/nas
run() {     # run <名稱> <HOME_NET 設定...>，pcap 從 stdin 讀
    local n=$1; shift
    local o=$T/$n
    [ -f "$o/done.txt" ] && return 0
    rm -rf "$o"; mkdir -p "$o"
    docker run --rm -i --memory 6g --user 1000:1000 -v "$R/rules":/rules:ro -v "$o":/out \
        wnc-suricata8 suricata -v -c /rules/detect_stats.yaml -S /rules/et_all.rules --runmode single \
        --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none \
        --set flow.memcap=4gb "$@" -r /dev/stdin -l /out > "$o/run.log" 2>&1
    echo done > "$o/done.txt"
}

python3 -I "$HERE/zip_pcap_concat.py" /dev/stdout /home/sixsquare/datasets/cicddos2019/zips/PCAP-01-12_*.zip 2>/dev/null \
    | run 0112 --set 'vars.address-groups.HOME_NET=[192.168.50.0/24]'

for f in DDoS-PSHACK_Flood DDoS-RSTFINFlood DDoS-TCP_Flood; do
    run "$f" --set 'vars.address-groups.HOME_NET=any' --set 'vars.address-groups.EXTERNAL_NET=any' \
        < "$NAS/dataset/ciciot2023/pcap_sample/$f.pcap"
done

tar -xzOf "$NAS/wnc_data/iot_23_datasets_full.tar.gz" --occurrence=1 \
    opt/Malware-Project/BigDataset/IoTScenarios/CTU-IoT-Malware-Capture-43-1/2019-01-10-19-22-51-192.168.1.198.pcap \
    | run iot23_43-1
