#!/bin/bash
# CICIoT2023 抽樣的 36 個 pcap（每種攻擊 1–2 個檔、Benign 1 個）跑 Suricata 8.0.7（full）。
# label 只到檔案層級，所以另外輸出 stats.log（flow 總數），之後算「有 alert 的 flow 比例」。
# 攻擊者（實驗網路裡的 Raspberry Pi）和受害設備在同一個區網，官方清單只有設備名稱沒有 IP，
# 所以 HOME_NET 和 EXTERNAL_NET 都設成 any：不分內外、所有方向的 rule 都適用（rule 能偵測到的上限）。
# 用法: run_ciciot2023.sh [平行數，預設 3]；只處理已下載並核對過 sha256 的檔（有 .ok）。
set -euo pipefail
SRC=/mnt/nas/dataset/ciciot2023/pcap_sample
R=/home/sixsquare/datasets/detection
one() {
    f=$1; n=$(basename "$f" .pcap); o=$R/ciciot2023/$n
    [ -f "$o/done.txt" ] && return 0
    mkdir -p "$R/ciciot2023"; exec 9>"$R/ciciot2023/.$n.lock"; flock -n 9 || return 0   # 同一個檔只讓一個流程跑
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
