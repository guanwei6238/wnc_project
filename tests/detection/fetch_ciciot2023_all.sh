#!/bin/bash
# CICIoT2023 其餘的 pcap（抽樣的 36 個以外）：下載 → Suricata 8.0.7（full，設定同 run_ciciot2023.sh）→ 存到 NAS。
# 每個檔：從 Hugging Face 鏡像下載到工作站（hf_download.sh 用 sha256 核對）→ 跑 Suricata → 複製到
# NAS 的 pcap/<資料夾>/ 並再核對一次 sha256 → 刪掉工作站上的檔。偵測讀工作站的檔，不從 NAS 讀回來。
# 用法: fetch_ciciot2023_all.sh [同時處理的檔數，預設 3]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
export HERE
export NAS=/mnt/nas/dataset/ciciot2023/pcap
export STAGE=/home/sixsquare/datasets/ciciot2023_stage
export R=/home/sixsquare/datasets/detection
mkdir -p "$NAS" "$STAGE" "$R/ciciot2023"

one() {
    folder=$1; file=$2; n=${file%.pcap}; o=$R/ciciot2023/$n; dst=$NAS/$folder
    [ -f "$dst/$file.ok" ] && [ -f "$o/done.txt" ] && return 0
    s=$STAGE/$folder; mkdir -p "$s" "$dst"
    if [ ! -f "$o/done.txt" ]; then
        bash "$HERE/hf_download.sh" bencorn/CIC-IoT-2023 "$s" "PCAP/$folder/$file" > "$s/$file.dl.log" 2>&1
        grep -q "^ok " "$s/$file.dl.log" || grep -q "^skip " "$s/$file.dl.log" || { echo "download failed: $folder/$file"; return 1; }
        rm -rf "$o"; mkdir -p "$o"
        set +e
        docker run --rm --memory 4g --user 1000:1000 -v "$s":/pcap:ro -v "$R/rules":/rules:ro -v "$o":/out \
            wnc-suricata8 suricata -v -c /rules/detect_stats.yaml -S /rules/et_all.rules --runmode single \
            --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none \
            --set 'vars.address-groups.HOME_NET=any' --set 'vars.address-groups.EXTERNAL_NET=any' \
            -r "/pcap/$file" -l /out > "$o/run.log" 2>&1
        rc=$?
        set -e
        echo "rc=$rc" > "$o/done.txt"
        [ $rc -eq 0 ] || { echo "suricata failed: $folder/$file rc=$rc"; return 1; }
    fi
    if [ ! -f "$dst/$file.ok" ]; then
        want=$(cat "$s/$file.ok")
        # 寫到 NAS（CIFS）時 dirty page 算在這個 cgroup：同一時間只讓一個檔寫 NAS（flock），避免記憶體被寫入佔滿
        exec 8>"$STAGE/.nas.lock"; flock 8
        cp "$s/$file" "$dst/$file.part"
        flock -u 8; exec 8>&-
        # 核對用 direct read 從 NAS 讀回來（不讀本機 page cache 裡剛寫的資料）
        got=$(dd if="$dst/$file.part" iflag=direct bs=16M status=none | sha256sum | cut -d' ' -f1)
        [ "$got" = "$want" ] || { echo "NAS copy mismatch: $folder/$file"; rm -f "$dst/$file.part"; return 1; }
        mv "$dst/$file.part" "$dst/$file"; echo "$want" > "$dst/$file.ok"
    fi
    rm -f "$s/$file" "$s/$file.ok"
    echo "$(date +%T) $folder/$file done"
}
export -f one

# 檔名沒有空白或引號（已檢查），一行兩個欄位：資料夾、檔名
# 跑兩輪：第二輪補第一輪失敗的檔（做完的會直接跳過）
for pass in 1 2; do
    awk -F'\t' 'NR>1 && $4==0 {print $1, $2}' "$HERE/results/ciciot2023_files.tsv" \
        | xargs -n 2 -P "${1:-3}" bash -c 'one "$1" "$2" || true' _
done
echo "all done"
