#!/bin/bash
# 對四個 dataset 的每個 pcap 跑 trust_sim，每個檔案的結果寫成 $OUT/<dataset>/<name>.tsv（已經有結果的跳過）。
# 本機的檔案和 NAS 上的檔案分兩組同時跑；pcap 對到的 eve.json 和偵測評估相同（../detection/）。
# 用法: run_all.sh [dataset ...]，dataset 是 iot23 cicids2017 cicddos2019 ciciot2023（預設全部）
# 建議用 systemd-run --user --unit trust-sim -p MemoryMax=8G -p MemorySwapMax=0 bash -c 'run_all.sh > log 2>&1' 跑
# （輸出才不會進 journal；不給 swap，記憶體不夠時直接失敗，不會卡住）
# IOT23_SKIP="43-1 ..." 跳過這些 IoT-23 scenario（43-1 的掃描同時有約 300 萬條連線，要另外給較多記憶體單獨跑）
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$HERE/target/release/trust_sim
DS=/home/sixsquare/datasets
DET=$DS/detection
OUT=${OUT:-$DS/trust_sim}
IOT23_DIR=$DS/iot23/extracted/run1/opt/Malware-Project/BigDataset/IoTScenarios
IOT23_TGZ=/mnt/nas/wnc_data/iot_23_datasets_full.tar.gz
CICIOT=/mnt/nas/dataset/ciciot2023
LOCAL_JOBS=${LOCAL_JOBS:-4}
NAS_JOBS=${NAS_JOBS:-2}
IOT23_SKIP=" ${IOT23_SKIP:-} "
export BIN OUT DET

one() {
    local dataset=$1 name=$2 eve=$3 src=$4
    local o=$OUT/$dataset/$name
    [ -s "$o.tsv" ] && return 0
    mkdir -p "$OUT/$dataset"
    if "$BIN" --name "$name" --eve "$eve" "$src" > "$o.tmp" 2> "$o.err"; then
        mv "$o.tmp" "$o.tsv"
    else
        echo "failed: $dataset $name (see $o.err)" >&2
        rm -f "$o.tmp"
    fi
}
export -f one

if [ "${1:-}" = --tar-member ]; then
    for line in $IOT23_MAP; do
        case "$TAR_FILENAME" in *"${line%%|*}") one iot23 "${line##*|}" "$DET/iot23/${line##*|}/eve.json" -; exit ;; esac
    done
    cat > /dev/null
    exit
fi

(cd "$HERE" && cargo build --release -q)

want() {
    local d
    for d in "${SELECTED[@]}"; do [ "$d" = "$1" ] && return 0; done
    return 1
}
SELECTED=("$@")
[ ${#SELECTED[@]} -eq 0 ] && SELECTED=(iot23 cicids2017 cicddos2019 ciciot2023)

iot23_list() {
    python3 -I - "$HERE/../iot23/results" <<'P'
import glob, json, os, sys
for f in sorted(glob.glob(os.path.join(sys.argv[1], '*.json'))):
    n = os.path.basename(f)[:-5]
    if n.startswith('CTU-IoT-Malware-Capture-'):
        name = n[len('CTU-IoT-Malware-Capture-'):]
    else:
        name = 'H' + n[len('CTU-Honeypot-Capture-'):].replace('__', '_')
    print('%s|%s|%s' % (name, n.replace('__', '/'), json.load(open(f))['pcap']))
P
}

local_jobs() {
    if want iot23; then
        iot23_list | while IFS='|' read -r name folder pcap; do
            if [ -f "$IOT23_DIR/$folder/$pcap" ] && [[ $IOT23_SKIP != *" $name "* ]]; then
                printf '%s\0' iot23 "$name" "$DET/iot23/$name/eve.json" "$IOT23_DIR/$folder/$pcap"
            fi
        done
    fi
    if want cicids2017; then
        for day in monday tuesday wednesday thursday friday; do
            printf '%s\0' cicids2017 "$day" "$DET/cicids2017/$day/eve.json" "$DS/cicids2017/pcap/$day.pcap"
        done
    fi
    if want cicddos2019; then
        printf '%s\0' cicddos2019 0311 "$DET/cicddos2019/0311/eve.json" "$DS/cicddos2019/pcap/0311.pcap"
    fi
}

run_local() {
    local_jobs | xargs -0 -n 4 -P "$LOCAL_JOBS" bash -c 'one "$@"' _
    if want cicddos2019 && [ ! -s "$OUT/cicddos2019/0112.tsv" ]; then
        mkdir -p "$OUT/cicddos2019"
        python3 -I "$HERE/../detection/zip_pcap_concat.py" /dev/stdout "$DS"/cicddos2019/zips/PCAP-01-12_*.zip \
            2> "$OUT/cicddos2019/0112.concat.err" \
        | one cicddos2019 0112 "$DET/cicddos2019/0112/eve.json" -
    fi
}

run_nas() {
    if want iot23; then
        local pats=() map=""
        while IFS='|' read -r name folder pcap; do
            if [ ! -f "$IOT23_DIR/$folder/$pcap" ] && [ ! -s "$OUT/iot23/$name.tsv" ] && [[ $IOT23_SKIP != *" $name "* ]]; then
                pats+=("*/IoTScenarios/$folder/$pcap")
                map+="$folder/$pcap|$name"$'\n'
            fi
        done < <(iot23_list)
        if [ ${#pats[@]} -gt 0 ]; then
            export IOT23_MAP=$map
            tar -xzf "$IOT23_TGZ" --wildcards "${pats[@]}" --to-command="bash $HERE/run_all.sh --tar-member" &
        fi
    fi
    if want ciciot2023; then
        tail -n +2 "$HERE/../detection/results/ciciot2023_files.tsv" | while IFS=$'\t' read -r folder file _ sampled; do
            local name=${file%.pcap} path=$CICIOT/pcap/$folder/$file
            if [ "$sampled" = 1 ]; then path=$CICIOT/pcap_sample/$file; fi
            printf '%s\0' ciciot2023 "$name" "$DET/ciciot2023/$name/eve.json" "$path"
        done | xargs -0 -n 4 -P "$NAS_JOBS" bash -c 'one "$@"' _
    fi
    wait
}

echo "start $(date -Is)"
run_local & a=$!
run_nas & b=$!
wait $a; echo "local done $(date -Is)"
wait $b; echo "nas done $(date -Is)"
