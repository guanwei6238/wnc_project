#!/bin/bash
# The remaining CICIoT2023 pcaps (beyond the 36 sampled): download -> Suricata 8.0.7 (full, same settings as run_ciciot2023.sh) -> store on the NAS.
# Per file: download from the Hugging Face mirror to the workstation (hf_download.sh checks sha256) -> run Suricata -> copy to
# pcap/<folder>/ on the NAS and check sha256 again -> delete the workstation copy. Detection reads the workstation copy, not the NAS.
# Usage: fetch_ciciot2023_all.sh [files processed at once, default 3]
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
        # Dirty pages from writing to the NAS (CIFS) count against this cgroup: only one file writes to the NAS at a time (flock), so writes don't fill memory
        exec 8>"$STAGE/.nas.lock"; flock 8
        cp "$s/$file" "$dst/$file.part"
        flock -u 8; exec 8>&-
        # Verify by reading back from the NAS with direct reads (not the just-written data in the local page cache)
        got=$(dd if="$dst/$file.part" iflag=direct bs=16M status=none | sha256sum | cut -d' ' -f1)
        [ "$got" = "$want" ] || { echo "NAS copy mismatch: $folder/$file"; rm -f "$dst/$file.part"; return 1; }
        mv "$dst/$file.part" "$dst/$file"; echo "$want" > "$dst/$file.ok"
    fi
    rm -f "$s/$file" "$s/$file.ok"
    echo "$(date +%T) $folder/$file done"
}
export -f one

# File names have no spaces or quotes (checked); two fields per line: folder, file name
# Two rounds: the second retries files that failed in the first (finished ones are skipped)
for pass in 1 2; do
    awk -F'\t' 'NR>1 && $4==0 {print $1, $2}' "$HERE/results/ciciot2023_files.tsv" \
        | xargs -n 2 -P "${1:-3}" bash -c 'one "$1" "$2" || true' _
done
echo "all done"
