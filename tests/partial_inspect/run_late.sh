#!/bin/bash
# run_late.sh — exp 5: mix.pcap → per-policy subsets (policy_filter.py) → Suricata full ET (HOME_NET = server subnet 10.0.2.0/24) → eval_late.py
# Usage: bash run_late.sh <late dir>   (run late_mix.py first to produce mix.pcap, truth.json)
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
L=$(cd "$1" && pwd); R=/home/sixsquare/datasets/detection/rules; JOBS=${JOBS:-2}
[ -f $L/pcap/kept.tsv ] || EXTRA=1 nice -n 10 python3 -I $HERE/policy_filter.py $L/mix.pcap $L/pcap 0 2e9 > $L/filter.log
run_one() {
  pol=$1; r=$L/run/$pol
  [ -f $r/done.txt ] && return 0
  rm -rf $r; mkdir -p $r
  docker run --rm --user 1000:1000 --memory 3g -v $L/pcap:/pcap:ro -v $R:/rules:ro -v $r:/out \
    wnc-suricata8 suricata -c /rules/detect.yaml -S /rules/et_all.rules --runmode single \
    --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none \
    --set 'vars.address-groups.HOME_NET=[10.0.2.0/24]' \
    --set stream.midstream=true --set stream.midstream-policy=ignore \
    -r /pcap/$pol.pcap -l /out > $r/run.log 2>&1
  echo done > $r/done.txt
}
export -f run_one; export L R
cut -f1 $L/pcap/kept.tsv | xargs -P $JOBS -I{} bash -c 'run_one {}'
python3 -I $HERE/eval_late.py $L
