#!/bin/bash
# run_policies.sh — exp 4: time slice → per-policy subsets (policy_filter.py) → Suricata full ET (same config as tests/detection) → alerts vs labels (match_iot23.py)
# Usage: bash run_policies.sh <slice name> <day> <t0> <t1>     results in $OUT/<slice>/
#   OUT defaults to ~/datasets/partial_inspect/policies; runs JOBS Suricata instances at once (default 3); FILTER_ONLY=1 only filters
set -e
HERE=$(cd "$(dirname "$0")" && pwd); DET=$HERE/../detection
name=$1; day=$2; t0=$3; t1=$4
OUT=${OUT:-/home/sixsquare/datasets/partial_inspect/policies}; R=/home/sixsquare/datasets/detection/rules
C=/home/sixsquare/datasets/cicids2017; JOBS=${JOBS:-3}
o=$OUT/$name; mkdir -p $o
if [ ! -f $o/kept.tsv ]; then
  EXTRA=1 nice -n 10 python3 -I $HERE/policy_filter.py $C/pcap/$day.pcap $o/pcap $t0 $t1 > $o/filter.log
  cp $o/pcap/kept.tsv $o/kept.tsv
fi
run_one() {
  pol=$1; r=$o/run/$pol
  [ -f $r/done.txt ] && return 0
  rm -rf $r; mkdir -p $r
  docker run --rm --user 1000:1000 --memory 3g -v $o/pcap:/pcap:ro -v $R:/rules:ro -v $r:/out \
    wnc-suricata8 suricata -c /rules/detect.yaml -S /rules/et_all.rules --runmode single \
    --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none \
    --set 'vars.address-groups.HOME_NET=[192.168.10.0/24]' \
    --set stream.midstream=true --set stream.midstream-policy=ignore \
    -r /pcap/$pol.pcap -l /out > $r/run.log 2>&1
  python3 -I $DET/match_iot23.py $C/conn/$day.conn.log.labeled $r/eve.json $R/gw_corp_sids.txt $R/iplist_sids.txt $r/match.json > $r/match.log 2>&1
  echo done > $r/done.txt
  echo "$(date -u +%T) $name $pol"
}
[ -n "${FILTER_ONLY:-}" ] && exit 0
export -f run_one; export o R C DET day name
cut -f1 $o/kept.tsv | xargs -P $JOBS -I{} bash -c 'run_one {}'
