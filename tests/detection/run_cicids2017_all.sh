#!/bin/bash
# Process the other CIC-IDS2017 days in order: wait until the day's pcaps are downloaded (.ok exists only after the mirror sha256 check), then run run_cicids2017.sh.
# Usage: run_cicids2017_all.sh <day>...
HERE=$(cd "$(dirname "$0")" && pwd)
C=/home/sixsquare/datasets/cicids2017
declare -A FILE=([monday]=Monday-WorkingHours [tuesday]=Tuesday-WorkingHours [wednesday]=Wednesday-workingHours
                 [thursday]=Thursday-WorkingHours [friday]=Friday-WorkingHours)
for day in "$@"; do
    f=$C/pcaps/${FILE[$day]}.pcap
    until [ -f "$f.ok" ] || [ -f "$C/pcap/$day.pcap.ok" ]; do sleep 30; done
    "$HERE/run_cicids2017.sh" "$day" > "$C/run_$day.log" 2>&1
    echo "$day rc=$?"
done
