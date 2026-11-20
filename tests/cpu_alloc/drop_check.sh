#!/bin/bash
# drop_check.sh — why Suricata itself drops packets without trust (U, ips) (supplement to exp 13, laptop side, bridge)
#   A = restart wnc-gw each time, send <slice>.gw once
#   B = same wnc-gw, send <slice>.gw three times in a row, read stats after each (does replaying the same TCP connections add stream errors)
#   C = restart each time, send <slice>.whole (gw_pcap.py: drops TCP connections in the slice whose first packet isn't a bare SYN, to see whether midstream pickup is the cause)
#   all at 5 kpps; after sending wait 10 s (stats.log is written every 8 s), then read ips.*, exception_policy.*, app_layer.error.* and other counters (cumulative)
# Prerequisites same as trust_run.sh (bridge topology); /out/trust/<slice>.whole.{pcap,cache}
# Usage: bash drop_check.sh <slice>...   one result line per run written to $OUT/drop_check.kvl
LAN=${LAN:-enx9c69d3241bd9}; WAN=${WAN:-eno2}; PI=${PI:-wnc@10.254.254.2}
OUT=${OUT:-/home/sixsquare/datasets/throughput/cpu_alloc}; KVL=${KVL:-drop_check.kvl}
G="docker exec wnc-gen"
SSH="ssh -o ConnectTimeout=20 -o ServerAliveInterval=5 -o ServerAliveCountMax=6 $PI"
RATE=5000

start() { r=$($SSH "sudo PROTECTION=ips bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1); echo "  $r"; case "$r" in ready*) ;; *) exit 1 ;; esac; }
stop() { $SSH "sudo bash ~/ids_inline/planb_pi.sh stop" | sed 's/^/  /'; }
counters() {
  $SSH "sudo awk '/^Date/{b = \"\"} {b = b \"\\n\" \$0} END{print b}' /var/log/wnc-gw/suricata/stats.log" \
    | awk -F'|' '/^(ips\.|exception_policy\.|app_layer\.error\.|tcp\.(sessions|midstream_pickups|pkt_on_wrong_thread|ack_unseen_data|reassembly_gap)|stream\.|flow\.(total|tcp))/ && $3 + 0 > 0 {gsub(/ /, "", $1); printf "%s=%d ", $1, $3}'
}
send() {  # send <file name> k=v...
  local f=$1; shift
  $G tcpreplay -i $LAN -I $WAN.20 -c /out/trust/$f.cache --pps=$RATE /out/trust/$f.pcap > $OUT/tcpreplay.txt 2>&1
  sleep 10
  local sent=$(grep -o "Actual: [0-9]* packets" $OUT/tcpreplay.txt | cut -d' ' -f2)
  local got=$(counters)
  case "$got" in *ips.accepted=*) ;; *) echo "error: no Suricata counters after sending $f"; stop; exit 1 ;; esac
  local line="$* pcap=$f pps=$RATE sent=$sent $got"
  echo "$line" >> $OUT/$KVL
  echo "  $(echo "$line" | grep -o -E '(case|send|sent|ips\.blocked|ips\.drop_reason\.[a-z_]*|exception_policy\.[a-z_.]*)=[^ ]*' | tr '\n' ' ')"
}

for s in "$@"; do
  echo "$(date -u +%T) $s A"; start; send $s.gw case=A slice=$s send=1; stop
  echo "$(date -u +%T) $s B"; start; for i in 1 2 3; do send $s.gw case=B slice=$s send=$i; done; stop
  echo "$(date -u +%T) $s C"; start; send $s.whole case=C slice=$s send=1; stop
done
echo "DROP CHECK DONE $(date -u +%FT%TZ)"
