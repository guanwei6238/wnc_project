#!/bin/bash
# drop_check.sh — 不信任（U、ips）時 Suricata 自己丟掉封包的原因（實驗 13 的補充，筆電端，bridge）
#   A = 每次重新啟動 wnc-gw，<切片>.gw 送一次
#   B = 同一個 wnc-gw 連送三次 <切片>.gw，每次之後讀一次統計（看重送同樣的 TCP 連線會不會多出 stream error）
#   C = 每次重新啟動，送 <切片>.whole（gw_pcap.py：去掉切片裡第一個封包不是純 SYN 的 TCP 連線，看從中途接上是不是原因）
#   都是 5 kpps；送完等 10 秒（stats.log 每 8 秒寫一次）再讀 ips.*、exception_policy.*、app_layer.error.* 等計數器（累計值）
# 前置同 trust_run.sh（拓樸是 bridge）；/out/trust/<切片>.whole.{pcap,cache}
# 用法: bash drop_check.sh <切片>...   結果一行一次寫進 $OUT/drop_check.kvl
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
send() {  # send <檔名> k=v...
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
