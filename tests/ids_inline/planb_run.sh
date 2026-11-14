#!/bin/bash
# 方案 B：外部產生流量的多 queue 量測，筆電端
#   流量產生器是 Docker 容器 wnc-gen（image wnc-lab-gen：wnc-lab 加 tcpreplay；--network host、NET_ADMIN、NET_RAW）
#   路由器（WAN 端）送的封包從 eno2.20 送進 Pi eth1.20，其他從 USB 網卡送進 Pi eth0；Pi 端用 planb_pi.sh
#   每個速率送一整個 pcap（不重複播放），比較 tcpreplay 送出的封包數和 Pi 轉送出去的封包數
#   cap_loss = kernel queue 滿而丟（nfq_drop）+ 網卡丟 + 沒收到（sent − pi_in）＝ 處理不過來；loss 另外包含 Suricata 自己的判決丟包（重播造成的 stream_error 等）
#   連續兩個速率 cap_loss > 1% 就停
# 用法: bash planb_run.sh setup|teardown
#       bash planb_run.sh sweep <empty|full> <queues> <0|1 全部信任> <pcap 名稱> <round> <pps...>
#       bash planb_run.sh matrix    2026-10-28 的量測：full、S_m17／S_m1／S_m60、1–4 個 queue、2 輪，加上全部信任
#       bash planb_run.sh nflog     2026-10-29 ids 候選 B：IMPL=nflog、full、S_m1／S_m17／S_m60、1–2 個 group，結果寫 nflog.kvl
#   IMPL=nflog（K、BUF 一起傳給 planb_pi.sh）：結果多 copy_loss_pct = netlink 丟掉的複本 ÷ log 規則送出的複本；停止條件仍只看 cap_loss
#   KVL：結果檔名（預設 planb.kvl）
#       bash planb_run.sh routed_pcap <pcap 名稱...>   planb_pi.sh 的 MODE=routed 用：把目的 MAC 改成 Pi 的介面（路由器那側 → eth1.20、
#           其他 → eth0），寫 /out/<名稱>.rt.pcap 和 .rt.cache；PI_LAN_MAC、PI_WAN_MAC 預設是 Pi 的 eth0、eth1
LAN=${LAN:-enx9c69d3241bd9}; WAN=${WAN:-eno2}; PI=${PI:-wnc@10.254.254.2}
PCAPS=${PCAPS:-/home/sixsquare/datasets/throughput/pcaps}; OUT=${OUT:-/home/sixsquare/datasets/throughput/planb}
G="docker exec wnc-gen"
SSH="ssh -o ConnectTimeout=20 -o ServerAliveInterval=5 -o ServerAliveCountMax=6 $PI"
IMPL=${IMPL:-wncgw}; ENV="IMPL=$IMPL K=${K:-none} BUF=${BUF:-1048576}"; KVL=${KVL:-planb.kvl}
router() { case $1 in S_h5) echo 82:e6:50:12:14:64 ;; S_m3) echo a6:d1:8c:1f:ce:64 ;; bulk_fixed) echo 02:00:00:00:01:01 ;; *) echo 78:8a:20:43:93:d5 ;; esac; }
case "$1" in
setup)
  mkdir -p $OUT
  docker run -d --name wnc-gen --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v $PCAPS:/pcaps:ro -v $OUT:/out --entrypoint sleep wnc-lab-gen:latest infinity > /dev/null
  $G ip link add link $WAN name $WAN.20 type vlan id 20
  $G ip link set $WAN.20 up
  shift
  for pc in "$@"; do $G tcpprep --mac=$(router $pc) --pcap=/pcaps/$pc.pcap --cachefile=/out/$pc.cache; done
  ;;
routed_pcap)
  shift
  for pc in "$@"; do
    $G tcprewrite --enet-dmac=${PI_WAN_MAC:-9c:69:d3:2a:11:54},${PI_LAN_MAC:-e4:5f:01:2d:03:bf} -c /out/$pc.cache -i /pcaps/$pc.pcap -o /out/$pc.rt.pcap
    $G tcpprep --mac=$(router $pc) --pcap=/out/$pc.rt.pcap --cachefile=/out/$pc.rt.cache
  done
  ;;
teardown)
  $G ip link del $WAN.20
  docker rm -f wnc-gen > /dev/null
  ;;
sweep)
  rs=$2; q=$3; trusted=$4; pc=$5; round=$6; shift 6
  $SSH "sudo $ENV bash ~/ids_inline/planb_pi.sh start $rs $q $trusted" | tail -1
  fails=0
  for rate in "$@"; do
    c0=$($SSH "sudo bash ~/ids_inline/planb_pi.sh counters")
    $G tcpreplay -i $WAN.20 -I $LAN -c /out/$pc.cache --pps=$rate /pcaps/$pc.pcap > $OUT/tcpreplay.txt 2>&1
    sleep 2
    c1=$($SSH "sudo bash ~/ids_inline/planb_pi.sh counters")
    sent=$(grep -o "Actual: [0-9]* packets" $OUT/tcpreplay.txt | cut -d" " -f2)
    actual=$(grep -o "Rated: [0-9.]* Bps, [0-9.]* Mbps, [0-9.]* pps" $OUT/tcpreplay.txt | awk '{print $6}')
    line=$(awk -v c0="$c0" -v c1="$c1" -v sent=$sent -v actual=$actual -v rs=$rs -v q=$q -v tr=$trusted -v pc=$pc -v round=$round -v rate=$rate -v impl=$IMPL 'BEGIN{
      n = split(c0, a, " "); for (i = 1; i <= n; i++) { split(a[i], p, "="); x[p[1]] = p[2] }
      n = split(c1, b, " "); for (i = 1; i <= n; i++) { split(b[i], p, "="); y[p[1]] = p[2] }
      in_ = (y["rx0"] - x["rx0"]) + (y["rx1"] - x["rx1"]); out = (y["tx0"] - x["tx0"]) + (y["tx1"] - x["tx1"])
      loss = sent ? 100 * (sent - out) / sent : 0
      nfq = y["nfq_drop"] - x["nfq_drop"]; miss = y["miss0"] - x["miss0"]; nd = (y["drop0"] - x["drop0"]) + (y["drop1"] - x["drop1"])
      short = sent - in_ > 0 ? sent - in_ : 0
      cap = sent ? 100 * (nfq + miss + nd + short) / sent : 0
      copy = y["nfl_log"] - x["nfl_log"]; cdrop = y["nfl_drop"] - x["nfl_drop"]
      printf "round=%d impl=%s pcap=%s rules=%s queues=%d trusted=%d pps=%d actual_pps=%.0f sent=%d pi_in=%d pi_out=%d loss_pct=%.3f cap_loss_pct=%.3f nfq_drop=%d nic_miss=%d nic_drop=%d ct_insert_failed=%d ct_drop=%d copies=%d copy_drop=%d copy_loss_pct=%.3f",
        round, impl, pc, rs, q, tr, rate, actual, sent, in_, out, loss, cap, nfq, miss, nd, y["ct_insert_failed"] - x["ct_insert_failed"], y["ct_drop"] - x["ct_drop"], copy, cdrop, (copy ? 100 * cdrop / copy : 0) }')
    echo "$line" >> $OUT/$KVL; echo "  $line"
    if awk -v l="$(echo "$line" | grep -o 'cap_loss_pct=[^ ]*' | cut -d= -f2)" 'BEGIN{exit !(l > 1)}'; then
      fails=$((fails + 1)); [ $fails -ge 2 ] && break
    else
      fails=0
    fi
  done
  $SSH "sudo $ENV bash ~/ids_inline/planb_pi.sh stop" | sed 's/^/  suricata: /'
  ;;
matrix)
  inspect="5000 10000 15000 20000 25000 30000 35000 40000 45000 50000 60000 70000 80000 100000 120000"
  trust="20000 40000 60000 80000 100000 120000 150000 200000 250000 300000"
  for round in 1 2; do
    for pc in S_m17 S_m1 S_m60; do
      for q in 1 2 3 4; do echo "$(date -u +%T) round=$round $pc queues=$q"; bash "$0" sweep full $q 0 $pc $round $inspect; done
      echo "$(date -u +%T) round=$round $pc trusted"; bash "$0" sweep full 1 1 $pc $round $trust
    done
  done
  echo "MATRIX DONE $(date -u +%FT%TZ)"
  ;;
nflog)
  rates="5000 10000 20000 30000 40000 50000 60000 70000 80000 100000 120000"
  for pc in S_m1 S_m17 S_m60; do
    for q in 1 2; do echo "$(date -u +%T) nflog $pc groups=$q"; IMPL=nflog KVL=nflog.kvl bash "$0" sweep full $q 0 $pc 1 $rates; done
  done
  echo "$(date -u +%T) wncgw S_m1 queues=1 (same-day check against 2026-10-28)"
  KVL=nflog.kvl bash "$0" sweep full 1 0 S_m1 1 $rates
  echo "NFLOG MATRIX DONE $(date -u +%FT%TZ)"
  ;;
*) sed -n '2,12p' "$0"; exit 2 ;;
esac
