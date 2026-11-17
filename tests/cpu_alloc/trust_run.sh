#!/bin/bash
# trust_run.sh — 不信任／ct mark 信任／TC 信任的每封包 CPU 與容量（實驗 13，筆電端）
#   U = 現在的 wnc-gw，沒有信任，送 <切片>.gw（經過 gateway 的全部封包）
#   C = 16137e0 的 wnc-gw（/tmp/wncgw/ctmark/wnc-gw，檔名要叫 wnc-gw，planb_pi.sh stop 才找得到），暖身後用 conntrack 把全部連線設成信任（ct mark 0x80000000），送 <切片>.fp
#   T = 現在的 wnc-gw，暖身後用 wnc-gw trust add 信任 <切片>.fp.flows 的全部連線，送 <切片>.fp
#   K = 現在的 wnc-gw 設 [trust] backend = "ctmark"（實驗 14），信任方式同 T（wnc-gw trust add 寫 ct mark），送 <切片>.fp
#   O = 加 backend 選項之前的 wnc-gw（/tmp/wncgw/old/wnc-gw，46a96d2），信任方式同 T；和 T 比，看加選項有沒有變慢
#   .fp 只有信任後會走 fast path 的封包（gw_pcap.py：TCP 沒有 SYN／FIN／RST、UDP、單播、沒有分片），兩版的控制封包都一律檢查，
#   所以 C 和 T 的差就是每個信任封包的差
# 前置：Pi 上 /tmp/wncgw/wnc-gw、/tmp/wncgw/ctmark/wnc-gw、make_configs.sh；~/cpu_alloc/trust/<切片>.fp.flows
#       筆電 planb_run.sh setup；/out/trust/<切片>.{gw,fp}[.rt].{pcap,cache}（gw_pcap.py 切、tcpprep --cidr 用內網網段分兩側）
# 用法: bash trust_run.sh sweep <U|C|T|K|O> <ips|ids> <切片> <round>   一個點的速率掃描（拓樸用目前的，MODE 要和 Pi 一致）
#       bash trust_run.sh round <round>                           兩種模式 × 切片 × $WORKLOADS（預設 U C T）× ips ids
#                                                                 （順序隨機，模式每輪對調）；EXP 寫進每一行（預設 13）
# 放置固定 I1（eth0 的 IRQ 29 → CPU1）；每個速率至少送 5 秒；連續兩個速率 cap_loss > 1% 就停
LAN=${LAN:-enx9c69d3241bd9}; WAN=${WAN:-eno2}; PI=${PI:-wnc@10.254.254.2}
OUT=${OUT:-/home/sixsquare/datasets/throughput/cpu_alloc}; KVL=${KVL:-trust.kvl}
HERE=$(cd "$(dirname "$0")" && pwd)
G="docker exec wnc-gen"
SSH="ssh -o ConnectTimeout=20 -o ServerAliveInterval=5 -o ServerAliveCountMax=6 $PI"
P="sudo bash ~/cpu_alloc/alloc_pi.sh"
CT=/home/wnc/ctbench/root/usr/sbin/conntrack
SLICES=${SLICES:-"S_m60 S_h5 C17_Benign C17_FTP-Patator D12_Benign I23_Benign_Final I23_DNS_Spoofing"}
FAST_RATES=${FAST_RATES:-"20000 50000 80000 100000 120000 150000 180000 220000 260000 300000 350000 400000"}
IPS_RATES="5000 10000 15000 20000 25000 30000 40000 50000 60000 80000"
mkdir -p $OUT

snap() { for i in 1 2 3; do s=$($SSH "$P snap" 2>/dev/null) && [ -n "$s" ] && { echo "$s"; return 0; }; sleep 3; done; return 1; }
cool() {
  for i in $(seq 1 30); do
    t=$($SSH "vcgencmd measure_temp" | tr -dc '0-9.'); awk -v t="$t" 'BEGIN{exit !(t > 70)}' || return 0
    echo "  cooling (temp $t)"; sleep 20
  done
}
files() {  # files <切片> <gw|fp>：設定 f、c（容器裡的路徑）和 n（封包數）
  local b=/out/trust/$1.$2; [ "${MODE:-bridge}" = routed ] && b=$b.rt
  f=$b.pcap; c=$b.cache
  n=$($G tcpprep --print-stats=$c 2>/dev/null | awk '/Total packets/{print $3}')
}
warm() {  # 背景以 10 kpps 一直重播，先送完整個 pcap 一次（每條連線都進 conntrack）
  $G sh -c "tcpreplay -i $LAN -I $WAN.20 -c $c --pps=10000 --loop=0 $f > /dev/null 2>&1" &
  sleep $(( n / 10000 + 3 ))
}
unwarm() { $G pkill -x tcpreplay; wait 2> /dev/null; sleep 2; }
pi_start() {  # pi_start <U|C|T> <ips|ids> <切片>
  local e="MODE=${MODE:-bridge} PROTECTION=$2" r
  case $1 in
  U|T) r=$($SSH "sudo $e bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K) r=$($SSH "sudo $e TRUST_BACKEND=ctmark bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  O) r=$($SSH "sudo $e GW=/tmp/wncgw/old/wnc-gw bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  C) r=$($SSH "sudo $e GW=/tmp/wncgw/ctmark/wnc-gw bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  esac
  echo "  $r"; case "$r" in ready*) ;; *) return 1 ;; esac
  case $1 in
  C) files $3 fp; warm
     echo "  ct mark: $($SSH "sudo ip netns exec wgw $CT -U -m 0x80000000/0x80000000 2>&1 | tail -1; sudo ip netns exec wgw $CT -L -m 0x80000000/0x80000000 2> /dev/null | wc -l; sudo ip netns exec wgw $CT -C")"
     unwarm ;;
  T|O) files $3 fp; warm
     hops=; [ "${MODE:-bridge}" = routed ] && hops=hops
     echo "  $($SSH "$P trust_flows /home/wnc/cpu_alloc/trust/$3.fp.flows $hops")"
     unwarm ;;
  K) files $3 fp; warm
     echo "  $($SSH "$P trust_flows /home/wnc/cpu_alloc/trust/$3.fp.flows")"
     echo "  ct mark: $($SSH "sudo ip netns exec wgw $CT -L -m 0x80000000/0x80000000 2> /dev/null | wc -l")"
     unwarm ;;
  esac
}
pi_stop() { $SSH "sudo bash ~/ids_inline/planb_pi.sh stop" | sed 's/^/  /'; }
point() {  # point <pps> k=v...：送一次流量（f、c、n 已設好），前後各 snap 一次，寫一行
  local rate=$1; shift
  cool
  s0=$(snap) || { echo "$* pps=$rate invalid=snap0" >> $OUT/$KVL; return 1; }
  local loop=$(( (5 * rate + n - 1) / n )) lo=""
  [ $loop -gt 1 ] && lo="--loop=$loop"
  $G tcpreplay -i $LAN -I $WAN.20 -c $c --pps=$rate $lo $f > $OUT/tcpreplay.txt 2>&1
  sleep 2
  s1=$(snap) || { echo "$* pps=$rate invalid=snap1" >> $OUT/$KVL; return 1; }
  line=$(python3 -I $HERE/alloc.py diff "$s0" "$s1" $OUT/tcpreplay.txt "$@" pps=$rate loop=$loop)
  echo "$line" >> $OUT/$KVL
  echo "  $(echo "$line" | grep -o -E ' (actual_pps|cap_loss_pct|copy_loss_pct|loss_pct|us_per_pkt|util1|temp)=[^ ]*' | tr '\n' ' ')"
}

case "$1" in
sweep)
  wl=$2; prot=$3; s=$4; round=$5
  echo "$(date -u +%T) sweep $wl $prot $s round=$round mode=${MODE:-bridge}"
  pi_start $wl $prot $s || { echo "$(date -u +%T) start failed"; pi_stop > /dev/null; exit 1; }
  $SSH "$P place I1" > /dev/null
  k=fp; [ $wl = U ] && k=gw
  files $s $k
  rates=$FAST_RATES; [ $wl$prot = Uips ] && rates=$IPS_RATES
  fails=0
  for rate in $rates; do
    point $rate exp=${EXP:-13} mode=${MODE:-bridge} workload=$wl protection=$prot slice=$s pcap=$s.$k placement=I1 round=$round || continue
    l=$(tail -1 $OUT/$KVL | grep -o 'cap_loss_pct=[^ ]*' | cut -d= -f2)
    if awk -v l="$l" 'BEGIN{exit !(l > 1)}'; then fails=$((fails + 1)); [ $fails -ge 2 ] && break; else fails=0; fi
  done
  # 信任的封包有沒有真的略過檢查：forward chain 每條規則的 counter（K 的 ct mark accept 那條要最大）和 ids chain
  [ $wl = U ] || echo "  nft: $($SSH "sudo ip netns exec wgw nft list table inet wnc_gw" | awk '/chain (forward|ids) /{c = $2} /packets/{for (i = 1; i < NF; i++) if ($i == "packets") printf "%s:%s ", c, $(i + 1)}')"
  pi_stop
  $SSH "$P place A0" > /dev/null
  ;;
round)
  round=$2; modes="bridge routed"; [ $((round % 2)) = 0 ] && modes="routed bridge"
  for m in $modes; do
    bash $HERE/alloc_run.sh mode $m
    for pt in $(for s in $SLICES; do for w in ${WORKLOADS:-U C T}; do for p in ips ids; do echo $w:$p:$s; done; done; done | shuf); do
      IFS=: read -r w p s <<< "$pt"
      MODE=$m EXP=${EXP:-13} bash "$0" sweep $w $p $s $round
    done
  done
  echo "TRUST ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
*) sed -n '2,15p' "$0"; exit 2 ;;
esac
