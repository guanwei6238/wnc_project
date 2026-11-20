#!/bin/bash
# trust_run.sh — per-packet CPU and capacity for no trust / ct mark trust / TC trust (exp 13, laptop side)
#   U = current wnc-gw, no trust, sends <slice>.gw (all packets through the gateway)
#   C = wnc-gw at 16137e0 (/tmp/wncgw/ctmark/wnc-gw; the file must be named wnc-gw for planb_pi.sh stop to find it); after warm-up, conntrack marks all connections trusted (ct mark 0x80000000), sends <slice>.fp
#   T = current wnc-gw; after warm-up, wnc-gw trust add trusts every connection in <slice>.fp.flows, sends <slice>.fp
#   K = current wnc-gw with [trust] backend = "ctmark" (exp 14), trusted the same way as T (wnc-gw trust add writes ct mark), sends <slice>.fp
#   O = wnc-gw before the backend option was added (/tmp/wncgw/old/wnc-gw, 46a96d2), trusted the same way as T; compared with T to see whether the option slowed it down
#   Fe/Fi/Fx = T plus one feature program (exp 15, FEATURE in planb_pi.sh): tc-egress, tc-ingress, xdp generic; compared with T to see the added cost per trusted packet
#   .fp has only packets that take the fast path after trust (gw_pcap.py: TCP without SYN/FIN/RST, UDP, unicast, not fragmented); both versions always inspect control packets,
#   so the C vs T difference is the per-trusted-packet difference
# Prerequisites: on the Pi /tmp/wncgw/wnc-gw, /tmp/wncgw/ctmark/wnc-gw, make_configs.sh; ~/cpu_alloc/trust/<slice>.fp.flows
#       on the laptop planb_run.sh setup; /out/trust/<slice>.{gw,fp}[.rt].{pcap,cache} (cut by gw_pcap.py, split into two sides by LAN subnet with tcpprep --cidr)
# Usage: bash trust_run.sh sweep <U|C|T|K|O> <ips|ids> <slice> <round>   rate sweep for one point (uses the current topology; MODE must match the Pi)
#       bash trust_run.sh round <round>                           both modes × slices × $WORKLOADS (default U C T) × ips ids
#                                                                 (random order, modes swapped each round); EXP written into each line (default 13); PROTS defaults to ips ids
# Placement fixed at I1 (eth0 IRQ 29 → CPU1); each rate sends for at least 5 s; stop after two consecutive rates with cap_loss > 1%
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
files() {  # files <slice> <gw|fp>: sets f, c (path inside the container) and n (packet count)
  local b=/out/trust/$1.$2; [ "${MODE:-bridge}" = routed ] && b=$b.rt
  f=$b.pcap; c=$b.cache
  n=$($G tcpprep --print-stats=$c 2>/dev/null | awk '/Total packets/{print $3}')
}
warm() {  # keep replaying at 10 kpps in the background; first let the whole pcap go through once (every connection enters conntrack)
  $G sh -c "tcpreplay -i $LAN -I $WAN.20 -c $c --pps=10000 --loop=0 $f > /dev/null 2>&1" &
  sleep $(( n / 10000 + 3 ))
}
unwarm() { $G pkill -x tcpreplay; wait 2> /dev/null; sleep 2; }
pi_start() {  # pi_start <U|C|T> <ips|ids> <slice>
  local e="MODE=${MODE:-bridge} PROTECTION=$2" r
  case $1 in
  U|T) r=$($SSH "sudo $e bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  Fe) r=$($SSH "sudo $e FEATURE=tc-egress bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  Fi) r=$($SSH "sudo $e FEATURE=tc-ingress bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  Fx) r=$($SSH "sudo $e FEATURE=xdp-generic bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K) r=$($SSH "sudo $e TRUST_BACKEND=ctmark bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  O) r=$($SSH "sudo $e GW=/tmp/wncgw/old/wnc-gw bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  C) r=$($SSH "sudo $e GW=/tmp/wncgw/ctmark/wnc-gw bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  esac
  echo "  $r"; case "$r" in ready*) ;; *) return 1 ;; esac
  case $1 in
  C) files $3 fp; warm
     echo "  ct mark: $($SSH "sudo ip netns exec wgw $CT -U -m 0x80000000/0x80000000 2>&1 | tail -1; sudo ip netns exec wgw $CT -L -m 0x80000000/0x80000000 2> /dev/null | wc -l; sudo ip netns exec wgw $CT -C")"
     unwarm ;;
  T|O|Fe|Fi|Fx) files $3 fp; warm
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
point() {  # point <pps> k=v...: send traffic once (f, c, n already set), snap before and after, write one line
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
  # whether trusted packets really skip inspection: per-rule counters of the forward chain (K's ct mark accept rule should be the largest) and the ids chain
  [ $wl = U ] || echo "  nft: $($SSH "sudo ip netns exec wgw nft list table inet wnc_gw" | awk '/chain (forward|ids) /{c = $2} /packets/{for (i = 1; i < NF; i++) if ($i == "packets") printf "%s:%s ", c, $(i + 1)}')"
  pi_stop
  $SSH "$P place A0" > /dev/null
  ;;
round)
  round=$2; modes="bridge routed"; [ $((round % 2)) = 0 ] && modes="routed bridge"
  for m in $modes; do
    bash $HERE/alloc_run.sh mode $m
    for pt in $(for s in $SLICES; do for w in ${WORKLOADS:-U C T}; do for p in ${PROTS:-ips ids}; do echo $w:$p:$s; done; done; done | shuf); do
      IFS=: read -r w p s <<< "$pt"
      MODE=$m EXP=${EXP:-13} bash "$0" sweep $w $p $s $round
    done
  done
  echo "TRUST ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
*) sed -n '2,15p' "$0"; exit 2 ;;
esac
