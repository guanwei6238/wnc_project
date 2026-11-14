#!/bin/bash
# alloc_run.sh — CPU 分配實驗的筆電端（流量產生器沿用 tests/ids_inline/planb_run.sh 的 wnc-gen 容器與 tcpprep cache）
# 前置：Pi 上 planb_pi.sh up、alloc_pi.sh pause off；筆電 bash tests/ids_inline/planb_run.sh setup S_m17 S_m1 S_m60
# 用法:
#   bash alloc_run.sh sweep <B0|B1|B2|B3> <placement> <pcap> <round> <pps...>   實驗 1：一個放置、一種工作負載的速率掃描
#   bash alloc_run.sh exp1 <round>        實驗 1 全部：B0／B1／B2 × A0 R1 R123 I1 T1（順序每輪隨機）
#   bash alloc_run.sh ai <strategy> <cpu|mem|mlp|none> <pps> <round> [threads]   實驗 2 的一個點（含同場的「只有 AI」基準）
#   bash alloc_run.sh exp2 <round>        實驗 2 全部：α β γ × none cpu mem，γ 另加 mem 1 執行緒
# 工作負載：B0 只有 bridge；B1 wnc-gw ips full 2 queue；B2 wnc-gw ips full 1 queue 全部信任；B3 wnc-gw ids（NFLOG）full 2 group；B4、B5 ips full 3、4 queue；
#           B6、B7、B8 ids full 1、3、4 group；B9 ips full 1 queue；
#           K0 = B6（ids 1 group）、K1／K2 再多 1／2 份完整的 NFLOG 複本給只讀的讀取端、K2h 多 2 份只有前 128 bytes 的複本；
#           U2 = K0 加 1 份 kernel 複本、由 user space 的 fanout 分給 2 個讀取端；K0g3、K2g3、U2g3 是 3 個 group 的版本
# 策略：alpha = 中斷在 CPU0、Suricata 綁 1,2、AI 1 執行緒綁 3；beta = RPS→CPU1、Suricata 綁 2,3、AI 2 執行緒在 2,3 用 SCHED_IDLE；
#       gamma = 都不綁、AI 3 執行緒；delta = IRQ 29 搬到 CPU1、Suricata 綁 2,3、AI 1 執行緒綁 CPU0
#   bash alloc_run.sh exp1b <round>       延伸：B4（3 queue）、B5（4 queue）× A0 I1 T1
#   bash alloc_run.sh exp2b <round>       延伸：delta × none cpu mem mlp、alpha × mlp、alpha × mem 工作比例 25／50%（環境變數 DUTY）
#   bash alloc_run.sh exp1c <round>       延伸：ids（B6 B3 B7 B8 = 1–4 group）× A0 I1 R123，另算檢查容量（漏掉的複本 ≤ 0.1%）
#   bash alloc_run.sh exp3 <round>        conntrack 計數（nf_conntrack_acct 0／1）每個封包多花多少：B2@40k、B1@40k、B3@30k，A0
#   bash alloc_run.sh exp1d <round>       延伸：S_m1 的 ips 1–4 queue、ids 1–4 group × A0 I1 R123；S_m17 補 ips 1 queue × 三種、3、4 queue × R123
#   bash alloc_run.sh mode <bridge|routed>  Pi 的拓樸換成這個模式（planb_pi.sh down、MODE=… up、PAUSE 關）
#   bash alloc_run.sh exp4 <round>        routed 對 bridge：B0 B2 B1 B7 × A0 R123，兩種模式（順序每輪對調）；routed 送 planb_run.sh routed_pcap 改過 MAC 的 pcap
#   bash alloc_run.sh exp5 <round>        ids 複製多份（bridge）：K0 K1 K2 K2h × A0 R123 × S_m17、bulk_fixed
#   bash alloc_run.sh night1104           exp5 1 → exp4 1 → exp4 2 → exp5 2，最後拓樸回到 bridge、PAUSE 開
#   bash alloc_run.sh exp6 <round>        多份複本的 (c) user space 分發：U2 × A0 R123；R123＋3 group：K0g3 K2g3 U2g3；S_m17、bulk_fixed
#   bash alloc_run.sh night1104b          先用一個點驗證 U2，再 exp6 1、exp6 2
#   bash alloc_run.sh exp7 <round>        exp5 的 K2h 重跑（讀取端 tcpdump 改 -s 0，截短交給規則的 snaplen）
#   bash alloc_run.sh night1104c          exp7 1、exp7 2
#   bash alloc_run.sh exp8 <round>        exp6 的 K0g3、K2g3 重跑（exp6 時 fanout 沒結束、佔著 group 20）
#   bash alloc_run.sh night1104d          exp7 1、exp8 1、exp7 2、exp8 2
# MODE=routed：sweep 用 routed 的 pcap、結果多 mode=；EXP：結果的 exp=（預設 1）
# 結果一行一點寫進 $OUT/$KVL（預設 alloc.kvl）；連續兩個速率 cap_loss > 1% 就停
LAN=${LAN:-enx9c69d3241bd9}; WAN=${WAN:-eno2}; PI=${PI:-wnc@10.254.254.2}
OUT=${OUT:-/home/sixsquare/datasets/throughput/cpu_alloc}; KVL=${KVL:-alloc.kvl}
HERE=$(cd "$(dirname "$0")" && pwd)
G="docker exec wnc-gen"
SSH="ssh -o ConnectTimeout=20 -o ServerAliveInterval=5 -o ServerAliveCountMax=6 $PI"
P="sudo bash ~/cpu_alloc/alloc_pi.sh"
mkdir -p $OUT

snap() { for i in 1 2 3; do s=$($SSH "$P snap" 2>/dev/null) && [ -n "$s" ] && { echo "$s"; return 0; }; sleep 3; done; return 1; }
cool() {
  for i in $(seq 1 30); do
    t=$($SSH "vcgencmd measure_temp" | tr -dc '0-9.'); awk -v t="$t" 'BEGIN{exit !(t > 70)}' || return 0
    echo "  cooling (temp $t)"; sleep 20
  done
}
pi_start() {
  E="MODE=${MODE:-bridge}"
  case $1 in
  B0) $SSH "sudo pkill -INT -x wnc-gw; echo bridge only" ;;
  B1) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 2 0" | tail -1) ;;
  B2) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 1 1" | tail -1) ;;
  B3) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 2 0" | tail -1) ;;
  B4) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 3 0" | tail -1) ;;
  B5) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 4 0" | tail -1) ;;
  B6) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  B7) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 3 0" | tail -1) ;;
  B8) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 4 0" | tail -1) ;;
  B9) r=$($SSH "sudo $E bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K0) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K1) r=$($SSH "sudo $E PROTECTION=ids COPIES=1 bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K2) r=$($SSH "sudo $E PROTECTION=ids COPIES=2 bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K2h) r=$($SSH "sudo $E PROTECTION=ids COPIES=2 SNAPLEN=128 bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  U2) r=$($SSH "sudo $E PROTECTION=ids FANOUT=2 bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1) ;;
  K0g3) r=$($SSH "sudo $E PROTECTION=ids bash ~/ids_inline/planb_pi.sh start full 3 0" | tail -1) ;;
  K2g3) r=$($SSH "sudo $E PROTECTION=ids COPIES=2 bash ~/ids_inline/planb_pi.sh start full 3 0" | tail -1) ;;
  U2g3) r=$($SSH "sudo $E PROTECTION=ids FANOUT=2 bash ~/ids_inline/planb_pi.sh start full 3 0" | tail -1) ;;
  esac
  [ "$1" = B0 ] && return 0
  echo "  $r"; case "$r" in ready*) return 0 ;; *) return 1 ;; esac
}
pi_stop() { [ "$1" = B0 ] || $SSH "sudo bash ~/ids_inline/planb_pi.sh stop" | grep reader | sed 's/^/  /'; }
# point <pcap> <pps> <loop> k=v...：送一次流量，前後各 snap 一次，寫一行
point() {
  pc=$1; rate=$2; loop=$3; shift 3
  cool
  s0=$(snap) || { echo "$* pps=$rate invalid=snap0" >> $OUT/$KVL; return 1; }
  lo=""; [ "$loop" -gt 1 ] && lo="--loop=$loop"
  if [ "${MODE:-bridge}" = routed ]; then f=/out/$pc.rt.pcap; c=/out/$pc.rt.cache; else f=/pcaps/$pc.pcap; c=/out/$pc.cache; fi
  $G tcpreplay -i $WAN.20 -I $LAN -c $c --pps=$rate $lo $f > $OUT/tcpreplay.txt 2>&1
  sleep 2
  s1=$(snap) || { echo "$* pps=$rate invalid=snap1" >> $OUT/$KVL; return 1; }
  line=$(python3 -I $HERE/alloc.py diff "$s0" "$s1" $OUT/tcpreplay.txt "$@" pcap=$pc pps=$rate loop=$loop)
  echo "$line" >> $OUT/$KVL
  echo "  $(echo "$line" | grep -o -E ' (actual_pps|cap_loss_pct|copy_loss_pct|xcopy_loss_pct|loss_pct|us_per_pkt|cpu0_us_per_pkt|reader_us_per_pkt|util0|util1|util2|util3|ai_ops_per_s|temp)=[^ ]*' | tr '\n' ' ')"
}
# ai_only k=v...：沒有流量，只量 AI 和背景（6 秒）
ai_only() {
  s0=$(snap) || return 1; sleep 6; s1=$(snap) || return 1
  line=$(python3 -I $HERE/alloc.py diff "$s0" "$s1" - "$@")
  echo "$line" >> $OUT/$KVL
  echo "  $(echo "$line" | grep -o -E '(ai_ops_per_s|ai_cpu_s_per_s|util0|util1|util2|util3)=[^ ]*' | tr '\n' ' ')"
}

case "$1" in
sweep)
  wl=$2; pl=$3; pc=$4; round=$5; shift 5
  echo "$(date -u +%T) sweep $wl $pl $pc round=$round mode=${MODE:-bridge}"
  pi_start $wl || { echo "$(date -u +%T) start failed" ; $SSH "sudo bash ~/ids_inline/planb_pi.sh stop" > /dev/null; exit 1; }
  $SSH "$P place $pl"
  fails=0
  for rate in "$@"; do
    n=200000; [ $pc = bulk_fixed ] && n=31433
    loop=1; case $wl in B0|B2) loop=$(( (5 * rate + n - 1) / n )) ;; esac
    [ $pc = bulk_fixed ] && loop=$(( (5 * rate + n - 1) / n ))
    point $pc $rate $loop exp=${EXP:-1} mode=${MODE:-bridge} workload=$wl placement=$pl round=$round || continue
    l=$(tail -1 $OUT/$KVL | grep -o 'cap_loss_pct=[^ ]*' | cut -d= -f2)
    if awk -v l="$l" 'BEGIN{exit !(l > 1)}'; then fails=$((fails + 1)); [ $fails -ge 2 ] && break; else fails=0; fi
  done
  pi_stop $wl
  $SSH "$P place A0" > /dev/null
  ;;
exp1)
  round=$2
  for wl in B0 B1 B2; do
    case $wl in
    B0) pc=S_m17; rates="50000 100000 150000 200000 250000 300000 350000 400000" ;;
    B1) pc=S_m17; rates="20000 30000 40000 45000 50000 55000 60000 70000 80000 100000" ;;
    B2) pc=S_m60; rates="50000 80000 100000 120000 150000 180000 220000 260000 300000" ;;
    esac
    for pl in $(printf '%s\n' A0 R1 R123 I1 T1 | shuf); do bash "$0" sweep $wl $pl $pc $round $rates; done
  done
  echo "EXP1 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
ai)
  st=$2; ai=$3; rate=$4; round=$5; th=$6; duty=${DUTY:-100}
  case $st in
  alpha) pl=A0; pin=1,2; th=${th:-1}; cpus=3; pol=normal ;;
  delta) pl=I1; pin=2,3; th=${th:-1}; cpus=0; pol=normal ;;
  beta) pl=R1; pin=2,3; th=${th:-2}; cpus=2,3; pol=idle ;;
  gamma) pl=A0; pin=none; th=${th:-3}; cpus=any; pol=normal ;;
  esac
  echo "$(date -u +%T) ai strategy=$st ai=$ai threads=$th pps=$rate round=$round"
  pi_start B1 || { echo "  start failed"; $SSH "sudo bash ~/ids_inline/planb_pi.sh stop" > /dev/null; exit 1; }
  $SSH "$P place $pl" > /dev/null
  echo "  pin: $($SSH "$P pin_suricata $pin")"
  [ $ai = none ] || echo "  $($SSH "$P burner_start $ai $th $cpus $pol $duty")"
  m="exp=2 strategy=$st ai=$ai threads=$th round=$round placement=$pl duty=$duty"
  point S_m17 $rate 1 $m traffic=S_m17
  ai_only $m traffic=none pps=0
  [ $ai = none ] || $SSH "$P burner_stop" > /dev/null
  pi_stop B1
  $SSH "$P place A0" > /dev/null
  ;;
exp2)
  round=$2; rate=${3:-40000}
  for pt in $(printf '%s\n' alpha:none alpha:cpu alpha:mem beta:none beta:cpu beta:mem gamma:none gamma:cpu gamma:mem | shuf); do
    bash "$0" ai ${pt%%:*} ${pt##*:} $rate $round
  done
  [ "$round" = 1 ] && bash "$0" ai gamma mem $rate $round 1
  echo "EXP2 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp1b)
  # 延伸：中斷移出 CPU 0 之後，3、4 個 queue 能不能把檢查容量推過 2 個 queue 的 55–60 kpps
  round=$2; rates="40000 50000 55000 60000 65000 70000 80000 90000 100000"
  for wl in B4 B5; do
    for pl in $(printf '%s\n' A0 I1 T1 | shuf); do bash "$0" sweep $wl $pl S_m17 $round $rates; done
  done
  echo "EXP1B ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp1c)
  # 延伸：ids（NFLOG）時轉送不等 Suricata，加 group、把收封包移出 CPU0 能不能提高轉送容量和檢查容量
  round=$2; rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000 250000 300000"
  for wl in B6 B3 B7 B8; do
    for pl in $(printf '%s\n' A0 I1 R123 | shuf); do bash "$0" sweep $wl $pl S_m17 $round $rates; done
  done
  echo "EXP1C ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
acctpt)
  v=$2; wl=$3; pc=$4; rate=$5; round=$6
  echo "$(date -u +%T) acct=$v $wl $pc $rate round=$round"
  $SSH "$P acct $v"
  pi_start $wl || { echo "  start failed"; $SSH "sudo bash ~/ids_inline/planb_pi.sh stop" > /dev/null; exit 1; }
  $SSH "$P place A0" > /dev/null
  loop=1; [ $wl = B2 ] && loop=$(( (5 * rate + 199999) / 200000 ))
  point $pc $rate $loop exp=3 workload=$wl placement=A0 acct=$v round=$round
  pi_stop $wl
  ;;
exp3)
  # 3d 要讀每條連線的封包數、bytes：開 nf_conntrack_acct 的轉送成本（dump 的成本在 tests/ctnetlink/bench）
  round=$2
  for pt in $(printf '%s\n' 0:B2:S_m60:40000 1:B2:S_m60:40000 0:B1:S_m17:40000 1:B1:S_m17:40000 0:B3:S_m17:30000 1:B3:S_m17:30000 | shuf); do
    IFS=: read -r v wl pc rate <<< "$pt"; bash "$0" acctpt $v $wl $pc $rate $round
  done
  $SSH "$P acct 0" > /dev/null
  echo "EXP3 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp1d)
  # 延伸：連線多但不全是掃描的 S_m1（49% 純 SYN），ips 和 ids 都量 1–4 個 queue／group
  round=$2; rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000 250000 300000"
  for pt in $(printf '%s\n' B9:A0 B9:I1 B9:R123 B4:R123 B5:R123 | shuf); do bash "$0" sweep ${pt%%:*} ${pt##*:} S_m17 $round $rates; done
  for wl in B9 B1 B4 B5 B6 B3 B7 B8; do
    for pl in $(printf '%s\n' A0 I1 R123 | shuf); do bash "$0" sweep $wl $pl S_m1 $round $rates; done
  done
  echo "EXP1D ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp2b)
  # 延伸：delta（IRQ 29 搬到 CPU1、Suricata 綁 2,3、AI 綁 CPU0）；alpha 的 mlp；alpha 的 mem 降低工作比例
  round=$2; rate=${3:-40000}
  for pt in $(printf '%s\n' delta:none delta:cpu delta:mem delta:mlp alpha:mlp | shuf); do
    bash "$0" ai ${pt%%:*} ${pt##*:} $rate $round
  done
  for d in 25 50; do DUTY=$d bash "$0" ai alpha mem $rate $round; done
  echo "EXP2B ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
mode)
  m=$2
  echo "$(date -u +%T) topology -> $m"
  $SSH "sudo bash ~/ids_inline/planb_pi.sh down; sudo MODE=$m bash ~/ids_inline/planb_pi.sh up && sudo ip netns exec wgw ip -br addr"
  $SSH "$P pause off" | sed 's/^/  /'
  ;;
exp4)
  # routed 對 bridge（todo：開發者 2026-11-04「routed 比較快，預設是不是應該用 routed」）
  round=$2; modes="bridge routed"; [ $((round % 2)) = 0 ] && modes="routed bridge"
  for m in $modes; do
    bash "$0" mode $m
    for pt in $(printf '%s\n' B0:A0 B0:R123 B2:A0 B2:R123 B1:A0 B1:R123 B7:A0 B7:R123 | shuf); do
      wl=${pt%%:*}; pl=${pt##*:}
      case $wl in
      B0) pc=S_m17; rates="50000 100000 150000 200000 250000 300000 350000 400000" ;;
      B2) pc=S_m60; rates="50000 80000 100000 120000 150000 180000 220000 260000 300000" ;;
      B1) pc=S_m17; rates="20000 30000 40000 45000 50000 55000 60000 70000 80000 100000" ;;
      B7) pc=S_m17; rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000 250000" ;;
      esac
      EXP=4 MODE=$m bash "$0" sweep $wl $pl $pc $round $rates
    done
  done
  echo "EXP4 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp5)
  # ids 複製 2–3 份（老師 2026-11-04 擔心：Suricata、edge AI、雲端特徵各一份）的上限：全部封包、整個封包，另加只複製標頭
  round=$2
  for pc in S_m17 bulk_fixed; do
    case $pc in
    S_m17) rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000" ;;
    bulk_fixed) rates="10000 20000 30000 40000 50000 60000 70000 80000 90000" ;;
    esac
    for pt in $(printf '%s\n' K0:A0 K0:R123 K1:A0 K1:R123 K2:A0 K2:R123 K2h:A0 K2h:R123 | shuf); do
      EXP=5 MODE=bridge bash "$0" sweep ${pt%%:*} ${pt##*:} $pc $round $rates
    done
  done
  echo "EXP5 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp6)
  round=$2
  for pc in S_m17 bulk_fixed; do
    case $pc in
    S_m17) rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000" ;;
    bulk_fixed) rates="10000 20000 30000 40000 50000 60000 70000 80000 90000" ;;
    esac
    for pt in $(printf '%s\n' U2:A0 U2:R123 K0g3:R123 K2g3:R123 U2g3:R123 | shuf); do
      EXP=6 MODE=bridge bash "$0" sweep ${pt%%:*} ${pt##*:} $pc $round $rates
    done
  done
  echo "EXP6 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp7)
  # exp5 的 K2h 重跑：exp5 的讀取端 tcpdump 用 -s 128，libpcap 接收緩衝太小，複本被截掉（S_m17 只收到約 1 成、bulk 讀取端直接結束），數據不算
  round=$2
  for pc in S_m17 bulk_fixed; do
    case $pc in
    S_m17) rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000" ;;
    bulk_fixed) rates="10000 20000 30000 40000 50000 60000 70000 80000 90000" ;;
    esac
    for pt in $(printf '%s\n' K2h:A0 K2h:R123 | shuf); do
      EXP=7 MODE=bridge bash "$0" sweep ${pt%%:*} ${pt##*:} $pc $round $rates
    done
  done
  echo "EXP7 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
exp8)
  # exp6 的 K0g3、K2g3 重跑：exp6 時第一次的 fanout 沒結束、一直佔著 group 20，K2g3 的第一份複本進了 fanout、K0g3 多了 fanout 空轉的 CPU
  round=$2
  for pc in S_m17 bulk_fixed; do
    case $pc in
    S_m17) rates="20000 30000 40000 50000 60000 70000 80000 100000 120000 150000 200000" ;;
    bulk_fixed) rates="10000 20000 30000 40000 50000 60000 70000 80000 90000" ;;
    esac
    for pt in $(printf '%s\n' K0g3:R123 K2g3:R123 | shuf); do
      EXP=8 MODE=bridge bash "$0" sweep ${pt%%:*} ${pt##*:} $pc $round $rates
    done
  done
  echo "EXP8 ROUND $round DONE $(date -u +%FT%TZ)"
  ;;
night1104d)
  bash "$0" mode bridge
  bash "$0" exp7 1
  bash "$0" exp8 1
  bash "$0" exp7 2
  bash "$0" exp8 2
  $SSH "$P pause on" | sed 's/^/  /'
  echo "NIGHT1104D DONE $(date -u +%FT%TZ)"
  ;;
night1104c)
  bash "$0" mode bridge
  bash "$0" exp7 1
  bash "$0" exp7 2
  $SSH "$P pause on" | sed 's/^/  /'
  echo "NIGHT1104C DONE $(date -u +%FT%TZ)"
  ;;
night1104b)
  bash "$0" mode bridge
  KVL=validate.kvl EXP=6 MODE=bridge bash "$0" sweep U2 A0 S_m17 0 20000
  if tail -1 $OUT/validate.kvl | grep -q 'workload=U2 .*xcopy_loss_pct='; then
    bash "$0" exp6 1
    bash "$0" exp6 2
  else
    echo "U2 validation failed; exp6 skipped"
  fi
  $SSH "$P pause on" | sed 's/^/  /'
  echo "NIGHT1104B DONE $(date -u +%FT%TZ)"
  ;;
night1104)
  bash "$0" mode bridge
  bash "$0" exp5 1
  bash "$0" exp4 1
  bash "$0" exp4 2
  bash "$0" mode bridge
  bash "$0" exp5 2
  $SSH "$P pause on" | sed 's/^/  /'
  echo "NIGHT1104 DONE $(date -u +%FT%TZ)"
  ;;
*) sed -n '2,29p' "$0"; exit 2 ;;
esac
