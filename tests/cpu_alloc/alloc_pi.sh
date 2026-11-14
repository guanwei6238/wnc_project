#!/bin/bash
# alloc_pi.sh — CPU 分配實驗的 Pi 端工具（拓樸、wnc-gw 啟停沿用 ~/ids_inline/planb_pi.sh）
# 用法（都要 sudo）:
#   alloc_pi.sh snap                 印一行 key=value：各 CPU 的忙碌時間、softnet、中斷、qdisc 丟包、方案 B 的計數、Suricata worker 與 burner 的 CPU、
#                                    額外 NFLOG 複本讀取端（tcpdump）的 CPU
#   alloc_pi.sh place <名稱>         A0 預設 | R1 RPS→CPU1 | R123 RPS→CPU1–3 | I1 eth0 的 IRQ 29→CPU1 | T1 threaded NAPI 綁 CPU1
#   alloc_pi.sh pin_suricata <cpu,...>  Suricata 的 worker（W#、W-NFQ#、W-NFLOG#）執行緒依序綁到這些 CPU（none = 不綁）
#   alloc_pi.sh pause <on|off>       eth0 的 Ethernet PAUSE，改完等 link 回到 1000 Mb/s
#   alloc_pi.sh burner_start <cpu|mem|mlp> <threads> <cpus|any> <normal|idle> [duty%，預設 100]   背景跑替身
#   alloc_pi.sh burner_stop
#   alloc_pi.sh acct <0|1>           wgw 裡的 net.netfilter.nf_conntrack_acct（之後建立的 conntrack entry 才有計數）
#   alloc_pi.sh fastpath_start <flows 檔>  在 eth0、eth1.20 的 TCX ingress 最前面掛 ebpf-bench v4（tests/ebpf/bench）：查到信任的五元組就直接 redirect 到另一個 port
#   alloc_pi.sh fastpath_stop        拿掉 fast path，印出它 redirect 的封包數
# 忙碌時間＝經過時間 − idle − iowait（/proc/stat 的 idle 在 NO_HZ 下是精確的，而且 idle 時處理的中斷不算 idle）；
# schedstat 的 rq_cpu_time 只當輔助（idle 時處理的中斷算不到）
W="ip netns exec wgw"
B=/home/wnc/cpu_alloc
OPS=/dev/shm/burner.ops
case "$1" in
snap)
  now=$(cat /proc/uptime | cut -d' ' -f1)
  stat=$(awk '/^cpu[0-9]/{c = substr($1, 4); printf "idle%s=%d iow%s=%d ", c, $5, c, $6}' /proc/stat)
  rq=$(awk '/^cpu[0-9]/{c = substr($1, 4); printf "rq%s=%s ", c, $8}' /proc/schedstat)
  sn=$(c=0; while read -ra f; do printf 'sn_proc%d=%d sn_drop%d=%d sn_sq%d=%d sn_rps%d=%d ' $c $((16#${f[0]})) $c $((16#${f[1]})) $c $((16#${f[2]})) $c $((16#${f[9]})); c=$((c + 1)); done < /proc/net/softnet_stat)
  irq=$(awk '$1 == "29:" || $1 == "30:" {n = substr($1, 1, length($1) - 1); for (i = 2; i <= 5; i++) printf "irq%s_c%d=%s ", n, i - 2, $i}' /proc/interrupts)
  nr=$(awk '/NET_RX/{for (i = 2; i <= 5; i++) printf "netrx_c%d=%s ", i - 2, $i} /NET_TX/{for (i = 2; i <= 5; i++) printf "nettx_c%d=%s ", i - 2, $i}' /proc/softirqs)
  qd() { awk '/dropped/{for (i = 1; i <= NF; i++) if ($i == "dropped") {gsub(",", "", $(i + 1)); s += $(i + 1)}} END{print s + 0}'; }
  q0=$($W /usr/sbin/tc -s qdisc show dev eth0 2>/dev/null | qd); q1=$($W /usr/sbin/tc -s qdisc show dev eth1.20 2>/dev/null | qd); qr=$(/usr/sbin/tc -s qdisc show dev eth1 | qd)
  e1=$(cat /sys/class/net/eth1/statistics/tx_dropped)
  pb=$(bash /home/wnc/ids_inline/planb_pi.sh counters 2>/dev/null)
  sp=$(pgrep -x Suricata-Main | head -1)
  sw=0; [ -n "$sp" ] && sw=$(for t in /proc/$sp/task/*; do grep -qE '^W[-#]' $t/comm 2>/dev/null && cut -d' ' -f1 $t/schedstat; done | awk '{s += $1} END{print s + 0}')
  rd=$(for p in $(pgrep -x tcpdump; pgrep -x fanout); do cat /proc/$p/task/*/schedstat 2>/dev/null; done | awk '{s += $1} END{print s + 0}')
  bp=$(pgrep -x burner | head -1)
  bc=0; [ -n "$bp" ] && bc=$(cat /proc/$bp/task/*/schedstat 2>/dev/null | awk '{s += $1} END{print s + 0}')
  read -r bo bt < $OPS 2>/dev/null
  t=$(vcgencmd measure_temp | tr -dc '0-9.'); th=$(vcgencmd get_throttled | cut -d= -f2); clk=$(vcgencmd measure_clock arm | cut -d= -f2)
  sw_=$(awk '/SwapTotal/{t = $2} /SwapFree/{f = $2} END{print t - f}' /proc/meminfo)
  echo "up=$now $stat$rq$sn$irq$nr qd_eth0=$q0 qd_eth120=$q1 qd_eth1=$qr txdrop_eth1=$e1 $pb sur_w_ns=$sw reader_ns=$rd $(cat /dev/shm/fanout.stats 2> /dev/null) burner_ns=$bc burner_ops=${bo:-0} burner_t=${bt:-0} temp=$t throttled=$th arm_hz=$clk swap_kb=$sw_"
  ;;
place)
  rps=0; irq=1; thr=0
  case "$2" in
  A0) ;; R1) rps=2 ;; R123) rps=e ;; I1) irq=2 ;; T1) thr=1 ;;
  *) echo "error: unknown placement $2"; exit 2 ;;
  esac
  $W sh -c "echo $rps > /sys/class/net/eth0/queues/rx-0/rps_cpus; echo $thr > /sys/class/net/eth0/threaded"
  echo $irq > /proc/irq/29/smp_affinity
  if [ $thr = 1 ]; then for p in $(pgrep '^napi/eth0'); do taskset -pc 1 $p > /dev/null; done; fi
  napi=$(for p in $(pgrep '^napi/eth0'); do printf '%s:%s ' "$(cat /proc/$p/comm)" "$(taskset -pc $p | awk '{print $NF}')"; done)
  echo "placement=$2 rps_cpus=$($W cat /sys/class/net/eth0/queues/rx-0/rps_cpus) irq29=$(cat /proc/irq/29/smp_affinity_list) eff=$(cat /proc/irq/29/effective_affinity_list 2>/dev/null) threaded=$($W cat /sys/class/net/eth0/threaded) napi=[$napi]"
  ;;
pin_suricata)
  sp=$(pgrep -x Suricata-Main | head -1); [ -n "$sp" ] || { echo "error: suricata not running"; exit 1; }
  if [ "$2" = none ]; then echo "suricata not pinned"; exit 0; fi
  IFS=, read -ra cpus <<< "$2"; i=0
  for t in /proc/$sp/task/*; do
    grep -qE '^W[-#]' $t/comm || continue
    taskset -pc ${cpus[$((i % ${#cpus[@]}))]} ${t##*/} > /dev/null; i=$((i + 1))
  done
  for t in /proc/$sp/task/*; do grep -qE '^W[-#]' $t/comm && printf '%s:%s ' "$(cat $t/comm)" "$(awk '/Cpus_allowed_list/{print $2}' $t/status)"; done; echo
  ;;
pause)
  v=$2; $W /usr/sbin/ethtool -A eth0 rx $v tx $v
  for i in $(seq 1 30); do
    sleep 1
    $W /usr/sbin/ethtool eth0 | grep -q 'Speed: 1000Mb/s' && $W /usr/sbin/ethtool eth0 | grep -q 'Link detected: yes' && break
  done
  sleep 2
  $W /usr/sbin/ethtool -a eth0 | tr '\n' ' '; echo; $W /usr/sbin/ethtool eth0 | grep -E 'Speed|Link detected' | tr '\n' ' '; echo
  ;;
burner_start)
  pkill -x burner; rm -f $OPS
  pre=""; [ "$5" = idle ] && pre="chrt -i 0"
  BURNER_OPS_FILE=$OPS nohup $pre $B/burner $2 $3 $4 ${6:-100} 100000 > /dev/shm/burner.out 2>&1 &
  sleep 3; echo "burner pid=$(pgrep -x burner) policy=$(chrt -p $(pgrep -x burner | head -1) | head -1 | awk -F: '{print $2}')"
  ;;
acct)
  $W sysctl -q -w net.netfilter.nf_conntrack_acct=$2; echo "nf_conntrack_acct=$($W cat /proc/sys/net/netfilter/nf_conntrack_acct)"
  ;;
burner_stop)
  pkill -x burner; sleep 0.5; rm -f $OPS; echo stopped
  ;;
fastpath_start)
  pkill -INT -x ebpf-bench; sleep 0.5
  $W $B/ebpf-bench v4 --flows $2 eth0 eth1.20 > /dev/shm/fastpath.out 2>&1 &
  for i in $(seq 1 50); do grep -q "prog_id=" /dev/shm/fastpath.out && break; sleep 0.1; done
  cat /dev/shm/fastpath.out
  ;;
fastpath_stop)
  pkill -INT -x ebpf-bench; sleep 0.5; tail -1 /dev/shm/fastpath.out
  ;;
*) sed -n '2,13p' "$0"; exit 2 ;;
esac
