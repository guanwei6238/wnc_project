#!/bin/bash
# autotrust_cost_pi.sh — 3d（讀 alert、自動信任）的成本（Pi，bridge，ids）
#   fcli(10.9.0.1) --veth-- x-lan [wgw: br0] x-wan --veth-- fsrv(10.9.0.2)（env.sh＋protection_pi.sh net up）
#   eve      wnc-gw 讀 EVE 的 CPU：每秒 0、100、1000 筆 alert（UDP 每個封包帶 PERF，規則有 content，每個封包都比對），各量 60 秒
#   latency  alert 從封包進來到 wnc-gw 讀到：每秒 1、10 筆，各 30 秒（--log-level debug，wnc-gw 的 log 時間 − eve 的 timestamp）
#   saving   自動信任省多少：8 條 TCP 連線，各每秒送 250 個 1000 bytes（TCP_NODELAY），[trust] auto off／on（其他用預設），
#            量第 15–75 秒的 Suricata、wnc-gw CPU 與 forward、ids chain 的封包數
#   check    每次讀 conntrack 的成本：0、1000、10000 條 UDP 連線（每 10 秒各送 1 個封包維持），check_interval 1，量 20 秒
#   2026-11-04 的結果裡 eve_watch=inotify 那幾行是刪掉 inotify 之前的版本量的（~/datasets/throughput/func_20261104/worktree_with_inotify.diff）
#   CPU 是 /proc/<pid>/task/*/schedstat 第一欄（ns，排程器精確累計）的總和
# 前置：pi_lab_mode.sh up 1000；sudo sh env.sh up；sudo bash protection_pi.sh net up；系統的 suricata 服務已停；wnc-gw 放在 $GW
# 用法: sudo bash autotrust_cost_pi.sh <eve|latency|saving|check|all>   結果一行一筆 key=value，附加到 $OUT
GW=${GW:-/tmp/wncgw/wnc-gw}; D=/tmp/wncgw/ac; SLOG=/var/log/wnc-gw/suricata
OUT=${OUT:-/home/wnc/ids_inline/results/autotrust_cost.kvl}
W="ip netns exec wgw"; C="ip netns exec fcli"; S="ip netns exec fsrv"

setup() {  # $1 = [suricata] 多的設定行，$2 = [trust] 的設定行
  mkdir -p $D
  cat > $D/test.rules <<'EOF'
alert udp any any -> any 9 (msg:"perf udp"; content:"PERF"; sid:1000401; rev:1;)
EOF
  printf '%%YAML 1.1\n---\ninclude: /etc/suricata/suricata.yaml\ndefault-rule-path: %s\nrule-files:\n  - test.rules\n' $D > $D/s.yaml
  printf 'mode = "bridge"\nxdp = "off"\n\n[ports]\nlan = "g-lan"\nwan = "g-wan"\n\n[suricata]\nconfig = "%s"\n%s\n\n[trust]\n%s\n' $D/s.yaml "$1" "$2" > $D/setting.toml
}

start() {  # $1 = log level
  rm -f $SLOG/fast.log $SLOG/eve.json $D/run.log $D/exit
  ( $W $GW --log-level $1 -c $D/setting.toml run > /dev/null 2> $D/run.log; echo $? > $D/exit ) > /dev/null 2>&1 < /dev/null &
  local i
  for i in $(seq 1 150); do
    grep -q "traffic is inspected" $D/run.log 2>/dev/null && return 0
    [ -e $D/exit ] && break; sleep 0.2
  done
  echo "wnc-gw did not start"; tail -5 $D/run.log; return 1
}

stop() { kill -INT $(pgrep -n -x wnc-gw); until [ -e $D/exit ]; do sleep 0.2; done; }

gw_pid() { pgrep -n -x wnc-gw; }
suricata_pid() { grep -o "suricata started pid=[0-9]*" $D/run.log | tail -1 | cut -d= -f2; }
cpu_ns() { cat /proc/$1/task/*/schedstat 2>/dev/null | awk '{s += $1} END {printf "%d", s}'; }
counter() { $W nft list chain inet wnc_gw $1 | grep -o "packets [0-9]*" | head -1 | cut -d" " -f2; }
alerts() { grep -c ':1000401:' $SLOG/fast.log 2>/dev/null; }
rate() { awk -v a=$1 -v b=$2 -v t=$3 -v f=$4 'BEGIN {printf f, (b - a) / t / 1e6}'; }  # ns 的差 → 每秒幾 ms
clock() { vcgencmd measure_clock arm | cut -d= -f2 | awk '{printf "%d", $1 / 1e6}'; }

udp_alerts() {  # $1 = 每秒幾個，$2 = 秒數
  $C python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); n = 0; t0 = time.time()
while time.time() - t0 < $2:
    s.sendto(b'PERF' + b'x' * 28, ('10.9.0.2', 9)); n += 1
    d = t0 + n / $1 - time.time()
    if d > 0: time.sleep(d)
print(n)"
}

server() {
  $S python3 -c "
import socket, threading  # acsrv
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('', 5001)); s.listen(64)
def drain(c):
    while c.recv(65536): pass
while True:
    threading.Thread(target=drain, args=(s.accept()[0],), daemon=True).start()
" > /dev/null 2>&1 < /dev/null &
  SRV=$!; sleep 0.5
}

eve() {
  local w r a0 c0 c1 sent pid
  for w in poll; do
    for r in 0 100 1000; do
      setup "" "auto = false"; start info || return 1
      pid=$(gw_pid); sleep 3
      a0=$(alerts); c0=$(cpu_ns $pid)
      if [ $r -gt 0 ]; then sent=$(udp_alerts $r 60); else sleep 60; sent=0; fi
      c1=$(cpu_ns $pid); sleep 1
      stop
      echo "test=eve eve_watch=$w rate=$r sent=$sent alerts=$(( $(alerts) - a0 )) gw_cpu_ms_per_s=$(rate $c0 $c1 60 %.3f) read=$(grep -o 'raised alerts alerts=[0-9]*' $D/run.log | cut -d= -f2 | awk '{s += $1} END {print s + 0}') clock_mhz=$(clock)" | tee -a $OUT
    done
  done
}

latency() {
  local w r
  for w in poll; do
    for r in 1 10; do
      setup "" "auto = false"; start debug || return 1
      sleep 2; udp_alerts $r 30 > /dev/null; sleep 2
      stop
      python3 - "$SLOG/eve.json" "$D/run.log" "$w" "$r" <<'PY' | tee -a $OUT
import json, sys, statistics
from datetime import datetime
eve, log, w, r = sys.argv[1:]
t = lambda s: datetime.strptime(s.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
a = [t(e["timestamp"]) for e in map(json.loads, open(eve)) if e.get("event_type") == "alert" and e["alert"]["signature_id"] == 1000401]
b = [t(l.split()[0]) for l in open(log) if "DEBUG suricata alert" in l and "sid=1000401" in l]
d = sorted((y - x) * 1000 for x, y in zip(a, b))
q = lambda p: d[min(len(d) - 1, int(p * len(d)))]
print(f"test=latency eve_watch={w} rate={r} eve_alerts={len(a)} gw_alerts={len(b)} p50_ms={q(0.5):.1f} p95_ms={q(0.95):.1f} max_ms={d[-1]:.1f} min_ms={d[0]:.1f}")
PY
    done
  done
}

saving() {
  local auto pid sp c0 c1 s0 s1 f0 f1 i0 i1 tp
  for auto in false true; do
    setup "" "auto = $auto"; start info || return 1; server
    pid=$(gw_pid); sp=$(suricata_pid)
    $C python3 -c "
import socket, threading, time
def run():
    c = socket.create_connection(('10.9.0.2', 5001)); c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    t0 = time.time(); n = 0; m = b'y' * 1000
    while time.time() - t0 < 80:
        c.sendall(m); n += 1
        d = t0 + n / 250 - time.time()
        if d > 0: time.sleep(d)
    c.close()
ts = [threading.Thread(target=run) for _ in range(8)]
[t.start() for t in ts]; [t.join() for t in ts]" &
    tp=$!
    sleep 15
    c0=$(cpu_ns $pid); s0=$(cpu_ns $sp); f0=$(counter forward); i0=$(counter ids)
    sleep 60
    c1=$(cpu_ns $pid); s1=$(cpu_ns $sp); f1=$(counter forward); i1=$(counter ids)
    wait $tp; kill $SRV; sleep 1
    stop
    echo "test=saving auto=$auto forward_pps=$(( (f1 - f0) / 60 )) ids_pps=$(( (i1 - i0) / 60 )) suricata_cpu_ms_per_s=$(rate $s0 $s1 60 %.2f) gw_cpu_ms_per_s=$(rate $c0 $c1 60 %.3f) trusted=$(grep -c 'connection trusted' $D/run.log) clock_mhz=$(clock)" | tee -a $OUT
  done
}

check() {
  local k pid c0 c1 tp n
  $S nft add rule inet t in udp dport 20000-39999 drop
  for k in 0 1000 10000; do
    setup "" "auto = true
check_interval = 1"; start info || return 1
    pid=$(gw_pid)
    if [ $k -gt 0 ]; then
      $C python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); t0 = time.time()
while time.time() - t0 < 35:
    for p in range($k): s.sendto(b'z', ('10.9.0.2', 20000 + p))
    time.sleep(10)" &
      tp=$!
    fi
    sleep 12
    n=$($W cat /proc/sys/net/netfilter/nf_conntrack_count); c0=$(cpu_ns $pid)
    sleep 20
    c1=$(cpu_ns $pid)
    [ $k -gt 0 ] && wait $tp
    stop
    echo "test=check flows=$k conntrack_count=$n gw_cpu_ms_per_s=$(rate $c0 $c1 20 %.3f) clock_mhz=$(clock)" | tee -a $OUT
    sleep 35  # 等 UDP 的 conntrack 逾時（30 秒），下一輪從乾淨的表開始
  done
  $S nft flush chain inet t in; $S nft add rule inet t in udp dport 9 counter name got drop
}

case "$1" in
eve | latency | saving | check) $1 ;;
all) eve; latency; saving; check ;;
*) sed -n '2,15p' "$0"; exit 2 ;;
esac
