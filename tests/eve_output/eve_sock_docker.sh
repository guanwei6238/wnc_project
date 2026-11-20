#!/bin/bash
# eve_sock_docker.sh — with EVE over unix_stream and a slow or stalled reader, does Suricata block or drop events (Docker testbed, Suricata 8.0.7)
#   offline <pcap>  suricata -r (--runmode single, no rules, flow events only): a regular file as baseline, unix_stream with reader fast/stall:10/slow:2000;
#                   compare event count and Suricata run time (blocks -> longer time, same events; drops -> same time, fewer events)
#   live <ids|ips>  wnc-gw run (routed, when_unavailable = "drop", one alert rule on UDP payload), EVE over unix_stream (alert, flow);
#                   cli sends 5000 UDP packets in 10 s (each a new connection, each alerting) while pinging every 10 ms; the reader does not read for the first 15 s:
#                   check ping packet loss and latency, missed copies logged by wnc-gw, Suricata's alert count and the events the reader received
# Suricata and the reader are pinned to CPUs 6, 7 (the laptop is running plan B's tcpreplay at the same time)
# Usage: bash eve_sock_docker.sh offline <pcap on the laptop>; bash eve_sock_docker.sh live <ids|ips>; finally bash eve_sock_docker.sh clean
G="docker exec wnc-gw"; GI="docker exec -i wnc-gw"; C="docker exec wnc-cli"
D=/tmp/eo; HERE=$(cd "$(dirname "$0")" && pwd); T="taskset -c 6,7"

prep() {
  $G mkdir -p $D/log; docker cp -q "$HERE/reader.py" wnc-gw:$D/reader.py; $G sh -c ": > $D/empty.rules"
}
yaml() {  # yaml <file name> <filetype> <filename> [extra config lines]
  $GI sh -c "cat > $D/$1" <<EOF
%YAML 1.1
---
include: /etc/suricata/suricata.yaml
$4
outputs:
  - eve-log:
      enabled: yes
      filetype: $2
      filename: $3
      types:
        - alert
        - flow
  - stats:
      enabled: yes
      filename: stats.log
      totals: yes
      threads: no
EOF
}
reader() {  # reader <mode>: start in the background, wait for the socket to appear
  $G rm -f $D/eve.sock $D/reader.out
  docker exec -d wnc-gw $T python3 $D/reader.py $D/eve.sock $1 $D/reader.out
  for i in $(seq 1 50); do $G test -S $D/eve.sock && return 0; sleep 0.1; done
  echo "reader did not start"; return 1
}

case "$1" in
offline)
  prep; docker cp -q "$2" wnc-gw:$D/in.pcap
  yaml y-regular.yaml regular eve.json; yaml y-unix.yaml unix_stream $D/eve.sock
  for mode in regular fast stall:10 slow:2000; do
    $G sh -c "rm -rf $D/log/*"
    if [ $mode = regular ]; then y=y-regular.yaml; else y=y-unix.yaml; reader $mode || exit 1; fi
    t0=$(date +%s.%N)
    $G $T suricata -c $D/$y -r $D/in.pcap -S $D/empty.rules -l $D/log --runmode single -k none > /tmp/eo-suri.txt 2>&1
    t1=$(date +%s.%N)
    if [ $mode = regular ]; then
      got="lines=$($G sh -c "wc -l < $D/log/eve.json")"
    else
      for i in $(seq 1 600); do $G test -s $D/reader.out && break; sleep 0.5; done
      got=$($G cat $D/reader.out)
    fi
    flows=$($G sh -c "grep -E '^flow\.(total|end)' $D/log/stats.log | tail -3 | tr -s ' ' | tr '\n' ' '")
    echo "mode=$mode suricata_s=$(awk -v a=$t0 -v b=$t1 'BEGIN{printf "%.1f", b - a}') $got"
    echo "   stats: $flows"
    grep -i -E "socket|unix|drop|eve|reconnect|block" /tmp/eo-suri.txt | grep -v -E "^\s*$" | head -5 | sed 's/^/   suricata: /'
  done
  rm -f /tmp/eo-suri.txt
  ;;
live)
  p=$2; prep
  $GI sh -c "cat > $D/test.rules" <<'EOF'
alert udp any any -> any 5555 (msg:"eo udp"; content:"EO-MARK"; sid:1000302; rev:1;)
EOF
  yaml s.yaml unix_stream $D/eve.sock "default-rule-path: $D
rule-files:
  - test.rules"
  $GI sh -c "cat > $D/setting.toml" <<EOF
mode = "routed"
protection = "$p"

[ports]
lan = "02:00:00:00:01:01"
wan = "02:00:00:00:02:01"

[suricata]
config = "$D/s.yaml"
when_unavailable = "drop"
EOF
  reader stall:15 || exit 1
  $G rm -f $D/run.log $D/exit
  docker exec -d wnc-gw sh -c "/opt/sg/wnc-gw -c $D/setting.toml run > /dev/null 2> $D/run.log & echo \$! > $D/pid; wait \$!; echo \$? > $D/exit"
  for i in $(seq 1 150); do $G grep -q "traffic is inspected" $D/run.log 2>/dev/null && break; sleep 0.2; done
  $G grep -q "traffic is inspected" $D/run.log || { echo "wnc-gw did not start"; $G tail -5 $D/run.log; exit 1; }
  sp=$($G grep -o "suricata started pid=[0-9]*" $D/run.log | tail -1 | cut -d= -f2)
  $G sh -c "taskset -pc 6,7 $sp > /dev/null; for t in /proc/$sp/task/*; do taskset -pc 6,7 \${t##*/} > /dev/null; done"
  echo "protection=$p; reader stalls for 15 s; 5000 UDP flows and ping every 10 ms for 10 s"
  $C ping -i 0.01 -c 1000 -W 1 -q 10.0.2.2 > /tmp/eo-ping.txt &
  $C python3 -c "
import socket, time
for i in range(5000):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'EO-MARK %d' % i, ('10.0.2.2', 5555)); s.close(); time.sleep(0.002)"
  wait; grep -E "transmitted|rtt" /tmp/eo-ping.txt | sed 's/^/   ping: /'; rm -f /tmp/eo-ping.txt
  sleep 21   # the reader resumes, and wnc-gw's CopyMonitor (every 10 s) sees it too
  $G sh -c "kill -INT \$(cat $D/pid)"; until $G test -e $D/exit; do sleep 0.2; done
  for i in $(seq 1 60); do $G test -s $D/reader.out && break; sleep 0.5; done
  echo "   reader: $($G cat $D/reader.out)"
  $G grep -E "missed packet copies|without inspection|is inspected|suricata stopped" $D/run.log | cut -c29-200 | sed 's/^/   /'
  $G sh -c "awk -F'|' '/^(ips\\.accepted|ips\\.blocked|ips\\.drop|detect\\.alert |capture\\.)/{gsub(/ /, \"\", \$1); gsub(/ /, \"\", \$3); v[\$1] = \$3} END{for (k in v) printf \"%s=%s \", k, v[k]}' /var/log/wnc-gw/suricata/stats.log" | sed 's/^/   stats: /'; echo
  ;;
clean)
  $G rm -rf $D; true
  ;;
*) sed -n '2,9p' "$0"; exit 2 ;;
esac
