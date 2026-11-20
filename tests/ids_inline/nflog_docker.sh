#!/bin/bash
# NFLOG as the ids-mode data path (Docker testbed, routed): the kernel forwards as usual and hands only copies to Suricata
#   bypasses wnc-gw: installs an nft log group (table inet nflt) directly in the gw container and receives with suricata --nflog
#   basic    alerts for both ICMP and TCP payload (marker after 1300 bytes) must appear: copies are full packets
#   trust    set the trust bit with wnc-gw trust add during a TCP transfer; the log rule counter must stop; it resumes after trust del
#   kill     SIGKILL Suricata during continuous ping: forwarding is unaffected
#   startup  start and stop Suricata 20 times under ping -f: must not crash (NFQ does)
#   groups   symhash over two log groups, two Suricata workers: both directions of each of 8 connections land in the same group, all 8 alerts present
#   overflow default netlink buffer (18 KB) plus a UDP flood: see where missed copies are recorded
#   K=all keeps checksum validation: unlike NFQ, NFLOG does not flag packets whose checksum is not computed yet, so veth/GRO packets look like checksum errors
# Usage: bash nflog_docker.sh <basic|trust|kill|startup|groups|overflow> ...   finally bash nflog_docker.sh clean
G="docker exec wnc-gw"; GI="docker exec -i wnc-gw"; C="docker exec wnc-cli"; S="docker exec wnc-srv"
D=/tmp/nfl
P=$((20000 + RANDOM % 20000))   # different source port each run to avoid the previous run's TIME_WAIT and conntrack entry

setup() {
  $G mkdir -p $D
  $GI sh -c "cat > $D/test.rules" <<'EOF'
alert icmp any any -> any any (msg:"nflog icmp"; sid:1000101; rev:1;)
alert tcp any any -> any 5001 (msg:"nflog payload"; flow:to_server,established; content:"NFLOG-PAYLOAD-MARKER"; sid:1000102; rev:1;)
EOF
  for groups in "2" "10 11"; do
    $GI sh -c "cat > $D/s-$(echo $groups | tr ' ' _).yaml" <<EOF
%YAML 1.1
---
include: /etc/suricata/suricata.yaml
default-rule-path: $D
rule-files:
  - test.rules
nflog:
$(for g in $groups; do printf '  - group: %s\n    buffer-size: %s\n' $g ${BUF:-18432}; done)
  - group: default
    qthreshold: 1
    qtimeout: 100
    max-size: 20000
EOF
  done
}

table() {  # $1 = 1 or 2 groups
  if [ "$1" = 1 ]; then body="counter log group 2"; else body="symhash mod 2 vmap { 0 : jump g0, 1 : jump g1 }"; fi
  $GI nft -f - <<EOF
table inet nflt
delete table inet nflt
table inet nflt {
  chain main {
    type filter hook forward priority 0; policy accept;
    ct mark & 0x80000000 == 0x80000000 counter accept
    $body
  }
  chain g0 {
    counter log group 10
  }
  chain g1 {
    counter log group 11
  }
}
EOF
}

counters() { $G nft list table inet nflt | grep -o "packets [0-9]*" | awk '{print $2}' | tr '\n' ' '; }

start() {  # $1 = yaml name (2 or 10_11)
  $G sh -c "rm -rf $D/log; mkdir -p $D/log; suricata -c $D/s-$1.yaml --nflog -k ${K:-none} -l $D/log --runmode workers --set unix-command.enabled=no > $D/log/stdout 2>&1 & echo \$! > $D/pid"
  local i
  for i in $(seq 1 100); do $G grep -q "Engine started" $D/log/stdout 2>/dev/null && return 0; alive || break; sleep 0.2; done
  echo "suricata did not start"; $G tail -5 $D/log/stdout; return 1
}

# PID 1 in the container does not reap children, so an exited Suricata stays a zombie and kill -0 cannot tell
alive() { $G sh -c 'p=$(cat '$D'/pid); [ -e /proc/$p ] && ! grep -q "Z (zombie)" /proc/$p/status'; }
stop() { $G sh -c "kill -TERM \$(cat $D/pid)"; while alive; do sleep 0.2; done; }

server() { $S pkill -f nflsrv; docker exec -d wnc-srv python3 -c "
import socket, threading  # nflsrv
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('', 5001)); s.listen(64)
def drain(c):
    while c.recv(65536): pass
while True:
    threading.Thread(target=drain, args=(s.accept()[0],), daemon=True).start()
"; sleep 0.5; }

client() {  # $1 = source port, $2 = seconds; a line every 0.1 s, the first preceded by 1300 bytes then the marker
  $C python3 -c "
import socket, time
c = socket.create_connection(('10.0.2.2', 5001), source_address=('10.0.1.2', $1))
c.sendall(b'x' * 1300 + b'NFLOG-PAYLOAD-MARKER\n')
end = time.time() + $2
while time.time() < end:
    c.sendall(b'line\n'); time.sleep(0.1)
c.close()"
}

alerts() { $G sh -c "cat $D/log/fast.log 2>/dev/null | grep -c \":$1:\""; }

case "$1" in
basic)
  setup; table 1; start 2 || exit 1; server
  $C ping -c 5 -i 0.2 -W 1 10.0.2.2 | grep -o "[0-9]* received"
  client $P 1
  sleep 1; echo "log rule packets: $(counters)"; stop
  echo "icmp alerts: $(alerts 1000101)  payload alerts: $(alerts 1000102)  tcp invalid checksum: $($G sh -c "grep tcp.invalid_checksum $D/log/stats.log | tail -1 | awk '{print \$NF}'")"
  ;;
trust)
  setup; table 1; start 2 || exit 1; server
  client $P 6 &
  sleep 2; $G /opt/sg/wnc-gw trust add tcp 10.0.1.2 $P 10.0.2.2 5001 2>&1 | grep -o "connection trusted"
  a=$(counters); sleep 2; b=$(counters)
  $G /opt/sg/wnc-gw trust del tcp 10.0.1.2 $P 10.0.2.2 5001 2>&1 | grep -o "no longer trusted"
  sleep 1.5; c=$(counters); wait
  echo "log rule packets (trusted accept, logged): after trust: $a  2 s later: $b  1.5 s after del: $c"
  stop
  ;;
kill)
  setup; table 1; start 2 || exit 1
  $C ping -c 100 -i 0.05 -W 1 10.0.2.2 > /tmp/nfl-ping.txt &
  sleep 1.5; $G sh -c "kill -KILL \$(cat $D/pid)"; echo "suricata killed"; wait
  grep -o "[0-9]* packets transmitted, [0-9]* received" /tmp/nfl-ping.txt; rm -f /tmp/nfl-ping.txt
  echo "log rule packets: $(counters)"
  ;;
startup)
  setup; table 1
  $C sh -c "timeout 120 ping -f -q 10.0.2.2 > /dev/null 2>&1 &"
  ok=0; crashed=0; warned=0
  for run in $(seq 1 20); do
    start 2 > /dev/null; sleep 1; stop
    # a zombie's exit status is field 52 of /proc/<pid>/stat (waitpid format)
    st=$($G sh -c "awk '{print \$52}' /proc/\$(cat $D/pid)/stat")
    if [ $((st & 127)) -ne 0 ]; then
      crashed=$((crashed + 1)); echo "run $run: signal $((st & 127)); $($G grep -o "stacktrace:sig [0-9]*:.*Init[^;]*" $D/log/stdout | cut -c1-160)"
    else
      ok=$((ok + 1))
    fi
    $G grep -q "nflog_handle_packet error" $D/log/stdout && warned=$((warned + 1))
  done
  $C pkill -x ping
  echo "under ping -f: clean $ok/20, crashed $crashed/20, runs with nflog_handle_packet errors $warned/20; log rule packets: $(counters)"
  ;;
groups)
  setup; table 2; start 10_11 || exit 1; server
  for p in $(seq $P $((P + 7))); do client $p 1 & done; wait
  sleep 1; echo "packets per group (trusted accept, g0, g1): $(counters)"; stop
  echo "payload alerts: $(alerts 1000102)/8"
  $G grep -E "W#0|W#1|threads" $D/log/stdout | head -4
  ;;
overflow)
  setup; table 1; start 2 || exit 1
  $S sh -c "pkill -x iperf3; iperf3 -s -D"; sleep 0.5
  $C iperf3 -u -b ${RATE:-2G} -l 1400 -t 3 -c 10.0.2.2 | grep -E "receiver"
  echo "netlink sockets of suricata (Rmem, Drops):"
  $G sh -c "awk -v p=\$(cat $D/pid) 'NR == 1 || (\$2 == 12)' /proc/net/netlink" | awk '{print $2, $3, $5, $9}' | head -6
  echo "log rule packets: $(counters)"
  stop
  $G sh -c "grep -i -E 'nflog|kernel|drop' $D/log/stats.log | sort -u -t'|' -k1,1 | tail -8; grep -i -E 'nflog|buffer|losing' $D/log/stdout | head -5"
  $S pkill -x iperf3
  ;;
clean)
  $G nft delete table inet nflt 2>/dev/null; $G rm -rf $D; $S pkill -f nflsrv; $S pkill -x iperf3; true
  ;;
*) sed -n '2,12p' "$0"; exit 2 ;;
esac
