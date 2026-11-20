#!/bin/bash
# wnc-gw ids/ips modes (Pi, bridge, wnc-gw run): Pi version of protection_docker.sh
#   fcli(10.9.0.1) --veth-- x-lan [wgw: br0] x-wan --veth-- fsrv(10.9.0.2); Suricata uses a yaml that includes the system suricata.yaml plus test rules
#   net up|down  create/delete fcli, fsrv
#   doctor       run doctor once each for ids and ips (as root, and as the wnc account inside wgw)
#   ids1 trust kill groups ips startup missed: same as protection_docker.sh; startup runs N times (default 20), missed sends UDP with python
#   bind         run another Suricata bound to group 10 inside wgw: doctor gives a hint, run logs ERROR and retries, ready once the other one stops
#   runmode      ids and ips with one and multiple queues/groups: Suricata has only W threads (workers), ICMP alerts; with AUTOFP=1 the yaml sets runmode: autofp explicitly
#   alerts autotrust: same as protection_docker.sh (PROTECTION=ips); autotrust first runs doctor once with nf_conntrack_acct=0
# Prerequisites: sudo sh env.sh up; system suricata service stopped; wnc-gw at $GW
# Usage: sudo bash protection_pi.sh <net up|net down|doctor|ids1|trust|kill|groups|ips|startup|missed|bind|runmode|alerts|autotrust|clean>
GW=${GW:-/tmp/wncgw/wnc-gw}; D=/tmp/wncgw/pt; SLOG=/var/log/wnc-gw/suricata
W="ip netns exec wgw"; C="ip netns exec fcli"; S="ip netns exec fsrv"
P=$((20000 + RANDOM % 20000))

setup() {  # $1 = extra top-level config lines, $2 = extra [suricata] lines, $3 = extra rules
  mkdir -p $D
  cat > $D/test.rules <<EOF
alert icmp any any -> any any (msg:"wt icmp"; sid:1000201; rev:1;)
alert tcp any any -> any 5001 (msg:"wt payload"; flow:to_server,established; content:"WT-PAYLOAD-MARKER"; sid:1000202; rev:1;)
$3
EOF
  printf '%%YAML 1.1\n---\ninclude: /etc/suricata/suricata.yaml\ndefault-rule-path: %s\nrule-files:\n  - test.rules\n' $D > $D/s.yaml
  printf 'mode = "bridge"\nxdp = "off"\n%s\n\n[ports]\nlan = "g-lan"\nwan = "g-wan"\n\n[suricata]\nconfig = "%s"\n%s\n' "$1" $D/s.yaml "$2" > $D/setting.toml
}

start() {
  rm -f $SLOG/fast.log $SLOG/eve.json $D/run.log $D/exit
  ( $W $GW ${RUNARGS:-} -c $D/setting.toml run > /dev/null 2> $D/run.log; echo $? > $D/exit ) &
  local i
  for i in $(seq 1 150); do
    grep -q "traffic is inspected" $D/run.log 2>/dev/null && return 0
    [ -e $D/exit ] && break; sleep 0.2
  done
  echo "wnc-gw did not start"; tail -5 $D/run.log; return 1
}

stop() { kill -INT $(pgrep -n -x wnc-gw); until [ -e $D/exit ]; do sleep 0.2; done; echo "wnc-gw exit=$(cat $D/exit)"; }

ids_rules() { $W nft list table inet wnc_gw | sed -n '/chain ids/,$p' | grep -E "chain|log|queue|vmap|accept|drop" | sed 's/^\s*/   /'; }
ids_count() { $W nft list chain inet wnc_gw ids | grep -o "packets [0-9]*" | head -1 | cut -d" " -f2; }
alerts() { grep -c ":$1:" $SLOG/fast.log 2>/dev/null; }
suricata_pid() { grep -o "suricata started pid=[0-9]*" $D/run.log | tail -1 | cut -d= -f2; }
threads() { cat /proc/$1/task/*/comm | sort | uniq -c | awk '{printf "%s×%s ", $2, $1}'; }
events() { grep -E "$1" $D/run.log | cut -c28-200 | sed 's/^/   /'; }

server() { pkill -f wtsrv; $S python3 -c "
import socket, threading  # wtsrv
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('', 5001)); s.listen(64)
def drain(c):
    while c.recv(65536): pass
while True:
    threading.Thread(target=drain, args=(s.accept()[0],), daemon=True).start()
" > /dev/null 2>&1 & sleep 0.5; }

client() {  # $1 = source port, $2 = seconds; first chunk is 1300 bytes then the marker, then a line every 0.1 s
  $C python3 -c "
import socket, time
c = socket.create_connection(('10.9.0.2', 5001), source_address=('10.9.0.1', $1))
c.sendall(b'x' * 1300 + b'WT-PAYLOAD-MARKER\n')
end = time.time() + $2
while time.time() < end:
    c.sendall(b'line\n'); time.sleep(0.1)
c.close()"
}

clean_client() {  # $1 = source port, $2 = seconds: a line every 0.1 s, no payload marker
  $C python3 -c "
import socket, time
c = socket.create_connection(('10.9.0.2', 5001), source_address=('10.9.0.1', $1))
end = time.time() + $2
while time.time() < end:
    c.sendall(b'line\\n'); time.sleep(0.1)
c.close()"
}

case "$1" in
net)
  if [ "$2" = up ]; then
    for ns in fcli fsrv; do ip netns add $ns; ip netns exec $ns sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1; ip -n $ns link set lo up; done
    ip link add c-lan netns fcli type veth peer name x-lan netns wgw
    ip link add s-wan netns fsrv type veth peer name x-wan netns wgw
    for l in x-lan x-wan; do ip -n wgw link set $l master br0; ip -n wgw link set $l up; done
    ip -n fcli addr add 10.9.0.1/24 dev c-lan; ip -n fcli link set c-lan up
    ip -n fsrv addr add 10.9.0.2/24 dev s-wan; ip -n fsrv link set s-wan up
    echo 'table inet t { counter got {}; chain in { type filter hook input priority 0; policy accept; udp dport 9 counter name "got" drop; }; }' | $S nft -f -
    modprobe nf_conntrack; $W sysctl -q -w net.netfilter.nf_conntrack_acct=1
    $C ping -c 1 -W 2 10.9.0.2 | grep -o "1 received"
  else
    for ns in fcli fsrv; do ip netns del $ns 2>/dev/null; done; true
  fi
  ;;
doctor)
  for prot in ids ips; do
    setup "protection = \"$prot\"" ""
    echo "===== protection = $prot (root)"; $W $GW -c $D/setting.toml doctor; echo "exit=$?"
    echo "===== protection = $prot (wnc)"; $W sudo -u wnc $GW -c $D/setting.toml doctor > $D/doctor-wnc.txt; echo "exit=$?"
    $W $GW -c $D/setting.toml doctor | diff - $D/doctor-wnc.txt | sed 's/^/   /'
  done
  ;;
ids1)
  setup "" ""; start || exit 1
  sp=$(suricata_pid)
  echo "== ids chain after ready"; ids_rules
  echo "== suricata: $(tr '\0' ' ' < /proc/$sp/cmdline | grep -o -- "--nflog --include [^ ]*")"
  sed 's/^/   /' /run/wnc-gw/suricata-nflog.yaml
  echo "== threads: $(threads $sp)"
  events 'source="suricata".*([Nn][Ff][Ll][Oo][Gg]|runmode|checksum)'
  server; $C ping -c 3 -i 0.2 -W 1 10.9.0.2 | grep -o "[0-9]* received"; client $P 1; sleep 1
  stop
  echo "icmp alerts: $(alerts 1000201)  payload alerts: $(alerts 1000202)"
  events "inspected|without inspection|suricata started"
  ;;
trust)
  setup "" ""; start || exit 1; server
  client $P 6 &
  sleep 2; $W $GW trust add tcp 10.9.0.1 $P 10.9.0.2 5001 2>&1 | grep -o "connection trusted"
  a=$(ids_count); sleep 2; b=$(ids_count)
  $W $GW trust del tcp 10.9.0.1 $P 10.9.0.2 5001 2>&1 | grep -o "no longer trusted"
  sleep 1.5; c=$(ids_count); wait $!
  echo "ids chain packets: after trust $a, 2 s later $b, 1.5 s after del $c"
  stop
  ;;
kill)
  setup "" "when_unavailable = \"${WHEN:-accept}\""; start || exit 1
  $C ping -c 120 -i 0.05 -W 1 10.9.0.2 > $D/ping.txt &
  pp=$!
  sleep 1.5; kill -KILL $(suricata_pid); echo "suricata killed (when_unavailable=${WHEN:-accept})"; wait $pp
  grep -o "[0-9]* packets transmitted, [0-9]* received" $D/ping.txt
  for i in $(seq 1 75); do grep -q "is inspected.*uninspected_ms" $D/run.log && break; sleep 0.2; done
  events "without inspection|is inspected|suricata (stopped|started)"
  stop
  ;;
groups)
  setup "" 'group = "10-11"'; start || exit 1
  echo "== ids chains after ready"; ids_rules
  echo "== threads: $(threads $(suricata_pid))"
  server; pids=; for p in $(seq $P $((P + 7))); do client $p 1 & pids="$pids $!"; done; wait $pids; sleep 1
  echo "per group: $($W nft list table inet wnc_gw | awk '/chain ids_g/{c=$2} /log group/{for (i = 1; i <= NF; i++) if ($i == "packets") printf "%s=%s ", c, $(i + 1)}')"
  stop
  echo "payload alerts: $(alerts 1000202)/8"
  ;;
ips)
  setup 'protection = "ips"' ""; start || exit 1
  sp=$(suricata_pid)
  echo "== ids chain after ready"; ids_rules
  echo "== suricata: $(tr '\0' ' ' < /proc/$sp/cmdline | grep -o -- "-q [0-9:]*")"
  echo "== threads: $(threads $sp)"
  $C ping -c 3 -i 0.2 -W 1 10.9.0.2 | grep -o "[0-9]* received"
  stop
  echo "icmp alerts: $(alerts 1000201)"
  ;;
startup)
  setup "" ""
  $C timeout 900 ping -f -q 10.9.0.2 > /dev/null 2>&1 &
  for run in $(seq 1 ${N:-20}); do
    start > /dev/null || { echo "run $run did not start"; break; }
    sleep 1; stop > /dev/null
    echo "run $run: $(grep -o 'suricata stopped pid=[0-9]* exit="[^"]*"' $D/run.log)"
  done
  pkill -x ping
  ;;
missed)
  setup "" ""; start || exit 1
  sp=$(suricata_pid)
  inodes=$(ls -l /proc/$sp/fd | grep -o 'socket:\[[0-9]*\]' | tr -dc '0-9\n' | tr '\n' ' ')
  $S nft reset counter inet t got > /dev/null
  $C python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); n = 0; t0 = time.time()
while n < 60000:
    for _ in range(100): s.sendto(b'x' * 64, ('10.9.0.2', 9))
    n += 100; time.sleep(max(0, t0 + n / 10000 - time.time()))
print('sent', n, 'in', round(time.time() - t0, 2), 's')" &
  cp=$!
  sleep 1; kill -STOP $sp; echo "suricata $sp stopped for 3 s"; sleep 3; kill -CONT $sp; wait $cp
  sleep 0.5; echo "   delivered: $($S nft list counter inet t got | grep -o 'packets [0-9]*')"
  for i in $(seq 1 30); do grep -q "missed packet copies" $D/run.log && break; sleep 0.5; done
  echo "kernel drops on suricata's netfilter sockets: $($W awk -v ids=" $inodes" '$2 == 12 && index(ids, " " $10 " ") {d += $9} END{print d + 0}' /proc/net/netlink)"
  events "missed packet copies|nflog sockets"
  stop
  ;;
bind)
  setup "" ""; rm -rf $D/other $D/other.pid; mkdir -p $D/other
  printf '%%YAML 1.1\n---\nnflog:\n  - group: 10\n    buffer-size: 18432\n  - group: default\n    qthreshold: 1\n    qtimeout: 100\n    max-size: 20000\n' > $D/other.yaml
  $W suricata -c $D/s.yaml --nflog --include $D/other.yaml -l $D/other --set unix-command.enabled=no --set coredump.max-dump=0 -D --pidfile $D/other.pid > /dev/null 2>&1
  for i in $(seq 1 100); do grep -q "Engine started" $D/other/suricata.log 2>/dev/null && break; sleep 0.2; done
  echo "== other suricata pid $(cat $D/other.pid)"
  echo "== doctor"; $W $GW -c $D/setting.toml doctor | grep -i -E -A3 "running suricata|nflog" | sed 's/^/   /'
  rm -f $D/run.log $D/exit
  ( $W $GW -c $D/setting.toml run > /dev/null 2> $D/run.log; echo $? > $D/exit ) &
  sleep 12; kill -TERM $(cat $D/other.pid); echo "== other suricata stopped"
  for i in $(seq 1 150); do grep -q "traffic is inspected" $D/run.log && break; sleep 0.2; done
  events "cannot bind|suricata stopped|is inspected|without inspection"
  stop
  ;;
runmode)
  for c in 'ids|' 'ids|group = "10-11"' 'ips|' 'ips|queue = "0-3"'; do
    p=${c%%|*}; extra=${c#*|}
    setup "protection = \"$p\"" "$extra"
    [ "$AUTOFP" = 1 ] && echo 'runmode: autofp' >> $D/s.yaml
    start || exit 1
    t=$(cat /proc/$(suricata_pid)/task/*/comm | grep -E "^(W|RX|TX)" | sort | tr '\n' ' ')
    $C ping -c 3 -i 0.2 -W 1 10.9.0.2 > /dev/null
    stop > /dev/null
    echo "$p ${extra:-default}: $t| icmp alerts: $(alerts 1000201)"
  done
  echo "yaml runmode: $(suricata --dump-config -c $D/s.yaml 2>/dev/null | grep '^runmode')"
  ;;
alerts)
  setup "" ""; RUNARGS="--log-level debug" start || exit 1; server
  grep -E "reading suricata's alerts" $D/run.log | cut -c28-220
  $C ping -c 3 -i 0.2 -W 1 10.9.0.2 | grep -o "[0-9]* received"; client $P 1; sleep 1
  echo "== rotate: mv eve.json eve.json.1, SIGHUP suricata"
  mv $SLOG/eve.json $SLOG/eve.json.1; kill -HUP $(suricata_pid); sleep 1
  client $((P + 1)) 1; sleep 1
  echo "== truncate eve.json"
  : > $SLOG/eve.json; sleep 1
  client $((P + 2)) 1; sleep 1
  stop
  echo "alerts in fast.log: icmp $(alerts 1000201), payload $(alerts 1000202)"
  echo "alert lines in wnc-gw's log: icmp $(grep -c 'DEBUG suricata alert.*sid=1000201' $D/run.log), payload $(grep -c 'DEBUG suricata alert.*sid=1000202' $D/run.log)"
  grep -m1 'DEBUG suricata alert.*sid=1000202' $D/run.log | cut -c28-260
  grep -E "raised alerts|replaced|truncated|appeared|cannot read|EVE" $D/run.log | grep -v 'DEBUG suricata alert' | cut -c28-300
  ;;
autotrust)
  setup "${PROTECTION:+protection = \"$PROTECTION\"}" "" \
    'alert tcp any any -> any 5001 (msg:"wt fin"; flow:to_server; flags:F+; sid:1000203; rev:1;)'
  printf '\n[trust]\nauto = true\nmin_packets = 5\nmin_age = 2\nttl = 10\ncheck_interval = 1\n' >> $D/setting.toml
  $W sysctl -q -w net.netfilter.nf_conntrack_acct=0
  echo "== doctor with nf_conntrack_acct = 0"; $W $GW -c $D/setting.toml doctor | grep -i -E "acct|trust" | sed 's/^/   /'
  $W sysctl -q -w net.netfilter.nf_conntrack_acct=1
  echo "== doctor with nf_conntrack_acct = 1"; $W $GW -c $D/setting.toml doctor | grep -i -E "acct|trust" | sed 's/^/   /'
  RUNARGS="--log-level debug" start || exit 1; server
  clean_client $P 25 &
  cp=$!
  sleep 1; c1=$(ids_count); sleep 4; c2=$(ids_count); sleep 3; c3=$(ids_count)
  echo "ids chain packets at 1 s, 5 s, 8 s: $c1 $c2 $c3 (trusted from about 3 s: grows by only a few after that)"
  client $((P + 1)) 6
  wait $cp; sleep 2
  stop
  echo "== clean connection: port $P, connection with the payload marker: port $((P + 1))"
  grep -E "automatic trust|connection trusted|trust expired|trust revoked|will not be trusted|watching the connection again" $D/run.log | cut -c28-300
  ;;
clean)
  rm -rf $D /run/wnc-gw/suricata-nflog.yaml; pkill -f wtsrv; true
  ;;
*) sed -n '2,11p' "$0"; exit 2 ;;
esac
