#!/bin/bash
# fastpath_docker.sh — 步驟 C：信任的連線在 TC 直接轉送（routed testbed：cli 10.0.1.2 — gw — srv 10.0.2.2）
# 用法: bash fastpath_docker.sh <tcp|udp|reuse|errors|options|ttl1|control|kill9|l007|idle|nexthop|stale|all>
#   BACKEND=ctmark：用 docker/wnc-gw/ctmark.toml（[trust] backend = "ctmark"）；信任的封包仍經過 forward chain，
#   所以改看 ids chain 的 counter 有沒有停（tc 時兩個都會停）；nexthop 只有 tc 有；stale 只有 ctmark 有
GW="docker exec wnc-gw"; CLI="docker exec wnc-cli"; SRV="docker exec wnc-srv"; B=/opt/sg/wnc-gw
BACKEND=${BACKEND:-tc}; CONF=; CHAIN=forward
[ "$BACKEND" = ctmark ] && { CONF="-c /etc/wnc-gw/ctmark.toml"; CHAIN=ids; }

start() {
  stop; $GW sh -c "rm -f /tmp/fp.log; ($B $CONF run > /dev/null 2> /tmp/fp.log &)"
  for i in $(seq 1 50); do $GW grep -q "traffic is inspected" /tmp/fp.log 2>/dev/null && return 0; sleep 0.2; done
  echo "run did not start"; $GW tail -5 /tmp/fp.log; return 1
}
# 容器的 PID 1 不回收子程序，結束的 wnc-gw 會留成 zombie，所以只等不是 Z 的
stop() { $GW sh -c 'pkill -INT -x wnc-gw; while ps -eo stat=,comm= | grep -q "^[^Z].* wnc-gw$"; do sleep 0.2; done'; }
fwd() { $GW nft list chain inet wnc_gw $CHAIN | grep -m1 -o "packets [0-9]*" | cut -d" " -f2; }
events() { $GW grep -E "$1" /tmp/fp.log | cut -c28-220 | sed 's/^/   /'; }

SRVPY='import socket, sys
proto = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IP, 12, 1)  # IP_RECVTTL
s.bind(("", 5001)); n = 0; ttls = set()
if proto == "tcp":
    s.listen(4)
    while True:
        c, _ = s.accept()
        for line in c.makefile(): n += 1
        print("lines", n, flush=True)
else:
    while True:
        data, anc, _, _ = s.recvmsg(2048, 64)
        n += 1
        ttls.update(val[0] for _, _, val in anc)
        print("datagrams", n, "ttl", sorted(ttls), flush=True)'
CLIPY='import socket, sys, time
proto, port, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.0.1.2", port)); s.connect(("10.0.2.2", 5001))
end = time.time() + secs; n = 0
while time.time() < end:
    s.send(b"line\n"); n += 1; time.sleep(0.1)
s.close(); print("sent", n)'
echo "$SRVPY" | docker exec -i wnc-srv sh -c 'cat > /tmp/fpsrv.py'
echo "$CLIPY" | docker exec -i wnc-cli sh -c 'cat > /tmp/fpcli.py'

server() {  # $1 = tcp|udp：srv 上收資料，印收到幾行（UDP 另外印 TTL）
  $SRV pkill -f /tmp/fpsrv.py; $SRV sh -c "python3 /tmp/fpsrv.py $1 > /tmp/fpsrv.out 2>&1 &"; sleep 0.5
}

client() {  # $1 = tcp|udp，$2 = 來源 port，$3 = 秒數：每 0.1 秒送一行
  $CLI python3 /tmp/fpcli.py "$@" &
}

udp_send() {  # $1 = 來源 port，$2 = 個數，$3 = 多的一行 Python（例如設 IP option）
  $CLI python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
$3
s.bind(('10.0.1.2', $1))
for _ in range($2):
    s.sendto(b'x' * 32, ('10.0.2.2', 5001)); time.sleep(0.01)"
}

case_flow() {  # $1 = tcp|udp
  echo "=== $1: trust at 3 s, del at about 9 s, 16 s in all"
  start || return 1; server $1
  client $1 41000 16; sleep 3
  $GW $B trust add $1 10.0.1.2 41000 10.0.2.2 5001 && echo "   trust add: ok"
  f0=$(fwd); sleep 3; f1=$(fwd)
  echo "   $CHAIN chain while trusted: $f0 -> $f1"
  $GW $B trust list | sed 's/^/   /'
  [ $1 = tcp ] && $SRV timeout 2 tcpdump -c 3 -n -v -i eth0 "tcp port 5001 and src 10.0.1.2" 2>/dev/null | grep -o "ttl [0-9]*" | sort | uniq -c | sed 's/^/   tcpdump: /'
  sleep 3; $GW $B trust del $1 10.0.1.2 41000 10.0.2.2 5001 && echo "   trust del: ok"
  f2=$(fwd); sleep 2; f3=$(fwd); echo "   $CHAIN chain after del: $f2 -> $f3"
  wait; sleep 1; $SRV cat /tmp/fpsrv.out | tail -1 | sed 's/^/   srv: /'
  stop; events "trusted by request|no longer trusted|core ebpf program detached"
}

case "$1" in
tcp|udp) case_flow $1 ;;
reuse)
  echo "=== a new connection from the same port drops the old trust (bare SYN)"
  start || exit 1; server tcp
  client tcp 41001 3; sleep 1
  $GW $B trust add tcp 10.0.1.2 41001 10.0.2.2 5001; $GW $B trust list | tail -n +2 | wc -l | sed 's/^/   trusted before: /'
  wait; sleep 1; client tcp 41001 2; sleep 0.5
  $GW $B trust list | tail -n +2 | wc -l | sed 's/^/   trusted after the new SYN: /'
  wait; stop
  ;;
errors)
  echo "=== failures"
  stop
  $GW $B trust list; echo "   exit=$? (run not running)"
  start || exit 1
  $GW $B trust add tcp 10.0.1.2 1 10.0.2.2 2; echo "   exit=$? (no such connection)"
  $GW $B trust add icmp 10.0.1.2 0 10.0.2.2 0; echo "   exit=$? (icmp)"
  echo 'import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("10.0.1.1", 7000)); s.listen(1)
c, _ = s.accept(); time.sleep(5)' | docker exec -i wnc-gw sh -c 'cat > /tmp/fplocal.py'
  $GW sh -c 'python3 /tmp/fplocal.py > /dev/null 2>&1 &'; sleep 0.5
  $CLI python3 -c "
import socket, time
s = socket.socket(); s.bind(('10.0.1.2', 41002)); s.connect(('10.0.1.1', 7000)); time.sleep(3)" &
  sleep 1; $GW $B trust add tcp 10.0.1.2 41002 10.0.1.1 7000; echo "   exit=$? (to the gateway itself)"
  $GW $B trust del tcp 10.0.1.2 41003 10.0.2.2 5001; echo "   exit=$? (not trusted)"
  docker exec -u nobody wnc-gw $B trust list; echo "   exit=$? (nobody)"
  wait; stop; $GW pkill -f /tmp/fplocal.py
  ;;
options)
  echo "=== IPv4 with IP options (NOP NOP NOP EOL) on a trusted UDP connection"
  start || exit 1; server udp
  udp_send 41020 5 ""; $GW $B trust add udp 10.0.1.2 41020 10.0.2.2 5001 && echo "   trust add: ok"
  f0=$(fwd); udp_send 41020 50 "s.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, bytes([1, 1, 1, 0]))"; sleep 0.5; f1=$(fwd)
  echo "   $CHAIN chain while 50 datagrams with options were sent: $f0 -> $f1"
  $SRV tail -1 /tmp/fpsrv.out | sed 's/^/   srv: /'; $GW $B trust list | tail -n +2 | sed 's/^/   /'
  stop
  ;;
ttl1)
  echo "=== a trusted packet with TTL 1 is left to the kernel (ICMP time exceeded), not forwarded"
  start || exit 1; server udp
  udp_send 41021 5 ""; $GW $B trust add udp 10.0.1.2 41021 10.0.2.2 5001 && echo "   trust add: ok"
  $CLI sh -c 'timeout 4 tcpdump -n -i eth0 "icmp[icmptype] == icmp-timxceed" 2>/dev/null | wc -l > /tmp/icmp.count &'; sleep 1
  udp_send 41021 10 "s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)"; sleep 3.5
  echo "   ICMP time exceeded seen by cli: $($CLI cat /tmp/icmp.count) (at least 1: the kernel sends at most one a second, net.ipv4.icmp_ratelimit)"
  $SRV tail -1 /tmp/fpsrv.out | sed 's/^/   srv: /'; echo "   (expect 5: only the first five reached srv)"
  stop
  ;;
control)
  echo "=== bad requests on control.sock get an error and run keeps answering"
  start || exit 1
  echo 'import socket, sys, time
def ask(data, wait=0):
    s = socket.socket(socket.AF_UNIX); s.connect("/run/wnc-gw/control.sock")
    if data: s.sendall(data)
    time.sleep(wait); s.settimeout(3)
    try: print("  ", s.recv(500).decode().strip()[:120])
    except Exception as e: print("  ", "no reply:", e)
ask(b"not json\n")
ask(b"{\"request\":\"trust\"}\n")
ask(b"x" * 70000)
ask(b"", 0)' | docker exec -i wnc-gw sh -c 'cat > /tmp/fpctl.py'
  $GW python3 /tmp/fpctl.py
  $GW $B trust list > /dev/null && echo "   trust list afterwards: ok"
  stop
  ;;
kill9)
  echo "=== kill -9 leaves control.sock behind; the next run replaces it"
  start || exit 1
  $GW sh -c 'kill -9 $(pgrep -n -x wnc-gw)'; sleep 1
  $GW ls -l /run/wnc-gw/control.sock | sed 's/^/   left: /'
  $GW $B trust list; echo "   trust list with run gone: exit=$?"
  start || exit 1
  $GW $B trust list > /dev/null && echo "   trust list on the next run: ok"
  stop
  ;;
l007)
  echo "=== another account that can reach the socket is rejected (L007)"
  start || exit 1
  $GW sh -c 'chmod 666 /run/wnc-gw/control.sock; chmod o+x /run/wnc-gw'
  docker exec -u nobody wnc-gw $B trust list; echo "   nobody: exit=$?"
  $GW sh -c 'chmod 600 /run/wnc-gw/control.sock; chmod o-x /run/wnc-gw'
  stop; events "L007"
  ;;
idle)
  echo "=== a trusted UDP connection that stops sending is untrusted after 120 s (checked every 10 s)"
  start || exit 1; server udp
  udp_send 41022 5 ""; $GW $B trust add udp 10.0.1.2 41022 10.0.2.2 5001 && echo "   trust add: ok"
  udp_send 41022 20 ""; t0=$(date +%s)
  for i in $(seq 1 30); do sleep 5; [ "$($GW $B trust list | tail -n +2 | wc -l)" = 0 ] && break; done
  echo "   untrusted about $(( $(date +%s) - t0 )) s after the last datagram"
  stop; events "idle"
  ;;
nexthop)
  echo "=== routed next hops: filled after trust, invalidated at once by a route change, refilled when routes are quiet"
  start || exit 1; server tcp
  client tcp 41040 100; sleep 2
  $GW $B trust add tcp 10.0.1.2 41040 10.0.2.2 5001 && echo "   trust add: ok"
  sleep 2; $GW $B trust list | tail -n +2 | awk '{print "   after trust:", $NF, $(NF-1), $(NF-2)}'
  f0=$(fwd); sleep 2; f1=$(fwd); echo "   $CHAIN chain while trusted: $f0 -> $f1"
  $SRV timeout 2 tcpdump -c 3 -n -v -i eth0 "tcp port 5001 and src 10.0.1.2" 2>/dev/null | grep -o "ttl [0-9]*" | sort | uniq -c | sed 's/^/   tcpdump: /'
  $GW ip route add 10.9.9.0/24 via 10.0.2.2; sleep 0.3
  $GW $B trust list | tail -n +2 | awk '{print "   right after a route change:", $NF, $(NF-1), $(NF-2)}'
  sleep 12; $GW $B trust list | tail -n +2 | awk '{print "   12 s later:", $NF, $(NF-1), $(NF-2)}'
  echo "   changing a route every 0.5 s for 70 s"
  for i in $(seq 1 70); do $GW ip route del 10.9.9.0/24; sleep 0.5; $GW ip route add 10.9.9.0/24 via 10.0.2.2; sleep 0.5; done
  f2=$(fwd); sleep 2; f3=$(fwd); echo "   $CHAIN chain during the changes: $f2 -> $f3"
  $GW ip route del 10.9.9.0/24; sleep 13
  $GW $B trust list | tail -n +2 | awk '{print "   after the changes stop:", $NF, $(NF-1), $(NF-2)}'
  wait; sleep 1; $SRV tail -1 /tmp/fpsrv.out | sed 's/^/   srv: /'
  stop; events "D007|D008|stable again|core ebpf program detached"
  ;;
stale)
  echo "=== ctmark: kill -9 leaves the trust mark in conntrack; the next run clears it before installing its table"
  start || exit 1; server tcp
  client tcp 41050 12; sleep 2
  $GW $B trust add tcp 10.0.1.2 41050 10.0.2.2 5001 && echo "   trust add: ok"
  $GW sh -c 'kill -9 $(pgrep -n -x wnc-gw)'; sleep 1
  $GW conntrack -L -m 0x80000000/0x80000000 2>/dev/null | wc -l | sed 's/^/   marked after kill -9: /'
  start || exit 1
  $GW conntrack -L -m 0x80000000/0x80000000 2>/dev/null | wc -l | sed 's/^/   marked after the next start: /'
  f0=$(fwd); sleep 2; f1=$(fwd); echo "   $CHAIN chain after the next start: $f0 -> $f1"
  wait; stop; events "earlier run|T005"
  ;;
all)
  cases="tcp udp reuse errors options ttl1 control kill9 l007 idle nexthop"
  [ "$BACKEND" = ctmark ] && cases="tcp udp reuse errors options ttl1 kill9 idle stale"
  for c in $cases; do bash "$0" $c; done ;;
*) echo "usage: bash fastpath_docker.sh <tcp|udp|reuse|errors|options|ttl1|control|kill9|l007|idle|nexthop|stale|all>"; exit 2 ;;
esac
