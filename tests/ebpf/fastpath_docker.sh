#!/bin/bash
# fastpath_docker.sh — 步驟 C：信任的連線在 TC 直接轉送（routed testbed：cli 10.0.1.2 — gw — srv 10.0.2.2）
# 用法: bash fastpath_docker.sh <tcp|udp|reuse|errors|all>
GW="docker exec wnc-gw"; CLI="docker exec wnc-cli"; SRV="docker exec wnc-srv"; B=/opt/sg/wnc-gw

start() {
  stop; $GW sh -c "rm -f /tmp/fp.log; ($B run > /dev/null 2> /tmp/fp.log &)"
  for i in $(seq 1 50); do $GW grep -q "traffic is inspected" /tmp/fp.log 2>/dev/null && return 0; sleep 0.2; done
  echo "run did not start"; $GW tail -5 /tmp/fp.log; return 1
}
# 容器的 PID 1 不回收子程序，結束的 wnc-gw 會留成 zombie，所以只等不是 Z 的
stop() { $GW sh -c 'pkill -INT -x wnc-gw; while ps -eo stat=,comm= | grep -q "^[^Z].* wnc-gw$"; do sleep 0.2; done'; }
fwd() { $GW nft list chain inet wnc_gw forward | grep -m1 -o "packets [0-9]*" | cut -d" " -f2; }
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

case_flow() {  # $1 = tcp|udp
  echo "=== $1: trust at 3 s, del at about 9 s, 16 s in all"
  start || return 1; server $1
  client $1 41000 16; sleep 3
  $GW $B trust add $1 10.0.1.2 41000 10.0.2.2 5001 && echo "   trust add: ok"
  f0=$(fwd); sleep 3; f1=$(fwd)
  echo "   forward chain while trusted: $f0 -> $f1"
  $GW $B trust list | sed 's/^/   /'
  [ $1 = tcp ] && $SRV timeout 2 tcpdump -c 3 -n -v -i eth0 "tcp port 5001 and src 10.0.1.2" 2>/dev/null | grep -o "ttl [0-9]*" | sort | uniq -c | sed 's/^/   tcpdump: /'
  sleep 3; $GW $B trust del $1 10.0.1.2 41000 10.0.2.2 5001 && echo "   trust del: ok"
  f2=$(fwd); sleep 2; f3=$(fwd); echo "   forward chain after del: $f2 -> $f3"
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
all) for c in tcp udp reuse errors; do bash "$0" $c; done ;;
*) echo "usage: bash fastpath_docker.sh <tcp|udp|reuse|errors|all>"; exit 2 ;;
esac
