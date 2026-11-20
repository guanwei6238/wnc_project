#!/bin/bash
# hook_docker.sh — 使用者的特徵程式掛在哪裡才看得到信任的封包（routed testbed：cli 10.0.1.2 — gw — srv 10.0.2.2）
#   gw 的 LAN 口 ingress（排在核心程式後面）和 WAN 口 egress 各掛一支 tcx_count.py，只數長度 342 的幀
#   （UDP 300 bytes payload），先送 20 個不信任的、trust add 之後再送 20 個
# 用法: bash hook_docker.sh   （BACKEND=ctmark 時用 ctmark.toml）
GW="docker exec wnc-gw"; CLI="docker exec wnc-cli"; SRV="docker exec wnc-srv"; B=/opt/sg/wnc-gw
CONF=; [ "${BACKEND:-tc}" = ctmark ] && CONF="-c /etc/wnc-gw/ctmark.toml"
LAN=$($GW sh -c '. /run/wnc-ifaces; echo $LAN_IF'); WAN=$($GW sh -c '. /run/wnc-ifaces; echo $WAN_IF')
P=$((42000 + RANDOM % 1000))

docker cp "$(dirname "$0")/tcx_count.py" wnc-gw:/tmp/tcx_count.py > /dev/null
$GW sh -c 'pkill -f "tcx_coun[t]"; pkill -INT -x wnc-gw; while ps -eo stat=,comm= | grep -q "^[^Z].* wnc-gw$"; do sleep 0.2; done; rm -f /tmp/hook.log /tmp/cnt.*'
$GW sh -c "($B $CONF run > /dev/null 2> /tmp/hook.log &)"
for i in $(seq 1 50); do $GW grep -q "traffic is inspected" /tmp/hook.log 2>/dev/null && break; sleep 0.2; done
$GW sh -c "python3 /tmp/tcx_count.py $LAN ingress 342 /tmp/cnt.lan_in > /tmp/cnt.err 2>&1 &"
$GW sh -c "python3 /tmp/tcx_count.py $WAN egress 342 /tmp/cnt.wan_out >> /tmp/cnt.err 2>&1 &"
sleep 1; $GW cat /tmp/cnt.err
$GW bpftool net show dev $LAN 2>/dev/null | grep -A3 tcx | sed 's/^/   /'

send() {
  $CLI python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.0.1.2', $P))
for _ in range(20):
    s.sendto(b'x' * 300, ('10.0.2.2', 5001)); time.sleep(0.02)"
  sleep 0.5
}
counts() { echo "lan ingress after core=$($GW cat /tmp/cnt.lan_in) wan egress=$($GW cat /tmp/cnt.wan_out)"; }

echo "=== backend ${BACKEND:-tc}, $LAN -> $WAN, source port $P"
send; echo "   20 untrusted: $(counts)"
$GW $B trust add udp 10.0.1.2 $P 10.0.2.2 5001 && echo "   trust add: ok"
send; echo "   +20 trusted:  $(counts)"
$GW $B trust list | sed 's/^/   /'
$GW sh -c 'pkill -f "tcx_coun[t]"; pkill -INT -x wnc-gw'
