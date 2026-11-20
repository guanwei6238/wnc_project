#!/bin/bash
# run_docker.sh — [[features]] 在 run 裡的端到端測試（routed testbed：cli 10.0.1.2 — gw — srv 10.0.2.2）
#   四個 feature 用同一支 prog/：egress（flows_tc、tc-egress、FLOWS）、ingress（flows_tc、tc-ingress、PFLOWS per-CPU）、
#   events（flows_tc、tc-egress、EVENTS ringbuf）、xdp（flows_xdp、xdp native、FLOWS）
#   cli 從同一個來源 port 送 20 個 UDP（payload 300 bytes，幀 342 bytes），trust add，再送 20 個
#   預期（backend tc）：egress、xdp 40 個；ingress 20 個（信任的在核心程式就被 redirect）；events 40 筆 len=342
#   BACKEND=ctmark 時 ingress 也是 40
# 用法: bash run_docker.sh   （先 bash doctor_docker.sh 編好 prog/ 並複製到容器）
D=$(cd "$(dirname "$0")" && pwd); GW="docker exec wnc-gw"; CLI="docker exec wnc-cli"; B=/opt/sg/wnc-gw
P=$((43000 + RANDOM % 1000)); OUT=/var/log/wnc-gw/features
$GW sh -c "pkill -INT -x wnc-gw; while ps -eo stat=,comm= | grep -q '^[^Z].* wnc-gw$'; do sleep 0.2; done; rm -rf $OUT /tmp/feat/run.log"
CONF=setting; [ "${BACKEND:-tc}" = ctmark ] && CONF=ctmark
$GW sh -c "cp /etc/wnc-gw/$CONF.toml /tmp/feat/run.toml
for n in egress:flows_tc:flows:tc-egress ingress:flows_tc:pflows:tc-ingress events:flows_tc:events:tc-egress xdp:flows_xdp:flows:xdp; do
  IFS=: read name entry def hook <<EOF
\$n
EOF
  printf '\n[[features]]\nname = \"%s\"\nprogram = \"/tmp/feat/prog.o\"\nentry = \"%s\"\ndefinition = \"/tmp/feat/%s.json\"\nhook = \"%s\"\n' \$name \$entry \$def \$hook >> /tmp/feat/run.toml
done
($B --log-level debug -c /tmp/feat/run.toml run > /dev/null 2> /tmp/feat/run.log &)"
for i in $(seq 1 75); do $GW grep -q "traffic is inspected" /tmp/feat/run.log 2>/dev/null && break; sleep 0.2; done
$GW grep -E "feature program|G0[0-9][0-9]" /tmp/feat/run.log | cut -c28-260 | sed 's/^/   /'

send() {
  $CLI python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.0.1.2', $P))
for _ in range(20):
    s.sendto(b'x' * 300, ('10.0.2.2', 5001)); time.sleep(0.02)"
}
echo "=== backend ${BACKEND:-tc}, source port $P"
send; sleep 2.5
$GW $B trust add udp 10.0.1.2 $P 10.0.2.2 5001 && echo "   trust add: ok"
send; sleep 2.5
$GW sh -c 'pkill -INT -x wnc-gw; while ps -eo stat=,comm= | grep -q "^[^Z].* wnc-gw$"; do sleep 0.2; done'
$GW grep -E "feature program detached" /tmp/feat/run.log | cut -c28-200 | sed 's/^/   /'
$GW ls -la $OUT | sed 's/^/   /'
$GW python3 -c "
import json
port = $P
for name in ['egress', 'ingress', 'xdp']:
    rows = [json.loads(l) for l in open('$OUT/' + name + '.jsonl')]
    mine = [r for r in rows if r['sport'] == port and r['saddr'] == '10.0.1.2']
    last = mine[-1] if mine else {}
    keys = ['packets', 'bytes', 'len_sumsq', 'hist', 'len_mean', 'len_std', 'len_p50', 'proto_name', 'span_s', 'pps']
    print(f'   {name:8} reads={len(mine):2}', ' '.join(f'{k}={last.get(k)}' for k in keys if k in last))
ev = [json.loads(l) for l in open('$OUT/events.jsonl')]
mine = [r for r in ev if r['saddr'] == '10.0.1.2' and r['len'] == 342]
print(f'   events   records from 10.0.1.2 with len 342: {len(mine)} (all records: {len(ev)})')
"
