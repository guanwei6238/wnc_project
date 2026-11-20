#!/bin/bash
# features_pi.sh — [[features]] 在 Pi 上的功能確認（bridge，veth）：Pi 的 kernel 沒有 vmlinux BTF、bridge 的
#   bpf_redirect 經過 egress，這兩件 Docker 驗不到
#   拓樸：env.sh 的 wgw 加 protection_pi.sh net up：fcli(10.9.0.1) c-lan — x-lan [wgw: br0] x-wan — s-wan fsrv(10.9.0.2)
#   四個 feature：egress（tc-egress FLOWS）、ingress（tc-ingress PFLOWS）、events（tc-egress EVENTS）、
#   xdp（xdp，XDP_MODE=native（預設，veth 有）或 generic；一張網卡只能掛一個 XDP 程式，所以一次只測一種）；
#   送 20 個不信任、20 個信任的 UDP，再跑 features test
# 前置：sudo sh ~/ids_inline/env.sh up; sudo bash ~/ids_inline/protection_pi.sh net up；系統的 suricata 已停
#   /tmp/wncgw/feat/ 放 prog.o、flows.json、pflows.json、events.json；wnc-gw 在 $GW
# 用法: sudo [BACKEND=ctmark] [XDP_MODE=generic] bash features_pi.sh
GW=${GW:-/tmp/wncgw/wnc-gw}; D=/tmp/wncgw/feat; OUT=/var/log/wnc-gw/features
W="ip netns exec wgw"; C="ip netns exec fcli"
P=$((43000 + RANDOM % 1000)); BACKEND=${BACKEND:-tc}
printf 'alert icmp any any -> any any (msg:"feat icmp"; sid:1000401; rev:1;)\n' > $D/test.rules
printf '%%YAML 1.1\n---\ninclude: /etc/suricata/suricata.yaml\ndefault-rule-path: %s\nrule-files:\n  - test.rules\n' $D > $D/s.yaml
printf 'mode = "bridge"\nxdp = "off"\n\n[ports]\nlan = "x-lan"\nwan = "x-wan"\n\n[suricata]\nconfig = "%s/s.yaml"\n\n[trust]\nbackend = "%s"\n' $D $BACKEND > $D/setting.toml
for n in egress:flows_tc:flows:tc-egress ingress:flows_tc:pflows:tc-ingress events:flows_tc:events:tc-egress \
         xdp:flows_xdp:flows:xdp:${XDP_MODE:-native}; do
  IFS=: read name entry def hook mode <<< "$n"
  printf '\n[[features]]\nname = "%s"\nprogram = "%s/prog.o"\nentry = "%s"\ndefinition = "%s/%s.json"\nhook = "%s"\n' \
    $name $D $entry $D $def $hook >> $D/setting.toml
  [ -n "$mode" ] && printf 'xdp_mode = "%s"\n' $mode >> $D/setting.toml
done
chown root:root $D/*; chmod 644 $D/*

echo "=== doctor (feature part)"
$W $GW -c $D/setting.toml doctor | sed -n '/^feature /,/^$/p;/G0[0-9][0-9]/p' | cut -c1-200

echo "=== run, backend $BACKEND, source port $P"
rm -rf $OUT $D/run.log $D/exit
( $W $GW --log-level debug -c $D/setting.toml run > /dev/null 2> $D/run.log; echo $? > $D/exit ) &
for i in $(seq 1 300); do grep -q "traffic is inspected" $D/run.log 2>/dev/null && break; [ -e $D/exit ] && break; sleep 0.2; done
grep -E "feature program|G0[0-9][0-9]" $D/run.log | cut -c28-240 | sed 's/^/   /'
send() {
  $C python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.9.0.1', $P))
for _ in range(20):
    s.sendto(b'x' * 300, ('10.9.0.2', 5001)); time.sleep(0.02)"
}
send; sleep 2.5
$W $GW trust add udp 10.9.0.1 $P 10.9.0.2 5001 && echo "   trust add: ok"
send; sleep 2.5
$W $GW trust list | sed 's/^/   /'
kill -INT $(pgrep -n -x wnc-gw); until [ -e $D/exit ]; do sleep 0.2; done
grep -E "feature program detached" $D/run.log | cut -c28-200 | sed 's/^/   /'
python3 -c "
import json, os
port = $P
for name in ['egress', 'ingress', 'xdp']:
    path = '$OUT/' + name + '.jsonl'
    if not os.path.exists(path):
        print(f'   {name:8} no output'); continue
    rows = [json.loads(l) for l in open(path)]
    mine = [r for r in rows if r['sport'] == port and r['saddr'] == '10.9.0.1']
    last = mine[-1] if mine else {}
    print(f'   {name:8} reads={len(mine):2}', ' '.join(f'{k}={last.get(k)}' for k in ['packets', 'bytes', 'hist', 'len_mean', 'proto_name']))
path = '$OUT/events.jsonl'
ev = [json.loads(l) for l in open(path)] if os.path.exists(path) else []
print(f'   events   records from 10.9.0.1 with len 342: {sum(1 for r in ev if r[\"saddr\"] == \"10.9.0.1\" and r[\"len\"] == 342)} (all: {len(ev)})')
"

echo "=== features test"
python3 -c "
import struct
def csum(b):
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
def frame(src, dst, proto, sport, dport, payload):
    l4 = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) if proto == 17 else struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 0x50, 0x10, 1024, 0, 0)
    l4 += payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return b'\x02\x00\x00\x00\x02\x01' + b'\x02\x00\x00\x00\x01\x02' + b'\x08\x00' + ip + l4
out = open('$D/test.pcap', 'wb')
out.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
frames = [frame([10,9,0,1], [10,9,0,2], 17, 43000, 5001, b'x' * 300) for _ in range(20)]
frames += [frame([10,9,0,9], [10,9,0,2], 6, 1234, 80, b'y' * 20) for _ in range(5)]
for i, f in enumerate(frames):
    out.write(struct.pack('<IIII', 1, i, len(f), len(f)) + f)
"
for name in egress ingress events xdp; do
  echo "   -- $name"
  $GW -c $D/setting.toml features test $name $D/test.pcap 2>&1 | grep -v "^note" | python3 -c "
import json, sys
for line in sys.stdin:
    if not line.startswith('{'):
        print('     ', line.rstrip()); continue
    r = json.loads(line)
    print('     ', {k: r[k] for k in ('saddr', 'sport', 'packets', 'bytes', 'hist', 'len') if k in r})
" | sort | uniq -c
done
