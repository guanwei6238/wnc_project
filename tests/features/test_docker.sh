#!/bin/bash
# test_docker.sh — wnc-gw features test (BPF_PROG_TEST_RUN dry run) in the testbed's wnc-gw container
#   generated pcap: 20 UDP 10.0.1.2:43000 → 10.0.2.2:5001 (342-byte frames), 5 TCP 10.0.1.9:1234 → 10.0.2.2:80 (74-byte frames)
#   runs once each for egress (FLOWS), ingress (PFLOWS per-CPU), events (ringbuf), xdp (FLOWS)
#   expected: two flows with packets 20 and 5; 25 events; TC returns TCX_NEXT ×25, XDP returns XDP_PASS ×25
# Usage: bash test_docker.sh   (run bash doctor_docker.sh and bash run_docker.sh first; they prepare /tmp/feat/prog.o and run.toml)
GW="docker exec wnc-gw"
$GW python3 -c "
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
out = open('/tmp/feat/test.pcap', 'wb')
out.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
frames = [frame([10,0,1,2], [10,0,2,2], 17, 43000, 5001, b'x' * 300) for _ in range(20)]
frames += [frame([10,0,1,9], [10,0,2,2], 6, 1234, 80, b'y' * 20) for _ in range(5)]
for i, f in enumerate(frames):
    out.write(struct.pack('<IIII', 1, i, len(f), len(f)) + f)
print('pcap frames:', len(frames), 'sizes:', sorted(set(len(f) for f in frames)))
"
for name in egress ingress events xdp; do
  echo "=== $name"
  $GW /opt/sg/wnc-gw -c /tmp/feat/run.toml features test $name /tmp/feat/test.pcap 2>&1 \
    | python3 -c "
import json, sys
for line in sys.stdin:
    if not line.startswith('{'):
        print('  ', line.rstrip()); continue
    r = json.loads(line)
    keep = {k: r[k] for k in ('saddr', 'sport', 'dport', 'proto_name', 'packets', 'bytes', 'len_mean', 'len_std', 'hist', 'len') if k in r}
    print('  ', keep)
" | sort | uniq -c | sed 's/^ */   /'
done
