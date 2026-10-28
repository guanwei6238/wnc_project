#!/bin/bash
# 3b 分片驗證（Pi，bridge）：wnc-gw 開 4 個 queue（symhash），同一條連線的分片會不會被分到不同 queue
#   每條連線 = 1 個小 UDP + 一個 3000 bytes UDP 的 3 個分片（192.168.1.10:40000+i → 203.0.113.5:5000），共 24 條
#   FAMILY=6：同樣的流量改成 IPv6（2001:db8:1::10 → 2001:db8:2::5，Fragment 擴充標頭，UDP checksum 照算）
#   wnc-gw 的 table 有 ct mark 規則 → conntrack 啟用 → kernel 進 queue 前先組回分片，預期 0 條被拆開、每條進 queue 2 個封包
# 前置：sudo sh env.sh up；sh make_configs.sh；系統的 suricata 服務已停；wnc-gw 放在 $GW
# 用法: sudo [FAMILY=6] bash frag_pi.sh
FAMILY=${FAMILY:-4}; GW=${GW:-/tmp/wncgw/wnc-gw}; M=${M:-/tmp/wncgw/m}; F=/tmp/wncgw/frag${FAMILY/4/}; L=/tmp/wncgw/ftgw
[ -f $F/flow23.pcap ] || { mkdir -p $F && python3 - $F $FAMILY <<'PY'
import struct, sys, pathlib
out = pathlib.Path(sys.argv[1])
def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack(f"!{len(b)//2}H", b)); s = (s >> 16) + (s & 0xffff); s += s >> 16
    return ~s & 0xffff
def ip(ident, frag_field, payload, src="192.168.1.10", dst="203.0.113.5"):
    a = bytes(map(int, src.split("."))); d = bytes(map(int, dst.split(".")))
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, frag_field, 64, 17, 0, a, d)
    return h[:10] + struct.pack("!H", csum(h)) + h[12:] + payload
eth = bytes.fromhex("020000000020" "020000000010" "0800")
def rec(frame): return struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
SRC6 = bytes.fromhex("20010db8000100000000000000000010"); DST6 = bytes.fromhex("20010db8000200000000000000000005")
def udp6(sport, payload):
    u = struct.pack("!HHHH", sport, 5000, 8 + len(payload), 0) + payload
    c = csum(SRC6 + DST6 + struct.pack("!IxxxB", len(u), 17) + u) or 0xffff
    return u[:6] + struct.pack("!H", c) + u[8:]
def ip6(nh, payload): return struct.pack("!IHBB", 0x60000000, len(payload), nh, 64) + SRC6 + DST6 + payload
def frag6(ident, offset, more, chunk): return ip6(44, struct.pack("!BBHI", 17, 0, offset | more, ident) + chunk)
if sys.argv[2] == "6":
    eth = eth[:12] + bytes.fromhex("86dd")
    for i in range(24):
        sport = 40000 + i
        big = udp6(sport, bytes(3000))
        ident = 1001 + i
        pkts = [ip6(17, udp6(sport, b"x")),
                frag6(ident, 0, 1, big[0:1448]),
                frag6(ident, 1448, 1, big[1448:2896]),
                frag6(ident, 2896, 0, big[2896:])]
        data = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + b"".join(rec(eth + p) for p in pkts)
        (out / f"flow{i:02d}.pcap").write_bytes(data)
    sys.exit()
for i in range(24):
    sport = 40000 + i
    small = struct.pack("!HHHH", sport, 5000, 8 + 1, 0) + b"x"
    big = struct.pack("!HHHH", sport, 5000, 8 + 3000, 0) + bytes(3000)
    ident = 1001 + 2 * i
    pkts = [ip(1000 + 2 * i, 0, small),
            ip(ident, 0x2000 | 0, big[0:1480]),
            ip(ident, 0x2000 | (1480 // 8), big[1480:2960]),
            ip(ident, 2960 // 8, big[2960:])]
    data = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + b"".join(rec(eth + p) for p in pkts)
    (out / f"flow{i:02d}.pcap").write_bytes(data)
PY
}
rm -rf $L; mkdir -p $L
ip netns exec wgw $GW -c $M/setting-empty-q4.toml run > $L/run.log 2>&1 &
gp=$!
until grep -q "traffic is inspected" $L/run.log; do sleep 0.2; kill -0 $gp 2>/dev/null || { cat $L/run.log; exit 1; }; done
ip netns exec wgw nft list chain inet wnc_gw ids | grep queue
q() { ip netns exec wgw cat /proc/net/netfilter/nfnetlink_queue | awk '{printf "%d ", $8}'; }
split=0; total=0; n=0; rx0=$(ip netns exec wtest cat /sys/class/net/t-wan/statistics/rx_packets)
for f in $F/flow*.pcap; do
  b=($(q)); ip netns exec wtest tcpreplay -q -i t-lan "$f" > /dev/null 2>&1; sleep 0.2; a=($(q))
  used=0; pk=0; d=""
  for k in 0 1 2 3; do x=$((a[k] - b[k])); d+="$x "; [ $x -gt 0 ] && used=$((used + 1)); pk=$((pk + x)); done
  n=$((n + 1)); [ $used -gt 1 ] && split=$((split + 1)); total=$((total + pk))
  [ $n -le 4 ] && echo "flow $n: per-queue [$d] packets=$pk queues_used=$used"
done
echo "== wnc-gw symhash mod 4: $n flows, split across queues: $split, packets queued: $total"
echo "frames out of t-wan: $(( $(ip netns exec wtest cat /sys/class/net/t-wan/statistics/rx_packets) - rx0 ))"
kill -INT $gp; wait $gp; echo "wnc-gw exit=$?"
