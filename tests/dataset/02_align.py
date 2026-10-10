#!/usr/bin/env python3
"""第 2 關：資料集的「標籤」能不能對回 PCAP 裡的「封包」？

IoT-23 的標籤不在 PCAP 裡，而是另一個 Zeek conn.log（每一列 = 一條 flow）。
要拿資料集測 gateway，必須知道「重播哪些封包時，預期結果是什麼」，
所以第一件事是確認：每一條有標籤的 flow，都能在 PCAP 裡找到對應的封包。

對齊方式（與 reproduce_cases.py 相同）：
  五元組（雙向都算）+ 時間落在 [ts, ts+duration] ±1µs
  找到的封包數 == conn.log 記錄的 orig_pkts + resp_pkts  → 算對齊成功

另外統計每種標籤底下 TCP payload 的封包數，用來回答：
  「標成 C&C 的流量裡，真的有 C&C 的內容嗎？」

只用 Python 標準函式庫，只讀檔，不送任何封包。
用法：python3 02_align.py [conn.log.labeled] [pcap]
"""
import collections
import ipaddress
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT = HERE / 'data' / '小樣本資料' / 'Hakai-8-1'
LOG = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT / 'conn.log.labeled'
PCAP = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT / '2018-07-31-15-15-09-192.168.100.113.pcap'
PROTO = {'tcp': 6, 'udp': 17, 'icmp': 1}
EPS = 1e-6


def read_packets(path):
    """回傳 {(proto, 端點A, 端點B): [(時間, tcp_payload長度, 封包編號), ...]}，端點排序過所以雙向同 key。"""
    data = path.read_bytes()
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}[data[:4]]
    index = collections.defaultdict(list)
    total = 0
    offset = 24
    while offset < len(data):
        sec, usec, cap, _ = struct.unpack(endian + 'IIII', data[offset:offset + 16])
        pkt = data[offset + 16:offset + 16 + cap]
        offset += 16 + cap
        total += 1
        ethertype = pkt[12:14]
        if ethertype == b'\x08\x00' and len(pkt) >= 34:        # IPv4
            ihl = (pkt[14] & 15) * 4
            proto = pkt[23]
            src, dst = pkt[26:30], pkt[30:34]
            l3_len = struct.unpack('!H', pkt[16:18])[0]
        elif ethertype == b'\x86\xdd' and len(pkt) >= 54:      # IPv6
            ihl = 40
            proto = pkt[20]
            src, dst = pkt[22:38], pkt[38:54]
            l3_len = 40 + struct.unpack('!H', pkt[18:20])[0]
            while proto in (0, 43, 60) and len(pkt) >= 14 + ihl + 2:  # 跳過 Hop-by-Hop 等 extension header
                proto, ihl = pkt[14 + ihl], ihl + (pkt[14 + ihl + 1] + 1) * 8
        else:                                                   # ARP 等非 IP 封包
            continue
        if proto == 58:  # ICMPv6 在 Zeek 裡記成 icmp
            proto = 1
        l4 = 14 + ihl
        sport = dport = 0
        payload = 0
        if proto in (6, 17) and len(pkt) >= l4 + 4:
            sport, dport = struct.unpack('!HH', pkt[l4:l4 + 4])
        if proto == 6 and len(pkt) >= l4 + 13:
            payload = l3_len - ihl - (pkt[l4 + 12] >> 4) * 4
        a, b = sorted([(src, sport), (dst, dport)])
        index[(proto, a, b)].append((sec + usec / 1e6, payload, total))
    return index, total


def ip_bytes(s):
    return ipaddress.ip_address(s).packed


def main():
    index, total_pkts = read_packets(PCAP)
    stats = collections.defaultdict(collections.Counter)
    covered = set()
    for line in LOG.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        f = line.split()
        ts, oh, op, rh, rp, proto = float(f[0]), f[2], int(f[3]), f[4], int(f[5]), f[6]
        dur = 0.0 if f[8] == '-' else float(f[8])
        expect = int(f[16]) + int(f[18])
        state = f[11]
        label = f[-2] if f[-1] == '-' else f'{f[-2]} {f[-1]}'
        p = PROTO.get(proto)
        if p is None:
            continue
        if p == 1:  # ICMP 的 port 欄位在 Zeek 裡是 type/code，封包索引裡一律記 0
            op = rp = 0
        a, b = sorted([(ip_bytes(oh), op), (ip_bytes(rh), rp)])
        found = [(pl, n) for t, pl, n in index.get((p, a, b), []) if ts - EPS <= t <= ts + dur + EPS]
        covered.update(n for _, n in found)
        s = stats[label]
        s['flows'] += 1
        s['aligned'] += len(found) == expect
        s['pkts'] += len(found)
        s['payload_pkts'] += sum(1 for pl, _ in found if pl > 0)
        s['state ' + state] += 1

    print(f'PCAP : {PCAP.name}  ({total_pkts:,} packets)')
    print(f'Label: {LOG.name}')
    print()
    print(f'{"標籤":<16}{"flow 數":>9}{"對齊成功":>10}{"對齊率":>9}{"封包數":>9}{"有 payload":>12}  conn_state')
    print('-' * 90)
    for label, s in sorted(stats.items()):
        states = ', '.join(f'{k[6:]}={v}' for k, v in s.most_common() if k.startswith('state '))
        rate = s['aligned'] / s['flows'] * 100
        print(f'{label:<16}{s["flows"]:>9,}{s["aligned"]:>10,}{rate:>8.1f}%{s["pkts"]:>9,}{s["payload_pkts"]:>12,}  {states}')
    print()
    print(f'PCAP 封包被有標籤的 flow 涵蓋：{len(covered):,} / {total_pkts:,}（{len(covered) / total_pkts * 100:.1f}%）')
    print('其餘為 ARP 等非 IP 封包，或 Zeek 沒有記成 flow 的封包，重播時沒有預期結果可比對')
    print()
    print('對齊成功 = PCAP 中找到的封包數 == conn.log 的 orig_pkts + resp_pkts')
    print('有 payload = TCP 封包且帶應用層資料（UDP 一律記 0）')


if __name__ == '__main__':
    main()
