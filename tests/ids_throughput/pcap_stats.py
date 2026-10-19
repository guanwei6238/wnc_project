#!/usr/bin/env python3
"""pcap_stats.py -- 用標準函式庫讀 classic pcap，印出一行 JSON 統計 (不依賴 Scapy/capinfos，Pi 上也能跑)。

用法:  python3 -I pcap_stats.py <file.pcap>

為什麼自己寫: 我們要的是「封包數、位元組、持續時間、payload 占比」這幾個數字，
而且要和引擎自報的 decoded 封包數對帳；自己算才知道定義是什麼。

定義 (報告裡會引用):
  packets        pcap 內的封包記錄數 (最後一筆若被截斷不算，另以 truncated_tail=true 標示)
  bytes_wire     sum(orig_len)  封包在線上的長度
  bytes_cap      sum(incl_len)  pcap 實際存下來的長度 (= 引擎看到的長度；沒有被 snaplen 截斷時兩者相同)
  duration       最後一個封包時間 - 第一個封包時間 (秒)
  avg_pkt_size   bytes_cap / packets
  payload 封包   TCP 或 UDP 且 L4 payload 長度 > 0 的封包 (ICMP、ARP、純 ACK/SYN 都不算)
  payload_pkt_share   payload 封包數 / packets
  payload_byte_share  sum(L4 payload 長度) / bytes_cap   (分母含 Ethernet/IP/TCP 標頭，所以永遠 < 1)
  L4 payload 長度 = IP total length - IP header - TCP/UDP header (用 IP 標頭的長度，所以不含 Ethernet 補零)
"""
import struct, sys, json

def main(path):
    f = open(path, 'rb')
    gh = f.read(24)
    if len(gh) < 24:
        sys.exit("not a pcap (too short)")
    magic = gh[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
        e = '<'
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        e = '>'
    else:
        sys.exit("unsupported magic %r (pcapng?)" % magic)
    nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    snaplen, linktype = struct.unpack(e + '8xII', gh[8:24])
    rec = struct.Struct(e + 'IIII')
    read = f.read
    n = bytes_wire = bytes_cap = 0
    t_first = t_last = None
    cnt = dict(tcp=0, udp=0, icmp=0, other_ip=0, non_ip=0, l4_unparsed=0)
    pl_pkts = pl_bytes = 0
    truncated = False
    while True:
        h = read(16)
        if not h:
            break
        if len(h) < 16:
            truncated = True; break
        sec, frac, incl, orig = rec.unpack(h)
        data = read(incl)
        if len(data) < incl:
            truncated = True; break
        t = sec + frac / (1e9 if nano else 1e6)
        if t_first is None: t_first = t
        t_last = t
        n += 1; bytes_wire += orig; bytes_cap += incl
        # --- 找到 IP 標頭的起點 ---
        if linktype == 1:           # Ethernet
            off = 14
            et = (data[12] << 8 | data[13]) if incl >= 14 else 0
            while et in (0x8100, 0x88a8) and incl >= off + 4:   # VLAN tag
                et = data[off + 2] << 8 | data[off + 3]; off += 4
        elif linktype == 101:       # raw IP
            off = 0
            et = 0x0800 if data[:1] and data[0] >> 4 == 4 else 0x86dd
        elif linktype == 113:       # Linux cooked
            off = 16; et = data[14] << 8 | data[15] if incl >= 16 else 0
        else:
            et = 0; off = 0
        proto = None; l4 = None; ip_end = None
        if et == 0x0800 and incl >= off + 20:
            ihl = (data[off] & 0x0f) * 4
            tot = data[off + 2] << 8 | data[off + 3]
            fragoff = (data[off + 6] & 0x1f) << 8 | data[off + 7]
            proto = data[off + 9]
            ip_end = min(off + tot, incl)
            l4 = off + ihl
            if fragoff: proto = -1          # 非第一個分片，沒有 L4 標頭
        elif et == 0x86dd and incl >= off + 40:
            plen = data[off + 4] << 8 | data[off + 5]
            proto = data[off + 6]
            ip_end = min(off + 40 + plen, incl)
            l4 = off + 40
        else:
            cnt['non_ip'] += 1
            continue
        pl = 0
        if proto == 6 and incl >= l4 + 13:
            cnt['tcp'] += 1
            pl = ip_end - (l4 + ((data[l4 + 12] >> 4) * 4))
        elif proto == 17 and incl >= l4 + 8:
            cnt['udp'] += 1
            pl = ip_end - (l4 + 8)
        elif proto in (1, 58):
            cnt['icmp'] += 1
        elif proto == -1 or proto in (6, 17):
            cnt['l4_unparsed'] += 1
        else:
            cnt['other_ip'] += 1
        if pl > 0:
            pl_pkts += 1; pl_bytes += pl
    dur = (t_last - t_first) if n else 0.0
    out = dict(file=path.split('/')[-1], packets=n, bytes_wire=bytes_wire, bytes_cap=bytes_cap,
               t_first=t_first, t_last=t_last, duration_s=round(dur, 6),
               avg_pkt_size=round(bytes_cap / n, 2) if n else 0,
               linktype=linktype, snaplen=snaplen, truncated_tail=truncated, **cnt,
               payload_pkts=pl_pkts, payload_bytes=pl_bytes,
               payload_pkt_share=round(pl_pkts / n, 6) if n else 0,
               payload_byte_share=round(pl_bytes / bytes_cap, 6) if bytes_cap else 0)
    print(json.dumps(out))

if __name__ == '__main__':
    main(sys.argv[1])
