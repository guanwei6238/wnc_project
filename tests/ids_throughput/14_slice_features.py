#!/usr/bin/env python3
"""14_slice_features.py — 算切片的流量特徵（和 10_scenario_features.py 的 features() 相同的定義），用來挑代表的切片。

特徵：avg_size、payload_pct、tcp/udp/icmp/other_pct、syn_pct、dst_ports、top_port、top_port_pct、dst_ips（定義見 10_scenario_features.py）。
用法: python3 -I 14_slice_features.py <輸出 tsv> <pcap>...
資料是不受信任的下載檔：只用 struct 解析標頭，不執行任何內容。
"""
import collections
import os
import struct
import sys

out = sys.argv[1]
N = 10 ** 9   # 切片本身就是 200,000 個 packet，整個檔都讀

def features(path):
    f = open(path, "rb")
    gh = f.read(24)
    e = "<" if gh[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    linktype = struct.unpack(e + "I", gh[20:24])[0]
    n = size = pay = tcp = udp = icmp = other = syn = 0
    ports = collections.Counter()
    ips = set()
    while n < N:
        h = f.read(16)
        if len(h) < 16:
            break
        incl = struct.unpack(e + "IIII", h)[2]
        d = f.read(incl)
        if len(d) < incl:
            break
        n += 1
        size += incl
        if linktype != 1 or len(d) < 14:
            other += 1
            continue
        et = struct.unpack("!H", d[12:14])[0]
        off = 14
        if et == 0x8100 and len(d) >= 18:
            et = struct.unpack("!H", d[16:18])[0]; off = 18
        if et == 0x0800 and len(d) >= off + 20:
            ihl = (d[off] & 0x0F) * 4
            tot = struct.unpack("!H", d[off + 2:off + 4])[0]
            proto = d[off + 9]
            ips.add(d[off + 16:off + 20])
            l4 = off + ihl
        elif et == 0x86DD and len(d) >= off + 40:
            tot = struct.unpack("!H", d[off + 4:off + 6])[0] + 40
            ihl = 40
            proto = d[off + 6]
            ips.add(d[off + 24:off + 40])
            l4 = off + 40
        else:
            other += 1
            continue
        if proto == 6 and len(d) >= l4 + 14:
            tcp += 1
            doff = (d[l4 + 12] >> 4) * 4
            flags = d[l4 + 13]
            if flags & 0x02 and not flags & 0x10:
                syn += 1
            ports[struct.unpack("!H", d[l4 + 2:l4 + 4])[0]] += 1
            if tot - ihl - doff > 0:
                pay += 1
        elif proto == 17 and len(d) >= l4 + 8:
            udp += 1
            ports[struct.unpack("!H", d[l4 + 2:l4 + 4])[0]] += 1
            if tot - ihl - 8 > 0:
                pay += 1
        elif proto in (1, 58):
            icmp += 1
        else:
            other += 1
    tu = tcp + udp
    top = ports.most_common(1)
    pct = lambda x: round(100.0 * x / n, 2) if n else 0
    return {"packets": n, "avg_size": round(size / n, 1) if n else 0, "payload_pct": pct(pay), "tcp_pct": pct(tcp),
            "udp_pct": pct(udp), "icmp_pct": pct(icmp), "other_pct": pct(other), "syn_pct": pct(syn),
            "dst_ports": len(ports), "top_port": top[0][0] if top else "",
            "top_port_pct": round(100.0 * top[0][1] / tu, 1) if (top and tu) else 0, "dst_ips": len(ips)}


cols = ["slice", "packets", "avg_size", "payload_pct", "tcp_pct", "udp_pct", "icmp_pct", "other_pct", "syn_pct",
        "dst_ports", "top_port", "top_port_pct", "dst_ips"]
with open(out, "w") as o:
    o.write("\t".join(cols) + "\n")
    for p in sys.argv[2:]:
        ft = features(p)
        row = [os.path.basename(p)[:-5]] + [str(ft[c]) for c in cols[1:]]
        o.write("\t".join(row) + "\n")
        print("\t".join(row), flush=True)
