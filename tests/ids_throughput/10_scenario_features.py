#!/usr/bin/env python3
"""10_scenario_features.py — 讀每個 IoT-23 場景主 pcap 的前 N 個封包，算流量特徵，用來挑「數據可能不一樣」的場景。

目的：挑會讓測試數據不同的場景，特徵類似的不重複測。IDS 引擎的成本取決於流量型態
（封包大小、有沒有 payload、TCP/UDP、新連線多不多、目的埠是否集中），所以先量化這些特徵再挑，而不是憑印象。
只讀前 N 個封包（與切片的取法一致；切片也是取檔案開頭），所以特徵代表的是「切片」而不是整個場景。

特徵（每個場景一列）：
  avg_size      平均封包大小（pcap 記錄長度）
  payload_pct   TCP/UDP 且 L4 payload > 0 的封包比例
  tcp/udp/icmp/other_pct   協定比例（other 含非 IP，如 ARP）
  syn_pct       只有 SYN、沒有 ACK 的 TCP 封包比例（新連線嘗試；掃描的特徵）
  dst_ports     不同的目的埠數（TCP/UDP）
  top_port_pct  最常見目的埠占 TCP/UDP 封包的比例
  dst_ips       不同的目的 IP 數
用法： python3 -I 10_scenario_features.py <IoTScenarios 目錄> <tests/iot23/results 目錄> <輸出 tsv> [N=200000]
資料是不受信任的下載檔：本腳本只用 struct 解析標頭，不執行任何內容。
"""
import collections
import glob
import json
import os
import struct
import sys

root, resdir, out = sys.argv[1], sys.argv[2], sys.argv[3]
N = int(sys.argv[4]) if len(sys.argv) > 4 else 200000


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


cols = ["scenario", "pcap", "packets", "avg_size", "payload_pct", "tcp_pct", "udp_pct", "icmp_pct", "other_pct", "syn_pct",
        "dst_ports", "top_port", "top_port_pct", "dst_ips"]
with open(out, "w") as o:
    o.write("\t".join(cols) + "\n")
    for jf in sorted(glob.glob(os.path.join(resdir, "*.json"))):
        j = json.load(open(jf))
        pc = j.get("pcap") or j.get("main_pcap")
        if not pc:
            continue
        path = pc if os.path.isabs(pc) else os.path.join(root, pc)
        if not os.path.exists(path):
            cand = glob.glob(os.path.join(root, "**", os.path.basename(pc)), recursive=True)
            if not cand:
                print("找不到", pc); continue
            path = cand[0]
        ft = features(path)
        name = os.path.basename(jf)[:-5].replace("CTU-IoT-Malware-Capture-", "Mal-").replace("CTU-Honeypot-Capture-", "Hon-")
        row = [name, os.path.relpath(path, root)] + [str(ft[c]) for c in cols[2:]]
        o.write("\t".join(row) + "\n")
        print("\t".join(row[:1] + row[2:]), flush=True)
