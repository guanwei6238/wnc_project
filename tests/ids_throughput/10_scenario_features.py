#!/usr/bin/env python3
"""10_scenario_features.py - read the first N packets of each IoT-23 scenario's main pcap and compute traffic features, to pick scenarios likely to give different numbers.

Goal: pick scenarios that change the test numbers and skip ones with similar features. IDS engine cost depends on traffic pattern
(packet size, payload or not, TCP/UDP, how many new connections, whether destination ports are concentrated), so quantify these first instead of picking by impression.
Only the first N packets are read (same as slicing, which also takes the start of the file), so the features describe the slice, not the whole scenario.

Features (one row per scenario):
  avg_size      average packet size (pcap record length)
  payload_pct   share of TCP/UDP packets with L4 payload > 0
  tcp/udp/icmp/other_pct   protocol shares (other includes non-IP, e.g. ARP)
  syn_pct       share of TCP packets with SYN only, no ACK (new connection attempts; a scan signature)
  dst_ports     number of distinct destination ports (TCP/UDP)
  top_port_pct  share of TCP/UDP packets to the most common destination port
  dst_ips       number of distinct destination IPs
Usage: python3 -I 10_scenario_features.py <IoTScenarios dir> <tests/iot23/results dir> <output tsv> [N=200000]
The data is untrusted downloads: this script only parses headers with struct and never executes content.
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
