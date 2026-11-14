#!/usr/bin/env python3
"""List the TCP and UDP five-tuples in a classic Ethernet pcap, one direction per flow, for ebpf-bench --flows.

usage: flows.py <pcap>   (prints "<tcp|udp> <src ip> <src port> <dst ip> <dst port> <packets>" to stderr as a summary)
"""
import ipaddress
import struct
import sys


def packets(path):
    with open(path, "rb") as f:
        header = f.read(24)
        magic = struct.unpack("<I", header[:4])[0]
        endian = {0xA1B2C3D4: "<", 0xA1B23C4D: "<", 0xD4C3B2A1: ">", 0x4D3CB2A1: ">"}[magic]
        if struct.unpack(endian + "I", header[20:24])[0] != 1:
            sys.exit("error: only Ethernet pcaps are supported")
        while record := f.read(16):
            caplen = struct.unpack(endian + "IIII", record)[2]
            yield f.read(caplen)


def five_tuple(frame):
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == 0x0800 and len(frame) >= 34:
        ihl = (frame[14] & 0x0F) * 4
        if struct.unpack("!H", frame[20:22])[0] & 0x3FFF:
            return None
        proto, src, dst, l4 = frame[23], frame[26:30], frame[30:34], 14 + ihl
    elif ethertype == 0x86DD and len(frame) >= 54:
        proto, src, dst, l4 = frame[20], frame[22:38], frame[38:54], 54
    else:
        return None
    if proto not in (6, 17) or len(frame) < l4 + 4:
        return None
    sport, dport = struct.unpack("!HH", frame[l4:l4 + 4])
    return ("tcp" if proto == 6 else "udp", ipaddress.ip_address(src), sport, ipaddress.ip_address(dst), dport)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    counts = {}
    total = 0
    for frame in packets(sys.argv[1]):
        total += 1
        key = five_tuple(frame)
        if key is None:
            continue
        proto, src, sport, dst, dport = key
        reverse = (proto, dst, dport, src, sport)
        flow = reverse if reverse in counts else key
        counts[flow] = counts.get(flow, 0) + 1
    for (proto, src, sport, dst, dport), n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"{proto} {src} {sport} {dst} {dport}")
    covered = sum(counts.values())
    print(f"flows={len(counts)} packets={total} tcp_udp_packets={covered} top_flow_packets={max(counts.values(), default=0)}",
          file=sys.stderr)


main()
