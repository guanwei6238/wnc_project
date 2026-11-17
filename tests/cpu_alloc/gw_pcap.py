#!/usr/bin/env python3
"""Cut a slice down to the packets that cross the gateway, and to the ones the TC fast path would forward.

usage: gw_pcap.py <in.pcap> <out prefix> <lan cidr>...
  <prefix>.gw.pcap     IPv4/IPv6 packets with exactly one end in the LAN (what the gateway sees)
  <prefix>.fp.pcap     the .gw packets the fast path takes once trusted: TCP without SYN/FIN/RST and UDP, unicast,
                       not fragmented, no IPv6 extension header (same checks as gw-ebpf)
  <prefix>.fp.flows    one line per connection in .fp.pcap: "<tcp|udp> <src ip> <src port> <dst ip> <dst port>"
  <prefix>.whole.pcap  the .gw packets minus TCP connections whose first packet in the slice is not a pure SYN
"""
import ipaddress
import struct
import sys

SYN, RST, FIN = 0x02, 0x04, 0x01


def records(path):
    with open(path, "rb") as f:
        header = f.read(24)
        magic = struct.unpack("<I", header[:4])[0]
        endian = {0xA1B2C3D4: "<", 0xA1B23C4D: "<", 0xD4C3B2A1: ">", 0x4D3CB2A1: ">"}[magic]
        if struct.unpack(endian + "I", header[20:24])[0] != 1:
            sys.exit("error: only Ethernet pcaps are supported")
        yield header
        while record := f.read(16):
            caplen = struct.unpack(endian + "IIII", record)[2]
            data = f.read(caplen)
            if len(data) < caplen:
                return
            yield record + data


def classify(frame, lan):
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == 0x0800 and len(frame) >= 34:
        ihl = (frame[14] & 0x0F) * 4
        fragment = struct.unpack("!H", frame[20:22])[0] & 0x3FFF != 0
        proto, l4 = frame[23], 14 + ihl
        src, dst = ipaddress.ip_address(frame[26:30]), ipaddress.ip_address(frame[30:34])
        extension = False
    elif ethertype == 0x86DD and len(frame) >= 54:
        fragment, proto, l4 = False, frame[20], 54
        src, dst = ipaddress.ip_address(frame[22:38]), ipaddress.ip_address(frame[38:54])
        extension = proto not in (6, 17, 58)
    else:
        return None
    inside = [any(a in n for n in lan) for a in (src, dst)]
    if inside[0] == inside[1]:
        return None
    unicast = not (frame[0] & 1 or dst.is_multicast or dst == ipaddress.ip_address("255.255.255.255"))
    fast = unicast and not fragment and not extension and proto in (6, 17) and len(frame) >= l4 + 4
    if fast and proto == 6:
        fast = len(frame) >= l4 + 14 and frame[l4 + 13] & (SYN | RST | FIN) == 0
    tcp = None
    if proto == 6 and len(frame) >= l4 + 14:
        sport, dport = struct.unpack("!HH", frame[l4:l4 + 4])
        tcp = (tuple(sorted([(src, sport), (dst, dport)])), frame[l4 + 13] & 0x12 == SYN)
    if not fast:
        return ("gw", None, tcp)
    sport, dport = struct.unpack("!HH", frame[l4:l4 + 4])
    return ("fp", ("tcp" if proto == 6 else "udp", src, sport, dst, dport), tcp)


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    path, prefix, lan = sys.argv[1], sys.argv[2], [ipaddress.ip_network(c) for c in sys.argv[3:]]
    stream = records(path)
    header = next(stream)
    flows, seen = [], set()
    count = {"all": 0, "gw": 0, "fp": 0, "whole": 0}
    opened = {}
    with open(prefix + ".gw.pcap", "wb") as gw, open(prefix + ".fp.pcap", "wb") as fp, \
            open(prefix + ".whole.pcap", "wb") as whole:
        gw.write(header)
        fp.write(header)
        whole.write(header)
        for record in stream:
            count["all"] += 1
            kind = classify(record[16:], lan)
            if kind is None:
                continue
            gw.write(record)
            count["gw"] += 1
            if kind[2] is None or opened.setdefault(kind[2][0], kind[2][1]):
                whole.write(record)
                count["whole"] += 1
            if kind[0] != "fp":
                continue
            fp.write(record)
            count["fp"] += 1
            proto, src, sport, dst, dport = kind[1]
            key = (proto,) + tuple(sorted([(src, sport), (dst, dport)]))
            if key not in seen:
                seen.add(key)
                flows.append(f"{proto} {src} {sport} {dst} {dport}")
    with open(prefix + ".fp.flows", "w") as out:
        out.write("".join(line + "\n" for line in flows))
    print(f"{path}: {count['all']} packets, {count['gw']} cross the gateway, {count['fp']} fast-path eligible, "
          f"{len(flows)} connections; {count['whole']} in TCP connections that start with a SYN, or not TCP")


if __name__ == "__main__":
    main()
