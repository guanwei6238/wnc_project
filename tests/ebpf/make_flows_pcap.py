#!/usr/bin/env python3
"""Write a pcap of N UDP flows sent round-robin, copying the Ethernet and IP header of a flow in a template pcap, and
the matching flows file for ebpf-bench --flows / alloc_pi.sh trust_flows.

usage: make_flows_pcap.py <template pcap> <src ip> <dst ip> <flows> <packets> <out.pcap> <out.flows>
The template's first UDP packet from <src ip> to <dst ip> gives the MAC addresses, so tcpprep and the routed MAC
rewrite treat the new packets like that flow. Source ports are 10000 + flow number.
"""
import ipaddress
import struct
import sys


def template(path, src, dst):
    with open(path, "rb") as f:
        f.read(24)
        while record := f.read(16):
            frame = f.read(struct.unpack("<IIII", record)[2])
            if frame[12:14] == b"\x08\x00" and frame[23] == 17 and frame[26:30] == src and frame[30:34] == dst:
                return frame[:14]
    sys.exit("error: no UDP packet from the source to the destination in the template")


def checksum(header):
    total = sum(struct.unpack("!10H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def main():
    if len(sys.argv) != 8:
        sys.exit(__doc__)
    path, src, dst, flows, packets, out_pcap, out_flows = sys.argv[1:]
    src_b, dst_b = ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed
    flows, packets = int(flows), int(packets)
    ethernet = template(path, src_b, dst_b)
    payload = b"\x00" * 18
    with open(out_pcap, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(packets):
            sport = 10000 + i % flows
            udp = struct.pack("!HHHH", sport, 80, 8 + len(payload), 0) + payload
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), i & 0xFFFF, 0, 64, 17, 0, src_b, dst_b)
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
            frame = ethernet + ip + udp
            out.write(struct.pack("<IIII", i // 100000, (i % 100000) * 10, len(frame), len(frame)) + frame)
    with open(out_flows, "w") as out:
        for n in range(flows):
            out.write(f"udp {src} {10000 + n} {dst} 80\n")
    print(f"{packets} packets in {flows} flows, {len(ethernet) + 20 + 8 + len(payload)} bytes each")


main()
