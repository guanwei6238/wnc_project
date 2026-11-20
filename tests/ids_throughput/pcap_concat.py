#!/usr/bin/env python3
"""pcap_concat.py -- concatenate one classic pcap N times (N times the data), to check that processing time scales linearly with data volume.

Usage: python3 -I pcap_concat.py <in.pcap> <out.pcap> <N>

Why shift timestamps: if the second copy's timestamps jumped back to the start, the engine would see time go backwards and flow timeout/cleanup would differ from real traffic.
So every timestamp in copy k (k=0..N-1) gets k * (file duration + 1 s) added, i.e. the same traffic happens again right after.
Only packet records are moved; packet contents are not parsed. (No mergecap/Scapy; the container and the Pi need only python3)
"""
import struct, sys

def main(src, dst, n):
    data = open(src, 'rb').read()
    magic = data[:4]
    if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'): e = '<'
    elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'): e = '>'
    else: sys.exit("unsupported pcap magic")
    nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    unit = 10**9 if nano else 10**6
    # First pass: collect each record's (offset, incl_len); drop a truncated tail
    recs = []; pos = 24; L = len(data)
    while pos + 16 <= L:
        incl = struct.unpack_from(e + 'I', data, pos + 8)[0]
        if pos + 16 + incl > L: break
        recs.append((pos, incl)); pos += 16 + incl
    if not recs: sys.exit("no packets")
    first = struct.unpack_from(e + 'II', data, recs[0][0]); last = struct.unpack_from(e + 'II', data, recs[-1][0])
    span = (last[0] - first[0]) + 1                     # seconds; integer is enough, +1 s gap
    with open(dst, 'wb') as out:
        out.write(data[:24])
        for k in range(n):
            shift = k * span
            for (p, incl) in recs:
                sec, frac = struct.unpack_from(e + 'II', data, p)
                out.write(struct.pack(e + 'II', sec + shift, frac))
                out.write(data[p + 8: p + 16 + incl])
    print("wrote %s: %d copies x %d packets" % (dst, n, len(recs)))

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], int(sys.argv[3]))
