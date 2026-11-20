#!/usr/bin/env python3
"""Concatenate a classic pcap split into many pieces inside zips (200 MB each for CIC-DDoS2019) into one pcap in order, without extracting to disk first.

CIC-DDoS2019 file names are SAT-03-11-2018_0, _01, _02 ... _0145: sorted by the number after the underscore (may span several zips).
Only packet records are copied, not parsed; the 24-byte header of every piece after the first is skipped (after checking linktype and time precision match).
Prints a warning if a piece's first packet is earlier than the previous piece's last (meaning the piece order or the capture is off).
--every N: take only 1 of every N pieces (pieces 0, N, 2N...), for time-sampling a very large day;
--windows: write [first, last packet time] of each piece used, later used to keep only flows fully inside those windows.
Usage: python3 -I zip_pcap_concat.py [--every N] [--windows windows.tsv] <out.pcap> <zip>...
"""
import argparse
import re
import struct
import sys
import zipfile

ap = argparse.ArgumentParser()
ap.add_argument('--every', type=int, default=1)
ap.add_argument('--windows')
ap.add_argument('out')
ap.add_argument('zips', nargs='+')
a = ap.parse_args()

members = []
for path in a.zips:
    z = zipfile.ZipFile(path)
    members += [(int(re.search(r'_(\d+)$', n).group(1)), n, z) for n in z.namelist() if not n.endswith('/')]
members.sort(key=lambda m: m[0])
members = members[::a.every]
head = None
last_ts = 0.0
packets = 0
windows = []
with open(a.out, 'wb') as out:
    for _, n, z in members:
        with z.open(n) as f:
            h = f.read(24)
            if head is None:
                head = h
                out.write(h)
            elif h[:4] != head[:4] or h[20:24] != head[20:24]:
                sys.exit(f'{n}: 檔頭和第一段不同')
            e = '<' if head[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
            div = 1e9 if head[:4] in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d') else 1e6
            first_ts = None
            buf = b''
            while True:
                chunk = f.read(16 << 20)
                if not chunk:
                    break
                buf += chunk
                pos = 0
                while pos + 16 <= len(buf):
                    sec, frac, incl, _ = struct.unpack_from(e + 'IIII', buf, pos)
                    if pos + 16 + incl > len(buf):
                        break
                    ts = sec + frac / div
                    if first_ts is None:
                        first_ts = ts
                        if ts < last_ts:
                            print(f'warning: {n} 的第一個 packet（{ts:.6f}）早於上一段的最後一個（{last_ts:.6f}）', file=sys.stderr)
                    last_ts = ts
                    packets += 1
                    pos += 16 + incl
                out.write(buf[:pos])
                buf = buf[pos:]
            if buf:
                print(f'warning: {n} 尾端有 {len(buf)} bytes 不完整的 packet，已捨棄', file=sys.stderr)
            if first_ts is not None:
                windows.append((n, first_ts, last_ts))
if a.windows:
    with open(a.windows, 'w') as w:
        for n, t0, t1 in windows:
            w.write(f'{n}\t{t0:.6f}\t{t1:.6f}\n')
print(f'{len(members)} files, {packets} packets -> {a.out}', file=sys.stderr)
