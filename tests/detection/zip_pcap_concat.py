#!/usr/bin/env python3
"""把 zip 裡切成很多段的 classic pcap（CIC-DDoS2019 每段 200 MB）依編號串成一個 pcap，不先解壓到磁碟。

CIC-DDoS2019 的檔名是 SAT-03-11-2018_0、_01、_02 … _0145：依底線後的數字排序（可以跨多個 zip）。
只搬動 packet 記錄，不解析內容；第二段之後的 24 bytes 檔頭跳過（檢查 linktype 與時間精度相同）。
每段的第一個 packet 時間若早於上一段的最後一個，印出警告（代表段落順序或錄製有問題）。
--every N：每 N 段只取 1 段（第 0、N、2N… 段），用來對很大的一天做時間抽樣；
--windows：輸出每個取用段落的 [第一個, 最後一個 packet 時間]，之後用來只留完整落在這些時段內的 flow。
用法: python3 -I zip_pcap_concat.py [--every N] [--windows 時段.tsv] <輸出.pcap> <zip>...
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
