#!/usr/bin/env python3
"""pcap_concat.py -- 把同一個 classic pcap 串接 N 次 (資料量變 N 倍)，用來驗證「處理時間與資料量成正比」。

用法: python3 -I pcap_concat.py <in.pcap> <out.pcap> <N>

為什麼要平移時間戳: 第二份若時間戳倒退回開頭，引擎會看到「時間倒流」，flow 逾時/清理的行為就和真實流量不同。
所以第 k 份 (k=0..N-1) 的每個時間戳加上 k * (整個檔案的持續時間 + 1 秒)，等於「同樣的流量接著再發生一次」。
只搬動封包記錄，不解析封包內容。(不用 mergecap/Scapy，容器和 Pi 都只需要 python3)
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
    # 先掃一遍，收集每筆記錄 (offset, incl_len)；遇到被截斷的尾端就丟掉
    recs = []; pos = 24; L = len(data)
    while pos + 16 <= L:
        incl = struct.unpack_from(e + 'I', data, pos + 8)[0]
        if pos + 16 + incl > L: break
        recs.append((pos, incl)); pos += 16 + incl
    if not recs: sys.exit("no packets")
    first = struct.unpack_from(e + 'II', data, recs[0][0]); last = struct.unpack_from(e + 'II', data, recs[-1][0])
    span = (last[0] - first[0]) + 1                     # 秒；整數即可，+1 秒間隔
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
