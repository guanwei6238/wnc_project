#!/usr/bin/env python3
"""06_ports_summary.py — 彙整 06_ports.awk 的輸出。
用法: python3 -I 06_ports_summary.py <場景名，例如 1-1> <awk 輸出的 tsv> ...  （成對給）
輸出每個標籤：flow 數、前 4 名（協定/目的埠）占比、前 2 名 conn_state、來源 IP（≥1000 條）個數。"""
import collections
import sys

args = sys.argv[1:]
for sc, path in zip(args[0::2], args[1::2]):
    ports = collections.defaultdict(collections.Counter)
    tot = collections.Counter()
    states = collections.defaultdict(collections.Counter)
    srcs = collections.defaultdict(collections.Counter)
    for line in open(path):
        f = line.rstrip('\n').split('\t')
        if f[0] == 'PORT':
            lab, proto, port = f[1].split('|'); ports[lab][(proto, port)] += int(f[2])
        elif f[0] == 'TOTAL':
            tot[f[1]] = int(f[2])
        elif f[0] == 'STATE':
            lab, st = f[1].split('|'); states[lab][st] += int(f[2])
        elif f[0] == 'SRC':
            lab, ip = f[1].split('|'); srcs[lab][ip] += int(f[2])
    print('==', sc)
    for lab, n in tot.most_common(4):
        top = ports[lab].most_common(4)
        print('  %-34s %10d  目的埠: %s  | 狀態: %s | 來源IP(≥1000條) %d 個' % (
            lab, n, ', '.join('%s/%s %.1f%%' % (p, q, 100 * c / n) for (p, q), c in top),
            ', '.join('%s %.0f%%' % (k, 100 * v / n) for k, v in states[lab].most_common(2)), len(srcs[lab])))
