#!/usr/bin/env python3
"""Keep only flows fully inside the sampled windows (ts >= window start, ts + duration <= window end).
Windows come from zip_pcap_concat.py --windows; flows outside them have no (or only some) packets in the sampled pcap.
Usage: python3 -I conn_in_windows.py <windows.tsv> <input conn.log.labeled> <output conn.log.labeled>
"""
import bisect
import sys

win = sorted((float(t0), float(t1)) for _, t0, t1 in (l.rstrip('\n').split('\t') for l in open(sys.argv[1])))
starts = [w[0] for w in win]
kept = total = 0
with open(sys.argv[2]) as f, open(sys.argv[3], 'w') as out:
    for line in f:
        if line.startswith('#'):
            out.write(line)
            continue
        x = line.split('\t', 9)
        ts = float(x[0])
        end = ts + (0.0 if x[8] == '-' else float(x[8]))
        total += 1
        i = bisect.bisect_right(starts, ts) - 1
        if i >= 0 and end <= win[i][1]:
            out.write(line)
            kept += 1
print(f'kept {kept} of {total} flows')
