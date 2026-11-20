#!/usr/bin/env python3
"""Convert CIC's CICFlowMeter CSV into the Zeek conn.log.labeled column layout,
so tests/iot23/align_stream.py (alignment) and match_iot23.py (alert-to-label matching) can be reused as is.

Supports: corrected CIC-IDS2017 (CNS 2022, CICIDS2017_improved) and the official CIC-DDoS2019 CSV.
Fills only the fields those two programs read: ts, uid, 5-tuple, proto, duration, orig_pkts, resp_pkts, label; others get '-' or 0.
  - strip whitespace around column names (DDoS2019 column names have leading spaces)
  - Timestamp plus --tz hours is treated as UTC (corrected CIC-IDS2017 is already UTC; for DDoS2019 confirm the offset by alignment rate)
  - Flow Duration is in microseconds
  - label fields cannot contain spaces (downstream splits on whitespace), so spaces become underscores:
      BENIGN -> "Benign -"; attack X -> "Malicious X"; Attempted Category != -1 -> "Attempted X"
Usage: python3 -I cic_to_conn.py [--tz hours] <output conn.log.labeled> <CSV>...
"""
import argparse
import csv
import sys
from datetime import datetime, timedelta, timezone

PROTO = {'6': 'tcp', '17': 'udp', '1': 'icmp'}

ap = argparse.ArgumentParser()
ap.add_argument('--tz', type=float, default=0.0)
ap.add_argument('out')
ap.add_argument('csv', nargs='+')
a = ap.parse_args()
shift = timedelta(hours=a.tz)
csv.field_size_limit(sys.maxsize)
n = 0
with open(a.out, 'w') as out:
    out.write('#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\t'
              'orig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\t'
              'orig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\tlabel\tdetailed-label\n')
    for path in a.csv:
        with open(path, newline='') as f:
            r = csv.reader(f)
            col = {name.strip(): i for i, name in enumerate(next(r))}
            isip, isp, idip, idp, ipr = (col[k] for k in ('Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol')) \
                if 'Src IP' in col else (col[k] for k in ('Source IP', 'Source Port', 'Destination IP',
                                                          'Destination Port', 'Protocol'))
            ifw = col.get('Total Fwd Packet', col.get('Total Fwd Packets'))
            ibw = col.get('Total Bwd packets', col.get('Total Backward Packets'))
            its, idur, ilab, iatt = col['Timestamp'], col['Flow Duration'], col['Label'], col.get('Attempted Category')
            for x in r:
                n += 1
                t = x[its]
                fmt = '%Y-%m-%d %H:%M:%S.%f' if '.' in t else '%Y-%m-%d %H:%M:%S'
                ts = (datetime.strptime(t, fmt) + shift).replace(tzinfo=timezone.utc).timestamp()
                lab = x[ilab].strip()
                if lab == 'BENIGN':
                    kind, detail = 'Benign', '-'
                else:
                    kind = 'Attempted' if iatt is not None and x[iatt] != '-1' else 'Malicious'
                    detail = lab.replace(' - Attempted', '').replace(' ', '_')
                out.write(f'{ts:.6f}\tC{n}\t{x[isip]}\t{x[isp]}\t{x[idip]}\t{x[idp]}\t{PROTO.get(x[ipr], "other")}\t-\t'
                          f'{int(float(x[idur])) / 1e6:.6f}\t0\t0\t-\t-\t-\t0\t-\t{x[ifw]}\t0\t{x[ibw]}\t0\t-\t'
                          f'{kind}\t{detail}\n')
