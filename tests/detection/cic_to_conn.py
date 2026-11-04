#!/usr/bin/env python3
"""把 CIC 的 CICFlowMeter CSV 轉成 Zeek conn.log.labeled 的欄位排列，
讓 tests/iot23/align_stream.py（對齊）和 match_iot23.py（alert 對 label）可以直接沿用。

支援：CIC-IDS2017 修正版（CNS 2022，CICIDS2017_improved）、CIC-DDoS2019 官方 CSV。
只填這兩支程式會讀的欄位：ts、uid、五元組、proto、duration、orig_pkts、resp_pkts、label；其他填 '-' 或 0。
  - 欄名前後的空白去掉（DDoS2019 的欄名有前導空白）
  - Timestamp 加上 --tz 小時後當成 UTC（CIC-IDS2017 修正版本來就是 UTC；DDoS2019 要用對齊率確認時差）
  - Flow Duration 是微秒
  - label 欄位不能有空白（下游用空白切欄位），所以空白換成底線：
      BENIGN -> "Benign -"；攻擊 X -> "Malicious X"；Attempted Category != -1 -> "Attempted X"
用法: python3 -I cic_to_conn.py [--tz 小時] <輸出 conn.log.labeled> <CSV>...
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
