#!/usr/bin/env python3
"""CICIoT2023：每個 pcap 一列（label = 檔案所屬的攻擊），整理 Suricata 的結果。

label 只到檔案層級，沒辦法逐條 flow 對 label。而且每個檔都有實驗網路的背景流量（ICMP ping、UPnP 等），
Benign 檔也會觸發這些 rule，所以「有沒有 alert」不能直接當成偵測到攻擊。
這裡以 Benign 檔為基準：Benign 檔出現過的 SID 視為背景，攻擊檔裡「Benign 沒出現過的 SID」才算攻擊特有的 alert。
每列輸出：packets、flows（Suricata 的 flow.total）、全部 alert 與有 alert 的 flow（distinct flow_id）、
攻擊特有 SID 的 alert 數與 flow 數（full／gw_corp／gw_corp+iplist）、最常出現的攻擊特有 SID。
用法: python3 -I summarize_ciciot2023.py <結果根目錄> <gw_corp_sids> <iplist_sids> <輸出.tsv> [Benign 檔名，逗號分隔，預設 BenignTraffic]
多個 Benign 檔時，基準是這些檔出現過的 SID 的聯集。
"""
import collections
import json
import os
import re
import sys

root, gw_path, ip_path, out = sys.argv[1:5]
benign_names = (sys.argv[5] if len(sys.argv) > 5 else 'BenignTraffic').split(',')
gw = {int(x) for x in open(gw_path) if x.strip()}
ip = {int(x) for x in open(ip_path) if x.strip()}


def counter(stats, name):
    v = 0
    for line in open(stats):
        m = re.match(rf'{re.escape(name)}\s*\|\s*Total\s*\|\s*(\d+)', line)
        if m:
            v = int(m.group(1))          # 取最後一次（結束時）的值
    return v


def load(n):
    alerts = []
    with open(os.path.join(root, n, 'eve.json')) as f:
        for line in f:
            e = json.loads(line)
            alerts.append((e['alert']['signature_id'], e['alert']['signature'], e.get('flow_id')))
    return alerts


benign_sids = {s for b in benign_names for s, _, _ in load(b)}
rows = []
for n in sorted(os.listdir(root)):
    d = os.path.join(root, n)
    if not os.path.isfile(os.path.join(d, 'done.txt')):
        continue
    cls = re.sub(r'\d+$', '', n).rstrip('-_')
    alerts = load(n)
    spec = [(s, m, fid) for s, m, fid in alerts if n in benign_names or s not in benign_sids]
    top = collections.Counter((s, m) for s, m, _ in spec).most_common(3)
    st = os.path.join(d, 'stats.log')
    rows.append({
        'class': cls, 'file': n, 'packets': counter(st, 'decoder.pkts'), 'flows': counter(st, 'flow.total'),
        'alerts': len(alerts), 'flows_alert': len({f for _, _, f in alerts}),
        'spec_alerts': len(spec), 'spec_sids': len({s for s, _, _ in spec}),
        'spec_flows_full': len({f for _, _, f in spec}),
        'spec_flows_gw': len({f for s, _, f in spec if s in gw}),
        'spec_flows_gwip': len({f for s, _, f in spec if s in gw or s in ip}),
        'top_spec_sids': '; '.join(f'{s} {m[:70]} ({c})' for (s, m), c in top),
    })

cols = list(rows[0].keys()) if rows else []
with open(out, 'w') as f:
    f.write('\t'.join(cols) + '\n')
    for r in rows:
        f.write('\t'.join(str(r[c]) for c in cols) + '\n')
