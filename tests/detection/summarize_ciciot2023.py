#!/usr/bin/env python3
"""CICIoT2023: one row per pcap (label = the attack the file belongs to), summarizing the Suricata results.

Labels are per file only, so flows can't be matched to labels one by one. Every file also has background traffic from the lab network (ICMP ping, UPnP, etc.),
and Benign files trigger those rules too, so "has alerts" can't be taken as detecting the attack.
Benign files are the baseline here: SIDs seen in a Benign file are background; only SIDs in attack files that never appear in Benign count as attack-specific alerts.
Each row: packets, flows (Suricata flow.total), all alerts and flows with alerts (distinct flow_id),
alert and flow counts for attack-specific SIDs (full / gw_corp / gw_corp+iplist), and the most frequent attack-specific SIDs.
Usage: python3 -I summarize_ciciot2023.py <results root> <gw_corp_sids> <iplist_sids> <out.tsv> [Benign file names, comma separated, default BenignTraffic]
With several Benign files, the baseline is the union of the SIDs seen in them.
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
            v = int(m.group(1))          # take the last value (at exit)
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
