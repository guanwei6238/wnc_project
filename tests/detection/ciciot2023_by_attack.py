#!/usr/bin/env python3
"""CICIoT2023: aggregate the results of all pcaps per attack (folder), for judging ✓/△/✗ one by one.

Labels are per file only. As in summarize_ciciot2023.py, Benign files are the baseline: SIDs seen in any Benign file are background,
and only SIDs in other files never seen in Benign count as attack-specific. One row per attack: file count, packets, flows (sum of Suricata flow.total),
list of attack-specific SIDs (per SID: how many files, how many flows, whether in gw_corp, msg).
Usage: python3 -I ciciot2023_by_attack.py <results root> <ciciot2023_files.tsv> <gw_corp_sids> <out.tsv>
"""
import collections
import json
import os
import re
import sys

root, files_tsv, gw_path, out = sys.argv[1:5]
gw = {int(x) for x in open(gw_path) if x.strip()}
folder = {}
for line in open(files_tsv):
    f = line.rstrip('\n').split('\t')
    if f[0] != 'folder':
        folder[f[1][:-5]] = f[0]


def counter(stats, name):
    v = 0
    for line in open(stats):
        m = re.match(rf'{re.escape(name)}\s*\|\s*Total\s*\|\s*(\d+)', line)
        if m:
            v = int(m.group(1))
    return v


def alerts(n):
    with open(os.path.join(root, n, 'eve.json')) as f:
        for line in f:
            e = json.loads(line)
            if e.get('event_type', 'alert') == 'alert':
                yield e['alert']['signature_id'], e['alert']['signature'], e.get('flow_id')


done = [n for n in folder if os.path.isfile(os.path.join(root, n, 'done.txt'))]
benign = [n for n in done if folder[n] == 'Benign_Final']
benign_sids = {s for n in benign for s, _, _ in alerts(n)}
agg = collections.defaultdict(lambda: {'files': 0, 'packets': 0, 'flows': 0, 'sids': {}})
for n in sorted(done):
    a = agg[folder[n]]
    st = os.path.join(root, n, 'stats.log')
    a['files'] += 1; a['packets'] += counter(st, 'decoder.pkts'); a['flows'] += counter(st, 'flow.total')
    per = collections.defaultdict(set); msg = {}
    for s, m, fid in alerts(n):
        if folder[n] == 'Benign_Final' or s not in benign_sids:
            per[s].add(fid); msg[s] = m
    for s, fl in per.items():
        d = a['sids'].setdefault(s, {'files': 0, 'flows': 0, 'msg': msg[s]})
        d['files'] += 1; d['flows'] += len(fl)
total = collections.Counter(folder.values())
with open(out, 'w') as o:
    o.write('attack\tfiles_done\tfiles_total\tpackets\tflows\tspec_sids\tspec_flows\tspec_flows_gw\tsids\n')
    for k in sorted(agg):
        a = agg[k]
        sids = sorted(a['sids'].items(), key=lambda kv: -kv[1]['flows'])
        o.write('\t'.join(map(str, [k, a['files'], total[k], a['packets'], a['flows'], len(sids),
                                     sum(d['flows'] for _, d in sids), sum(d['flows'] for s, d in sids if s in gw),
                                     ' | '.join(f"{s}{'*' if s in gw else ''} {d['msg'][:60]} ({d['files']} 檔, {d['flows']} flows)"
                                                for s, d in sids)])) + '\n')
print(f'{len(done)} files, {len(benign)} Benign files, {len(benign_sids)} Benign SIDs -> {out}')
