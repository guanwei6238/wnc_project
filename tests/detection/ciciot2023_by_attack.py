#!/usr/bin/env python3
"""CICIoT2023：依攻擊（資料夾）彙總全部 pcap 的結果，給逐一判斷 ✓／△／✗ 用。

label 只到檔案層級。和 summarize_ciciot2023.py 一樣以 Benign 檔為基準：全部 Benign 檔出現過的 SID 視為背景，
其他檔裡 Benign 沒出現過的 SID 才算「攻擊特有」。每種攻擊一列：檔數、packets、flows（Suricata flow.total 加總）、
攻擊特有 SID 的清單（每個 SID：在幾個檔出現、幾條 flow、是否在 gw_corp、msg）。
用法: python3 -I ciciot2023_by_attack.py <結果根目錄> <ciciot2023_files.tsv> <gw_corp_sids> <輸出.tsv>
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
