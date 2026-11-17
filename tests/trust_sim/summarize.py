#!/usr/bin/env python3
"""把 run_all.sh 每個檔案的結果合併，依 dataset（CICIoT2023 另外依攻擊類別）加總。

輸出 <結果目錄>/files.tsv（每個檔案兩列：ctmark、tc）和 summary.tsv（每組兩列），並把 summary 印出來。
IoT-23 的封包數和 ../iot23/results/*.json 的 pcap_packets 比對，不一致就印 warning。
用法: python3 -I summarize.py <run_all.sh 的輸出目錄> <結果目錄>
"""
import collections
import glob
import json
import os
import sys

src, dst = sys.argv[1:3]
here = os.path.dirname(os.path.abspath(__file__))
DATASETS = ['iot23', 'cicids2017', 'cicddos2019', 'ciciot2023']
SUM = ['packets', 'bytes', 'fast_packets', 'fast_bytes', 'trusted', 'expired', 'revoked', 'refused', 'idle_ended',
       'alerts_seen', 'alerts_missed', 'other_packets', 'vlan_packets', 'alerts_unplaced', 'alerts_beyond_end',
       'alerts_mismatched', 'alerts_out_of_order', 'idle_resumed', 'idle_resumed_packets']
CICIOT_GROUPS = {
    'Benign_Final': 'Benign', 'DNS_Spoofing': 'Spoofing', 'MITM-ArpSpoofing': 'Spoofing',
    'VulnerabilityScan': 'Recon', 'DictionaryBruteForce': 'BruteForce',
    'Backdoor_Malware': 'Web', 'BrowserHijacking': 'Web', 'CommandInjection': 'Web', 'SqlInjection': 'Web',
    'Uploading_Attack': 'Web', 'XSS': 'Web',
}

rows = []
for dataset in DATASETS:
    for path in sorted(glob.glob(os.path.join(src, dataset, '*.tsv'))):
        rows += [(dataset, line.rstrip('\n').split('\t')) for line in open(path)]
cols = ('name variant packets bytes fast_packets fast_bytes fast_packet_pct fast_byte_pct trusted expired revoked '
        'refused idle_ended alerts_seen alerts_missed peak_conntrack peak_trusted other_packets vlan_packets '
        'duration_s alerts_unplaced alerts_beyond_end alerts_mismatched alerts_out_of_order missed_sids '
        'idle_resumed idle_resumed_packets idle_resumed_ports').split()

folder = {}
for line in open(os.path.join(here, '..', 'detection', 'results', 'ciciot2023_files.tsv')):
    f = line.rstrip('\n').split('\t')
    if f[0] != 'folder':
        folder[f[1][:-5]] = f[0]


def group_of(dataset, name):
    if dataset != 'ciciot2023':
        return None
    d = folder[name]
    return 'ciciot2023/' + CICIOT_GROUPS.get(d, d.split('-')[0])


expected = {}
for path in glob.glob(os.path.join(here, '..', 'iot23', 'results', '*.json')):
    n = os.path.basename(path)[:-5]
    sid = (n[len('CTU-IoT-Malware-Capture-'):] if n.startswith('CTU-IoT-Malware-Capture-')
           else 'H' + n[len('CTU-Honeypot-Capture-'):].replace('__', '_'))
    expected[sid] = json.load(open(path)).get('pcap_packets')

os.makedirs(dst, exist_ok=True)
groups = collections.OrderedDict()
resumed_ports = {}
with open(os.path.join(dst, 'files.tsv'), 'w') as out:
    out.write('dataset\t' + '\t'.join(cols) + '\n')
    for dataset, f in rows:
        if len(f) != len(cols):
            sys.exit(f'error: {dataset}/{f[0]} has {len(f)} columns, expected {len(cols)}')
        r = dict(zip(cols, f))
        out.write(dataset + '\t' + '\t'.join(f) + '\n')
        if dataset == 'iot23' and r['variant'] == 'ctmark' and expected.get(r['name']) not in (None, int(r['packets'])):
            print(f'warning: iot23/{r["name"]} read {r["packets"]} packets, alignment saw {expected[r["name"]]}')
        for g in filter(None, [dataset, group_of(dataset, r['name'])]):
            acc = groups.setdefault((g, r['variant']), collections.Counter(files=0))
            acc['files'] += 1
            for c in SUM:
                acc[c] += int(r[c])
            if r['idle_resumed_ports'] != '-':
                ports = resumed_ports.setdefault(g, collections.Counter())
                for item in r['idle_resumed_ports'].split(','):
                    port, counts = item.split(':')
                    c, p = map(int, counts.split('/'))
                    ports[(port, 'conns')] += c
                    ports[(port, 'packets')] += p


def pct(a, b):
    return f'{100 * a / b:.3f}' if b else '0'


OUT_COLS = ['group', 'variant', 'files', 'packets', 'fast_packet_pct', 'fast_byte_pct', 'trusted', 'revoked',
            'refused', 'idle_ended', 'alerts_seen', 'alerts_missed', 'alerts_missed_pct', 'other_packet_pct',
            'alerts_unplaced', 'alerts_beyond_end', 'alerts_mismatched', 'alerts_out_of_order', 'idle_resumed',
            'idle_resumed_pkt_pct', 'idle_resumed_top_ports']
def top_ports(g):
    ports = resumed_ports.get(g, collections.Counter())
    names = sorted({p for p, _ in ports}, key=lambda p: -ports[(p, 'packets')])[:5]
    return ','.join(f'{p}:{ports[(p, "conns")]}/{ports[(p, "packets")]}' for p in names) or '-'


with open(os.path.join(dst, 'summary.tsv'), 'w') as out:
    out.write('\t'.join(OUT_COLS) + '\n')
    print('\t'.join(OUT_COLS))
    for (g, variant), a in groups.items():
        alerts = a['alerts_seen'] + a['alerts_missed']
        v = [g, variant, a['files'], a['packets'], pct(a['fast_packets'], a['packets']),
             pct(a['fast_bytes'], a['bytes']), a['trusted'], a['revoked'], a['refused'], a['idle_ended'],
             a['alerts_seen'], a['alerts_missed'], pct(a['alerts_missed'], alerts),
             pct(a['other_packets'], a['packets']), a['alerts_unplaced'], a['alerts_beyond_end'],
             a['alerts_mismatched'], a['alerts_out_of_order'], a['idle_resumed'],
             pct(a['idle_resumed_packets'], a['packets']), top_ports(g) if variant == 'tc' else '-']
        line = '\t'.join(map(str, v))
        out.write(line + '\n')
        print(line)
