#!/usr/bin/env python3
"""Summarize each label of the four datasets by one standard: flows, flows with alerts, flows matched by related rules, verdict.

Rule-matched flow: a flow with at least one alert whose SID is in that label's list in results/related_rules.tsv (ET SCAN* = msg starts with ET SCAN; "ET SCAN* -SID,SID" also removes the listed SIDs).
Verdict: ✓ rule-matched flows > 0; △ has alerts but none rule-matched; ✗ no alerts.
The IoT-23, CIC-IDS2017 and CIC-DDoS2019 match results only record how many flows each SID hit per label, not the SID combination of each flow,
so compute per scenario/day: no SID outside the list seen -> equals flows with alerts; no SID in the list seen -> 0;
only one SID in the list -> that SID's flow count; the listed SIDs are exactly the gw_corp SIDs seen -> equals the gw_corp flow count.
Otherwise output lower and upper bounds and mark exact=no. CICIoT2023 uses eve.json flow_id directly, and every flow in a file counts as that file's attack (official label).
Usage: python3 -I related_flows.py <out.tsv>
"""
import collections
import csv
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
D = '/home/sixsquare/datasets/detection'
MATCH = {
    'iot23': sorted(glob.glob(f'{D}/match/*.json')),
    'cicids2017': [f'{D}/match_cicids2017/{d}.json' for d in ('monday', 'tuesday', 'wednesday', 'thursday', 'friday')],
    'cicddos2019': [f'{D}/match_cicddos2019/0311_dedup.json', f'{D}/match_cicddos2019/0112.json'],
}
CICIOT = f'{D}/ciciot2023'
BENIGN_FILES = ['BenignTraffic', 'BenignTraffic1', 'BenignTraffic2', 'BenignTraffic3']

rules = {}
short = {}
for r in csv.DictReader(open(os.path.join(HERE, 'results', 'related_rules.tsv')), delimiter='\t'):
    rules[(r['dataset'], r['label'])] = r['related_sids']
    short[(r['dataset'], r['label'])] = r['rule_short']


def related_set(ds, label, msgs):
    spec = rules.get((ds, label))
    if not spec:
        return set()
    if spec.startswith('ET SCAN*'):
        drop = {int(x) for x in spec.split('-', 1)[1].split(',')} if ' -' in spec else set()
        return {s for s, m in msgs.items() if m.startswith('ET SCAN') and s not in drop}
    return {int(x) for x in spec.split(',')}


def one_label(v, rel, gw):
    full, sids = v['flows_alert_full'], {int(s): c for s, c in v['sids'].items()}
    present = set(sids)
    hit = present & rel
    if not hit:
        return 0, 0
    if hit == present:
        return full, full
    if len(hit) == 1:
        c = sids[next(iter(hit))]
        return c, c
    if hit == present & gw:
        return v['flows_alert_gw'], v['flows_alert_gw']
    lo = max(max(sids[s] for s in hit), full - sum(c for s, c in sids.items() if s not in rel))
    hi = min(full, sum(sids[s] for s in hit))
    return lo, hi


rows = collections.OrderedDict()


def add(ds, label, flows, full, gw, lo, hi):
    k = (ds, label)
    x = rows.setdefault(k, [0, 0, 0, 0, 0])
    for i, v in enumerate((flows, full, gw, lo, hi)):
        x[i] += v


for ds, files in MATCH.items():
    for f in files:
        d = json.load(open(f))
        msgs = {int(s): v['msg'] for s, v in d['sids'].items()}
        gw = {int(s) for s, v in d['sids'].items() if v['gw_corp']}
        day = ' (0311)' if '0311' in f else ' (0112)' if '0112' in f else ''
        for label, v in d['labels'].items():
            name = label + day if ds == 'cicddos2019' and not label.startswith('Benign') else label
            lo, hi = one_label(v, related_set(ds, name, msgs), gw)
            add(ds, name, v['flows'], v['flows_alert_full'], v['flows_alert_gw'], lo, hi)

gw_all = {int(x) for x in open(f'{D}/rules/gw_corp_sids.txt') if x.strip()}


def stats_flows(n):
    v = 0
    for line in open(os.path.join(CICIOT, n, 'stats.log')):
        m = re.match(r'flow\.total\s*\|\s*Total\s*\|\s*(\d+)', line)
        if m:
            v = int(m.group(1))
    return v


for n in sorted(os.listdir(CICIOT)):
    if not os.path.isfile(os.path.join(CICIOT, n, 'done.txt')):
        continue
    label = 'Benign' if n in BENIGN_FILES else re.sub(r'\d+$', '', n).rstrip('-_')
    fl = collections.defaultdict(set)
    msgs = {}
    for line in open(os.path.join(CICIOT, n, 'eve.json')):
        e = json.loads(line)
        s = e['alert']['signature_id']
        fl[e.get('flow_id')].add(s)
        msgs[s] = e['alert']['signature']
    rel = related_set('ciciot2023', label, msgs)
    full = len(fl)
    gw = sum(1 for v in fl.values() if v & gw_all)
    r = sum(1 for v in fl.values() if v & rel)
    add('ciciot2023', label, stats_flows(n), full, gw, r, r)

with open(sys.argv[1], 'w') as o:
    o.write('dataset\tlabel\tflows\talert_full\talert_gw\trelated\trelated_hi\texact\tjudgement\trule_short\n')
    for (ds, label), (flows, full, gw, lo, hi) in rows.items():
        benign = label.lower().startswith('benign')
        j = '' if benign else '✓' if lo > 0 else '△' if full > 0 else '✗'
        o.write(f'{ds}\t{label}\t{flows}\t{full}\t{gw}\t{lo}\t{hi}\t{"yes" if lo == hi else "no"}\t{j}\t'
                f'{short.get((ds, label), "")}\n')
