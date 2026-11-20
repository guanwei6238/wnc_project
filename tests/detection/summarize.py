#!/usr/bin/env python3
"""Turn match_iot23.py results into a TSV with one row per (scenario/day, label), plus a TSV of per-label totals across scenarios.

Usage: python3 -I summarize.py <name> <out dir> <match.json>...
  <name> e.g. iot23; each match.json file name (without .json) is used as the scenario name.
Output: <out dir>/<name>_by_scenario.tsv, <name>_by_label.tsv, <name>_sids.tsv
Columns: flows, number and share of flows with alerts per rule set; the sids file lists how many flows of which labels each SID hit.
"""
import collections
import json
import os
import sys

name, outdir, files = sys.argv[1], sys.argv[2], sys.argv[3:]
os.makedirs(outdir, exist_ok=True)
SETS = (('full', 'flows_alert_full'), ('gw_corp', 'flows_alert_gw'), ('gw_corp+iplist', 'flows_alert_gwip'))


def pct(a, b):
    return f'{100 * a / b:.2f}' if b else '-'


tot = collections.defaultdict(lambda: collections.Counter())
scen_with = collections.defaultdict(lambda: [0, 0])     # label -> [scenarios with this label, of which with alerts]
sid_rows = collections.Counter()
sid_msg, sid_set = {}, {}
with open(f'{outdir}/{name}_by_scenario.tsv', 'w') as f:
    f.write('scenario\tlabel\tflows' + ''.join(f'\t{s}_flows\t{s}_pct' for s, _ in SETS) + '\ttop_sids\n')
    for path in files:
        scen = os.path.basename(path)[:-5]
        d = json.load(open(path))
        for sid, v in d['sids'].items():
            sid_msg[sid] = v['msg']
            sid_set[sid] = 'gw_corp' if v['gw_corp'] else ('iplist' if v.get('iplist') else '-')
        for label, v in d['labels'].items():
            f.write(f'{scen}\t{label}\t{v["flows"]}' +
                    ''.join(f'\t{v[k]}\t{pct(v[k], v["flows"])}' for _, k in SETS) +
                    '\t' + ','.join(f'{s}:{n}' for s, n in list(v['sids'].items())[:5]) + '\n')
            t = tot[label]
            t['flows'] += v['flows']
            for _, k in SETS:
                t[k] += v[k]
            scen_with[label][0] += 1
            scen_with[label][1] += v['flows_alert_full'] > 0
            for sid, n in v['sids'].items():
                sid_rows[(sid, label)] += n

with open(f'{outdir}/{name}_by_label.tsv', 'w') as f:
    f.write('label\tscenarios\tscenarios_with_alert\tflows' + ''.join(f'\t{s}_flows\t{s}_pct' for s, _ in SETS) + '\n')
    for label, t in sorted(tot.items(), key=lambda kv: -kv[1]['flows']):
        f.write(f'{label}\t{scen_with[label][0]}\t{scen_with[label][1]}\t{t["flows"]}' +
                ''.join(f'\t{t[k]}\t{pct(t[k], t["flows"])}' for _, k in SETS) + '\n')

with open(f'{outdir}/{name}_sids.tsv', 'w') as f:
    f.write('sid\tset\tlabel\tflows\tmsg\n')
    for (sid, label), n in sorted(sid_rows.items(), key=lambda kv: -kv[1]):
        f.write(f'{sid}\t{sid_set.get(sid, "?")}\t{label}\t{n}\t{sid_msg.get(sid, "")}\n')
