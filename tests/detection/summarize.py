#!/usr/bin/env python3
"""把 match_iot23.py 的結果整理成每個 (scenario/day, label) 一列的 TSV，以及跨 scenario 依 label 合計的 TSV。

用法: python3 -I summarize.py <名稱> <輸出目錄> <match.json>...
  <名稱> 例如 iot23；每個 match.json 的檔名（去掉 .json）當成 scenario 名稱。
輸出: <輸出目錄>/<名稱>_by_scenario.tsv、<名稱>_by_label.tsv、<名稱>_sids.tsv
欄位: flows、各 rule set 有 alert 的 flow 數與比例；sids 檔列出每個 SID 打中哪些 label 的幾條 flow。
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
scen_with = collections.defaultdict(lambda: [0, 0])     # label -> [有這個 label 的 scenario 數, 其中有 alert 的]
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
