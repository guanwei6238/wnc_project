#!/usr/bin/env python3
"""把 align_stream.py --part i/K 的 K 個 JSON 合成一個（等同不分份跑一次的結果）。

同一個五元組的 flow 和 packet 一定在同一份，所以 flow、aligned、pcap_covered_packets、各 label 的統計直接相加；
pcap 的 packet 數、other proto 的 flow 數每份都一樣，取第一份（並檢查各份相同）。
用法: python3 -I merge_align.py <輸出.json> <part0.json> ... <partK-1.json>
"""
import collections
import json
import sys

out, paths = sys.argv[1], sys.argv[2:]
rs = [json.load(open(p)) for p in paths]
k = rs[0]['part'][1]
assert sorted(r['part'][0] for r in rs) == list(range(k)) and all(r['part'][1] == k for r in rs), 'parts 不完整'
same = ('pcap_packets', 'pcap_ip_packets', 'pcap_truncated_tail', 'pcap_linktype', 'pcap_time_range',
        'skipped_flows_other_proto', 'malformed_log_lines')
for key in same:
    assert all(r[key] == rs[0][key] for r in rs), f'{key} 各份不同'

m = {key: rs[0][key] for key in ('pcap', 'log') + same}
for key in ('pcap_covered_packets', 'flows', 'aligned', 'unaligned'):
    m[key] = sum(r[key] for r in rs)
lt = [r['log_time_range'] for r in rs if r['log_time_range']]
m['log_time_range'] = [min(t[0] for t in lt), max(t[1] for t in lt)] if lt else None
m['unaligned_kinds'] = dict(sum((collections.Counter(r['unaligned_kinds']) for r in rs), collections.Counter()))
m['unaligned_examples'] = sorted((e for r in rs for e in r['unaligned_examples']), key=lambda e: e['line'])[:5]
m['shards'] = [r['shards'] for r in rs]
m['parts'] = k
labels = collections.defaultdict(collections.Counter)
for r in rs:
    for lab, s in r['labels'].items():
        labels[lab].update(s)
m['labels'] = {lab: dict(s) for lab, s in sorted(labels.items())}
open(out, 'w').write(json.dumps(m, ensure_ascii=False, indent=1))
print(f'{out}: {m["flows"]:,} flows, aligned {m["aligned"]:,}, covered {m["pcap_covered_packets"]:,}/{m["pcap_packets"]:,}',
      file=sys.stderr)
