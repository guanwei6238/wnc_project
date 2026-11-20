#!/usr/bin/env python3
"""Merge the K JSONs from align_stream.py --part i/K into one (same as a single unsplit run).

Flows and packets of a given 5-tuple are always in the same part, so flows, aligned, pcap_covered_packets and per-label stats are summed directly;
the pcap packet count and other-proto flow counts are the same in every part, so take the first (and check they all match).
Usage: python3 -I merge_align.py <out.json> <part0.json> ... <partK-1.json>
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
