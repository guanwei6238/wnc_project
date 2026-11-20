#!/usr/bin/env python3
"""make_manifest.py -- build the manifest for frozen pcaps (packet count, bytes, duration, payload share, sha256, source and slicing method).

Usage: python3 -I make_manifest.py <pcap dir> <spec.tsv> <manifest.json>
spec.tsv, one line per file (tab-separated): file name <TAB> kind(slice|small|x2|synth) <TAB> source <TAB> slicing description
Stats are computed by pcap_stats.py (definitions at the top of that file); this only puts them together with sha256 and source info.
"""
import sys, os, json, hashlib, subprocess

pdir, spec, outp = sys.argv[1:4]
here = os.path.dirname(os.path.abspath(__file__))
items = []
for line in open(spec):
    line = line.rstrip('\n')
    if not line or line.startswith('#'): continue
    name, kind, source, method = line.split('\t')
    path = os.path.join(pdir, name)
    st = json.loads(subprocess.check_output([sys.executable, '-I', os.path.join(here, 'pcap_stats.py'), path]))
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for blk in iter(lambda: f.read(1 << 20), b''):
            h.update(blk)
    st.pop('file', None); st.pop('t_first', None); st.pop('t_last', None)
    items.append(dict(name=name, kind=kind, source=source, method=method,
                      file_bytes=os.path.getsize(path), sha256=h.hexdigest(), **st))
json.dump(items, open(outp, 'w'), indent=1, ensure_ascii=False)
print("wrote %s (%d files)" % (outp, len(items)))
