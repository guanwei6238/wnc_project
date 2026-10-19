#!/usr/bin/env python3
"""make_manifest.py -- 為凍結的 pcap 產生 manifest (封包數、位元組、持續時間、payload 占比、sha256、來源與切法)。

用法: python3 -I make_manifest.py <pcap 目錄> <spec.tsv> <manifest.json>
spec.tsv 每行 (Tab 分隔): 檔名 <TAB> 種類(slice|small|x2|synth) <TAB> 來源 <TAB> 切法說明
統計值由 pcap_stats.py 計算 (定義見該檔開頭)；這裡只負責把它們和 sha256、來源資訊放在一起。
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
