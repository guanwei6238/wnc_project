#!/usr/bin/env python3
"""產生 manifest.json：tar.gz 的 md5 / sha256，以及解壓後每個檔案的相對路徑、大小、sha256。
全部用串流方式算雜湊（一次讀 8 MB），不會把大檔載入記憶體。

用法：python3 -I 03_manifest.py <tar.gz> <解壓目錄> <輸出 manifest.json> <Zenodo 提供的 md5>
"""
import hashlib
import json
import os
import sys
import time


def hash_file(path, algos):
    hs = {a: hashlib.new(a) for a in algos}
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            for h in hs.values():
                h.update(chunk)
    return {a: h.hexdigest() for a, h in hs.items()}


def main():
    tar_path, root, out, md5_zenodo = sys.argv[1:5]
    t0 = time.time()
    h = hash_file(tar_path, ['md5', 'sha256'])
    manifest = {
        'source': 'Zenodo record 4743746 (DOI 10.5281/zenodo.4743746), CC-BY-4.0',
        'tarball': {
            'name': os.path.basename(tar_path),
            'size_bytes': os.path.getsize(tar_path),
            'md5_zenodo': md5_zenodo,
            'md5_computed': h['md5'],
            'md5_match': h['md5'] == md5_zenodo,
            'sha256_computed': h['sha256'],
        },
        'extracted_root': root,
        'files': [],
    }
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            p = os.path.join(dirpath, name)
            if os.path.islink(p):
                manifest['files'].append({'path': os.path.relpath(p, root), 'symlink': os.readlink(p)})
                continue
            manifest['files'].append({
                'path': os.path.relpath(p, root),
                'size_bytes': os.path.getsize(p),
                'sha256': hash_file(p, ['sha256'])['sha256'],
            })
            print(manifest['files'][-1]['path'], file=sys.stderr)
    manifest['file_count'] = len(manifest['files'])
    manifest['seconds'] = round(time.time() - t0)
    with open(out, 'w') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    print('done', manifest['file_count'], 'files', file=sys.stderr)


if __name__ == '__main__':
    main()
