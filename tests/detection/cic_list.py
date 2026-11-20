#!/usr/bin/env python3
"""List all files under a cicresearch.ca dataset (walking browse.php recursively) as TSV: path, raw size field, download URL.
The token is the cookie (named Token) the browser gets after filling in the download form, read from the CIC_TOKEN env var and never written to a file.
Usage: CIC_TOKEN=... python3 -I cic_list.py <base, e.g. https://cicresearch.ca/CICDataset/CIC-IDS-2017> > list.tsv
"""
import html
import os
import re
import sys
import urllib.parse
import urllib.request

base = sys.argv[1].rstrip('/')
hdr = {'Cookie': 'Token=' + os.environ['CIC_TOKEN'], 'User-Agent': 'curl/8.5.0'}


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), timeout=60) as r:
        return r.read().decode('utf-8', 'replace')


todo, seen = [''], set()
while todo:
    p = todo.pop()
    if p in seen:
        continue
    seen.add(p)
    page = get(f'{base}/browse.php' + (f'?p={urllib.parse.quote_plus(p)}' if p else ''))
    for m in re.finditer(r'href="(browse|download)\.php\?(p|file)=([^"]+)"([^<]*)</a>([^<\n]*)', page):
        kind, val = m.group(1), html.unescape(urllib.parse.unquote_plus(m.group(3)))
        if kind == 'browse':
            todo.append(val)
        else:
            print(f'{val}\t{html.unescape(m.group(5)).strip()}\t{base}/download.php?file={urllib.parse.quote(val)}')
