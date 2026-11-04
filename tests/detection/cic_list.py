#!/usr/bin/env python3
"""列出 cicresearch.ca 某個 dataset 底下的所有檔案（遞迴走 browse.php），輸出 TSV：路徑、大小欄位原文、download 網址。
token 是填完下載表單後瀏覽器拿到的 cookie（名稱 Token），從環境變數 CIC_TOKEN 讀，不寫進檔案。
用法: CIC_TOKEN=... python3 -I cic_list.py <base，例如 https://cicresearch.ca/CICDataset/CIC-IDS-2017> > list.tsv
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
