#!/usr/bin/env python3
"""對解壓目錄下的每個場景，各跑一次 align_stream.py，結果存成 results/<場景>.json。

「場景」= 解壓目錄裡「直接放有 *.pcap 或 bro/ 子資料夾」的資料夾。
  - 一般場景：CTU-IoT-Malware-Capture-1-1 之類，bro/conn.log.labeled 對應其中一個 pcap
  - CTU-Honeypot-Capture-7-1 底下還有 Somfy-01 ~ Somfy-06 六個子資料夾，各算一個場景
一個場景資料夾可能有多個 pcap（例如主 capture 之外還有裁切出來的小檔）。
本腳本固定拿「最大的那個 pcap」當主 capture 與 conn.log.labeled 對齊
（再用 conn.log 的時間範圍是否落在該 pcap 時間範圍內，當作合理性檢查，見 report）；
其餘 pcap 只記錄檔名與大小，不做對齊（報告會標示「沒做」）。
缺 pcap 或缺 conn.log.labeled 的場景：缺 log 的只數 pcap 封包；缺 pcap 的記錄原因。

一次只處理一個場景、一個 pcap（序列執行）。每個子行程都用 nice/ionice，
並限制位址空間 6 GB（超過會直接 MemoryError，而不是把電腦拖垮）。
已經有結果檔的場景會跳過，要重跑請先刪掉該 json。

用法：python3 -I 04_run_all.py <解壓目錄> <results 目錄> [--max-flows N] [場景名稱子字串 ...]
"""
import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MEM_LIMIT = 6 * 1024 ** 3


def limit_memory():
    resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT, MEM_LIMIT))


def find_scenarios(root):
    """回傳 [(顯示名稱, 資料夾)]：直接含有 *.pcap 或 bro/ 的資料夾。"""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        d = Path(dirpath)
        if 'bro' in dirnames or any(f.endswith('.pcap') for f in filenames):
            found.append((str(d.relative_to(root)).replace('/', '__').split('IoTScenarios__')[-1].split('BigDataset__')[-1], d))
    return sorted(found, key=lambda t: [int(x) if x.isdigit() else x for x in t[0].replace('-', ' ').replace('_', ' ').split()])


def first_pcap_ts(path):
    """讀 pcap 第一個封包的時間（只讀開頭，不掃整檔）。"""
    import struct
    with open(path, 'rb') as f:
        h = f.read(40)
    e = '<' if h[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    sec, frac = struct.unpack(e + 'II', h[24:32])
    return sec + frac / 1e6


def main():
    args = sys.argv[1:]
    max_flows = '3000000'
    if '--max-flows' in args:
        i = args.index('--max-flows')
        max_flows = args[i + 1]
        del args[i:i + 2]
    root, outdir = Path(args[0]), Path(args[1])
    only = args[2:]
    outdir.mkdir(parents=True, exist_ok=True)
    for name, sc in find_scenarios(root):
        if only and not any(o in name for o in only):
            continue
        out = outdir / (name + '.json')
        if out.exists():          # 只有成功才會寫 json，所以被中斷的場景下次會自動重跑
            print('skip', name, flush=True)
            continue
        pcaps = sorted(sc.glob('*.pcap'), key=lambda p: -p.stat().st_size)
        logs = sorted(sc.glob('bro/conn.log.labeled'))
        info = {'scenario': name,
                'main_pcap': pcaps[0].name if pcaps else None,
                'extra_pcaps': {p.name: p.stat().st_size for p in pcaps[1:]},
                'log_file': 'bro/conn.log.labeled' if logs else None}
        if not pcaps:
            info['error'] = '沒有 pcap'
            out.write_text(json.dumps(info, ensure_ascii=False, indent=1))
            print(name, info['error'], flush=True)
            continue
        if logs:
            info['pcap_first_ts'] = first_pcap_ts(pcaps[0])
        t0 = time.time()
        tmp = outdir / (name + '.partial')
        cmd = ['nice', '-n', '10', 'ionice', '-c3', 'python3', '-I', str(HERE / 'align_stream.py'),
               str(logs[0]) if logs else '-', str(pcaps[0]), '--json', str(tmp), '--max-flows', max_flows]
        r = subprocess.run(cmd, preexec_fn=limit_memory, capture_output=True, text=True)
        if r.returncode != 0:
            info['error'] = 'align_stream 失敗: ' + r.stderr[-500:]
            out.write_text(json.dumps(info, ensure_ascii=False, indent=1))
            print(name, info['error'], flush=True)
            continue
        res = json.loads(tmp.read_text())
        tmp.unlink()
        res.update(info)
        if not logs:
            res['note'] = '沒有 conn.log.labeled，只數封包，沒有做對齊'
        res['seconds'] = round(time.time() - t0)
        out.write_text(json.dumps(res, ensure_ascii=False, indent=1))
        print(f'{name}: {res["flows"]:,} flows, {res["aligned"]:,} aligned, '
              f'{res["pcap_packets"]:,} pkts, {res["seconds"]}s', flush=True)


if __name__ == '__main__':
    main()
