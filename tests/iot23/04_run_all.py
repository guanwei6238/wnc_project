#!/usr/bin/env python3
"""Run align_stream.py once for each scenario under the extract directory, saving results/<scenario>.json.

A "scenario" = a folder in the extract directory that directly contains *.pcap or a bro/ subfolder.
  - regular scenarios: e.g. CTU-IoT-Malware-Capture-1-1, where bro/conn.log.labeled matches one of the pcaps
  - CTU-Honeypot-Capture-7-1 also has six subfolders Somfy-01 ~ Somfy-06, each counted as a scenario
A scenario folder may hold several pcaps (e.g. small slices cut out besides the main capture).
This script always takes the largest pcap as the main capture to align with conn.log.labeled
(and checks that the conn.log time range falls inside that pcap's time range as a sanity check, see report);
other pcaps only get their name and size recorded, without alignment (the report marks them "not done").
Scenarios missing a pcap or conn.log.labeled: without a log, only pcap packets are counted; without a pcap, the reason is recorded.

One scenario, one pcap at a time (sequential). Every subprocess runs under nice/ionice
with a 6 GB address space limit (exceeding it raises MemoryError instead of dragging the machine down).
Scenarios that already have a result file are skipped; delete the json to rerun.

Usage: python3 -I 04_run_all.py <extract dir> <results dir> [--max-flows N] [scenario name substring ...]
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
    """Return [(display name, folder)]: folders that directly contain *.pcap or bro/."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        d = Path(dirpath)
        if 'bro' in dirnames or any(f.endswith('.pcap') for f in filenames):
            found.append((str(d.relative_to(root)).replace('/', '__').split('IoTScenarios__')[-1].split('BigDataset__')[-1], d))
    return sorted(found, key=lambda t: [int(x) if x.isdigit() else x for x in t[0].replace('-', ' ').replace('_', ' ').split()])


def first_pcap_ts(path):
    """Read the time of the pcap's first packet (reads only the start, not the whole file)."""
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
        if out.exists():          # json is written only on success, so interrupted scenarios rerun next time
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
