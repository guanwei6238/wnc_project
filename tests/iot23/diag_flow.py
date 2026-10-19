#!/usr/bin/env python3
"""診斷用：針對 conn.log.labeled 的幾條 flow（指定行號），列出 pcap 裡「同一個五元組」的所有封包，
標出每個封包相對於 flow 時間窗 [ts, ts+duration] 的位置，看對不上的原因。
只適合小 pcap / 少量 flow（會串流掃整個 pcap 一次）。

用法：python3 -I diag_flow.py <conn.log.labeled> <pcap> <行號> [<行號> ...]
"""
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location('al', Path(__file__).resolve().parent / 'align_stream.py')
al = importlib.util.module_from_spec(spec)
spec.loader.exec_module(al)

log, pcap, lines = sys.argv[1], sys.argv[2], {int(x) for x in sys.argv[3:]}
flows = {}
for lineno, f in al.iter_flows(log):
    if lineno in lines and f is not None:
        proto, key, ts, end, expect, state, label = al.flow_key(f)
        flows[key] = flows.get(key, []) + [(lineno, f, ts, end, expect)]
pk = {k: [] for k in flows}
for t, raw in al.PcapStream(pcap).packets():
    r = al.parse_packet(raw)
    if r is None:
        continue
    k = al.make_key(r[0], r[1], r[2])
    if k in pk:
        flags = raw[14 + (raw[14] & 15) * 4 + 13] if r[0] == 6 and raw[12:14] == b'\x08\x00' else None
        pk[k].append((t, r[3], flags))
for key, fl in flows.items():
    for lineno, f, ts, end, expect in fl:
        inw = [p for p in pk[key] if ts - al.EPS <= p[0] <= end + al.EPS]
        print(f'--- 行 {lineno} {f[6]} {f[2]}:{f[3]} -> {f[4]}:{f[5]} state={f[11]} history={f[15]} expect={expect} 窗內={len(inw)} 同五元組總數={len(pk[key])}')
        for t, pl, fg in pk[key]:
            pos = 'IN ' if ts - al.EPS <= t <= end + al.EPS else 'OUT'
            print(f'    {pos} t-ts={t - ts:+.6f}  (t-end={t - end:+.6f})  payload={pl} tcpflags={fg if fg is None else format(fg, "02x")}')
