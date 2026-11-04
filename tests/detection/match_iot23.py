#!/usr/bin/env python3
"""IoT-23：把 Suricata 的 alert 對回 conn.log.labeled 的 flow，算每個 label 的偵測結果。

對法（五元組與時間的定義和 tests/iot23/align_stream.py 相同）：
  - 五元組雙向都算（兩端點排序後當 key）；ICMP 不看 port
  - alert 的封包時間落在 conn 的 [ts, ts+duration]（兩端各放寬 1 µs）-> 對上
  - 落不進任何 conn 時，再看 alert 所屬 Suricata flow 的起始時間（flow.start）和 conn 的 ts 是否相差 ≤ 1 ms
    （例如 flow timeout 時才送出的 alert，時間會在 Zeek 記的最後一個封包之後）
  - 一筆 alert 可能落在多條 conn（同五元組、時間重疊），每條都算
一條 conn 只要有一筆 alert 對上，就算「有 alert」；gw_corp 只看 SID 在 gw_corp 清單裡的 alert；
gw_corp+iplist 再加上長 IP 清單的 rule（gateway 設計上改用 nftables 的 IP 集合比對，偵測面一樣）。

用法: python3 -I match_iot23.py <conn.log.labeled> <eve.json> <gw_corp_sids.txt> <iplist_sids.txt> <輸出.json> [批數，預設 1] [--cic]
--cic：label 來自原版 CICFlowMeter 的 CSV（CIC-DDoS2019）。它把解不出 TCP/UDP header 的 packet（ICMP、後續 fragment 等）記成
       Protocol 0、port 0/0 的 flow（conn 裡是 other），CSV 沒有 ICMP flow，所以非 TCP/UDP 的 alert 對到同一對 IP 的 other flow。
       CIC-IDS2017 修正版不要用：它有 ICMP flow，Protocol 0 是非 IP 的 frame。
alert 太多、記憶體不夠時（39-1 約 1,470 萬筆），依五元組分成幾批，每批各讀一次 eve.json 和 conn.log；結果和不分批相同。
"""
import array
import bisect
import collections
import ipaddress
import json
import sys
from datetime import datetime

EPS = 1e-6
FSTART_TOL = 1e-3
PROTO = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp', 'IPv6-ICMP': 'icmp'}
CIC = False


def norm_ip(ip):
    return ipaddress.ip_address(ip).compressed if ':' in ip else ip


def make_key(proto, h1, p1, h2, p2):
    if proto in ('icmp', 'other'):
        p1 = p2 = '0'
    a, b = f'{norm_ip(h1)}|{p1}', f'{norm_ip(h2)}|{p2}'
    return f'{proto} {a} {b}' if a < b else f'{proto} {b} {a}'


def epoch(s):
    return datetime.fromisoformat(s).timestamp()


def load_alerts(path, shards, shard):
    a_ts, a_fs, a_sid = array.array('d'), array.array('d'), array.array('i')
    by_key = collections.defaultdict(list)
    sid_info = {}
    other = collections.Counter()
    with open(path) as f:
        for line in f:
            d = json.loads(line)
            if d.get('event_type') != 'alert':
                continue
            sid = d['alert']['signature_id']
            proto = PROTO.get(d.get('proto'))
            if CIC and proto not in ('tcp', 'udp'):
                proto = 'other'
            if shard == 0:
                info = sid_info.setdefault(sid, [d['alert']['signature'], 0])
                info[1] += 1
                if proto is None or 'src_ip' not in d:
                    other[sid] += 1
            if proto is None or 'src_ip' not in d:
                continue
            key = make_key(proto, d['src_ip'], str(d.get('src_port', 0)), d['dest_ip'], str(d.get('dest_port', 0)))
            if hash(key) % shards != shard:
                continue
            i = len(a_sid)
            a_ts.append(epoch(d['timestamp']))
            a_fs.append(epoch(d['flow']['start']) if 'flow' in d else -1.0)
            a_sid.append(sid)
            by_key[key].append(i)
    return a_ts, a_fs, a_sid, by_key, sid_info, other


def main():
    global CIC
    argv = [a for a in sys.argv[1:] if a != '--cic']
    CIC = len(argv) < len(sys.argv) - 1
    conn_path, eve_path, gw_path, ip_path, out_path = argv[:5]
    shards = int(argv[5]) if len(argv) > 5 else 1
    conn_protos = ('tcp', 'udp', 'icmp', 'other') if CIC else ('tcp', 'udp', 'icmp')
    gw = {int(x) for x in open(gw_path) if x.strip()}
    gwip = gw | {int(x) for x in open(ip_path) if x.strip()}
    labels, flows = {}, collections.Counter()
    match_n = collections.Counter()
    unmatched = collections.Counter()
    lab_sids = collections.defaultdict(collections.Counter)    # label -> SID -> 有該 SID alert 的 flow 數
    det_full, det_gw, det_gwip = collections.Counter(), collections.Counter(), collections.Counter()
    lab_alerts = collections.Counter()
    for shard in range(shards):
        a_ts, a_fs, a_sid, by_key, si, ot = load_alerts(eve_path, shards, shard)
        if shard == 0:
            sid_info, other = si, ot
        n = len(a_sid)
        pairs = set()
        for k in by_key:
            _, a, b = k.split(' ')
            h1, h2 = a.split('|')[0], b.split('|')[0]
            pairs.add(h1 + ' ' + h2 if h1 < h2 else h2 + ' ' + h1)

        # 讀 conn.log：數每個 label 的 flow 數（只在第一批）；alert 有出現的五元組，記下它的 conn（ts, end, label 編號）
        conns = collections.defaultdict(list)
        with open(conn_path, errors='replace') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                x = line.split()
                if len(x) < 23 or x[6] not in conn_protos:
                    continue
                label = x[-2] if x[-1] == '-' else f'{x[-2]} {x[-1]}'
                lid = labels.setdefault(label, len(labels))
                if shard == 0:
                    flows[lid] += 1
                h1, h2 = norm_ip(x[2]), norm_ip(x[4])
                if (h1 + ' ' + h2 if h1 < h2 else h2 + ' ' + h1) not in pairs:
                    continue
                key = make_key(x[6], h1, x[3], h2, x[5])
                if key in by_key:
                    ts = float(x[0])
                    dur = 0.0 if x[8] == '-' else float(x[8])
                    conns[key].append((ts, ts + dur, lid))
        del pairs

        # 每個五元組各自配對 alert 與 conn
        how = bytearray(n)          # 0 = 沒對上，1 = 時間落在 conn 內，2 = 靠 flow.start 對上
        for key, idxs in by_key.items():
            cl = conns.get(key)
            if not cl:
                continue
            cl.sort()
            starts = [c[0] for c in cl]
            hit = collections.defaultdict(set)      # conn 序號 -> 對上的 SID
            for i in idxs:
                t = a_ts[i]
                j = bisect.bisect_right(starts, t + EPS)
                found = [c for c in range(max(0, j - 64), j) if cl[c][1] + EPS >= t]
                if found:
                    how[i] = 1
                else:
                    fs = a_fs[i]
                    lo = bisect.bisect_left(starts, fs - FSTART_TOL)
                    hi = bisect.bisect_right(starts, fs + FSTART_TOL)
                    found = list(range(lo, hi))
                    if found:
                        how[i] = 2
                if len(found) > 1:
                    match_n['multi_conn'] += 1
                for c in found:
                    hit[c].add(a_sid[i])
                for lid in {cl[c][2] for c in found}:
                    lab_alerts[lid] += 1
            for c, sids in hit.items():
                lid = cl[c][2]
                det_full[lid] += 1
                if sids & gw:
                    det_gw[lid] += 1
                if sids & gwip:
                    det_gwip[lid] += 1
                for s in sids:
                    lab_sids[lid][s] += 1
        match_n['in_time'] += how.count(1)
        match_n['by_flow_start'] += how.count(2)
        match_n['unmatched'] += how.count(0)
        for i in range(n):
            if how[i] == 0:
                unmatched[a_sid[i]] += 1
        del a_ts, a_fs, a_sid, by_key, conns, how

    inv = {v: k for k, v in labels.items()}
    out = {
        'conn_log': conn_path, 'eve': eve_path, 'shards': shards,
        'alerts': sum(v[1] for v in sid_info.values()),
        'alerts_gw': sum(v[1] for s, v in sid_info.items() if s in gw),
        'alerts_gwip': sum(v[1] for s, v in sid_info.items() if s in gwip),
        'alert_match': {k: match_n[k] for k in ('in_time', 'by_flow_start', 'unmatched', 'multi_conn')} |
                       {'non_tcp_udp_icmp': sum(other.values())},
        'unmatched_by_sid': dict(unmatched.most_common()),
        'labels': {inv[lid]: {'flows': flows[lid], 'flows_alert_full': det_full[lid], 'flows_alert_gw': det_gw[lid],
                              'flows_alert_gwip': det_gwip[lid],
                              'alerts': lab_alerts[lid], 'sids': dict(lab_sids[lid].most_common())}
                   for lid in sorted(flows, key=lambda l: -flows[l])},
        'sids': {s: {'msg': m, 'alerts': c, 'gw_corp': s in gw, 'iplist': s in gwip and s not in gw} for s, (m, c) in
                 sorted(sid_info.items(), key=lambda kv: -kv[1][1])},
    }
    json.dump(out, open(out_path, 'w'), ensure_ascii=False, indent=1)


if __name__ == '__main__':
    main()
