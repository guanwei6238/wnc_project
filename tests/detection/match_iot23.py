#!/usr/bin/env python3
"""IoT-23: match Suricata alerts back to conn.log.labeled flows and compute detection results per label.

Matching (5-tuple and time defined as in tests/iot23/align_stream.py):
  - 5-tuple in both directions (endpoints sorted to form the key); ports ignored for ICMP
  - the alert's packet time falls in the conn's [ts, ts+duration] (widened by 1 µs on each end) -> match
  - if it falls in no conn, check whether the start time of the alert's Suricata flow (flow.start) is within 1 ms of the conn's ts
    (e.g. alerts emitted only at flow timeout, timed after the last packet Zeek recorded)
  - one alert may fall in several conns (same 5-tuple, overlapping times); each one counts
A conn "has an alert" if any alert matches it; gw_corp only counts alerts whose SID is in the gw_corp list;
gw_corp+iplist also adds the rules with long IP lists (the gateway design matches those with nftables IP sets instead; same detection coverage).

Usage: python3 -I match_iot23.py <conn.log.labeled> <eve.json> <gw_corp_sids.txt> <iplist_sids.txt> <out.json> [shards, default 1] [--cic]
--cic: labels come from the original CICFlowMeter CSV (CIC-DDoS2019). It records packets whose TCP/UDP header it can't parse (ICMP, later fragments, etc.) as
       Protocol 0, port 0/0 flows (other in conn), and the CSV has no ICMP flows, so non-TCP/UDP alerts match the other flow of the same IP pair.
       Do not use it for the corrected CIC-IDS2017: that has ICMP flows and Protocol 0 is non-IP frames.
When there are too many alerts for memory (about 14.7 million for 39-1), split into shards by 5-tuple, reading eve.json and conn.log once per shard; results are the same as without sharding.
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
    lab_sids = collections.defaultdict(collections.Counter)    # label -> SID -> number of flows with an alert of that SID
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

        # Read conn.log: count flows per label (first shard only); for 5-tuples that have alerts, record their conns (ts, end, label id)
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

        # Match alerts to conns per 5-tuple
        how = bytearray(n)          # 0 = no match, 1 = time inside conn, 2 = matched via flow.start
        for key, idxs in by_key.items():
            cl = conns.get(key)
            if not cl:
                continue
            cl.sort()
            starts = [c[0] for c in cl]
            hit = collections.defaultdict(set)      # conn index -> matched SIDs
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
