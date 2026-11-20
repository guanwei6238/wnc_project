#!/usr/bin/env python3
"""IoT-23 single scenario: can each flow in conn.log.labeled be matched back to packets in the pcap? (streaming version)

This is the "large file" version of tests/dataset/02_align.py.
The alignment definition is exactly the same (explained in that script's comments):
  - 5-tuple, both directions (endpoints sorted to form the key)
  - packet time falls in [ts, ts+duration], widened by 1 microsecond on each end
  - packets found == orig_pkts + resp_pkts  -> the flow counts as "aligned"
  - only tcp / udp / icmp flows are processed (other protocols are excluded and counted separately)

The only difference from the original is how memory is used:
  original: reads the whole pcap into memory, then indexes every packet  -> blows up on multi-GB pcaps
  this one: reads the pcap a small chunk at a time (streaming); loads the conn.log flows into memory as the index instead,
        then looks up which flows each packet belongs to.
        If there are too many flows (> per-shard limit), they are split into K shards by key hash,
        and the pcap is scanned once per shard (trading time for memory). Results are identical to no sharding.

Usage:
  python3 -I align_stream.py <conn.log.labeled> <pcap> [--json out.json] [--max-flows 3000000] [--part i/K] [--text]
  --text prints a table in exactly the same format as 02_align.py (to compare the two versions)
  --cic      labels are the original CICFlowMeter CSV (CIC-DDoS2019, converted by cic_to_conn.py): Protocol 0 flows in the CSV (other,
             port 0/0 in conn) are included too; on the packet side, IPv4 non-TCP/UDP or fragment offset > 0 packets (and IPv6 non-TCP/UDP) count as Protocol 0.
             This CSV has no ICMP flows; ICMP is all in Protocol 0. Do not use it for the corrected CIC-IDS2017: that has ICMP flows and Protocol 0 is non-IP frames
  --part i/K only processes flow part i (split into K parts by 5-tuple; a given 5-tuple is always in the same part),
             so flows, aligned and pcap_covered_packets from each part can be summed directly (tests/detection/merge_align.py);
             the pcap can be a pipe (/dev/stdin), but it can only be scanned once, so each part's flow count must be <= --max-flows
"""
import argparse
import array
import bisect
import collections
import ipaddress
import json
import struct
import sys
import zlib
from pathlib import Path

PROTO = {'tcp': 6, 'udp': 17, 'icmp': 1}
EPS = 1e-6
CHUNK = 16 * 1024 * 1024      # read 16 MB from the pcap at a time
N_EXAMPLES = 5                # keep only the first few unaligned flows as examples
CIC = False                   # --cic: labels are the original CICFlowMeter CSV (see parse_packet)


# ---------------------------------------------------------------- pcap streaming reader
# PcapStream.packets() reads 16 MB at a time and yields the packets cut from it, never loading the whole file into memory.

class PcapStream:
    def __init__(self, path):
        self.path = path
        self.truncated = False
        self.f = open(path, 'rb')       # the first scan reads on from here, so the pcap can be a pipe (scanned once only)
        magic = self.f.read(24)
        if len(magic) < 24:
            raise ValueError('pcap 檔頭不完整')
        kinds = {b'\xd4\xc3\xb2\xa1': ('<', 1e-6), b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
                 b'\x4d\x3c\xb2\xa1': ('<', 1e-9), b'\xa1\xb2\x3c\x4d': ('>', 1e-9)}
        if magic[:4] not in kinds:
            raise ValueError('不是 libpcap 格式（可能是 pcapng）：%r' % magic[:4])
        self.endian, self.tick = kinds[magic[:4]]
        self.linktype = struct.unpack(self.endian + 'I', magic[20:24])[0]

    def packets(self):
        """yield (time, packet bytes)."""
        hdr = struct.Struct(self.endian + 'IIII')
        tick = self.tick
        # Same as 02_align.py: time = sec + usec/1e6 (nsec/1e9 for nanosecond files)
        div = 1e6 if tick == 1e-6 else 1e9
        buf = b''
        pos = 0
        if self.f is None:              # reopen the file from the second shard on
            self.f = open(self.path, 'rb')
            self.f.seek(24)
        f, self.f = self.f, None
        with f:
            while True:
                chunk = f.read(CHUNK)
                if chunk:
                    buf = buf[pos:] + chunk if buf else chunk
                    pos = 0
                else:
                    # end of file: leftover bytes in buf (less than a full packet) mean the pcap tail is truncated
                    if buf and len(buf) - pos > 0:
                        self.truncated = True
                    return
                n = len(buf)
                while pos + 16 <= n:
                    sec, frac, cap, _ = hdr.unpack_from(buf, pos)
                    if pos + 16 + cap > n:
                        break               # packet not complete yet, wait for the next chunk
                    yield sec + frac / div, buf[pos + 16:pos + 16 + cap]
                    pos += 16 + cap


def parse_packet(pkt):
    """Same as the inner logic of read_packets in 02_align.py.
    Returns (proto, endpoint A, endpoint B, tcp_payload length) or None (non-IP packet)."""
    ethertype = pkt[12:14]
    if ethertype == b'\x08\x00' and len(pkt) >= 34:            # IPv4
        ihl = (pkt[14] & 15) * 4
        proto = pkt[23]
        src, dst = pkt[26:30], pkt[30:34]
        l3_len = struct.unpack('!H', pkt[16:18])[0]
    elif ethertype == b'\x86\xdd' and len(pkt) >= 54:          # IPv6
        ihl = 40
        proto = pkt[20]
        src, dst = pkt[22:38], pkt[38:54]
        l3_len = 40 + struct.unpack('!H', pkt[18:20])[0]
        while proto in (0, 43, 60) and len(pkt) >= 14 + ihl + 2:   # skip extension headers
            proto, ihl = pkt[14 + ihl], ihl + (pkt[14 + ihl + 1] + 1) * 8
    else:
        return None
    if CIC:
        # The original CICFlowMeter records packets whose TCP/UDP header it can't parse (ICMP, later fragments, OSPF, etc.) as Protocol 0, port 0/0
        frag = ethertype == b'\x08\x00' and struct.unpack('!H', pkt[20:22])[0] & 0x1fff
        if proto not in (6, 17) or frag:
            return (0, *sorted([(src, 0), (dst, 0)]), 0)
    if proto == 58:                                            # Zeek logs ICMPv6 as icmp
        proto = 1
    l4 = 14 + ihl
    sport = dport = 0
    payload = 0
    if proto in (6, 17) and len(pkt) >= l4 + 4:
        sport, dport = struct.unpack('!HH', pkt[l4:l4 + 4])
    if proto == 6 and len(pkt) >= l4 + 13:
        payload = l3_len - ihl - (pkt[l4 + 12] >> 4) * 4
    a, b = sorted([(src, sport), (dst, dport)])
    return proto, a, b, payload


def make_key(proto, a, b):
    """Pack (proto, endpoint A, endpoint B) into one bytes object as the dict key (less memory than a tuple)."""
    return bytes([proto, len(a[0])]) + a[0] + struct.pack('!H', a[1]) + b[0] + struct.pack('!H', b[1])


# ---------------------------------------------------------------- conn.log reader
def iter_flows(log_path):
    """yield (line number, field list). Data lines only; malformed lines are yielded as (line number, None)."""
    with open(log_path, 'r', errors='replace') as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip() or line.startswith('#'):
                continue
            fields = line.split()          # same as 02_align.py: split on both tabs and spaces
            yield lineno, (fields if len(fields) >= 23 else None)


def shard_of(f, shards):
    """For sharding: both directions of a flow must land in the same shard, so sort the two endpoint strings and take crc32 (much faster than building the key)."""
    a, b = sorted([f'{f[2]} {f[3] if f[6] != "icmp" else 0}', f'{f[4]} {f[5] if f[6] != "icmp" else 0}'])
    return zlib.crc32(f'{f[6]} {a} {b}'.encode()) % shards


def flow_key(f):
    """Compute (proto name, key, ts, end time, expected packets, conn_state, label) from the fields of one conn.log line."""
    ts, oh, op, rh, rp, proto = float(f[0]), f[2], int(f[3]), f[4], int(f[5]), f[6]
    dur = 0.0 if f[8] == '-' else float(f[8])
    expect = int(f[16]) + int(f[18])
    label = f[-2] if f[-1] == '-' else f'{f[-2]} {f[-1]}'
    p = PROTO.get(proto)
    if p is None:
        return proto, None, ts, 0.0, expect, f[11], label
    if p in (0, 1):                         # ICMP ports are type/code in Zeek and 0 in CIC Protocol 0; always 0 on the packet side
        op = rp = 0
    a, b = sorted([(ipaddress.ip_address(oh).packed, op), (ipaddress.ip_address(rh).packed, rp)])
    return proto, make_key(p, a, b), ts, ts + dur, expect, f[11], label


# ---------------------------------------------------------------- main
def analyze(log_path, pcap_path, max_flows=3_000_000, part=None):
    if log_path is None:                     # scenario has no conn.log.labeled: only count packets
        pcap = PcapStream(pcap_path)
        n = ip = 0
        for _, pkt in pcap.packets():
            n += 1
            ip += parse_packet(pkt) is not None
        return {'pcap': Path(pcap_path).name, 'log': None, 'pcap_bytes': Path(pcap_path).stat().st_size,
                'pcap_packets': n, 'pcap_ip_packets': ip, 'pcap_truncated_tail': pcap.truncated,
                'pcap_linktype': pcap.linktype, 'pcap_covered_packets': 0, 'flows': 0, 'aligned': 0,
                'unaligned': 0, 'skipped_flows_other_proto': {}, 'malformed_log_lines': 0,
                'unaligned_kinds': {}, 'unaligned_examples': [], 'shards': 0, 'labels': {}}
    # First pass over conn.log: only count lines and protocols, to decide how many shards
    n_tracked = 0
    skipped = collections.Counter()
    malformed = 0
    for lineno, f in iter_flows(log_path):
        if f is None:
            malformed += 1
        elif f[6] in PROTO:
            n_tracked += part is None or shard_of(f, part[1]) == part[0]
        else:
            skipped[f[6]] += 1
    shards = max(1, -(-n_tracked // max_flows))
    if shards > 1 and not Path(pcap_path).is_file():
        sys.exit(f'pcap 不是一般檔案（pipe？）只能掃一次，但 {n_tracked:,} 條 flow 要分 {shards} 批：加大 --max-flows 或用 --part')

    pcap = PcapStream(pcap_path)
    labels = {}                                     # label string -> id
    stats = collections.defaultdict(collections.Counter)   # label -> Counter
    total_pkts = 0
    ip_pkts = 0
    pcap_t = (None, None)
    log_t = [float('inf'), 0.0]                     # earliest ts and latest end time in conn.log
    covered_total = 0
    shortfall = collections.Counter()               # zero / fewer / more
    examples = []                                   # (line number, found, expected)

    for shard in range(shards):
        # --- load this shard's flows as the index (numbers kept in arrays to save memory)
        f_ts = array.array('d')
        f_end = array.array('d')
        f_exp = array.array('I')
        f_lab = array.array('H')
        f_line = array.array('Q')
        index = {}                  # key -> flow id (one flow) or list (several)
        for lineno, f in iter_flows(log_path):
            if f is None or f[6] not in PROTO:
                continue
            if part and shard_of(f, part[1]) != part[0]:
                continue
            if shards > 1 and shard_of(f, shards) != shard:
                continue
            proto, key, ts, end, expect, state, label = flow_key(f)
            log_t[0] = min(log_t[0], ts)
            log_t[1] = max(log_t[1], end)
            lab = labels.setdefault(label, len(labels))
            fid = len(f_ts)
            f_ts.append(ts); f_end.append(end); f_exp.append(expect); f_lab.append(lab); f_line.append(lineno)
            stats[label]['state ' + state] += 1
            if key in index:
                v = index[key]
                if isinstance(v, list):
                    v.append(fid)
                else:
                    index[key] = [v, fid]
            else:
                index[key] = fid
        n = len(f_ts)
        found = array.array('I', bytes(4 * n))
        payl = array.array('I', bytes(4 * n))

        # When a key has several flows: sort by start time and precompute the latest end time so far,
        # so packet lookups can binary search instead of scanning them all
        for key, v in list(index.items()):
            if isinstance(v, list):
                v.sort(key=f_ts.__getitem__)
                tss = [f_ts[i] for i in v]
                pm = []
                m = -1.0
                for i in v:
                    m = max(m, f_end[i])
                    pm.append(m)
                index[key] = (v, tss, pm)

        # --- stream the pcap: for each packet, find the flows whose time window it falls in
        covered = 0
        pk_total = 0
        pk_ip = 0
        for t, pkt in pcap.packets():
            pk_total += 1
            if pk_total == 1:
                t_first = t
            t_last = t
            r = parse_packet(pkt)
            if r is None:
                continue
            pk_ip += 1
            proto, a, b, payload = r
            v = index.get(make_key(proto, a, b))
            if v is None:
                continue
            hit = False
            if isinstance(v, int):
                if f_ts[v] - EPS <= t <= f_end[v] + EPS:
                    found[v] += 1
                    if payload > 0:
                        payl[v] += 1
                    hit = True
            else:
                ids, tss, pm = v
                i = bisect.bisect_right(tss, t + 2 * EPS) - 1      # loose upper bound; exact check below
                while i >= 0 and pm[i] >= t - 2 * EPS:
                    fid = ids[i]
                    if f_ts[fid] - EPS <= t <= f_end[fid] + EPS:
                        found[fid] += 1
                        if payload > 0:
                            payl[fid] += 1
                        hit = True
                    i -= 1
            covered += hit
        if pk_total:
            pcap_t = (t_first, t_last)
        total_pkts, ip_pkts = pk_total, pk_ip       # totals are the same in every shard; keep the last
        covered_total += covered

        # --- add this shard's results to each label
        inv = {v: k for k, v in labels.items()}
        for fid in range(n):
            s = stats[inv[f_lab[fid]]]
            s['flows'] += 1
            ok = found[fid] == f_exp[fid]
            s['aligned'] += ok
            s['pkts'] += found[fid]
            s['payload_pkts'] += payl[fid]
            s['flows_with_payload'] += payl[fid] > 0
            if not ok:
                shortfall['zero' if found[fid] == 0 else ('fewer' if found[fid] < f_exp[fid] else 'more')] += 1
                examples.append((f_line[fid], found[fid], f_exp[fid]))
        del index, f_ts, f_end, f_exp, f_lab, f_line, found, payl

    # Unaligned flows: take the ones with the lowest line numbers and reread the log for details
    examples.sort()
    want = {ln: (fo, ex) for ln, fo, ex in examples[:N_EXAMPLES]}
    ex_out = []
    if want:
        for lineno, f in iter_flows(log_path):
            if lineno in want and f is not None:
                label = f[-2] if f[-1] == '-' else f'{f[-2]} {f[-1]}'
                ex_out.append({'line': lineno, 'uid': f[1], 'ts': f[0], 'proto': f[6],
                               'flow': f'{f[2]}:{f[3]} -> {f[4]}:{f[5]}', 'label': label,
                               'conn_state': f[11], 'found_pkts': want[lineno][0], 'expect_pkts': want[lineno][1]})

    flows = sum(s['flows'] for s in stats.values())
    aligned = sum(s['aligned'] for s in stats.values())
    return {
        'pcap': Path(pcap_path).name, 'log': Path(log_path).name,
        'pcap_bytes': Path(pcap_path).stat().st_size,
        'pcap_packets': total_pkts, 'pcap_ip_packets': ip_pkts,
        'pcap_truncated_tail': pcap.truncated, 'pcap_linktype': pcap.linktype,
        'pcap_covered_packets': covered_total,
        'pcap_time_range': pcap_t, 'log_time_range': log_t if flows else None,
        'flows': flows, 'aligned': aligned, 'unaligned': flows - aligned,
        'skipped_flows_other_proto': dict(skipped), 'malformed_log_lines': malformed,
        'unaligned_kinds': dict(shortfall),     # zero=none found, fewer=found fewer, more=found more
        'unaligned_examples': ex_out, 'shards': shards, 'part': list(part) if part else None,
        'labels': {k: {kk: vv for kk, vv in v.items()} for k, v in sorted(stats.items())},
    }


def print_text(r):
    """Print in exactly the same format as 02_align.py, for diffing."""
    print(f'PCAP : {r["pcap"]}  ({r["pcap_packets"]:,} packets)')
    print(f'Label: {r["log"]}')
    print()
    print(f'{"標籤":<16}{"flow 數":>9}{"對齊成功":>10}{"對齊率":>9}{"封包數":>9}{"有 payload":>12}  conn_state')
    print('-' * 90)
    for label, s in r['labels'].items():
        states = ', '.join(f'{k[6:]}={v}' for k, v in collections.Counter(
            {k: v for k, v in s.items() if k.startswith('state ')}).most_common())
        rate = s['aligned'] / s['flows'] * 100
        print(f'{label:<16}{s["flows"]:>9,}{s["aligned"]:>10,}{rate:>8.1f}%{s["pkts"]:>9,}{s["payload_pkts"]:>12,}  {states}')
    print()
    print(f'PCAP 封包被有標籤的 flow 涵蓋：{r["pcap_covered_packets"]:,} / {r["pcap_packets"]:,}'
          f'（{r["pcap_covered_packets"] / r["pcap_packets"] * 100:.1f}%）')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    ap.add_argument('pcap')
    ap.add_argument('--json')
    ap.add_argument('--max-flows', type=int, default=3_000_000)
    ap.add_argument('--part')
    ap.add_argument('--cic', action='store_true')
    ap.add_argument('--text', action='store_true')
    a = ap.parse_args()
    global CIC
    CIC = a.cic
    if CIC:
        PROTO['other'] = 0
    part = tuple(int(x) for x in a.part.split('/')) if a.part else None
    r = analyze(None if a.log == '-' else a.log, a.pcap, a.max_flows, part)
    if a.json:
        Path(a.json).write_text(json.dumps(r, ensure_ascii=False, indent=1))
    if a.text:
        print_text(r)
    else:
        print(f'{r["pcap"]}: {r["flows"]:,} flows, aligned {r["aligned"]:,}, pkts {r["pcap_packets"]:,}', file=sys.stderr)


if __name__ == '__main__':
    main()
