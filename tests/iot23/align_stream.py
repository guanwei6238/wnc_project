#!/usr/bin/env python3
"""IoT-23 單一場景：conn.log.labeled 的每條 flow 能不能對回 pcap 的封包？（串流版）

這是 tests/dataset/02_align.py 的「大檔版」。
對齊的【定義完全相同】（那支腳本的註解有說明）：
  - 五元組，雙向都算（兩端點排序後當 key）
  - 時間落在 [ts, ts+duration] 兩端各放寬 1 微秒
  - 找到的封包數 == orig_pkts + resp_pkts  -> 這條 flow 算「對齊成功」
  - 只處理 tcp / udp / icmp 的 flow（其他協定不納入，另外計數）

跟原版唯一的差別是「記憶體怎麼用」：
  原版：把整個 pcap 讀進記憶體，再為每個封包建索引  -> 幾 GB 的 pcap 會爆
  本版：pcap 一次只讀一小塊（串流）；改成把 conn.log 的 flow 載入記憶體當索引，
        然後逐個封包去查「它屬於哪些 flow」。
        如果 flow 太多（> 每批上限），就按 key 的雜湊值分成 K 批，
        每批各掃一次 pcap（用時間換記憶體）。結果跟不分批完全一樣。

用法：
  python3 -I align_stream.py <conn.log.labeled> <pcap> [--json 輸出.json] [--max-flows 3000000] [--text]
  --text 會印出和 02_align.py 一模一樣格式的表格（用來比對兩版結果）
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
CHUNK = 16 * 1024 * 1024      # 每次從 pcap 讀 16 MB
N_EXAMPLES = 5                # 對不上的 flow 只留前幾個當例子


# ---------------------------------------------------------------- pcap 串流讀取
# PcapStream.packets() 一次讀 16 MB，從中切出一個個封包 yield 出來，不會把整檔載入記憶體。

class PcapStream:
    def __init__(self, path):
        self.path = path
        self.truncated = False
        with open(path, 'rb') as f:
            magic = f.read(24)
        if len(magic) < 24:
            raise ValueError('pcap 檔頭不完整')
        kinds = {b'\xd4\xc3\xb2\xa1': ('<', 1e-6), b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
                 b'\x4d\x3c\xb2\xa1': ('<', 1e-9), b'\xa1\xb2\x3c\x4d': ('>', 1e-9)}
        if magic[:4] not in kinds:
            raise ValueError('不是 libpcap 格式（可能是 pcapng）：%r' % magic[:4])
        self.endian, self.tick = kinds[magic[:4]]
        self.linktype = struct.unpack(self.endian + 'I', magic[20:24])[0]

    def packets(self):
        """yield (時間, 封包 bytes)。"""
        hdr = struct.Struct(self.endian + 'IIII')
        tick = self.tick
        # 與 02_align.py 相同：時間 = sec + usec/1e6（奈秒檔用 nsec/1e9）
        div = 1e6 if tick == 1e-6 else 1e9
        buf = b''
        pos = 0
        with open(self.path, 'rb') as f:
            f.seek(24)
            while True:
                chunk = f.read(CHUNK)
                if chunk:
                    buf = buf[pos:] + chunk if buf else chunk
                    pos = 0
                else:
                    # 檔案讀完：buf 若還有殘餘（不足一個完整封包），代表 pcap 尾端被截斷
                    if buf and len(buf) - pos > 0:
                        self.truncated = True
                    return
                n = len(buf)
                while pos + 16 <= n:
                    sec, frac, cap, _ = hdr.unpack_from(buf, pos)
                    if pos + 16 + cap > n:
                        break               # 這個封包還沒讀完整，等下一塊
                    yield sec + frac / div, buf[pos + 16:pos + 16 + cap]
                    pos += 16 + cap


def parse_packet(pkt):
    """和 02_align.py 的 read_packets 內層邏輯相同。
    回傳 (proto, 端點A, 端點B, tcp_payload長度) 或 None（非 IP 封包）。"""
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
        while proto in (0, 43, 60) and len(pkt) >= 14 + ihl + 2:   # 跳過 extension header
            proto, ihl = pkt[14 + ihl], ihl + (pkt[14 + ihl + 1] + 1) * 8
    else:
        return None
    if proto == 58:                                            # ICMPv6 在 Zeek 記成 icmp
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
    """把 (proto, 端點A, 端點B) 壓成一個 bytes 當 dict key（比 tuple 省記憶體）。"""
    return bytes([proto, len(a[0])]) + a[0] + struct.pack('!H', a[1]) + b[0] + struct.pack('!H', b[1])


# ---------------------------------------------------------------- conn.log 讀取
def iter_flows(log_path):
    """yield (行號, 欄位 list)。只傳回資料行；格式不對的行以 (行號, None) 傳回。"""
    with open(log_path, 'r', errors='replace') as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip() or line.startswith('#'):
                continue
            fields = line.split()          # 與 02_align.py 一樣：tab 與空白都當分隔
            yield lineno, (fields if len(fields) >= 23 else None)


def shard_of(f, shards):
    """分批用：雙向同一條 flow 要落在同一批，所以兩端點字串排序後再取 crc32（比算 key 快很多）。"""
    a, b = sorted([f'{f[2]} {f[3] if f[6] != "icmp" else 0}', f'{f[4]} {f[5] if f[6] != "icmp" else 0}'])
    return zlib.crc32(f'{f[6]} {a} {b}'.encode()) % shards


def flow_key(f):
    """從 conn.log 一行欄位算出 (proto 名, key, ts, 結束時間, 預期封包數, conn_state, label)。"""
    ts, oh, op, rh, rp, proto = float(f[0]), f[2], int(f[3]), f[4], int(f[5]), f[6]
    dur = 0.0 if f[8] == '-' else float(f[8])
    expect = int(f[16]) + int(f[18])
    label = f[-2] if f[-1] == '-' else f'{f[-2]} {f[-1]}'
    p = PROTO.get(proto)
    if p is None:
        return proto, None, ts, 0.0, expect, f[11], label
    if p == 1:                              # ICMP 的 port 在 Zeek 是 type/code，封包這邊一律 0
        op = rp = 0
    a, b = sorted([(ipaddress.ip_address(oh).packed, op), (ipaddress.ip_address(rh).packed, rp)])
    return proto, make_key(p, a, b), ts, ts + dur, expect, f[11], label


# ---------------------------------------------------------------- 主流程
def analyze(log_path, pcap_path, max_flows=3_000_000):
    if log_path is None:                     # 場景沒有 conn.log.labeled：只數封包
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
    # 第一次掃 conn.log：只數行數與協定，決定要分幾批
    n_tracked = 0
    skipped = collections.Counter()
    malformed = 0
    for lineno, f in iter_flows(log_path):
        if f is None:
            malformed += 1
        elif f[6] in PROTO:
            n_tracked += 1
        else:
            skipped[f[6]] += 1
    shards = max(1, -(-n_tracked // max_flows))

    pcap = PcapStream(pcap_path)
    labels = {}                                     # label 字串 -> 編號
    stats = collections.defaultdict(collections.Counter)   # label -> Counter
    total_pkts = 0
    ip_pkts = 0
    pcap_t = (None, None)
    log_t = [float('inf'), 0.0]                     # conn.log 最早的 ts、最晚的結束時間
    covered_total = 0
    shortfall = collections.Counter()               # zero / fewer / more
    examples = []                                   # (行號, 找到, 預期)

    for shard in range(shards):
        # --- 載入這一批的 flow 當索引（用 array 存數值，省記憶體）
        f_ts = array.array('d')
        f_end = array.array('d')
        f_exp = array.array('I')
        f_lab = array.array('H')
        f_line = array.array('Q')
        index = {}                  # key -> flow 編號（只有一條）或 list（多條）
        for lineno, f in iter_flows(log_path):
            if f is None or f[6] not in PROTO:
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

        # 同一個 key 有多條 flow 時：依開始時間排序，並預先算「到目前為止最晚的結束時間」
        # 這樣查封包時可用二分搜尋，不必掃全部
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

        # --- 串流掃 pcap：每個封包查它落在哪些 flow 的時間窗裡
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
                i = bisect.bisect_right(tss, t + 2 * EPS) - 1      # 寬鬆上界，下面再用精確條件判斷
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
        total_pkts, ip_pkts = pk_total, pk_ip       # 每批掃到的總數都一樣，取最後一次
        covered_total += covered

        # --- 這一批的結果累加到各 label
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

    # 對不上的 flow：取行號最小的前幾個，再讀一次 log 抓出細節
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
        'unaligned_kinds': dict(shortfall),     # zero=一個都找不到, fewer=找到但較少, more=找到較多
        'unaligned_examples': ex_out, 'shards': shards,
        'labels': {k: {kk: vv for kk, vv in v.items()} for k, v in sorted(stats.items())},
    }


def print_text(r):
    """印成和 02_align.py 一模一樣的格式，方便 diff。"""
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
    ap.add_argument('--text', action='store_true')
    a = ap.parse_args()
    r = analyze(None if a.log == '-' else a.log, a.pcap, a.max_flows)
    if a.json:
        Path(a.json).write_text(json.dumps(r, ensure_ascii=False, indent=1))
    if a.text:
        print_text(r)
    else:
        print(f'{r["pcap"]}: {r["flows"]:,} flows, aligned {r["aligned"]:,}, pkts {r["pcap_packets"]:,}', file=sys.stderr)


if __name__ == '__main__':
    main()
