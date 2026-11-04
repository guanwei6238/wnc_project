#!/usr/bin/env python3
"""policy_filter.py — 實驗 4：讀一次 pcap，同時寫出各種「送給 Suricata 的子集」（ids 語意：Suricata 只拿到複本）

用法: python3 -I policy_filter.py <in.pcap> <輸出目錄> <t0> <t1>
  只處理時間在 [t0, t1] 的封包（epoch 秒）。輸出 <policy>.pcap 和 kept.tsv（每個策略留下的封包數、bytes）。
共同規則：非 TCP/UDP 的封包（ICMP、ARP…）一律留；TCP 的 SYN／FIN／RST 一律留（對應 L2：控制封包一定檢查）。
flow：雙向五元組；TCP 閒置 > 300 秒或在 FIN/RST 之後看到純 SYN 就算新 flow，UDP 閒置 > 120 秒算新 flow。
策略（k = 觀察期封包數 20、N = 2000 bytes、W = 10 秒、a = 10%）：
  full            全部（時間切片本身，當基準）
  first20         每條 flow 前 20 個封包，之後只留控制封包（＝信任後完全不看）
  cut4k           每條 flow 每個方向前 4096 bytes payload（Time Machine／Kučera 式 cutoff）；純 ACK 在它確認的那個方向還沒截斷前留
  dpa_ack10       DPA：每次傳輸方向改變後的前 N bytes；純 ACK 每 10 個留 1 個（讓 Suricata 的 ACK／視窗跟上）
  dpa_noack       DPA，純 ACK 都不留
  obs20_dpa_ack10 前 20 個封包全留，之後 DPA + 每 10 個純 ACK 留 1 個（候選設計）
  obs20_win_s{1,2,3}   前 20 個封包全留，之後以 W 秒為一格，每格以機率 a 整格全留（稽核窗），其餘只留控制封包 + 每 10 個純 ACK 留 1 個
  pkt_s{1,2,3}    每個封包以機率 a 留（控制封包一律留）
  obs20_flow_s{1,2,3}  前 20 個封包全留，之後以機率 a 挑整條 flow 全留，其餘只留控制封包
  flow_s{1,2,3}   以機率 a 挑整條 flow 全留，其餘只留控制封包（不含觀察期，對照 XNET 的 random flow）
環境變數 EXTRA=1 時另外寫（實驗 5 加的，抵抗「先塞資料再攻擊」的規避）：
  hpa_ack10       HPA：client→server 照 HTTP 的 Content-Length 切訊息，每個訊息前 N bytes；server→client 用 DPA；純 ACK 每 10 個留 1 個
  dpa_win_s{1,2,3}  DPA + 每 10 個純 ACK 留 1 個 + 以機率 a 整格（W 秒）全留
  dpa_rn_s{1,2,3}   DPA，但每條 flow 的 N 隨機取 1,000–16,000 bytes
隨機用 crc32（種子、flow、格子或封包序號）決定，結果可重現。
"""
import os
import struct
import sys
import zlib

K, N, W, A, ACK_K = 20, 2000, 10.0, 0.10, 10
TCP_IDLE, UDP_IDLE = 300.0, 120.0
SEEDS = (1, 2, 3)
POLICIES = ["full", "first20", "cut4k", "dpa_ack10", "dpa_noack", "obs20_dpa_ack10"] + \
    [f"{p}_s{s}" for p in ("obs20_win", "pkt", "obs20_flow", "flow") for s in SEEDS]
EXTRA = ["hpa_ack10"] + [f"{p}_s{s}" for p in ("dpa_win", "dpa_rn") for s in SEEDS]


def u(*parts):
    return zlib.crc32("|".join(map(str, parts)).encode()) / 4294967296.0


class Flow:
    __slots__ = ("first", "last", "n", "a", "closed", "dir", "seg", "acks", "bytes", "ackn", "hstate", "hbuf", "body", "mpos")

    def __init__(self, ts, a):
        self.first = ts
        self.last = ts
        self.n = 0
        self.a = a
        self.closed = False
        self.dir = None
        self.seg = 0
        self.acks = 0
        self.bytes = [0, 0]
        self.ackn = 0
        self.hstate = "hdr"
        self.hbuf = b""
        self.body = 0
        self.mpos = 0


def hpa(fl, pay):
    """client→server 的 HTTP/1.x：照 Content-Length 切出訊息，封包裡有任何 byte 落在某個訊息的前 N bytes 就留"""
    keep = False
    i = 0
    while i < len(pay):
        if fl.mpos < N:
            keep = True
        if fl.hstate == "hdr":
            buf = fl.hbuf + pay[i:]
            end = buf.find(b"\r\n\r\n")
            if end < 0:
                fl.hbuf = buf[-16384:]
                fl.mpos += len(pay) - i
                break
            used = end + 4 - len(fl.hbuf)
            cl = 0
            for line in buf[:end].split(b"\r\n"):
                if line[:15].lower() == b"content-length:":
                    try:
                        cl = int(line[15:].strip())
                    except ValueError:
                        cl = 0
            fl.hbuf = b""
            i += used
            fl.mpos += used
            fl.body = cl
            if cl == 0:
                fl.mpos = 0
            else:
                fl.hstate = "body"
        else:
            take = min(fl.body, len(pay) - i)
            i += take
            fl.mpos += take
            fl.body -= take
            if fl.body == 0:
                fl.hstate = "hdr"
                fl.mpos = 0
    return keep


def parse(b, linktype):
    """回傳 (proto, src, sport, dst, dport, flags, plen)；不是 TCP/UDP 時回傳 None"""
    off = 0
    if linktype == 1:
        if len(b) < 14:
            return None
        et = struct.unpack_from("!H", b, 12)[0]
        off = 14
        while et in (0x8100, 0x88A8) and len(b) >= off + 4:
            et = struct.unpack_from("!H", b, off + 2)[0]
            off += 4
    elif linktype == 101:
        et = 0x0800 if (b[0] >> 4) == 4 else 0x86DD
    else:
        return None
    if et == 0x0800:
        if len(b) < off + 20:
            return None
        ihl = (b[off] & 0x0F) * 4
        tot = struct.unpack_from("!H", b, off + 2)[0]
        frag = struct.unpack_from("!H", b, off + 6)[0] & 0x1FFF
        proto = b[off + 9]
        src, dst = b[off + 12:off + 16], b[off + 16:off + 20]
        l4 = off + ihl
        l4len = tot - ihl
        if frag:
            return None
    elif et == 0x86DD:
        if len(b) < off + 40:
            return None
        proto = b[off + 6]
        src, dst = b[off + 8:off + 24], b[off + 24:off + 40]
        l4 = off + 40
        l4len = struct.unpack_from("!H", b, off + 4)[0]
    else:
        return None
    if proto == 6 and len(b) >= l4 + 20:
        sp, dp = struct.unpack_from("!HH", b, l4)
        doff = (b[l4 + 12] >> 4) * 4
        flags = b[l4 + 13]
        return (6, src, sp, dst, dp, flags, max(l4len - doff, 0), l4 + doff)
    if proto == 17 and len(b) >= l4 + 8:
        sp, dp = struct.unpack_from("!HH", b, l4)
        return (17, src, sp, dst, dp, 0, max(l4len - 8, 0), l4 + 8)
    return None


def main():
    src, out, t0, t1 = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4])
    os.makedirs(out, exist_ok=True)
    f = open(src, "rb")
    gh = f.read(24)
    magic = struct.unpack("<I", gh[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        e = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        e = ">"
    else:
        sys.exit("error: not a classic pcap")
    nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
    linktype = struct.unpack(e + "I", gh[20:24])[0]
    pols = POLICIES + EXTRA if os.environ.get("EXTRA") else POLICIES
    outs = {p: open(os.path.join(out, p + ".pcap"), "wb", buffering=1 << 20) for p in pols}
    for o in outs.values():
        o.write(gh)
    kept = {p: [0, 0] for p in pols}
    flows = {}
    idx = 0
    rh = struct.Struct(e + "IIII")
    while True:
        h = f.read(16)
        if len(h) < 16:
            break
        sec, frac, incl, orig = rh.unpack(h)
        b = f.read(incl)
        ts = sec + frac * (1e-9 if nano else 1e-6)
        if ts < t0:
            continue
        if ts > t1:
            break
        idx += 1
        rec = h + b
        p = parse(b, linktype)
        if p is None:
            keep = set(pols)
        else:
            proto, s, sp, d, dp, flags, plen, poff = p
            ea, eb = (s, sp), (d, dp)
            key = (proto, ea, eb) if ea <= eb else (proto, eb, ea)
            fl = flows.get(key)
            syn_only = proto == 6 and flags & 0x02 and not flags & 0x10
            if fl is None or ts - fl.last > (TCP_IDLE if proto == 6 else UDP_IDLE) or (syn_only and fl.closed):
                fl = Flow(ts, ea)
                flows[key] = fl
            fl.last = ts
            fl.n += 1
            if proto == 6 and flags & 0x05:
                fl.closed = True
            d_ = 0 if ea == fl.a else 1
            ctrl = proto == 6 and flags & 0x07
            pure_ack = proto == 6 and plen == 0 and not ctrl
            obs = fl.n <= K
            # DPA 狀態（每條 flow 一份，所有 DPA 策略共用）
            dpa_keep = False
            ack_keep = False
            seg0 = 0
            if plen > 0:
                if fl.dir != d_:
                    fl.dir = d_
                    fl.seg = 0
                seg0 = fl.seg
                dpa_keep = fl.seg < N
                fl.seg += plen
            elif pure_ack:
                fl.acks += 1
                ack_keep = fl.acks % ACK_K == 0
            cut_keep = plen > 0 and fl.bytes[d_] < 4096 or pure_ack and fl.bytes[1 - d_] < 4096
            fl.bytes[d_] += plen
            keep = {"full"}
            if obs or ctrl:
                keep.add("first20")
            if ctrl or cut_keep:
                keep.add("cut4k")
            if ctrl or dpa_keep or ack_keep:
                keep.add("dpa_ack10")
            if ctrl or dpa_keep:
                keep.add("dpa_noack")
            if obs or ctrl or dpa_keep or ack_keep:
                keep.add("obs20_dpa_ack10")
            slot = int((ts - fl.first) / W)
            for sd in SEEDS:
                if obs or ctrl or ack_keep or u(sd, key, fl.first, slot) < A:
                    keep.add(f"obs20_win_s{sd}")
                if ctrl or u(sd, idx) < A:
                    keep.add(f"pkt_s{sd}")
                fsel = u(sd, key, fl.first) < A
                if obs or ctrl or fsel:
                    keep.add(f"obs20_flow_s{sd}")
                if ctrl or fsel:
                    keep.add(f"flow_s{sd}")
            if pols is not POLICIES and p is not None:
                if proto == 6 and plen > 0 and d_ == 0:
                    hk = hpa(fl, b[poff:poff + plen])
                else:
                    hk = dpa_keep
                if ctrl or ack_keep or hk:
                    keep.add("hpa_ack10")
                for sd in SEEDS:
                    if ctrl or ack_keep or dpa_keep or u(sd, key, fl.first, slot) < A:
                        keep.add(f"dpa_win_s{sd}")
                    nf = 1000 + u(sd, "n", key, fl.first) * 15000
                    if ctrl or ack_keep or (plen > 0 and seg0 < nf):
                        keep.add(f"dpa_rn_s{sd}")
        for pol in keep:
            outs[pol].write(rec)
            kept[pol][0] += 1
            kept[pol][1] += incl
    for o in outs.values():
        o.close()
    with open(os.path.join(out, "kept.tsv"), "w") as k:
        for pol in pols:
            k.write(f"{pol}\t{kept[pol][0]}\t{kept[pol][1]}\t{kept[pol][0] / max(kept['full'][0], 1):.4f}\t{kept[pol][1] / max(kept['full'][1], 1):.4f}\n")
    print(f"packets={kept['full'][0]} flows={len(flows)}")


if __name__ == "__main__":
    main()
