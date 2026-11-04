"""tcpgen.py — 產生可控制的 TCP 封包序列（不需要 scapy），每個封包帶標記，方便切出「Suricata 看得到的子集」

封包是 Ethernet + IPv4 + TCP，checksum 都算對。每個封包附一個 dict 標記：
  dir（c2s／s2c）、kind（syn、synack、ack、data、fin）、tx（第幾個交易，從 1 起）、msg（req／resp）、seg（訊息內第幾段，從 0 起）、off（這段在訊息中的 byte 位移）
Session 記錄雙方的 seq，send() 可以只推進序號不產生封包（emit=False），用來模擬「中間被跳過的大量資料」而不讓 pcap 變大。
"""
import struct

MSS = 1448


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ip4(a):
    return bytes(int(x) for x in a.split("."))


class Session:
    def __init__(self, cip, cport, sip, sport, t0=1_700_000_000.0, isn_c=1000, isn_s=500000, wscale=None):
        self.wscale = wscale
        self.c = (ip4(cip), cport)
        self.s = (ip4(sip), sport)
        self.seq = {"c2s": isn_c, "s2c": isn_s}
        self.t = t0
        self.pkts = []  # (ts, bytes, mark)
        self.ipid = 1
        self.tx = 0

    def _pkt(self, d, flags, payload=b"", mark=None, seq=None, ack=None):
        src, dst = (self.c, self.s) if d == "c2s" else (self.s, self.c)
        o = "s2c" if d == "c2s" else "c2s"
        seq = self.seq[d] if seq is None else seq
        ack = self.seq[o] if ack is None else ack
        opt = b""
        if self.wscale is not None and flags & 0x02:
            opt = b"\x01\x03\x03" + bytes([self.wscale])  # NOP + window scale
        tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, (5 + len(opt) // 4) << 4, flags, 65535, 0, 0) + opt
        pseudo = src[0] + dst[0] + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
        c = csum(pseudo + tcp + payload)
        tcp = tcp[:16] + struct.pack("!H", c) + tcp[18:]
        tot = 20 + len(tcp) + len(payload)
        iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, self.ipid & 0xFFFF, 0x4000, 64, 6, 0, src[0], dst[0])
        iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
        self.ipid += 1
        mac_c, mac_s = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"
        eth = (mac_s + mac_c if d == "c2s" else mac_c + mac_s) + b"\x08\x00"
        m = {"dir": d}
        m.update(mark or {})
        self.pkts.append((self.t, eth + iph + tcp + payload, m))
        self.t += 0.001

    def handshake(self):
        self._pkt("c2s", 0x02, mark={"kind": "syn"})
        self.seq["c2s"] += 1
        self._pkt("s2c", 0x12, mark={"kind": "synack"})
        self.seq["s2c"] += 1
        self._pkt("c2s", 0x10, mark={"kind": "ack"})

    def ack(self, d, emit=True, **mark):
        if emit:
            self._pkt(d, 0x10, mark={"kind": "ack", **mark})

    def send(self, d, data, msg, emit=True, ack_every=2):
        """把 data 切成 MSS 送出；對方每 ack_every 段回一個純 ACK。emit=False 只推進序號。"""
        o = "s2c" if d == "c2s" else "c2s"
        off = 0
        seg = 0
        while off < len(data):
            chunk = data[off:off + MSS]
            if emit:
                self._pkt(d, 0x18, chunk, mark={"kind": "data", "tx": self.tx, "msg": msg, "seg": seg, "off": off})
            self.seq[d] += len(chunk)
            off += len(chunk)
            seg += 1
            if seg % ack_every == 0 or off >= len(data):
                self.ack(o, emit=emit, tx=self.tx, msg=msg + "_ack", seg=seg)
        return seg

    def skip(self, d, nbytes):
        """對方送了 nbytes 但完全不產生封包（含 ACK），只推進序號。"""
        self.seq[d] += nbytes

    def fin(self):
        self._pkt("c2s", 0x11, mark={"kind": "fin"})
        self.seq["c2s"] += 1
        self._pkt("s2c", 0x11, mark={"kind": "fin"})
        self.seq["s2c"] += 1
        self._pkt("c2s", 0x10, mark={"kind": "ack"})

    def idle(self, seconds):
        self.t += seconds


def http_req(path, body=b""):
    h = f"{'POST' if body else 'GET'} {path} HTTP/1.1\r\nHost: test.local\r\nUser-Agent: tcpgen\r\nAccept: */*\r\n"
    if body:
        h += f"Content-Type: application/octet-stream\r\nContent-Length: {len(body)}\r\n"
    return (h + "\r\n").encode() + body


def http_resp(n, fill=b"x"):
    head = f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {n}\r\n\r\n".encode()
    return head + (fill * n)[:n]


def write_pcap(path, pkts):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, b, _ in pkts:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(b), len(b)))
            f.write(b)
