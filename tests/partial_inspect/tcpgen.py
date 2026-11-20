"""tcpgen.py — generate controllable TCP packet sequences (no scapy needed), each packet tagged so "the subset Suricata gets to see" is easy to slice out

Packets are Ethernet + IPv4 + TCP with correct checksums. Each packet carries a dict tag:
  dir (c2s/s2c), kind (syn, synack, ack, data, fin), tx (transaction number, from 1), msg (req/resp), seg (segment within the message, from 0), off (byte offset of this segment in the message)
Session tracks both sides' seq; send() can advance seq without emitting packets (emit=False), to model "lots of skipped data in between" without growing the pcap.
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
        """Split data into MSS segments and send; the peer replies with a pure ACK every ack_every segments. emit=False only advances seq."""
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
        """The peer sent nbytes, but no packets (ACKs included) are emitted; only seq advances."""
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
