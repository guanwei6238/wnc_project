#!/usr/bin/env python3
"""Generate deterministic synthetic pcaps for smoke tests and frame-size sweeps.

Pure stdlib (struct); valid IP/UDP/TCP checksums so engines do not discard
packets. Output (in --outdir, default ./pcaps):
  udp-64.pcap udp-128.pcap ... udp-1518.pcap   fixed frame size UDP
  imix.pcap                                    7:4:1 of 64/570/1518 byte frames
  http.pcap                                    TCP handshake+request+response+FIN
Frame size = bytes in the pcap record (Ethernet header included, FCS excluded).
"""
import argparse, os, random, struct

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")
LINK_MIN = 14 + 20 + 8  # eth + ip + udp


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip_hdr(src, dst, proto, payload_len, ident):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ident & 0xFFFF,
                    0x4000, 64, proto, 0, src, dst)
    return h[:10] + struct.pack("!H", csum(h)) + h[12:]


def pseudo(src, dst, proto, length):
    return struct.pack("!4s4sBBH", src, dst, 0, proto, length)


def udp_frame(src, dst, sport, dport, payload, ident, smac=MAC_A, dmac=MAC_B):
    ulen = 8 + len(payload)
    u = struct.pack("!HHHH", sport, dport, ulen, 0) + payload
    c = csum(pseudo(src, dst, 17, ulen) + u) or 0xFFFF
    u = u[:6] + struct.pack("!H", c) + u[8:]
    return dmac + smac + b"\x08\x00" + ip_hdr(src, dst, 17, ulen, ident) + u


def tcp_frame(src, dst, sport, dport, seq, ack, flags, payload, ident, fwd=True):
    smac, dmac = (MAC_A, MAC_B) if fwd else (MAC_B, MAC_A)
    t = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                    5 << 4, flags, 65535, 0, 0) + payload
    c = csum(pseudo(src, dst, 6, len(t)) + t)
    t = t[:16] + struct.pack("!H", c) + t[18:]
    return dmac + smac + b"\x08\x00" + ip_hdr(src, dst, 6, len(t), ident) + t


class Pcap:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.n = 0
        self.t = 0

    def add(self, frame, dt_us=10):
        self.t += dt_us
        self.f.write(struct.pack("<IIII", 1700000000 + self.t // 1000000,
                                 self.t % 1000000, len(frame), len(frame)))
        self.f.write(frame)
        self.n += 1

    def close(self):
        self.f.close()


def ip4(a, b, c, d):
    return bytes((a, b, c, d))


def udp_of_size(rng, size, i):
    src = ip4(10, 0, 1 + (i % 200), 1 + (i // 200) % 250)
    dst = ip4(192, 168, 0, 1 + (i % 50))
    sport = 1024 + (i * 7919) % 60000
    dport = 5000 + (i % 16)
    plen = max(0, size - LINK_MIN)
    payload = bytes(rng.getrandbits(8) for _ in range(min(plen, 64))) + b"\x00" * max(0, plen - 64)
    return udp_frame(src, dst, sport, dport, payload, i)


def gen_udp(path, size, n, seed):
    rng = random.Random(seed + size)
    p = Pcap(path)
    for i in range(n):
        p.add(udp_of_size(rng, size, i))
    p.close()


def gen_imix(path, n, seed):
    rng = random.Random(seed)
    sizes = [64] * 7 + [570] * 4 + [1518]
    p = Pcap(path)
    for i in range(n):
        p.add(udp_of_size(rng, sizes[i % 12], i))
    p.close()


def gen_http(path, flows, seed):
    rng = random.Random(seed)
    p = Pcap(path)
    ident = 1
    body = (b"<html><body>" + b"hello bench " * 80 + b"</body></html>")
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n"
            b"Server: bench\r\n\r\n" % len(body)) + body
    for fl in range(flows):
        c = ip4(10, 0, 1 + (fl // 250) % 200, 1 + fl % 250)
        s = ip4(192, 168, 0, 10 + fl % 20)
        cp = 20000 + fl % 40000
        sp = 80
        cs = rng.getrandbits(32)
        ss = rng.getrandbits(32)
        req = (b"GET /index%d.html HTTP/1.1\r\nHost: bench.example\r\n"
               b"User-Agent: bench/1.0\r\nAccept: */*\r\n\r\n" % fl)

        def C(seq, ack, flags, data=b""):
            nonlocal ident
            ident += 1
            p.add(tcp_frame(c, s, cp, sp, seq, ack, flags, data, ident, True))

        def S(seq, ack, flags, data=b""):
            nonlocal ident
            ident += 1
            p.add(tcp_frame(s, c, sp, cp, seq, ack, flags, data, ident, False))
        SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
        C(cs, 0, SYN)
        S(ss, cs + 1, SYN | ACK)
        C(cs + 1, ss + 1, ACK)
        C(cs + 1, ss + 1, PSH | ACK, req)
        S(ss + 1, cs + 1 + len(req), ACK)
        # response split in MSS-sized segments
        off = 0
        while off < len(resp):
            seg = resp[off:off + 1400]
            S(ss + 1 + off, cs + 1 + len(req), PSH | ACK, seg)
            off += len(seg)
        C(cs + 1 + len(req), ss + 1 + len(resp), ACK)
        C(cs + 1 + len(req), ss + 1 + len(resp), FIN | ACK)
        S(ss + 1 + len(resp), cs + 2 + len(req), FIN | ACK)
        C(cs + 2 + len(req), ss + 2 + len(resp), ACK)
    p.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--outdir", default="pcaps")
    ap.add_argument("--packets", type=int, default=20000, help="packets per UDP/IMIX pcap")
    ap.add_argument("--flows", type=int, default=500, help="HTTP flows")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    for size in (64, 128, 256, 512, 1024, 1518):
        gen_udp(os.path.join(a.outdir, "udp-%d.pcap" % size), size, a.packets, a.seed)
    gen_imix(os.path.join(a.outdir, "imix.pcap"), a.packets, a.seed)
    gen_http(os.path.join(a.outdir, "http.pcap"), a.flows, a.seed)
    for f in sorted(os.listdir(a.outdir)):
        print("%-14s %d bytes" % (f, os.path.getsize(os.path.join(a.outdir, f))))


if __name__ == "__main__":
    main()
