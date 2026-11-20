#!/usr/bin/env python3
"""late_mix.py — exp 5: many long-lived HTTP keep-alive connections, with real attack requests (extracted from CIC-IDS2017) inserted late in the connection

Usage: python3 -I late_mix.py <attacks.json> <output dir> [seed]
  writes mix.pcap and truth.json (per connection: client port, type, attack kind, which transaction has the attack)
Connection types (all with window scale 7, 12–40 transactions, lognormal response size (median 30 KB, max 4 MB), mean 2 s idle between transactions):
  late     attack request in some transaction in the second half (replacing a normal GET)
  early    attack request in the 1st transaction (control: truncation policies should catch it)
  pipe     in the second half, first a POST with a 4 KB body, then right away (without waiting for the response) the attack request (DPA evasion: the attack falls outside the N bytes after the direction change)
  benign   all normal
"""
import base64
import json
import math
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tcpgen import Session, http_req, http_resp, write_pcap

COUNTS = {"late": 120, "early": 30, "pipe": 60, "benign": 120}


def req(i, n):
    return (f"GET /app/item?id={i}-{n} HTTP/1.1\r\nHost: shop.example\r\n"
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n").encode()


def main():
    att = json.load(open(sys.argv[1]))
    out = sys.argv[2]
    rnd = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
    os.makedirs(out, exist_ok=True)
    pkts, truth = [], []
    i = 0
    for kind, n in COUNTS.items():
        for _ in range(n):
            i += 1
            port = 20000 + i
            s = Session(f"10.0.1.{i % 250 + 1}", port, "10.0.2.2", 80, t0=1_700_000_000.0 + i * 0.37, wscale=7)
            s.handshake()
            T = rnd.randint(12, 40)
            j = 1 if kind == "early" else rnd.randint(math.ceil(T / 2), T) if kind in ("late", "pipe") else 0
            ak = rnd.choice(["xss", "xss", "sqli"]) if j else None
            payload = base64.b64decode(rnd.choice(att[ak])) if ak else None
            for tx in range(1, T + 1):
                s.tx = tx
                s.idle(rnd.expovariate(1 / 2.0))
                size = int(min(max(rnd.lognormvariate(math.log(30000), 1.2), 500), 4_000_000))
                if tx == j and kind == "pipe":
                    s.send("c2s", http_req("/upload", b"q" * 4000) + payload, "req")
                    s.send("s2c", http_resp(2000) + http_resp(size), "resp")
                    continue
                s.send("c2s", payload if tx == j else req(i, tx), "req")
                s.send("s2c", http_resp(size), "resp")
            s.fin()
            pkts.extend(s.pkts)
            truth.append({"port": port, "client": f"10.0.1.{i % 250 + 1}", "kind": kind, "attack": ak, "tx": j, "T": T,
                          "dur_s": round(s.pkts[-1][0] - s.pkts[0][0], 1)})
    pkts.sort(key=lambda p: p[0])
    write_pcap(os.path.join(out, "mix.pcap"), pkts)
    json.dump(truth, open(os.path.join(out, "truth.json"), "w"))
    print(f"connections={len(truth)} packets={len(pkts)}")


if __name__ == "__main__":
    main()
