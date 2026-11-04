#!/usr/bin/env python3
"""late_mix.py — 實驗 5：很多條 HTTP keep-alive 長連線，真實的攻擊 request（CIC-IDS2017 抽出）插在連線後段

用法: python3 -I late_mix.py <attacks.json> <輸出目錄> [seed]
  輸出 mix.pcap 和 truth.json（每條連線的 client port、類型、攻擊種類、攻擊在第幾個交易）
連線類型（都帶 window scale 7，交易數 12–40，response 大小 lognormal（中位數 30 KB，上限 4 MB），交易間閒置平均 2 秒）：
  late     攻擊 request 在後半段的某個交易（取代一個正常 GET）
  early    攻擊 request 在第 1 個交易（對照：截斷類策略應該抓得到）
  pipe     後半段先送一個 4 KB body 的 POST，緊接著（不等 response）送攻擊 request（DPA 的規避手法：攻擊落在方向改變後 N bytes 之外）
  benign   全部正常
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
