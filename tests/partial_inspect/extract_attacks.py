#!/usr/bin/env python3
"""extract_attacks.py — 從 CIC-IDS2017 Thursday 的 web 攻擊流量抽出真實的攻擊 request（給實驗 5 插進合成連線）

用法: python3 -I extract_attacks.py <thu_web full.pcap> <輸出 json>
  只看 172.16.0.1 → 192.168.10.50:80 的 client→server payload，以 GET／POST 開頭、URL decode 後含
  XSS（"<script"）或 SQLi（"information_schema"、"select user"）的 request；各類去重後存成 base64。
"""
import base64
import json
import struct
import sys
import urllib.parse


def main():
    f = open(sys.argv[1], "rb")
    gh = f.read(24)
    e = "<" if struct.unpack("<I", gh[:4])[0] in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    out = {"xss": {}, "sqli": {}}
    att, srv = bytes([172, 16, 0, 1]), bytes([192, 168, 10, 50])
    while True:
        h = f.read(16)
        if len(h) < 16:
            break
        incl = struct.unpack(e + "IIII", h)[2]
        b = f.read(incl)
        if len(b) < 54 or b[12:14] != b"\x08\x00" or b[23] != 6:
            continue
        ihl = (b[14] & 0x0F) * 4
        if b[26:30] != att or b[30:34] != srv:
            continue
        l4 = 14 + ihl
        if struct.unpack_from("!H", b, l4 + 2)[0] != 80:
            continue
        pay = b[l4 + (b[l4 + 12] >> 4) * 4:]
        if not (pay.startswith(b"GET ") or pay.startswith(b"POST ")):
            continue
        line = urllib.parse.unquote_plus(pay.split(b"\r\n", 1)[0].decode("latin-1")).lower()
        kind = "xss" if "<script" in line else "sqli" if ("information_schema" in line or "select user" in line) else None
        if kind and len(out[kind]) < 40:
            out[kind].setdefault(pay, None)
    res = {k: [base64.b64encode(p).decode() for p in v] for k, v in out.items()}
    json.dump(res, open(sys.argv[2], "w"))
    print({k: len(v) for k, v in res.items()})


if __name__ == "__main__":
    main()
