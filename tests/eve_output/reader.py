#!/usr/bin/env python3
"""reader.py — EVE unix_stream 的讀取端（Suricata 是 client，這裡先 listen）

用法: python3 reader.py <socket 路徑> <fast|stall:秒|slow:行每秒> <結果檔>
  fast      收到就讀
  stall:N   接受連線後 N 秒都不讀，之後全速讀到 EOF
  slow:R    每秒最多讀 R 行
結果檔一行 key=value：lines、bytes、first_s、last_s（相對於接受連線）
"""
import os, socket, sys, time

path, mode, out = sys.argv[1:4]
if os.path.exists(path):
    os.unlink(path)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(path)
s.listen(1)
c, _ = s.accept()
t0 = time.monotonic()
lines = nbytes = 0
first = last = None
if mode.startswith("stall:"):
    time.sleep(float(mode.split(":")[1]))
rate = float(mode.split(":")[1]) if mode.startswith("slow:") else None
while True:
    d = c.recv(4096 if rate else 1 << 20)
    if not d:
        break
    now = time.monotonic() - t0
    first = now if first is None else first
    last = now
    n = d.count(b"\n")
    lines += n
    nbytes += len(d)
    if rate:
        time.sleep(n / rate)
with open(out, "w") as f:
    f.write(f"lines={lines} bytes={nbytes} first_s={first or 0:.2f} last_s={last or 0:.2f}\n")
