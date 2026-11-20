#!/usr/bin/env python3
"""reader.py — reader side of EVE unix_stream (Suricata is the client, so this listens first)

Usage: python3 reader.py <socket path> <fast|stall:seconds|slow:lines per second> <result file>
  fast      read as soon as data arrives
  stall:N   do not read for N seconds after accepting, then read at full speed until EOF
  slow:R    read at most R lines per second
Result file is one line of key=value: lines, bytes, first_s, last_s (relative to accept)
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
