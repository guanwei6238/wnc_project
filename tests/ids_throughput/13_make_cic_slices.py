#!/usr/bin/env python3
"""13_make_cic_slices.py - speed test slices for the three CIC datasets: take N packets (default 200,000) starting at a given time.

In CIC-IDS2017 and CIC-DDoS2019 an attack is a period within a day, so slices start at the attack start time (0.5th percentile of start ts in the labels),
representing the traffic the gateway would receive then (including concurrent background traffic); CICIoT2023 has one file per attack, so start 0 takes the file from the beginning.
Each pcap is read once: multiple slices from the same source are cut together (times may overlap). Each slice also gets a .small (first 500 packets, for the Suricata empty difference method).
Usage: python3 -I 13_make_cic_slices.py <source pcap, - for stdin> <output dir> <name=start_epoch> ...  [--n 200000]
The data is untrusted downloads: only pcap record headers are parsed with struct; contents are not interpreted.
"""
import struct
import sys

args = sys.argv[1:]
N = 200000
if "--n" in args:
    i = args.index("--n"); N = int(args[i + 1]); del args[i:i + 2]
src, outdir = args[0], args[1]
wins = []
for a in args[2:]:
    name, t = a.split("=")
    wins.append({"name": name, "start": float(t), "n": 0, "f": None, "s": None})

f = sys.stdin.buffer if src == "-" else open(src, "rb")
gh = f.read(24)
magic = gh[:4]
if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
    e = "<"
elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
    e = ">"
else:
    sys.exit("not a pcap file (pcapng is not supported)")
div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
pending = sorted(wins, key=lambda w: w["start"])
active = []
total = 0
while pending or active:
    h = f.read(16)
    if len(h) < 16:
        break
    sec, frac, incl, _ = struct.unpack(e + "IIII", h)
    d = f.read(incl)
    if len(d) < incl:
        break
    total += 1
    ts = sec + frac / div
    while pending and ts >= pending[0]["start"]:
        w = pending.pop(0)
        w["f"] = open("%s/%s.pcap" % (outdir, w["name"]), "wb"); w["f"].write(gh)
        w["s"] = open("%s/%s.small.pcap" % (outdir, w["name"]), "wb"); w["s"].write(gh)
        w["t0"] = ts
        active.append(w)
    for w in list(active):
        w["f"].write(h); w["f"].write(d)
        if w["n"] < 500:
            w["s"].write(h); w["s"].write(d)
        w["n"] += 1
        if w["n"] >= N:
            w["f"].close(); w["s"].close(); w["t1"] = ts
            active.remove(w)
for w in active:
    w["f"].close(); w["s"].close(); w["t1"] = None
for w in wins:
    if w["f"] is None:
        print("%s\tnot started (no packet at or after %.6f)" % (w["name"], w["start"]))
    else:
        print("%s\t%d packets\tstart %.6f\tfirst %.6f\tlast %s" % (w["name"], w["n"], w["start"], w["t0"], w.get("t1")))
print("read %d packets" % total, file=sys.stderr)
