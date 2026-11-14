#!/usr/bin/env python3
"""Summarize cost_pi.sh results: per-variant mean and stdev, and the difference to the previous variant.

usage: summarize.py <cost.kvl> [tag]
"""
import statistics
import sys


def rows(path, tag):
    for line in open(path):
        row = dict(field.split("=", 1) for field in line.split())
        if tag is None or row["tag"] == tag:
            yield row


def stats(values):
    return statistics.mean(values), (statistics.stdev(values) if len(values) > 1 else 0.0)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    data = list(rows(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
    for mode, field, unit in (("cpu", "cpu_us_per_pkt", "µs/packet (whole Pi)"), ("stats", "ns_per_run", "ns/run (program only)")):
        selected = [r for r in data if r["mode"] == mode]
        if not selected:
            continue
        print(f"{mode}: {unit}")
        print(f"  {'variant':<8} {'n':>2} {'mean':>9} {'stdev':>7} {'vs previous':>12}")
        previous = None
        for variant in sorted({r["variant"] for r in selected}):
            values = [float(r[field]) for r in selected if r["variant"] == variant]
            mean, stdev = stats(values)
            diff = "" if previous is None else f"{mean - previous:+.3f}"
            print(f"  {variant:<8} {len(values):>2} {mean:>9.3f} {stdev:>7.3f} {diff:>12}")
            previous = mean
        bad = [r for r in selected if r["throttled"] != "0x0,0x0" or r["mhz"] != "1000"]
        print(f"  throttled or not at 1000 MHz: {len(bad)} of {len(selected)}")


main()
