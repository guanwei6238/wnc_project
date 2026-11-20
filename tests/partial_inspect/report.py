#!/usr/bin/env python3
"""report.py — exp 3 summary: per case × mode, alerts (sid:count), app_proto, key stats

Usage: python3 -I report.py <cases dir> [res subdir name, default res]
"""
import json
import os
import sys

KEYS = ["decoder.pkts", "ips.accepted", "ips.blocked", "ips.drop_reason.stream_error", "ips.drop_reason.stream_midstream",
        "tcp.midstream_pickups", "tcp.sessions", "tcp.ack_unseen_data", "tcp.reassembly_gap", "tcp.pkt_on_wrong_thread",
        "app_layer.flow.http", "app_layer.flow.mqtt", "app_layer.flow.failed_tcp", "app_layer.tx.http", "app_layer.tx.mqtt"]
SHORT = {"decoder.pkts": "pkts", "ips.accepted": "acc", "ips.blocked": "blk", "ips.drop_reason.stream_error": "drop_stream_err",
         "ips.drop_reason.stream_midstream": "drop_midstream", "tcp.midstream_pickups": "midstream", "tcp.sessions": "sess",
         "tcp.ack_unseen_data": "ack_unseen", "tcp.reassembly_gap": "gap", "tcp.pkt_on_wrong_thread": "wrongthr",
         "app_layer.flow.http": "http_flow", "app_layer.flow.mqtt": "mqtt_flow", "app_layer.flow.failed_tcp": "app_failed",
         "app_layer.tx.http": "http_tx", "app_layer.tx.mqtt": "mqtt_tx"}


def stats(path):
    out = {}
    try:
        lines = open(path).read().splitlines()
    except OSError:
        return out
    # stats.log may have several sections; take the last one
    block = []
    for ln in lines:
        if ln.startswith("Date:"):
            block = []
        block.append(ln)
    for ln in block:
        p = [x.strip() for x in ln.split("|")]
        if len(p) == 3 and p[1] == "Total":
            out[p[0]] = int(p[2])
    return out


def eve(path):
    alerts, protos, drops = {}, set(), 0
    try:
        f = open(path)
    except OSError:
        return alerts, protos, drops
    for ln in f:
        e = json.loads(ln)
        t = e.get("event_type")
        if t == "alert":
            sid = e["alert"]["signature_id"]
            alerts.setdefault(sid, []).append(e.get("pcap_cnt"))
        elif t == "flow":
            protos.add(e.get("app_proto", "-"))
        elif t == "drop":
            drops += 1
    return alerts, protos, drops


def main():
    d = sys.argv[1]
    res = sys.argv[2] if len(sys.argv) > 2 else "res"
    cases = [l.split("\t") for l in open(os.path.join(d, "manifest.tsv")).read().splitlines()]
    print("| case | 封包 | 模式 | alert（sid×次數@第一個 pcap_cnt） | app_proto | 關鍵 stats（非 0） |")
    print("|---|---|---|---|---|---|")
    for name, n, note in cases:
        for mode in ("ids", "ips"):
            o = os.path.join(d, res, f"{name}.{mode}")
            al, pr, dr = eve(os.path.join(o, "eve.json"))
            st = stats(os.path.join(o, "stats.log"))
            a = " ".join(f"R{s}×{len(v)}@{min(x for x in v if x is not None) if any(x is not None for x in v) else '-'}" for s, v in sorted(al.items())) or "（無）"
            s = " ".join(f"{SHORT[k]}={st[k]}" for k in KEYS if st.get(k))
            if dr:
                s += f" drop_events={dr}"
            print(f"| {name} | {n} | {mode} | {a} | {','.join(sorted(pr)) or '-'} | {s} |")


if __name__ == "__main__":
    main()
