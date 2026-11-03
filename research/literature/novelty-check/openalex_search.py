#!/usr/bin/env python3
"""openalex_search.py — 新穎性查核的第一步：用 OpenAlex 做關鍵字搜尋，並從起點論文往前、往後追引用

用法: python3 -I openalex_search.py <輸出目錄>
  輸出：
    candidates.jsonl  每篇一行（OpenAlex id、DOI、標題、年份、出處、被引數、摘要、開放全文網址、來源＝哪個查詢或哪篇起點）
    search_log.tsv    每個查詢或起點：時間（UTC）、類型、內容、取得筆數
    seeds.tsv         起點論文對到的 OpenAlex id（對不到的標 NOT_FOUND）
  只收 2005 年之後。查詢與起點清單寫在本檔，改了就重跑，結果覆蓋。
OpenAlex 沒有 API key 時，每個 IP 每天共用 0.10 美元：title_and_abstract 搜尋每次 0.001、filter（cites、openalex_id）每頁 0.0001、
autocomplete 與單篇查詢免費。所以起點用 autocomplete 找，關鍵字查詢每個只取第一頁（依相關度 200 筆），剩不到 0.005 美元就停。
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import hashlib
from datetime import datetime, timezone

API = "https://api.openalex.org/works"
SELECT = "id,doi,title,publication_year,primary_location,cited_by_count,abstract_inverted_index,open_access,type,referenced_works"
FROM = "from_publication_date:2005-01-01"

# 主張（C1–C4，見 SPEC.md）各自的關鍵字查詢；OpenAlex 的 search 支援 AND／OR／NOT 和引號片語
QUERIES = {
    "C1": [
        '"intrusion detection" AND (bypass OR shunting OR whitelist OR "fast path") AND (sampling OR audit OR "re-inspection" OR revoke OR revocation)',
        '"intrusion detection" AND ("trusted flows" OR "trusted traffic" OR "benign flows") AND (bypass OR offload) AND (sampling OR inspection)',
        '"flow shunting" OR "traffic shunting" AND (intrusion OR IDS OR monitoring)',
        '"deep packet inspection" AND sampling AND ("long flows" OR "elephant flows" OR bypass)',
        '"intrusion detection" AND (cutoff OR "first packets" OR "first bytes") AND (evasion OR "delayed attack" OR "late attack")',
        '("security monitoring" OR "intrusion detection") AND "dynamic sampling" AND (Suricata OR Snort OR Zeek)',
        '"whitelist" AND "programmable switch" AND ("intrusion detection" OR "malicious traffic") AND (evasion OR revalidation OR re-verification)',
    ],
    "C2": [
        '"payload aggregation" AND ("intrusion detection" OR Snort OR Suricata)',
        '("partial payload" OR "truncated payload" OR "packet truncation") AND ("intrusion detection" OR Snort OR Suricata)',
        '(Suricata OR Snort) AND (midstream OR "stream reassembly" OR "TCP reassembly") AND (gap OR evasion OR "packet loss" OR "partial")',
        '("intrusion prevention" OR "inline IDS" OR NFQUEUE) AND ("Raspberry Pi" OR ARM OR embedded) AND (Suricata OR Snort)',
        '(Suricata OR Snort) AND "Raspberry Pi" AND (performance OR throughput)',
        '"HTTP" AND ("message boundary" OR "per-request") AND ("intrusion detection" OR "payload inspection") AND (filter OR reduction)',
    ],
    "C3": [
        '("intrusion detection" OR Snort OR Suricata) AND ("machine learning" OR "deep learning") AND ("edge" OR gateway) AND ("resource allocation" OR "CPU allocation" OR scheduling OR "resource sharing")',
        '("memory bandwidth" OR "cache interference" OR "co-location" OR colocation) AND ("network function" OR "packet processing" OR "intrusion detection") AND ("inference" OR "machine learning" OR "neural network")',
        '"hybrid intrusion detection" AND ("Raspberry Pi" OR "edge gateway" OR "IoT gateway") AND (Snort OR Suricata)',
        '"load shedding" AND ("intrusion detection" OR "network monitoring") AND ("machine learning" OR adaptive)',
        '("edge AI" OR "edge inference") AND ("intrusion detection" OR "packet processing") AND (interference OR contention)',
    ],
    "C4": [
        '(eBPF OR XDP OR "traffic control") AND ("intrusion detection" OR IDS OR Suricata OR Snort) AND (bypass OR offload OR "fast path") AND ("Raspberry Pi" OR ARM OR "IoT gateway" OR embedded)',
        '("connection tracking" OR conntrack OR "ct mark") AND (bypass OR offload OR "fast path") AND ("intrusion detection" OR IDS OR inspection)',
        '(NFQUEUE OR netfilter) AND (Suricata OR Snort) AND (performance OR bypass OR offload)',
        '"IoT gateway" AND ("intrusion detection" OR "deep packet inspection") AND ("fast path" OR bypass OR offload OR "trusted")',
    ],
}

# 起點論文：往後（它引用的）和往前（引用它的）都追
SEEDS = [
    ("C1", "Shunting: a hardware/software architecture for flexible, high-performance network intrusion prevention"),
    ("C1", "Improving the accuracy of network intrusion detection systems under load using selective packet discarding"),
    ("C1", "General IDS Acceleration for High-Speed Networks"),
    ("C1", "Building a time machine for efficient recording and retrieval of high-volume network traffic"),
    ("C1", "Enriching network security analysis with time travel"),
    ("C1", "SciPass: a 100Gbps capable secure Science DMZ using OpenFlow and Bro"),
    ("C1", "Retina: analyzing 100GbE traffic on commodity hardware"),
    ("C1", "An Efficient Design of Intelligent Network Data Plane"),
    ("C1", "XNET: Intelligent Dynamic Sampling for High-Speed Network Security Monitoring"),
    ("C1", "Is sampled data sufficient for anomaly detection?"),
    ("C1", "immUNITY: Detecting and Mitigating Low Volume & Slow Attacks with Programmable Switches and SmartNICs"),
    ("C1", "P4-ONIDS: A P4-based NIDS optimized for constrained programmable data planes in SDN"),
    ("C1", "Attacks on Dynamic Protocol Detection of Open Source Network Security Monitoring Tools"),
    ("C2", "High Performance Intrusion Detection Using HTTP-Based Payload Aggregation"),
    ("C2", "Dialog-based payload aggregation for intrusion detection"),
    ("C2", "Flow-based front payload aggregation"),
    ("C2", "Detecting evasion attacks at high speeds without reassembly"),
    ("C2", "Achieving 100Gbps Intrusion Prevention on a Single Server"),
    ("C2", "A Realtime IoT Malicious Traffic Detection Framework using Programmable Switches"),
    ("C3", "RealGuard: A Lightweight Network Intrusion Detection System for IoT Gateways"),
    ("C3", "Passban IDS: An Intelligent Anomaly-Based Intrusion Detection System for IoT Edge Devices"),
    ("C3", "RT-Gang: Real-Time Gang Scheduling Framework for Safety-Critical Systems"),
    ("C3", "An Energy-Efficient Intrusion Detection Offloading Based on DNN for Edge Computing"),
    ("C3", "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection"),
    ("C4", "Galette: a Lightweight XDP Dataplane on your Raspberry Pi"),
    ("C4", "Bypassing Linux Kernel Network Stack in the Implementation of an XDP-based NIDS"),
    ("C4", "Real-Time eBPF/XDP-Based Deep Learning Framework for Anomaly Traffic Detection in IoT Networks"),
    ("C4", "Efficient Intrusion Detection on Low-Performance Industrial IoT Edge Node Devices"),
]


REMAINING = [1.0]
CACHE = [""]


def get(params, retries=4, base=API):
    if REMAINING[0] < 0.005:
        raise RuntimeError("error: openalex daily budget almost used up")
    url = base + ("?" + urllib.parse.urlencode(params, safe=":,|*") if params else "")
    cf = os.path.join(CACHE[0], hashlib.sha1(url.encode()).hexdigest() + ".json")
    if os.path.exists(cf):
        return json.load(open(cf))
    for i in range(retries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "wnc-novelty-check/1.0"}), timeout=60) as r:
                rem = r.headers.get("x-ratelimit-remaining-usd")
                if rem is not None:
                    REMAINING[0] = float(rem)
                time.sleep(0.3)
                d = json.load(r)
                json.dump(d, open(cf, "w"))
                return d
        except urllib.error.HTTPError as e:  # 401／429：讀錯誤內容，退避重試
            body = e.read()[:300].decode("utf-8", "replace")
            err = f"{e.code} {body}"
            time.sleep(5 * 2 ** i)
        except Exception as e:
            err = str(e)
            time.sleep(2 ** i)
    raise RuntimeError(f"error: openalex request failed: {err} url={url[:200]}")


def abstract(inv):
    if not inv:
        return ""
    pos = {}
    for w, idx in inv.items():
        for i in idx:
            pos[i] = w
    return " ".join(pos[i] for i in sorted(pos))


def rec(w, src):
    loc = w.get("primary_location") or {}
    srcname = ((loc.get("source") or {}).get("display_name")) or ""
    oa = (w.get("open_access") or {}).get("oa_url") or ""
    return {"id": w["id"].rsplit("/", 1)[-1], "doi": (w.get("doi") or "").replace("https://doi.org/", ""),
            "title": w.get("title") or "", "year": w.get("publication_year"), "venue": srcname, "type": w.get("type"),
            "cited_by": w.get("cited_by_count", 0), "oa_url": oa, "abstract": abstract(w.get("abstract_inverted_index")),
            "src": [src]}


def paged(params, limit):
    # 沒有 API key 不能用 cursor 翻頁，改用 page=N（每頁 200 筆）
    out = []
    page = 1
    while len(out) < limit:
        d = get(dict(params, **{"per-page": 200, "page": page, "select": SELECT}))
        out.extend(d["results"])
        if len(d["results"]) < 200:
            break
        page += 1
    return out[:limit]


def norm(t):
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    CACHE[0] = os.path.join(out, "cache")
    os.makedirs(CACHE[0], exist_ok=True)
    cands, log, seeds = {}, [], []

    def add(ws, src):
        for w in ws:
            if (w.get("publication_year") or 0) < 2005:
                continue
            r = rec(w, src)
            if r["id"] in cands:
                cands[r["id"]]["src"].append(src)
            else:
                cands[r["id"]] = r

    now = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for claim, qs in QUERIES.items():
        for q in qs:
            ws = paged({"filter": f"{FROM},title_and_abstract.search:{q}", "sort": "relevance_score:desc"}, 200)
            add(ws, f"q:{claim}:{q}")
            log.append((now(), "query", claim, q, len(ws)))
    for claim, title in SEEDS:
        ac = get({"q": title}, base="https://api.openalex.org/autocomplete/works")["results"][:5]
        full = [get(None, base="https://api.openalex.org/works/" + a["id"].rsplit("/", 1)[-1] + "?select=" + SELECT) for a in ac]
        ok = [w for w in full if norm(w.get("title"))[:40] == norm(title)[:40] or norm(title)[:40] in norm(w.get("title"))]
        hit = max(ok, key=lambda w: w.get("cited_by_count") or 0) if ok else None
        if hit is None:
            seeds.append((claim, title, "NOT_FOUND", "", 0))
            log.append((now(), "seed", claim, title, 0))
            continue
        wid = hit["id"].rsplit("/", 1)[-1]
        seeds.append((claim, title, wid, hit.get("title"), hit.get("publication_year")))
        add([hit], f"seed:{claim}:{wid}")
        citing = paged({"filter": f"cites:{wid}"}, 1000)
        add(citing, f"citing:{claim}:{wid}")
        refs = [r.rsplit("/", 1)[-1] for r in hit.get("referenced_works") or []]
        got = []
        for i in range(0, len(refs), 50):
            got += get({"filter": "openalex_id:" + "|".join(refs[i:i + 50]), "per-page": 50, "select": SELECT})["results"]
        add(got, f"ref:{claim}:{wid}")
        log.append((now(), "seed", claim, f"{wid} citing={len(citing)} refs={len(got)}", len(citing) + len(got)))
    with open(os.path.join(out, "candidates.jsonl"), "w") as f:
        for r in sorted(cands.values(), key=lambda r: (-len(r["src"]), -(r["cited_by"] or 0))):
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(out, "search_log.tsv"), "w") as f:
        f.write("utc\ttype\tclaim\tquery_or_seed\tresults\n")
        for l in log:
            f.write("\t".join(map(str, l)) + "\n")
    with open(os.path.join(out, "seeds.tsv"), "w") as f:
        f.write("claim\tgiven_title\topenalex_id\tmatched_title\tyear\n")
        for s in seeds:
            f.write("\t".join(map(str, s)) + "\n")
    print(f"candidates={len(cands)} queries={sum(len(v) for v in QUERIES.values())} seeds_found={sum(1 for s in seeds if s[2] != 'NOT_FOUND')}/{len(seeds)} openalex_remaining_usd={REMAINING[0]}")


if __name__ == "__main__":
    main()
