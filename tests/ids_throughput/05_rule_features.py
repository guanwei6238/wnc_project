#!/usr/bin/env python3
"""05_rule_features.py - extract classification features of every ET Open (Suricata version) rule into a TSV (results/rule_features.tsv),
used by 12_gateway_rule_corp.py to pick rules by category, and to count ET Open rules per category.

Extracted fields:
  - category: the "ET <category>" at the start of msg (e.g. ET SCAN, ET MALWARE); rules without this prefix (e.g. old GPL rules) are recorded as "(其他)",
    then split further by msg in 12_gateway_rule_corp.py (GPL by subcategory, Threatview as its own category)
  - classtype
  - metadata affected_product / attack_target / deployment / signature_severity
  - protocol (http/dns/tls/tcp...), header comma count (same test as 04_make_sel_rules.py, to find long lists)
  - flowbits set/isset names (a subset must keep the rules it depends on, or isset rules never fire)
  - msg
This script only extracts features and does not decide which rules to pick; that is in 12_gateway_rule_corp.py.

Usage: python3 -I 05_rule_features.py <suricata_full.rules> <output tsv>
"""
import re
import sys

src, out = sys.argv[1], sys.argv[2]
cols = ["sid", "category", "classtype", "affected_product", "attack_target", "deployment", "severity",
        "proto", "header_commas", "fb_set", "fb_isset", "msg"]
n = 0
with open(src, errors="replace") as f, open(out, "w") as o:
    o.write("\t".join(cols) + "\n")
    for line in f:
        if not line.startswith("alert"):
            continue
        m = re.search(r"sid:(\d+);", line)
        if not m:
            continue
        sid = m.group(1)
        cm = re.search(r'msg:"(.*?)";', line)
        msg = cm.group(1) if cm else ""
        c = re.match(r"ET ([A-Z0-9_]+) ", msg)
        category = c.group(1) if c else "(其他)"
        ct = re.search(r"classtype:([\w-]+)", line)
        i = line.find("metadata:")
        md = line[i + 9:].split(";")[0] if i >= 0 else ""

        def g(k):
            mm = re.search(r"(?:^|, ?)" + k + r" ([^,]+)", md)
            return mm.group(1).strip() if mm else ""
        header = line.split("(", 1)[0]
        fbs = ",".join(sorted(set(re.findall(r"flowbits:set,([^;,]+)", line))))
        fbi = ",".join(sorted(set(re.findall(r"flowbits:(?:isset|isnotset),([^;]+)", line))))
        fbi = fbi.replace("|", ",").replace("&", ",")
        row = [sid, category, ct.group(1) if ct else "", g("affected_product"), g("attack_target"), g("deployment"),
               g("signature_severity"), line.split()[1], str(header.count(",")), fbs, fbi, msg.replace("\t", " ")]
        o.write("\t".join(row) + "\n")
        n += 1
print("wrote", out, "rules:", n)
