#!/usr/bin/env python3
"""05_rule_features.py — 把 ET Open（Suricata 版）每條規則的分類特徵抽成一張 TSV（results/rule_features.tsv），
供 12_gateway_rule_corp.py 依 category 挑規則，也用來統計 ET Open 各 category 的規則數。

抽出的欄位：
  - category：msg 開頭的 "ET <類別>"（例如 ET SCAN、ET MALWARE）；沒有這個前綴的（例如舊版 GPL 規則）記為 "(其他)"，
    由 12_gateway_rule_corp.py 再依 msg 細分（GPL 依子類別、Threatview 單獨一類）
  - classtype
  - metadata 的 affected_product / attack_target / deployment / signature_severity
  - 協定（http／dns／tls／tcp…）、header 逗號數（與 04_make_sel_rules.py 同判準，用來找長清單）
  - flowbits 的 set／isset 名稱（子集合要保留被依賴的規則，否則 isset 的規則永遠不會觸發）
  - msg
這支腳本只「抽特徵」，不決定要挑哪些規則；挑法在 12_gateway_rule_corp.py。

用法： python3 -I 05_rule_features.py <suricata_full.rules> <輸出 tsv>
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
