#!/usr/bin/env python3 -I
"""從 Snort 3 的載入 log 找出「被拒絕的規則行」，把它們從規則檔移除，寫出新規則檔。
用法: python3 -I 16b_drop_bad_rules.py <輸入規則檔> <snort out.log> <輸出規則檔> <removed.tsv(附加寫入)> <round>
為什麼要這樣做：Snort 3 只要有一條規則出錯，載入結束時就 FATAL，沒辦法直接知道「剩下的規則能不能載入」。
所以要「移除壞規則 -> 重載」迭代到沒有 ERROR 為止，並把每一輪移除了哪些 sid、為什麼記下來。
log 格式(已實測)： "ERROR: <檔>:<行號> <原因>"；同一條規則可能有多個 ERROR。
結束碼： 0 = 這輪沒有任何 ERROR(不必再迭代)；1 = 有移除規則(要再跑下一輪)；2 = 有 ERROR 但無法對回行號(人工檢查)。
"""
import re, sys, collections
rules_in, log, rules_out, removed_tsv, rnd = sys.argv[1:6]
RE_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
errs = collections.defaultdict(list)   # 行號 -> [原因...]
unattributed = []
for l in open(log, errors="replace"):
    if not l.startswith("ERROR:"):
        continue
    m = re.match(r"ERROR: \S+?:(\d+) (.*)", l)
    if m: errs[int(m.group(1))].append(m.group(2).strip())
    else: unattributed.append(l.strip())
if unattributed:
    print("無法對回行號的 ERROR:", *unattributed, sep="\n  "); sys.exit(2)
if not errs:
    print("round %s: 無 ERROR" % rnd); sys.exit(0)
lines = open(rules_in, errors="replace").read().split("\n")
with open(removed_tsv, "a") as rm:
    for n in sorted(errs):
        sid = RE_SID.search(lines[n - 1]).group(1)
        rm.write("%s\t%s\t%s\n" % (rnd, sid, " | ".join(errs[n])))
        print("round %s: 移除 sid=%s (行 %d): %s" % (rnd, sid, n, errs[n][0][:120]))
open(rules_out, "w").write("\n".join(l for i, l in enumerate(lines, 1) if i not in errs))
sys.exit(1)
