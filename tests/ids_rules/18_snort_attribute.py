#!/usr/bin/env python3 -I
"""Snort 版 ET 規則的逐條歸因：每個 sid 是否被 snort2lua 轉換、是否被 Snort 3 載入、原因、哪一輪被移除。
用法: python3 -I 18_snort_attribute.py <work/snort_pack> <runs 目錄> <輸出完整 tsv(放 repo 外)> <輸出摘要 txt>
資料來源：
  et_all.map.tsv                 行號->sid/category (02_prep_rules.py)
  snort3_converted.rules         snort2lua 輸出。轉不了的整行被 '#' 註解；原因有兩種來源：
                                   (a) snort2lua_err.txt 的 "Failed to convert rule" 區塊(末行 '^^^^ 原因')
                                   (b) 規則前一行的 "# The 'asn1' rule option keyword is no longer supported" 這類註解(此時 err 檔沒有區塊)
  snort_iter/removed.tsv         16_snort_iter_load.sh 每輪移除的 sid 與 Snort ERROR 原因
"""
import re, sys, os, collections
work, runs, out_full, out_sum = sys.argv[1:5]
RE_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
RE_RULE = re.compile(r"^(alert|drop|reject|pass|rejectsrc|rejectdst|rejectboth)\s")
cat = {}; order = []
for l in open(os.path.join(work, "et_all.map.tsv")):
    _, sid, c = l.rstrip("\n").split("\t"); cat[sid] = c; order.append(sid)
# snort2lua err 區塊
err_reason = {}
txt = open(os.path.join(runs, "snort_s2l", "snort2lua_err.txt"), errors="replace").read()
for blk in txt.split("Failed to convert rule:")[1:]:
    sm = RE_SID.search(blk); rm = re.search(r"\^\^\^\^ (.*)", blk)
    if sm: err_reason[sm.group(1)] = rm.group(1).strip() if rm else "unknown"
# 轉換後檔案
active = set(); commented = {}   # sid -> 前一行註解(原因)
prev = ""
for l in open(os.path.join(work, "snort3_converted.rules"), errors="replace"):
    l = l.rstrip("\n")
    if l.startswith("#"):
        body = l.lstrip("# ").lstrip()
        if RE_RULE.match(body): commented[RE_SID.search(body).group(1)] = prev
    elif RE_RULE.match(l): active.add(RE_SID.search(l).group(1))
    prev = l
# 載入被移除
removed = {}
for l in list(open(os.path.join(runs, "snort_iter", "removed.tsv")))[1:]:
    r, sid, why = l.rstrip("\n").split("\t"); removed[sid] = (r, why)
rows = []
for s in order:
    if s in active:
        s2l, s2l_why = "converted", ""
        if s in removed: load, round_, why = "fail", removed[s][0], removed[s][1]
        else: load, round_, why = "ok", "", ""
    else:
        s2l = "not_converted"
        s2l_why = err_reason.get(s) or ("(snort2lua 註解) " + commented.get(s, "").lstrip("# ")) if (s in err_reason or s in commented) else "unknown"
        load, round_, why = "NA", "", ""
    final = "ok" if load == "ok" else "fail"
    rows.append((s, cat[s], s2l, s2l_why, load, round_, why, final))
with open(out_full, "w") as f:
    f.write("sid\tcategory\tsnort2lua\tsnort2lua_reason\tsnort_load\tremoved_round\tsnort_load_error\tsnort_final\n")
    for r in rows: f.write("\t".join(r) + "\n")
n = len(rows); c = collections.Counter(r[2] for r in rows); fin = sum(1 for r in rows if r[7] == "ok")
lines = ["Snort 版 ET Open（Snort 3.12.2.0 載入，經 snort2lua 轉換）逐條歸因摘要",
         "啟用規則 %d；snort2lua 轉換成功 %d、未轉換 %d；載入被拒絕 %d；最終接受 %d (%.2f%%)" % (n, c["converted"], c["not_converted"], len(removed), fin, 100.0 * fin / n), ""]
def top(title, counter):
    lines.append("== %s (total=%d)" % (title, sum(counter.values())))
    lines.extend("%7d  %s" % (v, k) for k, v in counter.most_common()); lines.append("")
top("snort2lua 未轉換原因", collections.Counter(r[3] for r in rows if r[2] == "not_converted"))
top("Snort 3 載入被拒絕原因(摘要)", collections.Counter(re.sub(r"pcre2 compile of .* failed at offset \d+ : ", "pcre2 compile failed: ", r[6]) for r in rows if r[4] == "fail"))
lines.append("== 迭代移除紀錄"); lines.extend("round %s  sid %s  %s" % (r, s, w[:110]) for s, (r, w) in sorted(removed.items(), key=lambda x: x[1][0]))
lines.append("")
open(out_sum, "w").write("\n".join(lines) + "\n"); print("\n".join(lines))
