#!/usr/bin/env python3 -I
"""把快照裡「啟用」的規則合併成一個檔案，並產生 行號->(sid, category) 對照表。

用法: python3 -I 02_prep_rules.py <快照 rules 目錄> <輸出目錄>
輸出: <輸出目錄>/et_all.rules   (每行一條啟用規則)
      <輸出目錄>/et_all.map.tsv (line_no, sid, category)

為什麼要合併：兩個引擎的錯誤訊息都會帶「檔案:行號」。合併成一個檔後，
行號就能唯一對回 sid，這是「逐條規則歸因」的基礎。
(被 # 註解掉的規則兩個引擎都會直接忽略，所以不放進去。)
"""
import re, sys, glob, os

RE_ON  = re.compile(r"^\s*(?:alert|drop|reject|pass|rejectsrc|rejectdst|rejectboth)\s")
RE_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")

rules_dir, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
n = 0
with open(os.path.join(outdir, "et_all.rules"), "w") as fr, \
     open(os.path.join(outdir, "et_all.map.tsv"), "w") as fm:
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.rules"))):
        cat = os.path.basename(path)
        for line in open(path, encoding="utf-8", errors="replace"):
            if not RE_ON.match(line):
                continue
            line = line.strip()
            n += 1
            fr.write(line + "\n")
            fm.write("%d\t%s\t%s\n" % (n, RE_SID.search(line).group(1), cat))
print("wrote %d enabled rules" % n)
