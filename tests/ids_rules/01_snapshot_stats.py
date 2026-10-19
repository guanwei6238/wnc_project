#!/usr/bin/env python3 -I
"""統計規則快照：每個 category(檔名) 有幾條「啟用」與「被註解停用」的規則。

用法: python3 -I 01_snapshot_stats.py <rules 目錄> <輸出 tsv>

為什麼這樣判斷：ET 的規則一條一行。啟用的規則以動作(alert/drop/...)開頭；
停用的規則是整行前面加 '#'，後面接同樣的動作。其餘 '#' 開頭的是純註解，不算規則。
"""
import re, sys, glob, os

ACTION = r"(?:alert|drop|reject|pass|rejectsrc|rejectdst|rejectboth)"
RE_ON  = re.compile(r"^\s*" + ACTION + r"\s")
RE_OFF = re.compile(r"^\s*#+\s*" + ACTION + r"\s")
RE_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")

rules_dir, out = sys.argv[1], sys.argv[2]
tot_on = tot_off = 0
rows = []
all_sids = {}
for path in sorted(glob.glob(os.path.join(rules_dir, "*.rules"))):
    on = off = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if RE_ON.match(line):
                on += 1
            elif RE_OFF.match(line):
                off += 1
            else:
                continue
            m = RE_SID.search(line)
            if m:
                all_sids.setdefault(m.group(1), os.path.basename(path))
    rows.append((os.path.basename(path), on, off))
    tot_on += on; tot_off += off

with open(out, "w") as f:
    f.write("category_file\tenabled\tdisabled_commented\n")
    for r in rows:
        f.write("%s\t%d\t%d\n" % r)
    f.write("TOTAL\t%d\t%d\n" % (tot_on, tot_off))
print("enabled=%d disabled=%d total=%d unique_sids=%d" % (tot_on, tot_off, tot_on+tot_off, len(all_sids)))
