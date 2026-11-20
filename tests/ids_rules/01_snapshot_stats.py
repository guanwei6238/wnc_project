#!/usr/bin/env python3 -I
"""Count rules in the snapshot: for each category (file name), how many are enabled and how many are commented out.

Usage: python3 -I 01_snapshot_stats.py <rules dir> <output tsv>

Why this test: ET rules are one per line. Enabled rules start with an action (alert/drop/...);
disabled rules are the same line prefixed with '#'. Other lines starting with '#' are plain comments, not rules.
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
