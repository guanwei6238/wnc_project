#!/usr/bin/env python3 -I
"""Merge the enabled rules in the snapshot into one file and produce a line number->(sid, category) map.

Usage: python3 -I 02_prep_rules.py <snapshot rules dir> <output dir>
Output: <output dir>/et_all.rules   (one enabled rule per line)
        <output dir>/et_all.map.tsv (line_no, sid, category)

Why merge: both engines report errors as "file:line". After merging into one file,
the line number maps back to a unique sid, which is the basis for per-rule attribution.
(Rules commented out with # are ignored by both engines, so they are left out.)
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
