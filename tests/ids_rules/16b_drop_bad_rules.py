#!/usr/bin/env python3 -I
"""Find the rejected rule lines in the Snort 3 load log, remove them from the rules file, and write a new rules file.
Usage: python3 -I 16b_drop_bad_rules.py <input rules file> <snort out.log> <output rules file> <removed.tsv (appended)> <round>
Why: Snort 3 goes FATAL at the end of loading if any single rule has an error, so there is no direct way to tell whether the remaining rules would load.
So iterate "remove bad rules -> reload" until there is no ERROR, recording which sids each round removed and why.
Log format (verified): "ERROR: <file>:<line> <reason>"; one rule may have several ERRORs.
Exit code: 0 = no ERROR this round (stop iterating); 1 = rules removed (run another round); 2 = ERRORs that cannot be mapped to a line (check by hand).
"""
import re, sys, collections
rules_in, log, rules_out, removed_tsv, rnd = sys.argv[1:6]
RE_SID = re.compile(r"\bsid\s*:\s*(\d+)\s*;")
errs = collections.defaultdict(list)   # line number -> [reasons...]
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
