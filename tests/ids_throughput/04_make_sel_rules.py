#!/usr/bin/env python3
"""04_make_sel_rules.py - build the "sel" rule set: the full rules minus rules whose header has many IP entries.

Why: Snort 3 with full is very slow on scan traffic (only 0.37 kpps on slice A on the Pi), and nearly all the cost comes from about 3% of the rules:
rules with long IP lists in the header (mostly ET IP reputation lists such as TOR exit nodes, CINS, DROP (Snort version 1,559 rules: TOR 803, CINS 596, DROP 69, others about 91)).
sel measures on the Pi how much speed comes back from dropping just this small class (Snort 3 on slice A on the Pi: full 0.37 kpps -> sel 64.3 kpps).

Criterion (simple, reproducible): the enabled rule's header (text before the first '(') has >= 8 commas (i.e. many IP entries).
Note: this selects by cost, not by detection value. The detection lost by removing these rules is not measured here; do not treat them as safe to remove.

Method: the Snort full rules decide which sids to remove, then the same sids are removed from the Suricata full rules, so both engines' sel cover the same sids.
Output (same dir as *_full.rules): suricata_sel.rules, snort_sel.rules; the removed sid list is also saved for reproduction.

Usage: python3 -I 04_make_sel_rules.py <rules dir> [--check-snort-sha256 <expected sha256>]
"""
import hashlib
import re
import sys
from pathlib import Path

THRESHOLD = 8                                   # header comma threshold
ACT = re.compile(r'^(alert|drop|reject|pass|log|sdrop)\s')
SID = re.compile(r'\bsid:\s*(\d+)\s*;')


def header(line):
    i = line.find('(')
    return line[:i] if i > 0 else line


def main():
    args = sys.argv[1:]
    expect = None
    if '--check-snort-sha256' in args:
        i = args.index('--check-snort-sha256'); expect = args[i + 1]; del args[i:i + 2]
    d = Path(args[0])

    snort = (d / 'snort_full.rules').read_text(errors='replace').split('\n')
    removed = set()
    kept_snort = []
    for line in snort:
        if ACT.match(line.strip()) and header(line).count(',') >= THRESHOLD:
            m = SID.search(line)
            if m:
                removed.add(m.group(1))
            continue
        kept_snort.append(line)
    out_snort = '\n'.join(kept_snort)
    (d / 'snort_sel.rules').write_text(out_snort)

    suri = (d / 'suricata_full.rules').read_text(errors='replace').split('\n')
    kept_suri, n_removed_suri = [], 0
    for line in suri:
        m = SID.search(line)
        if ACT.match(line.strip()) and m and m.group(1) in removed:
            n_removed_suri += 1
            continue
        kept_suri.append(line)
    (d / 'suricata_sel.rules').write_text('\n'.join(kept_suri))

    (d / 'sel_removed_sids.txt').write_text('\n'.join(sorted(removed, key=int)) + '\n')
    sha = hashlib.sha256((d / 'snort_sel.rules').read_bytes()).hexdigest()
    print(f"門檻: header 逗號數 >= {THRESHOLD}")
    print(f"Snort 版：移除 {len(removed)} 條 -> snort_sel.rules  sha256 {sha}")
    print(f"Suricata 版：依同一批 sid 移除 {n_removed_suri} 條 -> suricata_sel.rules"
          f"（{len(removed) - n_removed_suri} 個 sid 在 Suricata 版沒有對應規則）")
    if expect:
        ok = sha == expect
        print(("✔ 與預期 sha256 相同" if ok else "✘ 與預期 sha256 不同") + f"（預期 {expect}）")
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
