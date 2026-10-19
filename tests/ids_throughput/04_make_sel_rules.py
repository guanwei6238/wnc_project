#!/usr/bin/env python3
"""04_make_sel_rules.py — 產生「sel」規則集：全量規則扣掉「header 含大量 IP 項目」的規則。

為什麼：Snort 3 掛 full 在掃描型流量下非常慢（Pi 上 A 切片只有 0.37 kpps），成本幾乎全來自約 3% 的規則——
header 裡有很長 IP 清單的規則（以 ET 的 TOR 出口節點清單、CINS、DROP 等 IP 信譽清單為主（Snort 版 1,559 條：TOR 803、CINS 596、DROP 69、其他約 91））。
sel 就是用來在 Pi 上量「只挑掉這一小類規則，能換回多少速度」（Pi 上 A 切片的 Snort 3：full 0.37 kpps → sel 64.3 kpps）。

判準（簡單、可重現）：啟用規則的 header（第一個 '(' 之前的文字）裡，逗號數 >= 8（即 IP 項目很多）。
注意：這是「依成本」挑選，不是「依偵測價值」挑選。移除這些規則會失去什麼偵測力，這個實驗沒有量，不能當成可以安全移除。

做法：用 Snort 版全量規則決定「要移除哪些 sid」，再從 Suricata 版全量規則移除同樣的 sid，兩個引擎的 sel 對應同一批 sid。
輸出（與 *_full.rules 同目錄）：suricata_sel.rules、snort_sel.rules；另存被移除的 sid 清單供重現。

用法： python3 -I 04_make_sel_rules.py <規則目錄> [--check-snort-sha256 <預期 sha256>]
"""
import hashlib
import re
import sys
from pathlib import Path

THRESHOLD = 8                                   # header 逗號數門檻
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
