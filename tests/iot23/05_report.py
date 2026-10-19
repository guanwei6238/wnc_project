#!/usr/bin/env python3
"""把 results/*.json 整理成 report.md（markdown 表格）。
若同目錄有 summary_notes.md（人工寫的原因分析），會放在報告最前面。

用法：python3 -I 05_report.py <results 目錄> <輸出 report.md> [summary_notes.md]
"""
import json
import sys
from pathlib import Path


def human(n):
    for u in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or u == 'GB':
            return f'{n:.1f} {u}' if u != 'B' else f'{n} B'
        n /= 1024


def pct(a, b):
    return f'{a / b * 100:.2f}%' if b else 'n/a'


def key(r):
    return [int(x) if x.isdigit() else x for x in r['scenario'].replace('-', ' ').split()]


def main():
    resdir, out = Path(sys.argv[1]), Path(sys.argv[2])
    notes = Path(sys.argv[3]).read_text() if len(sys.argv) > 3 and Path(sys.argv[3]).exists() else ''
    rs = sorted((json.loads(p.read_text()) for p in resdir.glob('*.json')), key=key)
    ok = [r for r in rs if 'error' not in r]
    L = []
    L.append('# IoT-23 全部場景：label 對應驗證報告\n')
    if notes:
        L.append(notes + '\n')

    # ---- 摘要數字
    tp = sum(r['pcap_packets'] for r in ok)
    tf = sum(r['flows'] for r in ok)
    ta = sum(r['aligned'] for r in ok)
    tc = sum(r['pcap_covered_packets'] for r in ok)
    L.append('## 摘要數字（自動計算）\n')
    aligned_sc = [r for r in ok if r['flows']]
    L.append(f'- 場景（含 Somfy 子資料夾）總數：{len(rs)}；有做對齊的：{len(aligned_sc)}；'
             f'只有 pcap 沒有 conn.log.labeled：{len([r for r in ok if r.get("log_file") is None])}；沒有 pcap 或失敗：{len(rs) - len(ok)}')
    L.append(f'- 總封包數（有跑對齊的場景）：{tp:,}')
    L.append(f'- 總 labeled flow 數（tcp/udp/icmp）：{tf:,}')
    L.append(f'- 整體對齊：{ta:,} / {tf:,} = {pct(ta, tf)}')
    L.append(f'- 被 flow 涵蓋的封包：{tc:,} / {tp:,} = {pct(tc, tp)}')
    skipped = {}
    for r in ok:
        for k, v in r['skipped_flows_other_proto'].items():
            skipped[k] = skipped.get(k, 0) + v
    L.append(f'- 因協定不是 tcp/udp/icmp 而不納入對齊的 flow：{skipped or "無"}')
    L.append(f'- 格式異常（欄位不足）的 log 行：{sum(r["malformed_log_lines"] for r in ok)}')
    bad = [r for r in ok if r['aligned'] != r['flows']]
    L.append(f'- 對齊率 < 100% 的場景：{len(bad)} 個\n')

    # ---- 一場景一列
    L.append('## 每個場景一列\n')
    L.append('| 場景 | pcap 大小 | 封包數 | labeled flow | 對齊 | 對齊率 | 對不上 | 有 payload 的 flow | 封包被涵蓋 | 備註 |')
    L.append('|---|---:|---:|---:|---:|---:|---:|---:|---:|---|')
    for r in rs:
        if 'error' in r:
            L.append(f'| {r["scenario"]} | - | - | - | - | - | - | - | - | **{r["error"]}** |')
            continue
        fp = sum(s.get('flows_with_payload', 0) for s in r['labels'].values())
        note = []
        if r.get('log_file') is None:
            note.append('**沒有 conn.log.labeled（只數封包，沒做對齊）**')
        if r['pcap_truncated_tail']:
            note.append('pcap 尾端被截斷')
        if r['pcap_linktype'] != 1:
            note.append(f'linktype={r["pcap_linktype"]}（非 Ethernet）')
        if r['skipped_flows_other_proto']:
            note.append(f'略過其他協定 flow {sum(r["skipped_flows_other_proto"].values()):,}')
        if r['shards'] > 1:
            note.append(f'分 {r["shards"]} 批')
        if r.get('extra_pcaps'):
            note.append(f'另有 {len(r["extra_pcaps"])} 個 pcap 未對齊（{", ".join(f"{n} {human(sz)}" for n, sz in r["extra_pcaps"].items())}）')
        lt, pt = r.get('log_time_range'), r.get('pcap_time_range')
        if lt and pt and pt[0] is not None and not (pt[0] - 1 <= lt[0] and lt[1] <= pt[1] + 1):
            note.append(f'log 時間範圍超出 pcap（log {lt[0]:.0f}~{lt[1]:.0f}, pcap {pt[0]:.0f}~{pt[1]:.0f}）')
        if lt and pt and pt[0] is not None and pt[1] - lt[1] > 60:
            note.append(f'log 比 pcap 早結束 {(pt[1] - lt[1]) / 3600:.1f} 小時（log 只涵蓋 pcap 時間的 {(lt[1] - pt[0]) / (pt[1] - pt[0]) * 100:.0f}%）')
        L.append(f'| {r["scenario"]} | {human(r["pcap_bytes"])} | {r["pcap_packets"]:,} | {r["flows"]:,} | {r["aligned"]:,} '
                 f'| {pct(r["aligned"], r["flows"])} | {r["unaligned"]:,} | {pct(fp, r["flows"])} '
                 f'| {pct(r["pcap_covered_packets"], r["pcap_packets"])} | {"; ".join(note)} |')
    L.append('')

    # ---- 每個場景的 label 明細
    L.append('## 各場景、各 label 的 flow 數與 payload\n')
    L.append('「有 payload 的 flow」= 對得到的封包中至少有一個 TCP 封包帶應用層資料（UDP 一律記 0，所以純 UDP label 這欄會是 0）。\n')
    for r in [r for r in ok if r['labels']]:
        L.append(f'### {r["scenario"]}\n')
        L.append('| label | flow 數 | 對齊 | 對齊率 | 封包數 | 有 payload 的 flow | 比例 | payload 封包數 |')
        L.append('|---|---:|---:|---:|---:|---:|---:|---:|')
        for lab, s in r['labels'].items():
            L.append(f'| {lab} | {s["flows"]:,} | {s["aligned"]:,} | {pct(s["aligned"], s["flows"])} | {s["pkts"]:,} '
                     f'| {s.get("flows_with_payload", 0):,} | {pct(s.get("flows_with_payload", 0), s["flows"])} | {s["payload_pkts"]:,} |')
        L.append('')

    # ---- 對不上的例子
    L.append('## 對不上的 flow（每場景前 5 條）\n')
    any_bad = False
    for r in bad:
        any_bad = True
        k = r['unaligned_kinds']
        L.append(f'### {r["scenario"]}：{r["unaligned"]:,} 條對不上'
                 f'（一個封包都找不到 {k.get("zero", 0):,}；找到但比預期少 {k.get("fewer", 0):,}；找到比預期多 {k.get("more", 0):,}）\n')
        L.append('| conn.log 行號 | proto | flow | label | conn_state | 找到封包 | 預期封包 |')
        L.append('|---:|---|---|---|---|---:|---:|')
        for e in r['unaligned_examples']:
            L.append(f'| {e["line"]} | {e["proto"]} | {e["flow"]} | {e["label"]} | {e["conn_state"]} | {e["found_pkts"]} | {e["expect_pkts"]} |')
        L.append('')
    if not any_bad:
        L.append('（無）\n')
    out.write_text('\n'.join(L))
    print('wrote', out)


if __name__ == '__main__':
    main()
