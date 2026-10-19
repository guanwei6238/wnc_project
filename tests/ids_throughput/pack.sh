#!/bin/bash
# pack.sh -- 把 Pi 上需要的東西打成一個 tar.gz + sha256，給你用 scp 傳過去（本腳本不會連線、不會傳）。
# 內容: 腳本（量測：measure.sh run_matrix.py summarize.py pcap_stats.py lib.sh；批次：run_pi_main.sh run_pi_scen2.sh
#       run_pi_mem_scen.sh pi_set_total_mem.sh；04_make_sel_rules.py；README.md manifest.json）
#       + data/pcaps（manifest 裡的 4 個切片、14 個 scenario 切片，以及它們的 .small）
#       + data/rules（common/full/sel/gw_corp 各兩個引擎的規則檔 + sel_removed_sids.txt + SHA256SUMS）
#       common 只有 run_pi_main.sh 會用到。
# 用法: ./pack.sh            # 壓縮前約 1.3 GB
# 輸出: $BIG/ids_throughput_pi.tar.gz  和  $BIG/ids_throughput_pi.tar.gz.sha256
source "$(dirname "$0")/lib.sh"
stage=$(mktemp -d "$BIG/pack_stage.XXXXXX"); trap 'rm -rf "$stage"' EXIT
d=$stage/ids_throughput; mkdir -p "$d/data/pcaps" "$d/data/rules" "$d/results"
for f in measure.sh run_matrix.py summarize.py pcap_stats.py README.md manifest.json lib.sh run_pi_main.sh run_pi_scen2.sh run_pi_mem_scen.sh pi_set_total_mem.sh 04_make_sel_rules.py; do cp "$HERE/$f" "$d/"; done
# 切片、scenario 切片與 small（以 manifest 的 kind 為準，synth_ 開頭的不帶；用 symlink 再 tar -h 解參照，避免多複製一份大檔）
python3 -I - "$HERE/manifest.json" > "$stage/files.txt" <<'P'
import json, sys
for m in json.load(open(sys.argv[1])):
    if m["kind"] in ("slice", "scen", "small") and not m["name"].startswith("synth_"):
        print(m["name"])
P
while read -r n; do ln -s "$PCAPS/$n" "$d/data/pcaps/$n"; done < "$stage/files.txt"
for r in suricata_common suricata_full suricata_sel suricata_gw_corp snort_common snort_full snort_sel snort_gw_corp; do ln -s "$RULES/$r.rules" "$d/data/rules/$r.rules"; done
ln -s "$RULES/sel_removed_sids.txt" "$d/data/rules/sel_removed_sids.txt"   # sel 規則集移除的 sid 清單（重現用）
cp "$RULES/SHA256SUMS" "$d/data/rules/SHA256SUMS"
(cd "$d/data/pcaps" && sha256sum * > ../pcaps.SHA256SUMS)
chmod +x "$d"/*.sh "$d"/*.py
tar -C "$stage" -h -czf "$BIG/ids_throughput_pi.tar.gz" ids_throughput
(cd "$BIG" && sha256sum ids_throughput_pi.tar.gz | tee ids_throughput_pi.tar.gz.sha256)
ls -la "$BIG/ids_throughput_pi.tar.gz"; tar -tzf "$BIG/ids_throughput_pi.tar.gz" | head -40
