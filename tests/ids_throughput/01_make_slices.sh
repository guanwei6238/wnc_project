#!/bin/bash
# 01_make_slices.sh -- cut the 4 main-matrix traffic slices from IoT-23, plus small (for the difference method) and x2 (concatenated twice, for summarize.py's linearity check). All done in a container with --network none.
#
# Why slice this way:
#  * Untrusted pcaps are read only by tcpdump inside the container; source data is mounted read-only; all later stats use python3 -I.
#  * "First N packets" is the simplest reproducible cut, but biased: it represents only the start of the file, not the whole scenario
#    (e.g. at the start of 39-1 payload packets are 3.4%, over the whole file only about 0.07%). So the start of each scenario was inspected before picking slices,
#    and the report states what each slice does and does not represent.
#  * Why not whole files: engine speeds differ a lot (Snort 3 with full on the Pi does under 1 kpps on scan traffic), GB-sized files would take hours,
#    and they do not fit in the Pi's tmpfs/memory. Slices are capped at ~150 MB.
#  * Slice file names are fixed and frozen once made; sha256 is in manifest.json.
#
# Slices (kind A=scan/flood, B=with payload, C=small and complete):
#   A_scan17   17-1 first 600,000 packets : almost all 60B TCP SYN (scan), payload packets ~0.08%
#   B1_pay5    5-1  first 140,000 packets : large packets, payload packets ~66% (64% over the whole file, start is close to overall)
#   B2_mix3    3-1  whole file           : mixed (SYN scan + SSH/IRC etc.), payload packets ~18%, whole file so no start-of-file bias
#   C_somfy02  Honeypot-7-1 (door lock) whole file : everyday traffic of a benign IoT device (small and complete)
source "$(dirname "$0")/lib.sh"
cd "$HERE"
SP=$PCAPS
spec=$BIG/slice_spec.tsv; : > "$spec"; log=$BIG/slices.log; : > "$log"
S=CTU-IoT-Malware-Capture
# name | source (relative to IoTScenarios) | -c packet count (0=whole file) | description
slices=(
 "A_scan17|$S-17-1/2018-09-06-11-43-12-192.168.100.111.pcap|600000|IoT-23 Malware-17-1 檔案開頭"
 "B1_pay5|CTU-Honeypot-Capture-5-1/2018-09-21-capture.pcap|140000|IoT-23 Honeypot-5-1 檔案開頭"
 "B2_mix3|$S-3-1/2018-05-21_capture.pcap|0|IoT-23 Malware-3-1 整個檔案"
 "C_somfy02|CTU-Honeypot-Capture-7-1/Somfy-02/2019-07-03-16-41-09-192.168.1.158.pcap|0|IoT-23 Honeypot-7-1/Somfy-02 整個檔案"
)
for s in "${slices[@]}"; do
  IFS='|' read -r name src n desc <<< "$s"
  opt=(); method="tcpdump -r <src> -w $name.pcap"
  if [ "$n" != 0 ]; then opt=(-c "$n"); method="tcpdump -r <src> -c $n -w $name.pcap"; fi
  echo "== $name ($src)" | tee -a "$log"
  dk -v "$IOT23":/iot:ro -v "$PCAPS":/p -- tcpdump -r "/iot/$src" "${opt[@]}" -w "/p/$name.pcap" >> "$log" 2>&1
  echo "tcpdump exit=$?" | tee -a "$log"     # tcpdump errors and returns nonzero on a truncated tail; check the log
  printf '%s\t%s\t%s\t%s\n' "$name.pcap" slice "$desc: $src" "$method" >> "$spec"
  # small: first 500 packets of the same slice (difference method); x2: concatenated twice (linearity check, B2/A only)
  dk -v "$PCAPS":/p -- tcpdump -r "/p/$name.pcap" -c 500 -w "/p/$name.small.pcap" >> "$log" 2>&1
  printf '%s\t%s\t%s\t%s\n' "$name.small.pcap" small "$name.pcap 的前 500 個封包" "tcpdump -r $name.pcap -c 500 -w $name.small.pcap" >> "$spec"
done
for name in B2_mix3 A_scan17; do
  dk -v "$HERE":/s:ro -v "$PCAPS":/p -- python3 -I /s/pcap_concat.py /p/$name.pcap /p/$name.x2.pcap 2 | tee -a "$log"
  printf '%s\t%s\t%s\t%s\n' "$name.x2.pcap" x2 "$name.pcap 串接兩次" "pcap_concat.py $name.pcap $name.x2.pcap 2 (第二份時間戳平移)" >> "$spec"
done
# Optional: any synthetic synth_*.pcap in $PCAPS also gets a small version and goes into spec; skipped if none (no current experiment uses them)
for f in "$PCAPS"/synth_*.pcap; do
  [ -e "$f" ] || continue
  b=$(basename "$f" .pcap); case $b in *.small) continue ;; esac
  dk -v "$PCAPS":/p -- tcpdump -r "/p/$b.pcap" -c 500 -w "/p/$b.small.pcap" >> "$log" 2>&1
  printf '%s\t%s\t%s\t%s\n' "$b.pcap" synth "Scapy 合成的對照流量" "合成 pcap（不是從 IoT-23 切出來的）" >> "$spec"
  printf '%s\t%s\t%s\t%s\n' "$b.small.pcap" small "$b.pcap 的前 500 個封包" "tcpdump -c 500" >> "$spec"
done
echo "切片完成；接著 python3 -I make_manifest.py（在容器內）產生 manifest.json"
