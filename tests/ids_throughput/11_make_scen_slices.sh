#!/bin/bash
# 11_make_scen_slices.sh - slices for the multi-scenario test: each scenario takes its first 200,000 packets (whole file if shorter), the same for all.
#
# Goal: test scenarios with different traffic patterns that change the numbers, with the same packet count per scenario for both IDSes.
#   - Scenarios are picked from the traffic features in 10_scenario_features.py (results/scenario_features.tsv):
#     single-port SYN scans (different ports each, since rules are grouped by port and cost may differ), heavy UDP (small/large packets),
#     multi-port scan + UDP probing, mixed TCP/UDP with payload, small mixed (with ICMP, C2), benign IoT (two devices), large TLS download.
#     Scenarios with nearly identical features (e.g. Somfy-01 to 06, several port-23 scans) are taken only once.
#   - Sized by packet count rather than MB: IDS cost is mostly per packet and per connection; by MB, small-packet scenarios would have over 20x more packets.
#   - The 4 main-matrix slices (A/B1/B2/C, 01_make_slices.sh) have different packet counts; here the same scenarios are also cut to the first 200k packets, named with an S_ prefix to keep them apart from the main-matrix slices.
# Each slice also gets a .small (first 500 packets, for the Suricata empty-rule difference method).
source "$(dirname "$0")/lib.sh"
cd "$HERE"
N=200000
spec=$BIG/slice_spec.tsv; log=$BIG/scen_slices.log; : > "$log"
H=CTU-Honeypot-Capture; M=CTU-IoT-Malware-Capture
# name | source (relative to IoTScenarios) | description
slices=(
 "S_m17|$M-17-1/2018-09-06-11-43-12-192.168.100.111.pcap|SYN 掃描 8081/80（原 A 的場景）"
 "S_h5|$H-5-1/2018-09-21-capture.pcap|TLS 大檔下載（原 B1 的場景）"
 "S_m3|$M-3-1/2018-05-21_capture.pcap|SSH 掃描＋IRC C2（原 B2 的場景）"
 "S_somfy02|$H-7-1/Somfy-02/2019-07-03-16-41-09-192.168.1.158.pcap|良性 IoT：Somfy（原 C 的場景）"
 "S_m36|$M-36-1/$(cd "$IOT23/$M-36-1" && ls *.pcap | head -1)|SYN 探測 37215（Okiru）"
 "S_m48|$M-48-1/$(cd "$IOT23/$M-48-1" && ls *.pcap | head -1)|SYN 掃描 23（Telnet）＋Telnet 攻擊"
 "S_m39|$M-39-1/$(cd "$IOT23/$M-39-1" && ls *.pcap | head -1)|SYN 掃描 22（SSH）＋SSH 攻擊"
 "S_m60|$M-60-1/$(cd "$IOT23/$M-60-1" && ls *.pcap | head -1)|大量 UDP、小封包（DDoS）"
 "S_m44|$M-44-1/$(cd "$IOT23/$M-44-1" && ls *.pcap | head -1)|大量 UDP、大封包"
 "S_m1|$M-1-1/2018-05-09-192.168.100.103.pcap|多埠掃描（3 萬種埠）＋UDP 探測"
 "S_m34|$M-34-1/$(cd "$IOT23/$M-34-1" && ls *.pcap | grep -v irc | head -1)|TCP/UDP 混合、帶 payload（DDoS）"
 "S_m20|$M-20-1/$(cd "$IOT23/$M-20-1" && ls *.pcap | head -1)|小型混合、ICMP 多、C2 走 443（Torii）"
 "S_m42|$M-42-1/$(cd "$IOT23/$M-42-1" && ls *.pcap | head -1)|小型：良性＋檔案下載"
 "S_h4|$H-4-1/$(cd "$IOT23/$H-4-1" && ls *.pcap | grep -v Hue | head -1)|良性 IoT：與 Somfy 不同的設備（UDP、ICMP 多）"
)
# Remove old S_ entries from spec first (re-runnable)
grep -v -P '^S_' "$spec" > "$spec.tmp"; mv "$spec.tmp" "$spec"
for s in "${slices[@]}"; do
  IFS='|' read -r name src desc <<< "$s"
  echo "== $name ($src)" | tee -a "$log"
  dk -v "$IOT23":/iot:ro -v "$PCAPS":/p -- tcpdump -r "/iot/$src" -c $N -w "/p/$name.pcap" >> "$log" 2>&1
  echo "tcpdump exit=$?" | tee -a "$log"
  dk -v "$PCAPS":/p -- tcpdump -r "/p/$name.pcap" -c 500 -w "/p/$name.small.pcap" >> "$log" 2>&1
  printf '%s\t%s\t%s\t%s\n' "$name.pcap" scen "$desc: $src" "tcpdump -r <src> -c $N -w $name.pcap" >> "$spec"
  printf '%s\t%s\t%s\t%s\n' "$name.small.pcap" small "$name.pcap 的前 500 個封包" "tcpdump -r $name.pcap -c 500 -w $name.small.pcap" >> "$spec"
done
echo "切片完成；接著 python3 -I make_manifest.py $PCAPS $spec manifest.json"
