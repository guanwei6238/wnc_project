#!/bin/bash
# 11_make_scen_slices.sh — 多場景測試用的切片：每個場景取「前 200,000 個封包」（不足就整檔），全部一致。
#
# 目的：挑流量型態不同、會讓數據不一樣的場景測試，且兩個 IDS、各場景分析的封包量一致。
#   - 場景是依 10_scenario_features.py 的流量特徵挑的（results/scenario_features.tsv）：
#     單一埠 SYN 掃描（各掃不同的埠，因為規則依埠分組，成本可能不同）、大量 UDP（小封包／大封包）、
#     多埠掃描＋UDP 探測、TCP/UDP 混合帶 payload、小型混合（含 ICMP、C2）、良性 IoT（兩種設備）、TLS 大檔下載。
#     特徵幾乎相同的場景（例如 Somfy-01～06、多個掃 23 埠的場景）只取一個。
#   - 統一用「封包數」而不是 MB：IDS 成本主要是每個封包、每條連線的處理；若用 MB，小封包的場景封包數會多出 20 倍以上。
#   - 主矩陣的 4 個切片（A／B1／B2／C，01_make_slices.sh）封包數不一致；這裡把同樣的場景也切成前 20 萬封包，名稱用 S_ 開頭，和主矩陣的切片分開。
# 每個切片另做 .small（前 500 封包，Suricata 空規則的差分法用）。
source "$(dirname "$0")/lib.sh"
cd "$HERE"
N=200000
spec=$BIG/slice_spec.tsv; log=$BIG/scen_slices.log; : > "$log"
H=CTU-Honeypot-Capture; M=CTU-IoT-Malware-Capture
# 名稱 | 來源（相對 IoTScenarios） | 說明
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
# 先移除 spec 裡舊的 S_ 項目（可重跑）
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
