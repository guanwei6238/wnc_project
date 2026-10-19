#!/bin/bash
# 01_make_slices.sh -- 從 IoT-23 切出主矩陣用的 4 個流量切片，並產生 small(差分法用)、x2(串接兩次，summarize.py 的線性檢查用)。全部在容器內做、--network none。
#
# 為什麼這樣切:
#  * 只用容器內的 tcpdump 讀不受信任的 pcap；唯讀掛載來源資料；之後所有統計都是 python3 -I。
#  * 「取前 N 個封包」是最簡單、可重現的切法，但有偏差: 只代表檔案開頭，不代表整個場景
#    (例: 39-1 開頭 payload 封包占 3.4%，整檔只有約 0.07%)。所以選切片時先看過各場景開頭的型態，
#    並在報告裡寫明「這個切片代表什麼、不代表什麼」。
#  * 為什麼不直接用整檔: 引擎處理速度差很大 (Pi 上 Snort 3 掛 full 在掃描流量不到 1 kpps)，整檔 GB 級要跑好幾小時，
#    而且 Pi 的 tmpfs/記憶體放不下。切片上限 ~150 MB。
#  * 切片檔名固定、凍結後不再改；sha256 在 manifest.json。
#
# 切片 (種類 A=掃描/flood, B=帶 payload, C=小而完整):
#   A_scan17   17-1 前 600,000 個封包  : 幾乎全是 60B 的 TCP SYN (掃描)，payload 封包占比 ~0.08%
#   B1_pay5    5-1  前 140,000 個封包  : 大封包、payload 封包占比 ~66%（整檔 64%，開頭與整體接近）
#   B2_mix3    3-1  整檔               : 混合 (SYN 掃描 + SSH/IRC 等)，payload 封包 ~18%，整檔所以沒有「開頭偏差」
#   C_somfy02  Honeypot-7-1 (door lock) 整檔 : 良性 IoT 設備的日常流量（小而完整）
source "$(dirname "$0")/lib.sh"
cd "$HERE"
SP=$PCAPS
spec=$BIG/slice_spec.tsv; : > "$spec"; log=$BIG/slices.log; : > "$log"
S=CTU-IoT-Malware-Capture
# 名稱 | 來源(相對 IoTScenarios) | -c 封包數(0=整檔) | 說明
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
  echo "tcpdump exit=$?" | tee -a "$log"     # 碰到被截斷的尾端時 tcpdump 會報錯並回傳非 0；要看 log
  printf '%s\t%s\t%s\t%s\n' "$name.pcap" slice "$desc: $src" "$method" >> "$spec"
  # small: 同一切片的前 500 個封包（差分法用）；x2: 串接兩次（線性驗證用，只做 B2/A）
  dk -v "$PCAPS":/p -- tcpdump -r "/p/$name.pcap" -c 500 -w "/p/$name.small.pcap" >> "$log" 2>&1
  printf '%s\t%s\t%s\t%s\n' "$name.small.pcap" small "$name.pcap 的前 500 個封包" "tcpdump -r $name.pcap -c 500 -w $name.small.pcap" >> "$spec"
done
for name in B2_mix3 A_scan17; do
  dk -v "$HERE":/s:ro -v "$PCAPS":/p -- python3 -I /s/pcap_concat.py /p/$name.pcap /p/$name.x2.pcap 2 | tee -a "$log"
  printf '%s\t%s\t%s\t%s\n' "$name.x2.pcap" x2 "$name.pcap 串接兩次" "pcap_concat.py $name.pcap $name.x2.pcap 2 (第二份時間戳平移)" >> "$spec"
done
# 選用：$PCAPS 裡若有合成的 synth_*.pcap，同樣各給一個 small 版本並寫進 spec；沒有就略過（目前的實驗都用不到）
for f in "$PCAPS"/synth_*.pcap; do
  [ -e "$f" ] || continue
  b=$(basename "$f" .pcap); case $b in *.small) continue ;; esac
  dk -v "$PCAPS":/p -- tcpdump -r "/p/$b.pcap" -c 500 -w "/p/$b.small.pcap" >> "$log" 2>&1
  printf '%s\t%s\t%s\t%s\n' "$b.pcap" synth "Scapy 合成的對照流量" "合成 pcap（不是從 IoT-23 切出來的）" >> "$spec"
  printf '%s\t%s\t%s\t%s\n' "$b.small.pcap" small "$b.pcap 的前 500 個封包" "tcpdump -c 500" >> "$spec"
done
echo "切片完成；接著 python3 -I make_manifest.py（在容器內）產生 manifest.json"
