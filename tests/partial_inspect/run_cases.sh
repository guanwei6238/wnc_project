#!/bin/bash
# run_cases.sh — 實驗 3：每個 case 的 pcap 用 Suricata 8.0.7 offline 跑兩次（ids；ips = --simulate-ips）
#   設定照 wnc-gw 強制的（security_gateway/src/ids/spawned.rs）：midstream=true、midstream-policy=ignore、exception-policy=ignore 系列、checksum 不檢查；
#   另外 flow-timeouts.tcp.established=30（E5 測「閒置超過逾時」）、runmode single（結果固定）
# 用法: [RES=res] [EXTRA_SET="--set k=v ..."] bash run_cases.sh <cases 目錄>   結果在 <cases 目錄>/$RES/<case>.<mode>/eve.json
D=$(cd "$1" && pwd)
RES=${RES:-res}; mkdir -p $D/$RES
docker run --rm --user "$(id -u):$(id -g)" --memory 2g --network none -e EXTRA_SET="${EXTRA_SET:-}" -e RES=$RES -v $D:/w --entrypoint bash wnc-lab-gw:latest -c '
for c in $(cut -f1 /w/manifest.tsv); do
  for mode in ids ips; do
    o=/w/$RES/$c.$mode; rm -rf $o; mkdir -p $o
    extra=""; [ $mode = ips ] && extra="--simulate-ips"
    suricata -r /w/$c.pcap -S /w/rules.txt -l $o -k none --runmode single $extra \
      --set stream.midstream=true --set stream.midstream-policy=ignore \
      --set exception-policy=ignore --set stream.memcap-policy=ignore --set stream.reassembly.memcap-policy=ignore \
      --set flow.memcap-policy=ignore --set defrag.memcap-policy=ignore --set app-layer.error-policy=ignore \
      --set flow-timeouts.tcp.established=30 --set flow-timeouts.tcp.emergency-established=10 --set unix-command.enabled=no --set coredump.max-dump=0 \
      ${EXTRA_SET:-} > $o/stdout.txt 2>&1
    echo "$c $mode exit=$?"
  done
done' | awk '{printf "%s ", $0} END{print ""}'
