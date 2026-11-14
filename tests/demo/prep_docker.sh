#!/bin/bash
# prep_docker.sh — Docker demo 的準備（先 cd docker && ./up.sh；gw 容器重建後要再跑一次）
#   1. ET Open 完整規則複製到 docker/suricata-rules/（掛到 gw 的 /var/lib/suricata/rules）
#   2. gw 加 dataset 網段的路由：192.168.0.0/16 往 LAN、其他往 WAN，下一跳是不存在的 MAC，封包經過 forward 後送出去就沒人收
#   3. dataset 的 pcap 修正 checksum、依路由器的 MAC 分兩邊、目的 MAC 改成 gw 的，放到 tests/demo/pcaps/（wnc-rep 的 /pcaps）
# 用法: bash tests/demo/prep_docker.sh    PCAPS=、RULES= 可以換來源
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PCAPS=${PCAPS:-$HOME/datasets/throughput/pcaps}
RULES=${RULES:-$HOME/datasets/detection/rules/et_all.rules}

cp -u "$RULES" "$HERE/../../docker/suricata-rules/et_all.rules"
echo "rules: docker/suricata-rules/et_all.rules ($(grep -c '^alert' "$RULES") rules)"

docker exec wnc-gw sh -c '. /run/wnc-ifaces
  ip neigh replace 10.0.1.200 lladdr 02:00:00:00:01:fe dev $LAN_IF nud permanent
  ip neigh replace 10.0.2.200 lladdr 02:00:00:00:02:fe dev $WAN_IF nud permanent
  ip route replace 192.168.0.0/16 via 10.0.1.200
  ip route replace default via 10.0.2.200'
echo "gw routes:"; docker exec wnc-gw ip route | sed 's/^/  /'

while read -r name src router; do
  cp "$PCAPS/$src.pcap" "$HERE/pcaps/$name.orig.pcap"
  docker exec -u "$(id -u):$(id -g)" -w /pcaps wnc-rep sh -c "
    tcprewrite --fixcsum -i $name.orig.pcap -o $name.csum.pcap 2> /dev/null &&
    tcpprep --mac=$router -i $name.csum.pcap -o $name.cache &&
    tcprewrite -c $name.cache --enet-dmac=02:00:00:00:02:01,02:00:00:00:01:01 -i $name.csum.pcap -o $name.pcap &&
    rm $name.orig.pcap $name.csum.pcap"
  echo "tests/demo/pcaps/$name.pcap <- $src.pcap"
done << EOF
somfy C_somfy02.small 78:8a:20:43:93:d5
muhstik S_m3.small a6:d1:8c:1f:ce:64
mirai S_m34.small 78:8a:20:43:93:d5
EOF
