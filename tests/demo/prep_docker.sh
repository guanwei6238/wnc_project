#!/bin/bash
# prep_docker.sh — prepare the Docker demo (cd docker && ./up.sh first; rerun after the gw container is rebuilt)
#   1. copy the full ET Open rules to docker/suricata-rules/ (mounted at gw's /var/lib/suricata/rules)
#   2. add routes for the dataset subnets on gw: 192.168.0.0/16 toward LAN, the rest toward WAN; the next hop is a nonexistent MAC, so packets go out after forward and nobody receives them
#   3. fix dataset pcap checksums, split by the router's MAC, rewrite the destination MAC to gw's, put them in tests/demo/pcaps/ (/pcaps in wnc-rep)
# Usage: bash tests/demo/prep_docker.sh    PCAPS=, RULES= change the sources
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
