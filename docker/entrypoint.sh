#!/bin/bash
# Configure this node's network according to ROLE, then keep running.
#
# Note: interface names are looked up by IP subnet, not hardcoded as eth0/eth1.
# Docker does not guarantee interface order with multiple networks, and USB NIC names on real hardware can change too,
# so looking up by subnet is the only reliable way - the same habit applies on the Pi later.
set -euo pipefail

LAN_NET_PREFIX="10.0.1."
WAN_NET_PREFIX="10.0.2."
GW_LAN_IP="10.0.1.1"
GW_WAN_IP="10.0.2.1"

find_if() {   # $1 = IP prefix -> prints the interface name
  ip -o -4 addr show | awk -v p="$1" '$4 ~ "^"p {print $2; exit}'
}

ROLE="${ROLE:?必須設定 ROLE=cli|gw|srv|rep}"

case "$ROLE" in
  cli)
    LAN_IF=$(find_if "$LAN_NET_PREFIX")
    # Docker points the default route at the bridge (10.0.1.254) by default; point it at our gateway instead
    ip route replace default via "$GW_LAN_IP" dev "$LAN_IF"
    ;;
  gw)
    LAN_IF=$(find_if "$LAN_NET_PREFIX")
    WAN_IF=$(find_if "$WAN_NET_PREFIX")
    # Write the resolved interface names to a file for nftables rules and other scripts
    printf 'LAN_IF=%s\nWAN_IF=%s\n' "$LAN_IF" "$WAN_IF" > /run/wnc-ifaces
    ;;
  srv)
    WAN_IF=$(find_if "$WAN_NET_PREFIX")
    # Return route: packets to the LAN side go back through the gateway
    ip route replace 10.0.1.0/24 via "$GW_WAN_IP" dev "$WAN_IF"
    # Start the iperf3 server right away for convenience
    iperf3 -s -D --logfile /var/log/iperf3.log
    ;;
  rep)
    # Rename the two NICs to fixed names so tcpreplay can use -i wan -I lan directly
    LAN_IF=$(find_if "$LAN_NET_PREFIX")
    WAN_IF=$(find_if "$WAN_NET_PREFIX")
    ip link set "$LAN_IF" down; ip link set "$LAN_IF" name lan; ip link set lan up
    ip link set "$WAN_IF" down; ip link set "$WAN_IF" name wan; ip link set wan up
    ;;
  *)
    echo "未知的 ROLE: $ROLE" >&2; exit 1 ;;
esac

echo "=============================================="
echo " 節點: $ROLE   ($(hostname))"
echo "=============================================="
ip -brief -4 addr show | grep -v '^lo'
echo "--- 路由表 ---"
ip route show
if [[ "$ROLE" == "gw" ]]; then
  echo "--- 轉發狀態 ---"
  echo "net.ipv4.ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"
  echo "LAN_IF=$LAN_IF (內網)  WAN_IF=$WAN_IF (外網)"
fi
echo "=============================================="

exec sleep infinity
