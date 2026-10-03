#!/bin/bash
# 依 ROLE 環境變數設定該節點的網路，然後保持執行。
#
# 注意介面名稱是「用 IP 網段反查」出來的，不是寫死 eth0/eth1。
# Docker 掛載多個網路時介面順序不保證，實機上 USB 網卡的命名也可能變動，
# 所以用網段反查是唯一可靠的做法 —— 這個習慣之後在 Pi 上同樣適用。
set -euo pipefail

LAN_NET_PREFIX="10.0.1."
WAN_NET_PREFIX="10.0.2."
GW_LAN_IP="10.0.1.1"
GW_WAN_IP="10.0.2.1"

find_if() {   # $1 = IP 前綴 -> 印出介面名稱
  ip -o -4 addr show | awk -v p="$1" '$4 ~ "^"p {print $2; exit}'
}

ROLE="${ROLE:?必須設定 ROLE=cli|gw|srv}"

case "$ROLE" in
  cli)
    LAN_IF=$(find_if "$LAN_NET_PREFIX")
    # Docker 預設把 default route 指向 bridge(10.0.1.254)，要改指向我們的閘道器
    ip route replace default via "$GW_LAN_IP" dev "$LAN_IF"
    ;;
  gw)
    LAN_IF=$(find_if "$LAN_NET_PREFIX")
    WAN_IF=$(find_if "$WAN_NET_PREFIX")
    # 把解出來的介面名寫到檔案，方便 nftables 規則和其他腳本引用
    printf 'LAN_IF=%s\nWAN_IF=%s\n' "$LAN_IF" "$WAN_IF" > /run/wnc-ifaces
    ;;
  srv)
    WAN_IF=$(find_if "$WAN_NET_PREFIX")
    # 回程路由：往內網的封包要走回閘道器
    ip route replace 10.0.1.0/24 via "$GW_WAN_IP" dev "$WAN_IF"
    # 方便起見直接把 iperf3 server 跑起來
    iperf3 -s -D --logfile /var/log/iperf3.log
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
