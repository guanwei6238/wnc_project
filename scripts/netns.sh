#!/bin/sh
# 把 enx9c69d3241bd9 搬進 netns "lan"，在同一台筆電上扮演 LAN client。
# eno2 留在 root ns 扮演 WAN 端。兩邊只能透過實體線經過 Pi 互通。
set -e

ip netns add lan

# 介面搬進 namespace 時，它身上的 IP 會被清掉，所以要在裡面重設
ip link set enx9c69d3241bd9 netns lan
ip -n lan addr add 10.254.127.1/24 dev enx9c69d3241bd9
ip -n lan link set lo up
ip -n lan link set enx9c69d3241bd9 up

# LAN client 把 Pi 的 LAN port 當 gateway
ip -n lan route add default via 10.254.127.2

# WAN 端（root ns），replace：已經有這個位址也不會報錯
ip addr replace 10.254.254.1/24 dev eno2
ip link set eno2 up

# 回程路由（純路由模式）：往 LAN 網段的封包交給 Pi 的 WAN port。
# 少了這條，reply 會走 default route 從 wlo1 出去。
ip route add 10.254.127.0/24 via 10.254.254.2
