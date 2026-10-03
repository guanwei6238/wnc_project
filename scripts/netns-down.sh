#!/bin/sh
# 還原 netns.sh：把 enx9c69d3241bd9 搬回 root ns，刪掉 netns "lan"。

# 先刪回程路由，否則等一下 enx 加回 10.254.127.1 時，
# 直連路由 10.254.127.0/24 dev enx 會跟它撞在一起而建不起來。
ip route del 10.254.127.0/24 via 10.254.254.2

# 再明確搬回 root ns（netns 1 = PID 1 所在的 namespace）。
# 直接 `ip netns del` 也會讓實體網卡回到 root，但那是非同步的，馬上設 IP 可能會失敗。
ip -n lan link set enx9c69d3241bd9 netns 1
ip netns del lan

# 回到 net.sh 的狀態
ip addr add 10.254.127.1/24 dev enx9c69d3241bd9
ip link set enx9c69d3241bd9 up
