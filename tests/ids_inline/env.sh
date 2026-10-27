#!/bin/sh
# env.sh — 在 Pi 上建立／拆除 inline 量測的環境（不碰 eth0、eth1）
#   wtest(t-wan) --veth-- g-wan [wgw: br0] g-lan --veth-- (t-lan)wtest
#   wnc-gw 在 wgw 裡跑（bridge 模式），tcpreplay 在 wtest 裡同時拿兩端
#   Suricata 的 log 目錄掛 tmpfs，和 offline 量測一樣讓輸出寫在記憶體
# 用法: sudo sh env.sh up|down
LOG=/var/log/wnc-gw/suricata
case "$1" in
up)
  modprobe br_netfilter
  for ns in wgw wtest; do
    ip netns add $ns
    ip netns exec $ns sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
    ip -n $ns link set lo up
  done
  ip link add t-lan netns wtest mtu 9000 type veth peer name g-lan netns wgw mtu 9000
  ip link add t-wan netns wtest mtu 9000 type veth peer name g-wan netns wgw mtu 9000
  ip -n wgw link add br0 mtu 9000 type bridge
  ip -n wgw link set g-lan master br0
  ip -n wgw link set g-wan master br0
  for l in br0 g-lan g-wan; do ip -n wgw link set $l up; done
  for l in t-lan t-wan; do ip -n wtest link set $l up; done
  mkdir -p $LOG
  mountpoint -q $LOG || mount -t tmpfs -o size=1g,mode=0750 wncgw-suricata-log $LOG
  ;;
down)
  for ns in wgw wtest; do ip netns del $ns 2>/dev/null; done
  mountpoint -q $LOG && umount $LOG
  ;;
*) echo "usage: sudo sh env.sh up|down"; exit 2 ;;
esac
