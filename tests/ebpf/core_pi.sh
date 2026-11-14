#!/bin/bash
# 核心 eBPF 程式（步驟 A1）在 Pi 上的功能驗證；不碰 eth0、eth1
#   ecli(c0 10.8.0.1) --veth-- lan0 [egw: br0] wan0 --veth-- s0(esrv 10.8.0.2)
# 用法: sudo bash core_pi.sh up|run|show|tcx|kill9|down（tcx 要 foreign_tcx.py 放在同一個目錄）
GW=${GW:-/tmp/wncgw/wnc-gw}; D=/tmp/wncgw/ebpf
G="ip netns exec egw"; C="ip netns exec ecli"

setup() {
  mkdir -p $D
  echo 'alert icmp any any -> any any (msg:"core icmp"; sid:1000301; rev:1;)' > $D/test.rules
  printf '%%YAML 1.1\n---\ninclude: /etc/suricata/suricata.yaml\ndefault-rule-path: %s\nrule-files:\n  - test.rules\n' $D > $D/s.yaml
  printf 'mode = "bridge"\n\n[ports]\nlan = "lan0"\nwan = "wan0"\n\n[suricata]\nconfig = "%s"\n' $D/s.yaml > $D/setting.toml
}

start() {
  rm -f $D/run.log $D/exit
  ( $G $GW -c $D/setting.toml run > /dev/null 2> $D/run.log; echo $? > $D/exit ) &
  for i in $(seq 1 150); do
    grep -q "traffic is inspected" $D/run.log 2>/dev/null && return 0
    [ -e $D/exit ] && break; sleep 0.2
  done
  echo "wnc-gw did not start"; tail -5 $D/run.log; return 1
}

case "$1" in
up)
  modprobe br_netfilter
  for ns in ecli esrv egw; do
    ip netns add $ns
    ip netns exec $ns sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
    ip -n $ns link set lo up
  done
  ip link add c0 netns ecli type veth peer name lan0 netns egw
  ip link add s0 netns esrv type veth peer name wan0 netns egw
  ip -n egw link add br0 type bridge
  for l in lan0 wan0; do ip -n egw link set $l master br0; ip -n egw link set $l up; done
  ip -n egw link set br0 up
  ip -n ecli addr add 10.8.0.1/24 dev c0; ip -n ecli link set c0 up
  ip -n esrv addr add 10.8.0.2/24 dev s0; ip -n esrv link set s0 up
  $C ping -c 1 -W 2 10.8.0.2 | grep -o "1 received"
  ;;
run)
  setup; start || exit 1
  $C ping -c 5 -i 0.2 -W 2 10.8.0.2 | grep -o "[0-9]* received"
  kill -INT $(pgrep -n -x wnc-gw); until [ -e $D/exit ]; do sleep 0.2; done
  echo "wnc-gw exit=$(cat $D/exit)"
  grep -E "core ebpf|D001|ERROR" $D/run.log | cut -c28-
  ;;
show)
  setup; start || exit 1
  $C ping -c 3 -i 0.2 -W 2 10.8.0.2 | grep -o "[0-9]* received"
  $G bpftool net show | grep tcx
  map=$(bpftool prog show name wnc_gw_ingress | grep -o "map_ids [0-9]*" | cut -d" " -f2)
  bpftool map dump id $map
  kill -INT $(pgrep -n -x wnc-gw); until [ -e $D/exit ]; do sleep 0.2; done
  ;;
tcx)
  setup
  F="$(dirname "$0")/foreign_tcx.py"
  $G python3 $F lan0 last before_run > /dev/null & F0=$!; sleep 1
  echo "--- doctor (root)"; $G $GW -c $D/setting.toml doctor | sed -n '/TCX INGRESS/,/^$/p;/D00/p'
  echo "--- doctor (wnc)"; $G sudo -u wnc $GW -c $D/setting.toml doctor | sed -n '/TCX INGRESS/,/^$/p;/D00/p'
  start || exit 1
  $G bpftool net show dev lan0 | grep tcx
  $G python3 $F lan0 first jumper > /dev/null & F1=$!; sleep 11
  kill $F1; sleep 10
  link=$($G bpftool net show dev lan0 | grep wnc_gw_ingress | grep -o "link_id [0-9]*" | cut -d" " -f2)
  bpftool link detach id $link; sleep 10
  kill -INT $(pgrep -n -x wnc-gw); until [ -e $D/exit ]; do sleep 0.2; done
  kill $F0
  echo "--- run log"; grep -E "D00|core ebpf" $D/run.log | cut -c28-
  ;;
kill9)
  setup; start || exit 1
  $G bpftool net show dev lan0 2>/dev/null | grep tcx
  kill -9 $(pgrep -n -x wnc-gw); sleep 1
  echo "tcx programs on lan0 after kill -9: $($G bpftool net show dev lan0 2>/dev/null | grep -c tcx)"
  $G nft delete table inet wnc_gw 2>/dev/null; true
  ;;
down)
  for ns in ecli esrv egw; do ip netns del $ns 2>/dev/null; done; true
  ;;
*) echo "usage: sudo bash core_pi.sh up|run|show|tcx|kill9|down"; exit 2 ;;
esac
