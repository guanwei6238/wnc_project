#!/bin/bash
# demo.sh — 11/09 demo：wnc-gw 的 ids、讀 alert、自動信任（3d）
#   TARGET=phys（在筆電上跑）：實機。筆電 USB 網卡 ── Pi eth0 [wgw: br0，bridge] Pi eth1.20 ── 筆電 eno2.20（VLAN 20）；
#     client（10.9.0.1）、server（10.9.0.130）是筆電上的容器（macvlan 掛在兩張網卡上），Pi 那一半用 ssh 交給 Pi 上的這支腳本（TARGET=pigw）
#   TARGET=pi（預設，在 Pi 上用 sudo 跑）：fcli(10.9.0.1) --veth-- [wgw: br0，bridge] --veth-- fsrv(10.9.0.2)，全部在 Pi 裡
#   TARGET=docker（在筆電上跑）：Docker testbed 的 cli(10.0.1.2) -- [wnc-gw，routed] -- srv(10.0.2.2)
#   up             建立拓樸、寫設定（ids、[trust] auto：10 個封包、5 秒、ttl 60 秒、每 2 秒檢查）
#   doctor         wnc-gw doctor
#   run            前景跑 wnc-gw run（LEVEL=debug 會印每筆 alert 和信任到期；預設 debug），Ctrl-C 停止
#   run-bg | stop  背景跑／停止（log 在 run.log）
#   normal [秒]    一條沒有問題的長連線（client 每 0.1 秒送一行到 server:5001，預設 120 秒）
#   attack [秒]    client 連 server:8080，server 回「uid=0(root)」觸發 GPL ATTACK_RESPONSE（sid 2100498），之後持續送資料（預設 60 秒）
#   ping           client ping server 3 次（觸發 ICMP 規則）
#   status         ids chain 的計數、被信任的連線、Suricata 的 CPU、最近的 alert
#   kill-suricata  SIGKILL Suricata：wnc-gw 記沒檢查的時段並重啟它
#   wiring         只有 phys：找出筆電哪張有線網卡接到 Pi 的 eth1（管理線＋WAN，只有它回 IPv6）、哪張接到 eth0（LAN），印出要用的設定
#   replay [pcap] [pps]  只有 phys：從筆電的兩張網卡重播 dataset 的 pcap（預設 S_m3.small：IoT-23 3-1 Muhstik 的 SSH 掃描和 IRC，500 個封包，
#                  每秒 50 個）；要 RULES=full 才有 alert
#   down           拆掉拓樸（Pi／phys）／清掉設定（Docker）
# RULES=full（up）：除了 demo 的兩條規則，再載入 ET Open 的完整規則（FULL_RULES，Pi 上的快照）；Suricata 啟動要比較久
# Pi 的前置：wnc-gw 執行檔放在這個腳本旁邊；sudo；TARGET=pi 時 tests/ids_inline/env.sh 放在 ../ids_inline/ 或用 ENV_SH 指定
# phys 的前置：Pi 上有 ~/demo/wnc-gw；接到 Pi eth1 的筆電網卡有 10.254.254.1、ssh 免密碼登入 Pi（PI=wnc@10.254.254.2）；
#   另一張接 Pi eth0。LAN_NIC、WAN_NIC 沒給時用 wiring 的方法自動判斷（WAN_NIC＝接到 Pi eth1 的那張）
HERE=$(cd "$(dirname "$0")" && pwd)
TARGET=${TARGET:-pi}; LEVEL=${LEVEL:-debug}; RULES=${RULES:-demo}
FULL_RULES=${FULL_RULES:-/home/wnc/ids_throughput/data/rules/suricata_full.rules}
if [ "$TARGET" = docker ]; then
  W="docker exec wnc-gw"; WI="docker exec -i wnc-gw"; WT="docker exec -it wnc-gw"
  C="docker exec wnc-cli"; S="docker exec wnc-srv"
  GW=/opt/sg/wnc-gw; D=/tmp/demo; CLI=10.0.1.2; SRV=10.0.2.2
  MODE=routed; LAN=02:00:00:00:01:01; WAN=02:00:00:00:02:01
elif [ "$TARGET" = phys ]; then
  PI=${PI:-wnc@10.254.254.2}
  C="docker exec dcli"; S="docker exec dsrv"; CLI=10.9.0.1; SRV=10.9.0.130
else
  W="ip netns exec wgw"; WI="ip netns exec wgw"; WT="ip netns exec wgw"
  GW=${GW:-$HERE/wnc-gw}; D=$HERE/run
  MODE=bridge
  if [ "$TARGET" = pigw ]; then
    LAN=eth0; WAN=eth1.20
  else
    C="ip netns exec fcli"; S="ip netns exec fsrv"; CLI=10.9.0.1; SRV=10.9.0.2
    # port 是 fcli、fsrv 接上的 x-lan、x-wan：信任的封包在這兩個 port 的 TC 轉送（g-lan、g-wan 是 env.sh 給 tcpreplay 用的）
    LAN=x-lan; WAN=x-wan
    ENV_SH=${ENV_SH:-$HERE/../ids_inline/env.sh}
  fi
fi
SLOG=/var/log/wnc-gw/suricata

write() { $WI sh -c "mkdir -p $D && cat > $1"; }

config() {
  {
    if [ "$RULES" = full ] && grep -q 'sid:2100498;' "$FULL_RULES" 2> /dev/null; then
      :  # ET Open 已經有這條，重複的 sid 會載入失敗
    else
      echo 'alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7;)'
    fi
    echo 'alert icmp any any -> any any (msg:"demo ICMP echo request"; itype:8; sid:1000301; rev:1;)'
  } | write $D/demo.rules
  full=; [ "$RULES" = full ] && full="  - $FULL_RULES"
  write $D/s.yaml <<EOF
%YAML 1.1
---
include: /etc/suricata/suricata.yaml
default-rule-path: $D
rule-files:
  - demo.rules
$full
EOF
  write $D/setting.toml <<EOF
mode = "$MODE"
xdp = "off"
protection = "ids"

[ports]
lan = "$LAN"
wan = "$WAN"

[suricata]
config = "$D/s.yaml"

[trust]
auto = true
min_packets = 10
min_age = 5
ttl = 60
check_interval = 2
EOF
}

SRVPY="
import socket, threading, time  # demosrv
def listen(port, handle):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('', port)); s.listen(64)
    while True:
        threading.Thread(target=handle, args=(s.accept()[0],), daemon=True).start()
def drain(c):
    while c.recv(65536): pass
def shell(c):
    c.recv(65536)
    c.sendall(b'uid=0(root) gid=0(root) groups=0(root)\n')
    try:
        while True:
            c.sendall(b'.' * 100 + b'\n'); time.sleep(0.05)
    except OSError:
        pass
threading.Thread(target=listen, args=(8080, shell), daemon=True).start()
listen(5001, drain)
"

servers() {
  if [ "$TARGET" = phys ]; then
    docker exec -d dsrv python3 -c "$SRVPY"
  else
    $S pkill -f demosrv > /dev/null 2>&1
    $S python3 -c "$SRVPY" > /dev/null 2>&1 &
  fi
  sleep 0.5
}

# 筆電的實體有線網卡：有接線、能看到 Pi eth1 的 IPv6 link-local 的是 WAN（Pi eth0 的 IPv6 是關的）
wired() {
  own=$(ip -6 -br addr | awk '{for (i = 3; i <= NF; i++) print $i}' | cut -d/ -f1)  # 筆電自己的位址都不算（量測時 Pi 的 bridge 會把兩張網卡接在一起）
  for n in $(ls /sys/class/net); do
    case $n in lo | wl* | docker* | br-* | veth* | *.*) continue ;; esac
    [ -e /sys/class/net/$n/device ] || continue
    peer=$(ping -6 -c 2 -W 1 ff02::1%$n 2> /dev/null | grep -o 'from [^ ]*' | cut -d' ' -f2 | sed 's/%.*//; s/:$//' | grep -v -x -F "${own:-none}" | sort -u | head -1)
    echo "$n $(cat /sys/class/net/$n/carrier 2> /dev/null || echo 0) ${peer:-none} $(ip -4 -br addr show dev $n | awk '{print $3}')"
  done
}
nics() {
  [ -n "$LAN_NIC" ] && [ -n "$WAN_NIC" ] && return 0
  # 剛拆掉拓樸時 Pi 的網卡要幾秒才重新 link up，最多等 10 秒
  for i in 1 2 3 4 5; do
    w=$(wired)
    wan=${WAN_NIC:-$(echo "$w" | awk '$2 == 1 && $3 != "none" {print $1; exit}')}
    lan=${LAN_NIC:-$(echo "$w" | awk -v wan="$wan" '$2 == 1 && $1 != wan {print $1; exit}')}
    [ -n "$lan" ] && [ -n "$wan" ] && break
    sleep 2
  done
  WAN_NIC=$wan; LAN_NIC=$lan
  echo "LAN_NIC=$LAN_NIC (to Pi eth0) WAN_NIC=$WAN_NIC (to Pi eth1)"
  [ -n "$LAN_NIC" ] && [ -n "$WAN_NIC" ] || { echo "error: cannot tell which laptop NIC goes to which Pi port; run wiring"; return 1; }
}

if [ "$TARGET" = phys ]; then
  pi() { ssh $TTY $PI "sudo TARGET=pigw LEVEL=$LEVEL RULES=$RULES bash demo/demo.sh $*"; }
  case "$1" in
  wiring)
    echo "NIC              CABLE  SEES PI eth1 (IPv6)          IPv4"
    wired | while read -r n c p a; do printf '%-16s %-6s %-28s %s\n' $n $([ "$c" = 1 ] && echo yes || echo no) $p "${a:--}"; done
    LAN_NIC= WAN_NIC= nics > /dev/null 2>&1
    w=$(wired | awk '$2 == 1 && $3 != "none" {print $1; exit}')
    if [ -z "$w" ]; then
      echo "no laptop NIC sees Pi eth1: check that a cable goes into the Pi's USB network adapter (eth1) and the Pi is on"
      exit 1
    fi
    l=$(wired | awk -v wan="$w" '$2 == 1 && $1 != wan {print $1; exit}')
    echo
    echo "Pi eth1 (management + WAN) is on $w; Pi eth0 (LAN) is on ${l:-<no other NIC with a cable>}"
    ip -4 addr show dev $w | grep -q 'inet 10\.254\.254\.1/' || echo "give $w the management address first: sudo ip addr add 10.254.254.1/24 dev $w"
    echo "use: LAN_NIC=${l:-?} WAN_NIC=$w TARGET=phys bash $0 up   (up picks the same ones by itself)"
    exit
    ;;
  up)
    nics || exit 1
    scp -q "$0" $PI:demo/demo.sh || exit 1
    pi up || exit 1
    docker network create -d macvlan -o parent=$LAN_NIC --subnet 10.9.0.0/25 --gateway 10.9.0.126 demo-lan > /dev/null || exit 1
    docker network create -d macvlan -o parent=$WAN_NIC.20 --subnet 10.9.0.128/25 --gateway 10.9.0.254 demo-wan > /dev/null || exit 1
    docker run -d --name dcli --network demo-lan --ip $CLI --cap-add NET_ADMIN --entrypoint sleep wnc-lab:latest infinity > /dev/null
    docker run -d --name dsrv --network demo-wan --ip $SRV --cap-add NET_ADMIN --entrypoint sleep wnc-lab:latest infinity > /dev/null
    $C ip route add 10.9.0.128/25 dev eth0; $S ip route add 10.9.0.0/25 dev eth0
    servers
    # Pi 的 eth0 移進 netns 後要 2–3 秒才 link up
    ok="NOT reachable"; for i in 1 2 3 4 5; do $C ping -c 1 -W 2 $SRV > /dev/null && { ok=reachable; break; }; done
    echo "client $CLI ($LAN_NIC) -> Pi eth0 [br0] eth1.20 -> server $SRV ($WAN_NIC.20): $ok"
    exit
    ;;
  doctor|run|run-bg|stop|status|kill-suricata) TTY=-t; pi "$1"; exit ;;
  replay)
    LAN_NIC=${LAN_NIC:-$(docker network inspect demo-lan -f '{{index .Options "parent"}}' 2> /dev/null)}
    WAN_NIC=${WAN_NIC:-$(docker network inspect demo-wan -f '{{index .Options "parent"}}' 2> /dev/null)}; WAN_NIC=${WAN_NIC%.20}
    [ -n "$LAN_NIC" ] && [ -n "$WAN_NIC" ] || { echo "error: run up first"; exit 1; }
    pc=${2:-S_m3.small}; rate=${3:-50}
    case $pc in S_m3*) mac=a6:d1:8c:1f:ce:64 ;; S_h5*) mac=82:e6:50:12:14:64 ;; *) mac=${ROUTER_MAC:-78:8a:20:43:93:d5} ;; esac
    # IoT-23 從路由器那側來的封包 IP checksum 是 0，Pi 的 br_netfilter 會丟掉（IP_INHDR），先修正
    echo "replaying $pc at $rate pps: packets from the router ($mac) enter Pi eth1.20, the rest enter Pi eth0"
    docker run --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW -v ${PCAPS:-$HOME/datasets/throughput/pcaps}:/pcaps:ro \
      --entrypoint sh wnc-lab-gen:latest -c "tcprewrite --fixcsum --infile=/pcaps/$pc.pcap --outfile=/tmp/p.pcap && \
        tcpprep --mac=$mac --pcap=/tmp/p.pcap --cachefile=/tmp/c && \
        tcpreplay -i $WAN_NIC.20 -I $LAN_NIC -c /tmp/c --pps=$rate /tmp/p.pcap 2>&1 | grep -E 'Actual|Rated'"
    exit
    ;;
  down)
    docker rm -f dcli dsrv > /dev/null 2>&1; docker network rm demo-lan demo-wan > /dev/null 2>&1
    pi down
    exit
    ;;
  esac
fi

case "$1" in
up)
  if [ "$TARGET" = pi ]; then
    systemctl stop suricata 2> /dev/null
    sh "$ENV_SH" up
    for ns in fcli fsrv; do
      ip netns add $ns; ip netns exec $ns sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
      ip -n $ns link set lo up
    done
    ip link add c-lan netns fcli type veth peer name x-lan netns wgw
    ip link add s-wan netns fsrv type veth peer name x-wan netns wgw
    for l in x-lan x-wan; do ip -n wgw link set $l master br0; ip -n wgw link set $l up; done
    ip -n fcli addr add $CLI/24 dev c-lan; ip -n fcli link set c-lan up
    ip -n fsrv addr add $SRV/24 dev s-wan; ip -n fsrv link set s-wan up
  elif [ "$TARGET" = pigw ]; then
    systemctl stop suricata 2> /dev/null
    modprobe br_netfilter
    ip netns add wgw; $W sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
    ip -n wgw link set lo up
    ip link add link eth1 name eth1.20 type vlan id 20
    ip link set eth1.20 netns wgw; ip link set eth0 netns wgw
    ip -n wgw link add br0 type bridge
    for l in eth0 eth1.20; do ip -n wgw link set $l master br0; ip -n wgw link set $l up; done
    ip -n wgw link set br0 up
    mkdir -p $SLOG; mountpoint -q $SLOG || mount -t tmpfs -o size=1g,mode=0750 wncgw-suricata-log $SLOG
  fi
  if [ "$TARGET" != docker ]; then
    modprobe nf_conntrack
    $W sysctl -q -w net.netfilter.nf_conntrack_acct=1
  fi
  config
  [ "$TARGET" = pigw ] || servers
  echo "topology up: $LAN <-> $WAN ($MODE, rules=$RULES); config in $D"
  ;;
doctor) $W $GW -c $D/setting.toml doctor ;;
run) $WT $GW --log-level "$LEVEL" -c $D/setting.toml run ;;
run-bg)
  $W sh -c "rm -f $D/run.log $D/exit; ($GW --log-level $LEVEL -c $D/setting.toml run > /dev/null 2> $D/run.log; echo \$? > $D/exit) > /dev/null 2>&1 < /dev/null &"
  for i in $(seq 1 600); do $W grep -q "traffic is inspected" $D/run.log 2> /dev/null && break; sleep 0.2; done
  $W tail -3 $D/run.log
  ;;
stop) $W pkill -INT -x wnc-gw; sleep 3; $W tail -3 $D/run.log ;;
normal)
  echo "client $CLI -> server $SRV:5001, one line every 0.1 s for ${2:-120} s"
  $C python3 -c "
import socket, time
c = socket.create_connection(('$SRV', 5001))
print('connection: tcp %s:%d -> %s:%d' % (c.getsockname() + c.getpeername()), flush=True)
end = time.time() + ${2:-120}
while time.time() < end:
    c.sendall(b'normal traffic\n'); time.sleep(0.1)
c.close()"
  ;;
attack)
  echo "client $CLI -> server $SRV:8080: the server answers 'uid=0(root)' (GPL ATTACK_RESPONSE id check returned root)"
  $C python3 -c "
import socket, time
c = socket.create_connection(('$SRV', 8080))
print('connection: tcp %s:%d -> %s:%d' % (c.getsockname() + c.getpeername()), flush=True)
c.sendall(b'id\n')
print('server says:', c.recv(100).decode().strip(), flush=True)
end = time.time() + ${2:-60}
while time.time() < end:
    c.recv(65536)
c.close()"
  ;;
ping) $C ping -c 3 -i 0.5 $SRV ;;
status)
  echo "== ids chain (packets sent to suricata)"; $W nft list chain inet wnc_gw ids 2> /dev/null | grep -E "counter" | sed 's/^\s*/   /'
  echo "== trusted connections"; $W $GW trust list 2> /dev/null | sed 's/^/   /'
  echo "== suricata"; $W sh -c 'ps -o pid,pcpu,rss,etime,comm -C Suricata-Main' 2> /dev/null | sed 's/^/   /'
  echo "== last alerts"; $W sh -c "tail -n 3 $SLOG/fast.log 2> /dev/null" | cut -c1-160 | sed 's/^/   /'
  ;;
kill-suricata)
  pid=$($W pgrep -x Suricata-Main | head -1)
  [ -n "$pid" ] && $W kill -9 $pid && echo "killed suricata (pid $pid)"
  ;;
down)
  if [ "$TARGET" = pigw ]; then
    $W pkill -INT -x wnc-gw 2> /dev/null; sleep 2
    ip netns del wgw 2> /dev/null
    mountpoint -q $SLOG && umount $SLOG
    echo "topology down (eth0 is back in the main namespace)"
    exit 0
  fi
  $S pkill -f demosrv > /dev/null 2>&1
  if [ "$TARGET" = pi ]; then
    for ns in fcli fsrv; do ip netns del $ns 2> /dev/null; done
    sh "$ENV_SH" down
  else
    $W rm -rf $D
  fi
  ;;
*) sed -n '2,23p' "$0"; exit 2 ;;
esac
