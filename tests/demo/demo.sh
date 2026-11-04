#!/bin/bash
# demo.sh — 11/09 demo：wnc-gw 的 ids、讀 alert、自動信任（3d）
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
#   down           拆掉拓樸（Pi）／清掉設定（Docker）
# Pi 的前置：wnc-gw 執行檔放在這個腳本旁邊；sudo；tests/ids_inline/env.sh 放在 ../ids_inline/ 或用 ENV_SH 指定
HERE=$(cd "$(dirname "$0")" && pwd)
TARGET=${TARGET:-pi}; LEVEL=${LEVEL:-debug}
if [ "$TARGET" = docker ]; then
  W="docker exec wnc-gw"; WI="docker exec -i wnc-gw"; WT="docker exec -it wnc-gw"
  C="docker exec wnc-cli"; S="docker exec wnc-srv"
  GW=/opt/sg/wnc-gw; D=/tmp/demo; CLI=10.0.1.2; SRV=10.0.2.2
  MODE=routed; LAN=02:00:00:00:01:01; WAN=02:00:00:00:02:01
else
  W="ip netns exec wgw"; WI="ip netns exec wgw"; WT="ip netns exec wgw"
  C="ip netns exec fcli"; S="ip netns exec fsrv"
  GW=${GW:-$HERE/wnc-gw}; D=$HERE/run; CLI=10.9.0.1; SRV=10.9.0.2
  MODE=bridge; LAN=g-lan; WAN=g-wan
  ENV_SH=${ENV_SH:-$HERE/../ids_inline/env.sh}
fi
SLOG=/var/log/wnc-gw/suricata

write() { $WI sh -c "mkdir -p $D && cat > $1"; }

config() {
  write $D/demo.rules <<'EOF'
alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7;)
alert icmp any any -> any any (msg:"demo ICMP echo request"; itype:8; sid:1000301; rev:1;)
EOF
  write $D/s.yaml <<EOF
%YAML 1.1
---
include: /etc/suricata/suricata.yaml
default-rule-path: $D
rule-files:
  - demo.rules
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

servers() {
  $S pkill -f demosrv > /dev/null 2>&1
  $S python3 -c "
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
" > /dev/null 2>&1 &
  sleep 0.5
}

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
    modprobe nf_conntrack
    $W sysctl -q -w net.netfilter.nf_conntrack_acct=1
  fi
  config; servers
  echo "topology up: client $CLI -> server $SRV ($MODE); config in $D"
  ;;
doctor) $W $GW -c $D/setting.toml doctor ;;
run) $WT $GW --log-level "$LEVEL" -c $D/setting.toml run ;;
run-bg)
  $W sh -c "rm -f $D/run.log $D/exit; ($GW --log-level $LEVEL -c $D/setting.toml run > /dev/null 2> $D/run.log; echo \$? > $D/exit) > /dev/null 2>&1 < /dev/null &"
  for i in $(seq 1 150); do $W grep -q "traffic is inspected" $D/run.log 2> /dev/null && break; sleep 0.2; done
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
  $S pkill -f demosrv > /dev/null 2>&1
  if [ "$TARGET" = pi ]; then
    for ns in fcli fsrv; do ip netns del $ns 2> /dev/null; done
    sh "$ENV_SH" down
  else
    $W rm -rf $D
  fi
  ;;
*) sed -n '2,17p' "$0"; exit 2 ;;
esac
