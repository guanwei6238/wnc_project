#!/bin/bash
# wnc-gw 的 ids／ips 模式（Docker testbed，routed，wnc-gw run）
#   ids1     預設（ids、group 10）：ids chain 是 log group 10 accept、Suricata 帶 --nflog；ICMP 和 TCP payload（1300 bytes 之後的標記）都 alert
#   trust    ids：TCP 連線傳輸中 wnc-gw trust add，ids chain 的計數停住；trust del 後恢復
#   kill     ids：持續 ping 時 SIGKILL Suricata；WHEN=accept 不掉，WHEN=drop 重啟期間掉；log 記沒檢查的時段
#   groups   group = "10-11"：ids chain 是 symhash vmap、ids_g10／ids_g11 各一條 log；8 條連線 8 個 alert
#   ips      protection = "ips"：ids chain 是 queue、Suricata 帶 -q（和原本一樣）
#   startup  ids：ping -f 持續送時啟動、停止 wnc-gw 10 次，Suricata 不能當（log 規則要等 READY=1 才裝）
#   missed   ids：UDP 送的同時 SIGSTOP Suricata 3 秒，轉送照常、複本被丟；wnc-gw 的 WARN 數字要等於 kernel 的 Drops
#   runmode  ids、ips 各一個和多個 queue／group：Suricata 只有 W 執行緒（workers）、ICMP 有 alert；AUTOFP=1 時 yaml 明寫 runmode: autofp
#   alerts   wnc-gw 讀 Suricata 的 eve.json：每筆 alert 有 debug log、停止時有摘要；
#            eve.json 被換掉（mv 之後對 Suricata 送 SIGHUP 重開）、被截斷後都接著讀
#   autotrust 自動信任（[trust] auto，5 個封包、2 秒、ttl 10 秒）：乾淨的長連線被信任、ids chain 計數停住、到期後再信任；
#            帶 payload 標記（有 alert）的連線不被信任；已信任的連線結束時 FIN 觸發 alert，信任被撤銷。PROTECTION=ips 換模式
# 用法: bash protection_docker.sh <ids1|trust|kill|groups|ips|startup|missed|runmode|alerts|autotrust>；最後 bash protection_docker.sh clean
G="docker exec wnc-gw"; GI="docker exec -i wnc-gw"; C="docker exec wnc-cli"; S="docker exec wnc-srv"
D=/tmp/wt; SLOG=/var/log/wnc-gw/suricata
P=$((20000 + RANDOM % 20000))   # 來源 port 每次不同，避免撞到上一次的 TIME_WAIT

setup() {  # $1 = 最上層多的設定行，$2 = [suricata] 多的設定行，$3 = 多的規則
  $G mkdir -p $D
  $GI sh -c "cat > $D/test.rules" <<EOF
alert icmp any any -> any any (msg:"wt icmp"; sid:1000201; rev:1;)
alert tcp any any -> any 5001 (msg:"wt payload"; flow:to_server,established; content:"WT-PAYLOAD-MARKER"; sid:1000202; rev:1;)
$3
EOF
  $GI sh -c "cat > $D/s.yaml" <<EOF
%YAML 1.1
---
include: /etc/suricata/suricata.yaml
default-rule-path: $D
rule-files:
  - test.rules
EOF
  $GI sh -c "cat > $D/setting.toml" <<EOF
mode = "routed"
$1

[ports]
lan = "02:00:00:00:01:01"
wan = "02:00:00:00:02:01"

[suricata]
config = "$D/s.yaml"
$2
EOF
}

start() {
  $G sh -c "rm -f $SLOG/fast.log $SLOG/eve.json $D/run.log $D/exit"
  docker exec -d wnc-gw sh -c "/opt/sg/wnc-gw ${RUNARGS:-} -c $D/setting.toml run > /dev/null 2> $D/run.log & echo \$! > $D/pid; wait \$!; echo \$? > $D/exit"
  local i
  for i in $(seq 1 100); do
    $G grep -q "traffic is inspected" $D/run.log 2>/dev/null && return 0
    $G test -e $D/exit && break; sleep 0.2
  done
  echo "wnc-gw did not start"; $G tail -5 $D/run.log; return 1
}

stop() { $G sh -c "kill -INT \$(cat $D/pid)"; until $G test -e $D/exit; do sleep 0.2; done; echo "wnc-gw exit=$($G cat $D/exit)"; }

ids_rules() { $G nft list table inet wnc_gw | sed -n '/chain ids/,$p' | grep -E "chain|log|queue|vmap|accept|drop" | sed 's/^\s*/   /'; }
ids_count() { $G nft list chain inet wnc_gw ids | grep -o "packets [0-9]*" | head -1 | cut -d" " -f2; }
alerts() { $G sh -c "cat $SLOG/fast.log 2>/dev/null | grep -c \":$1:\""; }
suricata_pid() { $G grep -o "suricata started pid=[0-9]*" $D/run.log | tail -1 | cut -d= -f2; }

server() { $S pkill -f wtsrv; docker exec -d wnc-srv python3 -c "
import socket, threading  # wtsrv
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('', 5001)); s.listen(64)
def drain(c):
    while c.recv(65536): pass
while True:
    threading.Thread(target=drain, args=(s.accept()[0],), daemon=True).start()
"; sleep 0.5; }

client() {  # $1 = 來源 port，$2 = 秒數；第一段是 1300 bytes 再接標記，之後每 0.1 秒一行
  $C python3 -c "
import socket, time
c = socket.create_connection(('10.0.2.2', 5001), source_address=('10.0.1.2', $1))
c.sendall(b'x' * 1300 + b'WT-PAYLOAD-MARKER\n')
end = time.time() + $2
while time.time() < end:
    c.sendall(b'line\n'); time.sleep(0.1)
c.close()"
}

clean_client() {  # $1 = 來源 port，$2 = 秒數：每 0.1 秒一行，沒有 payload 標記
  $C python3 -c "
import socket, time
c = socket.create_connection(('10.0.2.2', 5001), source_address=('10.0.1.2', $1))
end = time.time() + $2
while time.time() < end:
    c.sendall(b'line\\n'); time.sleep(0.1)
c.close()"
}

case "$1" in
ids1)
  setup "" ""; start || exit 1
  echo "== ids chain after ready"; ids_rules
  echo "== suricata: $($G sh -c "tr '\0' ' ' < /proc/$(suricata_pid)/cmdline" | grep -o -- "--nflog --include [^ ]*")"
  $G cat /run/wnc-gw/suricata-nflog.yaml | sed 's/^/   /'
  server; $C ping -c 3 -i 0.2 -W 1 10.0.2.2 | grep -o "[0-9]* received"; client $P 1; sleep 1
  stop
  echo "icmp alerts: $(alerts 1000201)  payload alerts: $(alerts 1000202)"
  $G grep -E "inspected|without inspection|suricata started" $D/run.log | cut -c29-160
  ;;
trust)
  setup "" ""; start || exit 1; server
  client $P 6 &
  sleep 2; $G /opt/sg/wnc-gw trust add tcp 10.0.1.2 $P 10.0.2.2 5001 2>&1 | grep -o "connection trusted"
  a=$(ids_count); sleep 2; b=$(ids_count)
  $G /opt/sg/wnc-gw trust del tcp 10.0.1.2 $P 10.0.2.2 5001 2>&1 | grep -o "no longer trusted"
  sleep 1.5; c=$(ids_count); wait
  echo "ids chain packets: after trust $a, 2 s later $b, 1.5 s after del $c"
  stop
  ;;
kill)
  setup "" "when_unavailable = \"${WHEN:-accept}\""; start || exit 1
  $C ping -c 120 -i 0.05 -W 1 10.0.2.2 > /tmp/wt-ping.txt &
  sleep 1.5; $G sh -c "kill -KILL $(suricata_pid)"; echo "suricata killed (when_unavailable=${WHEN:-accept})"; wait
  grep -o "[0-9]* packets transmitted, [0-9]* received" /tmp/wt-ping.txt; rm -f /tmp/wt-ping.txt
  $G grep -E "without inspection|is inspected|suricata (stopped|started)" $D/run.log | cut -c29-170
  stop
  ;;
groups)
  setup "" 'group = "10-11"'; start || exit 1
  echo "== ids chains after ready"; ids_rules
  server; for p in $(seq $P $((P + 7))); do client $p 1 & done; wait; sleep 1
  echo "per group: $($G nft list table inet wnc_gw | awk '/chain ids_g/{c=$2} /log group/{for (i = 1; i <= NF; i++) if ($i == "packets") printf "%s=%s ", c, $(i + 1)}')"
  stop
  echo "payload alerts: $(alerts 1000202)/8"
  ;;
ips)
  setup 'protection = "ips"' ""; start || exit 1
  echo "== ids chain after ready"; ids_rules
  echo "== suricata: $($G sh -c "tr '\0' ' ' < /proc/$(suricata_pid)/cmdline" | grep -o -- "-q [0-9:]*")"
  $C ping -c 3 -i 0.2 -W 1 10.0.2.2 | grep -o "[0-9]* received"
  stop
  echo "icmp alerts: $(alerts 1000201)"
  ;;
startup)
  setup "" ""
  $C sh -c "timeout 300 ping -f -q 10.0.2.2 > /dev/null 2>&1 &"
  for run in $(seq 1 10); do
    start > /dev/null || { echo "run $run did not start"; break; }
    sleep 1; stop > /dev/null
    $G grep -o 'suricata stopped pid=[0-9]* exit="[^"]*"' $D/run.log | sed "s/^/run $run: /"
  done
  $C pkill -x ping
  ;;
missed)
  setup "" ""; start || exit 1
  sp=$(suricata_pid)
  inodes=$($G sh -c "ls -l /proc/$sp/fd | grep -o 'socket:\[[0-9]*\]' | tr -dc '0-9\n' | tr '\n' ' '")
  $S sh -c "pkill -x iperf3; iperf3 -s -D"; sleep 0.5
  $C iperf3 -u -b 200M -l 1400 -t 6 -c 10.0.2.2 > /tmp/wt-iperf.txt 2>&1 &
  sleep 1; $G kill -STOP $sp; echo "suricata $sp stopped for 3 s"; sleep 3; $G kill -CONT $sp; wait
  grep -E "receiver" /tmp/wt-iperf.txt | sed 's/^/   iperf3 /'; rm -f /tmp/wt-iperf.txt
  for i in $(seq 1 30); do $G grep -q "missed packet copies" $D/run.log && break; sleep 0.5; done
  echo "kernel drops on suricata's netfilter sockets: $($G awk -v ids=" $inodes" '$2 == 12 && index(ids, " " $10 " ") {d += $9} END{print d + 0}' /proc/net/netlink)"
  $G grep -E "missed packet copies|nflog sockets" $D/run.log | cut -c29-200
  stop; $S pkill -x iperf3
  ;;
runmode)
  for c in 'ids|' 'ids|group = "10-11"' 'ips|' 'ips|queue = "0-3"'; do
    p=${c%%|*}; extra=${c#*|}
    setup "protection = \"$p\"" "$extra"
    [ "$AUTOFP" = 1 ] && $G sh -c "echo 'runmode: autofp' >> $D/s.yaml"
    start || exit 1
    threads=$($G sh -c "cat /proc/$(suricata_pid)/task/*/comm" | grep -E "^(W|RX|TX)" | sort | tr '\n' ' ')
    $C ping -c 3 -i 0.2 -W 1 10.0.2.2 > /dev/null
    stop > /dev/null
    echo "$p ${extra:-default}: $threads| icmp alerts: $(alerts 1000201)"
  done
  echo "yaml runmode: $($G sh -c "suricata --dump-config -c $D/s.yaml 2>/dev/null | grep '^runmode'")"
  ;;
alerts)
  setup "" ""; RUNARGS="--log-level debug" start || exit 1; server
  $G grep -E "reading suricata's alerts" $D/run.log | cut -c29-220
  $C ping -c 3 -i 0.2 -W 1 10.0.2.2 | grep -o "[0-9]* received"; client $P 1; sleep 1
  echo "== rotate: mv eve.json eve.json.1, SIGHUP suricata"
  $G sh -c "mv $SLOG/eve.json $SLOG/eve.json.1; kill -HUP $(suricata_pid)"; sleep 1
  client $((P + 1)) 1; sleep 1
  echo "== truncate eve.json"
  $G sh -c ": > $SLOG/eve.json"; sleep 1
  client $((P + 2)) 1; sleep 1
  stop
  echo "alerts in fast.log: icmp $(alerts 1000201), payload $(alerts 1000202)"
  echo "alert lines in wnc-gw's log: icmp $($G grep -c 'DEBUG suricata alert.*sid=1000201' $D/run.log), payload $($G grep -c 'DEBUG suricata alert.*sid=1000202' $D/run.log)"
  $G grep -m1 'DEBUG suricata alert.*sid=1000202' $D/run.log | cut -c29-260
  $G grep -E "raised alerts|replaced|truncated|appeared|cannot read|EVE" $D/run.log | grep -v 'DEBUG suricata alert' | cut -c29-300
  ;;
autotrust)
  setup "${PROTECTION:+protection = \"$PROTECTION\"}" "" \
    'alert tcp any any -> any 5001 (msg:"wt fin"; flow:to_server; flags:F+; sid:1000203; rev:1;)'
  $GI sh -c "cat >> $D/setting.toml" <<'EOF'

[trust]
auto = true
min_packets = 5
min_age = 2
ttl = 10
check_interval = 1
EOF
  RUNARGS="--log-level debug" start || exit 1; server
  clean_client $P 25 &
  sleep 1; c1=$(ids_count); sleep 4; c2=$(ids_count); sleep 3; c3=$(ids_count)
  echo "ids chain packets at 1 s, 5 s, 8 s: $c1 $c2 $c3 (trusted from about 3 s: grows by only a few after that)"
  client $((P + 1)) 6
  wait; sleep 2
  stop
  echo "== clean connection: port $P, connection with the payload marker: port $((P + 1))"
  $G grep -E "automatic trust|connection trusted|trust expired|trust revoked|will not be trusted|watching the connection again" $D/run.log | cut -c29-300
  ;;
clean)
  $G rm -rf $D /run/wnc-gw/suricata-nflog.yaml; $S pkill -f wtsrv; true
  ;;
*) sed -n '2,14p' "$0"; exit 2 ;;
esac
