#!/bin/bash
# 3c：TCP 舊連線沒有 FIN/RST 經過 gw 就消失（裝置重開機之類），同一組五元組的新連線會不會沿用舊 entry 的信任（Docker）
#   wnc-gw run（Suricata 的 tcp established flow 逾時改成 5 秒，模擬「信任很久、Suricata 的 flow 已經閒置逾時」）
#   cli 從固定的 port 40100 連 srv:5001、送 15 行，第 1.5 秒 wnc-gw trust add；接著另一張 table 在 prerouting（-350，conntrack 之前）
#   丟掉 FIN/RST，兩端都用 SO_LINGER 0 中斷；等 15 秒（Suricata 的 flow 逾時）後，cli 從同一個 port 重新連線、送 10 行
#   預期：conntrack 重新同步到舊 entry（id 不變）。noclear 時 mark 被沿用、新連線的資料不進 Suricata；clear 時 SYN 經過就清掉
#   Suricata 自己的 flow 還沒逾時的話，它會把新的 SYN 當成 stream error 丟掉（ips.drop_reason.stream_error），新連線連不上
# 用法: bash synreuse_docker.sh <clear|noclear>   noclear = run 起來後把「純 SYN 清 bit」那條規則刪掉
v=$1
G="docker exec wnc-gw"
$G sh -c 'pkill -INT -x wnc-gw; sleep 1; nft delete table inet tdrop 2>/dev/null; rm -rf /tmp/tr; mkdir -p /tmp/tr'
$G conntrack -D -p tcp --orig-port-dst 5001 >/dev/null 2>&1
$G sh -c 'sed -e "s/^\(    established: \)[0-9]*/\15/" /etc/suricata/suricata.yaml > /tmp/tr/s.yaml
cp /etc/wnc-gw/setting.toml /tmp/tr/setting.toml; printf "\n[suricata]\nconfig = \"/tmp/tr/s.yaml\"\n" >> /tmp/tr/setting.toml'
$G nft add table inet tdrop
$G nft add chain inet tdrop pre '{ type filter hook prerouting priority -350; policy accept; }'
$G sh -c '/opt/sg/wnc-gw -c /tmp/tr/setting.toml run > /dev/null 2> /tmp/tr/run.log &'
until $G grep -q "forwarded traffic is inspected" /tmp/tr/run.log 2>/dev/null; do sleep 0.2; done
if [ "$v" = noclear ]; then
  h=$($G nft -a list chain inet wnc_gw forward | grep "ct mark set ct mark & 0x7fffffff" | sed 's/.*# handle //')
  $G nft delete rule inet wnc_gw forward handle "$h"
fi
echo "== $v (suricata tcp established timeout: $($G suricata --dump-config -c /tmp/tr/s.yaml 2>/dev/null | grep '^flow-timeouts.tcp.established' | sed 's/.* = //') s)"
$G nft list chain inet wnc_gw forward | sed -n '4,7p' | sed 's/^\t*/   /'
docker exec -i wnc-srv sh -c 'cat > /tmp/srv.py' <<'PY'
import socket, struct
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 5001)); s.listen(4)
out = open("/tmp/srv.log", "w")
n = 0
while True:
    c, a = s.accept(); n += 1
    out.write(f"accept {n} {a}\n"); out.flush()
    f = c.makefile()
    for line in f:
        out.write(f"{n} {line}"); out.flush()
        if line.startswith("BYE"):
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            break
    f.close(); c.close()
PY
docker exec -i wnc-cli sh -c 'cat > /tmp/cli.py' <<'PY'
import socket, struct, time, os, sys
phase, lines = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.settimeout(10)
s.bind(("", 40100)); s.connect(("10.0.2.2", 5001))
for i in range(lines):
    s.sendall(f"{phase} line {i}\n".encode()); time.sleep(0.2)
if phase == "old":
    while not os.path.exists("/tmp/go"): time.sleep(0.1)
    s.sendall(b"BYE\n"); time.sleep(0.5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
s.close()
open(f"/tmp/cli-{phase}.done", "w").close()
PY
docker exec wnc-cli rm -f /tmp/go /tmp/cli-old.done /tmp/cli-new.done
docker exec wnc-srv sh -c 'pkill -f /tmp/srv.py; rm -f /tmp/srv.log'
docker exec -d wnc-srv python3 /tmp/srv.py
sleep 0.5
cnt() { $G nft list table inet wnc_gw | awk '/syn ct mark/{match($0,/packets [0-9]+/); c=substr($0,RSTART+8,RLENGTH-8)} /== 0x80000000 counter.*accept/{match($0,/packets [0-9]+/); t=substr($0,RSTART+8,RLENGTH-8)} /chain ids/{i=1} i&&/counter packets/{match($0,/packets [0-9]+/); q=substr($0,RSTART+8,RLENGTH-8); i=0} END{printf "cleared=%s trusted=%s ids=%s", (c==""?"-":c), t, q}'; }
entry() { $G conntrack -L -p tcp --orig-port-src 40100 -o id 2>/dev/null | sed -E 's/^tcp +6 +[0-9]+ //; s/ src=10.0.2.2.*mark=/ ... mark=/; s/ use=.*id=/ id=/'; }
sflows() { $G sh -c 'grep "40100" /var/log/wnc-gw/suricata/eve.json | grep "\"event_type\":\"flow\"" | grep -o "\"reason\":\"[a-z]*\"" | tr "\n" " "'; }
$G sh -c ': > /var/log/wnc-gw/suricata/eve.json'

docker exec -d wnc-cli python3 /tmp/cli.py old 15
sleep 1.5
$G /opt/sg/wnc-gw trust add tcp 10.0.1.2 40100 10.0.2.2 5001 2>&1 | sed 's/^.*Z  INFO /   trust: /'
sleep 2
echo "-- old connection, trusted:      $(cnt)"
$G nft add rule inet tdrop pre tcp dport 5001 tcp flags \& \(fin \| rst\) != 0 drop
$G nft add rule inet tdrop pre tcp sport 5001 tcp flags \& \(fin \| rst\) != 0 drop
docker exec wnc-cli touch /tmp/go
until docker exec wnc-cli test -f /tmp/cli-old.done; do sleep 0.1; done
$G nft flush chain inet tdrop pre
echo "-- both ends aborted silently:   $(cnt)"
echo "   entry: $(entry)"
sleep 15
echo "-- 15 s later, suricata flow records for port 40100: $(sflows)"
docker exec wnc-cli python3 /tmp/cli.py new 10 2>&1 | tail -1
sleep 0.5
echo "-- new connection, same port:    $(cnt)"
echo "   entry: $(entry)"
echo "   srv: $(docker exec wnc-srv sh -c 'grep -c "^1 old" /tmp/srv.log') old lines, $(docker exec wnc-srv sh -c 'grep -c "^2 new" /tmp/srv.log') new lines"
docker exec wnc-srv pkill -f /tmp/srv.py
$G pkill -INT -x wnc-gw; sleep 2; $G nft delete table inet tdrop
echo "   suricata: $($G sh -c 'grep -h -E "Verdict" /tmp/tr/run.log | sed "s/.*Verdict: //; s/ source=.*//"')"
$G conntrack -D -p tcp --orig-port-dst 5001 >/dev/null 2>&1
