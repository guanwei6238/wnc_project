#!/bin/bash
# 3c：synreuse_docker.sh 的 Pi 版（bridge）：被信任的舊連線無聲消失後，同一組五元組的新連線會不會沿用信任
#   fcli(10.9.0.1) --veth-- x-lan [wgw: br0] x-wan --veth-- fsrv(10.9.0.2)；wnc-gw run，Suricata 的 tcp established 逾時改成 5 秒
#   fcli 從 port 40100 連 fsrv:5001、送 15 行，第 1.5 秒 wnc-gw trust add；接著 wgw 裡另一張 table 在 prerouting（-350，conntrack 之前）
#   丟掉 FIN/RST，兩端用 SO_LINGER 0 中斷，再從同一個 port 重連、送 10 行
#   clear：等 15 秒（Suricata 的 flow 逾時）再重連，預期 SYN 清掉信任 bit，新連線全部進 Suricata
#   noclear：同上但把「純 SYN 清 bit」的規則刪掉，預期新連線沿用信任
#   early：不等就重連，預期 Suricata 把新的 SYN 當成 stream error 丟掉，連不上
# 前置：sudo sh env.sh up；sh make_configs.sh；系統的 suricata 服務已停；wnc-gw 放在 $GW
# 用法: sudo bash synreuse_pi.sh <clear|noclear|early>
v=${1:?usage: synreuse_pi.sh <clear|noclear|early>}
CT=${CT:-/home/wnc/ctbench/root/usr/sbin/conntrack}; GW=${GW:-/tmp/wncgw/wnc-gw}; M=${M:-/tmp/wncgw/m}; L=/tmp/wncgw/synreuse
W="ip netns exec wgw"
rm -rf $L; mkdir -p $L; rm -f /var/log/wnc-gw/suricata/stats.log
for ns in fcli fsrv; do ip netns add $ns; ip netns exec $ns sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1; ip -n $ns link set lo up; done
ip link add c-lan netns fcli type veth peer name x-lan netns wgw
ip link add s-wan netns fsrv type veth peer name x-wan netns wgw
for l in x-lan x-wan; do ip -n wgw link set $l master br0; ip -n wgw link set $l up; done
ip -n fcli addr add 10.9.0.1/24 dev c-lan; ip -n fcli link set c-lan up
ip -n fsrv addr add 10.9.0.2/24 dev s-wan; ip -n fsrv link set s-wan up
$W $CT -F 2>/dev/null
sed -e "s/^\(    established: \)[0-9]*/\15/" $M/suricata-empty.yaml > $L/s.yaml
sed -e "s|^config = .*|config = \"$L/s.yaml\"|" $M/setting-empty.toml > $L/setting.toml
$W nft add table inet tdrop
$W nft add chain inet tdrop pre '{ type filter hook prerouting priority -350; policy accept; }'
$W $GW -c $L/setting.toml run > /dev/null 2> $L/run.log &
gp=$!
until grep -q "traffic is inspected" $L/run.log; do sleep 0.2; kill -0 $gp 2>/dev/null || { cat $L/run.log; exit 1; }; done
if [ "$v" = noclear ]; then
  h=$($W nft -a list chain inet wnc_gw forward | grep "ct mark set ct mark & 0x7fffffff" | sed 's/.*# handle //')
  $W nft delete rule inet wnc_gw forward handle "$h"
fi
echo "== $v (suricata tcp established timeout: $(suricata --dump-config -c $L/s.yaml 2>/dev/null | grep '^flow-timeouts.tcp.established' | sed 's/.* = //') s)"
cat > $L/srv.py <<'PY'
import socket, struct, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 5001)); s.listen(4)
out = open(sys.argv[1], "w")
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
cat > $L/cli.py <<'PY'
import socket, struct, time, os, sys
phase, lines, d = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.settimeout(10)
s.bind(("", 40100)); s.connect(("10.9.0.2", 5001))
for i in range(lines):
    s.sendall(f"{phase} line {i}\n".encode()); time.sleep(0.2)
if phase == "old":
    while not os.path.exists(f"{d}/go"): time.sleep(0.1)
    s.sendall(b"BYE\n"); time.sleep(0.5)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
s.close()
open(f"{d}/cli-{phase}.done", "w").close()
PY
ip netns exec fsrv python3 $L/srv.py $L/srv.log &
sp=$!
sleep 0.5
cnt() { $W nft list table inet wnc_gw | awk '/syn ct mark/{match($0,/packets [0-9]+/); c=substr($0,RSTART+8,RLENGTH-8)} /== 0x80000000 counter.*accept/{match($0,/packets [0-9]+/); t=substr($0,RSTART+8,RLENGTH-8)} /chain ids/{i=1} i&&/counter packets/{match($0,/packets [0-9]+/); q=substr($0,RSTART+8,RLENGTH-8); i=0} END{printf "cleared=%s trusted=%s ids=%s", (c==""?"-":c), t, q}'; }
entry() { $W $CT -L -p tcp --orig-port-src 40100 -o id 2>/dev/null | sed -E 's/^tcp +6 +[0-9]+ //; s/ src=10.9.0.2.*mark=/ ... mark=/; s/ use=.*id=/ id=/'; }
ip netns exec fcli python3 $L/cli.py old 15 $L &
sleep 1.5
$W $GW trust add tcp 10.9.0.1 40100 10.9.0.2 5001 2>&1 | sed 's/^.*Z  INFO /   trust: /'
sleep 2
echo "-- old connection, trusted:      $(cnt)"
$W nft add rule inet tdrop pre tcp dport 5001 tcp flags \& \(fin \| rst\) != 0 drop
$W nft add rule inet tdrop pre tcp sport 5001 tcp flags \& \(fin \| rst\) != 0 drop
touch $L/go
until [ -f $L/cli-old.done ]; do sleep 0.1; done
$W nft flush chain inet tdrop pre
echo "-- both ends aborted silently:   $(cnt)"
echo "   entry: $(entry)"
[ "$v" != early ] && sleep 15
ip netns exec fcli python3 $L/cli.py new 10 $L 2>&1 | tail -1
sleep 0.5
echo "-- new connection, same port:    $(cnt)"
echo "   entry: $(entry)"
echo "   srv: $(grep -c "^1 old" $L/srv.log) old lines, $(grep -c "^2 new" $L/srv.log) new lines"
kill $sp
kill -INT $gp; wait $gp
echo "   suricata: $(grep -h -E "Verdict" $L/run.log | sed "s/.*Verdict: //; s/ source=.*//")"
grep -h "drop_reason" /var/log/wnc-gw/suricata/stats.log 2>/dev/null | tail -3 | sed 's/^/   /'
$W nft delete table inet tdrop
$W $CT -D -p tcp --orig-port-dst 5001 >/dev/null 2>&1
for ns in fcli fsrv; do ip netns del $ns; done
