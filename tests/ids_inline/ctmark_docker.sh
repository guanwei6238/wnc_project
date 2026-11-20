#!/bin/bash
# 3a functional check (Docker): Suricata runs NFQ directly + a test table; set and clear the ct mark midway through a continuous TCP connection
# Usage: bash ctmark_docker.sh <nol2|l2>
v=$1
docker exec -i wnc-gw sh -c "mkdir -p /tmp/t3a/rules; cat > /tmp/t3a/rules/mid.rules" <<'R'
alert tcp any any -> any 5001 (msg:"wnc midstream mark"; content:"WNC-MARK"; sid:1000002; rev:1;)
R
docker exec wnc-gw sh -c 'sed -e "s|^default-rule-path: .*|default-rule-path: /tmp/t3a/rules|" -e "s|^  - suricata.rules\$|  - mid.rules|" /etc/suricata/suricata.yaml > /tmp/t3a/s.yaml; rm -f /tmp/t3a/fast.log; suricata -c /tmp/t3a/s.yaml -q 0 -l /tmp/t3a --set unix-command.enabled=no --set coredump.max-dump=0 --set stream.midstream=true --set stream.midstream-policy=ignore > /tmp/t3a/out.txt 2>&1 & echo $! > /tmp/t3a/pid'
until docker exec wnc-gw grep -q "Engine started" /tmp/t3a/out.txt 2>/dev/null; do sleep 0.2; done
l2=""; [ "$v" = l2 ] && l2='meta l4proto tcp tcp flags & (fin | syn | rst) != 0 counter name "l2" queue num 0'
docker exec -i wnc-gw nft -f - <<NFT
table inet t3a {
  counter trusted {}
  counter queued {}
  counter l2 {}
  chain forward {
    type filter hook forward priority 0; policy accept;
    $l2
    ct mark & 0x1 == 0x1 counter name "trusted" accept
    counter name "queued" queue num 0
  }
}
NFT
docker exec -d wnc-srv python3 -c '
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("", 5001)); s.listen(1)
c, _ = s.accept(); f = c.makefile(); out = open("/tmp/srv.log", "w")
for line in f:
    out.write(line); out.flush()
'
sleep 0.5
docker exec -d wnc-cli bash -c 'exec 3<>/dev/tcp/10.0.2.2/5001; for i in $(seq 100); do echo "line $i WNC-MARK" >&3 || exit 1; sleep 0.2; done; exec 3>&-'
mark() { docker exec wnc-gw conntrack -U -p tcp --orig-src 10.0.1.2 --orig-dst 10.0.2.2 --orig-port-dst 5001 --mark $1 2>&1 | tail -1; }
cnt() { docker exec wnc-gw nft list counters table inet t3a | awk '/counter /{n=$2} /packets/{printf "%s=%s ", n, $2}'; }
echo "== $v"
for t in $(seq 1 24); do
  sleep 1
  case $t in 4) echo "   -- t=4 set mark 1: $(mark 1 | grep -o "mark=[0-9]*")";; 10) [ "$v" = nol2 ] && echo "   -- t=10 set mark 0: $(mark 0)";; esac
  printf "t=%-3s %s alerts=%s srv_lines=%s\n" $t "$(cnt)" "$(docker exec wnc-gw sh -c 'grep -c 1000002 /tmp/t3a/fast.log 2>/dev/null || echo 0')" "$(docker exec wnc-srv sh -c 'wc -l < /tmp/srv.log 2>/dev/null || echo 0')"
done
docker exec wnc-gw sh -c 'kill -INT $(cat /tmp/t3a/pid); sleep 3; grep -E "Treated|Verdict" /tmp/t3a/out.txt | sed "s/^.*nfq: //"; tac /tmp/t3a/stats.log | awk "/^Date:/{exit} {print}" | grep -E "midstream|drop_reason|stream\.reassembly_gap|tcp\.pkt_on_wrong|stream.*gap" | awk "{print \$1, \$NF}" | grep -v " 0\$"; nft delete table inet t3a'
docker exec wnc-srv sh -c 'pkill -f "[s].listen"; rm -f /tmp/srv.log'
