#!/bin/bash
# settings wnc-gw forces for when Suricata cannot inspect (Pi, bridge)
#   accept|drop: Suricata's flow memcap set to 512 KiB, fcli sends 1 UDP packet to each of 5000 ports on fsrv (each a new flow)
#     when_unavailable = accept → exception policy is ignore, expect all delivered; drop → flow uses drop-packet, expect drops once memory runs out
#   badrule: one good and one broken rule in the rule file, the yaml adds engine.init-failure-fatal: yes
#     running Suricata directly should fail to start; via wnc-gw (forces init-failure-fatal=no) it should become ready and log WARN "could not load some rules"
# Prerequisites: sudo sh env.sh up; sh make_configs.sh; system suricata service stopped; wnc-gw at $GW
# Usage: sudo bash exception_policy_pi.sh <accept|drop|badrule>
v=${1:?usage: exception_policy_pi.sh <accept|drop|badrule>}
GW=${GW:-/tmp/wncgw/wnc-gw}; M=${M:-/tmp/wncgw/m}; L=/tmp/wncgw/ep
W="ip netns exec wgw"
rm -rf $L; mkdir -p $L/rules $L/log; rm -f /var/log/wnc-gw/suricata/stats.log
start() {
  $W $GW -c $L/setting.toml run > /dev/null 2> $L/run.log &
  gp=$!
  until grep -q "traffic is inspected" $L/run.log; do sleep 0.2; kill -0 $gp 2>/dev/null || { tail -5 $L/run.log; exit 1; }; done
  grep -E "master exception-policy|rules failed|could not load|error parsing|is ready" $L/run.log | cut -c28-200 | sed 's/^/   /'
}
stop() { kill -INT $gp; wait $gp; echo "   suricata: $(grep -h -E "Verdict" $L/run.log | sed "s/.*Verdict: //; s/ source=.*//")"; }

if [ "$v" = badrule ]; then
  printf 'alert ip any any -> 192.0.2.1 any (msg:"never"; sid:9000001; rev:1;)\nalert tcp any any -> any any (msg:"broken"; content:"x"; nosuchkeyword; sid:9000002; rev:1;)\n' > $L/rules/test.rules
  sed -e "s|^  - $M/rules/never.rules\$|  - $L/rules/test.rules|" $M/suricata-empty.yaml > $L/s.yaml
  printf '\nengine:\n  init-failure-fatal: yes\n' >> $L/s.yaml
  sed -e "s|^config = .*|config = \"$L/s.yaml\"|" $M/setting-empty.toml > $L/setting.toml
  echo "== suricata directly (yaml says init-failure-fatal: yes)"
  timeout 120 $W suricata -c $L/s.yaml -q 7 -l $L/log --set unix-command.enabled=no > $L/direct.txt 2>&1
  echo "   exit=$?"; grep -E "^E:|^Error|Engine started|Loading signatures" $L/direct.txt | cut -c1-140 | sed 's/^/   /'
  echo "== through wnc-gw run"
  start; stop
  exit
fi

for ns in fcli fsrv; do ip netns add $ns; ip netns exec $ns sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1; ip -n $ns link set lo up; done
ip link add c-lan netns fcli type veth peer name x-lan netns wgw
ip link add s-wan netns fsrv type veth peer name x-wan netns wgw
for l in x-lan x-wan; do ip -n wgw link set $l master br0; ip -n wgw link set $l up; done
ip -n fcli addr add 10.9.0.1/24 dev c-lan; ip -n fcli link set c-lan up
ip -n fsrv addr add 10.9.0.2/24 dev s-wan; ip -n fsrv link set s-wan up
ip netns exec fsrv nft -f - <<'NFT'
table inet t { counter got {}; chain in { type filter hook input priority 0; policy accept; udp dport 10000-20000 counter name "got" drop; }; }
NFT
sed -e '/^flow:/,/^[a-z]/ { s/^  memcap: .*/  memcap: 512kb/; s/^  hash-size: .*/  hash-size: 256/; s/^  prealloc: .*/  prealloc: 10/ }' $M/suricata-empty.yaml > $L/s.yaml
sed -e "s|^config = .*|config = \"$L/s.yaml\"|" -e "s|^when_unavailable = .*|when_unavailable = \"$v\"|" $M/setting-empty.toml > $L/setting.toml
echo "== when_unavailable=$v ($(suricata --dump-config -c $L/s.yaml 2>/dev/null | grep -E '^flow\.(memcap|hash-size|prealloc) ' | tr '\n' ' '))"
start
ip netns exec fcli python3 -c '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(5000):
    s.sendto(b"x", ("10.9.0.2", 10000 + i)); time.sleep(0.0005)
'
sleep 3
echo "   sent 5000, delivered: $(ip netns exec fsrv nft list counter inet t got | grep -o 'packets [0-9]*')"
stop
grep -E "flow\.memcap|drop_reason|exception_policy" /var/log/wnc-gw/suricata/stats.log | sort -u -t'|' -k1,1 | sed 's/^/   /'
for ns in fcli fsrv; do ip netns del $ns; done
