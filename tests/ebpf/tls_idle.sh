#!/bin/bash
# tls_idle.sh — does a trusted long-lived TLS connection (HTTPS keep-alive) break when it goes back to Suricata inspection (auto trust, default 10 packets, 5 s, ttl 900)
#   idle <tc|ctmark> <ids|ips>: busy 20 s (a line every 0.2 s, echoed) → idle 640 s → busy 330 s (a line per second)
#        tc: idle-evicted after 600 s, so it goes back to inspection when traffic resumes; ctmark: no idle eviction, inspected again only at ttl (900 s after trust).
#        Both cases are a midstream pickup after Suricata has already forgotten the flow (flow-timeouts.tcp.established 600 s)
#   gap  <tc|ctmark> <ids|ips>: busy 20 s → wnc-gw trust del → busy another 30 s. Suricata still remembers the flow but misses the data from the trust period
#   Every 10 s log the trusted entry count and the ids chain counter; at the end read Suricata's stats.log (ips.*, app_layer.error.tls.*, tcp.midstream_pickups, etc.)
#   and the tls, anomaly, flow events of this connection in eve.json; stats has stream-events enabled, stream.* are per-stream-event counts
# TARGET=docker (default, routed testbed: cli 10.0.1.2 — gw — srv 10.0.2.2) or TARGET=pi (run as root on the Pi,
#   env.sh's wgw plus fcli 10.9.0.1, fsrv 10.9.0.2 from protection_pi.sh net up, bridge; wnc-gw's ports are x-lan, x-wan,
#   since those two veths are on the connection's path)
#   WHEN=accept|drop (default accept): [suricata] when_unavailable. With ips, drop makes wnc-gw set Suricata's app-layer.error-policy
#   to drop-flow (drop the whole flow on a TLS parser error), accept sets ignore; with ids it is always ignore
#   CAPTURE=1: capture this connection's packets on both the client and server NICs (tcpdump -S), then list packets sent by one side but not received by the other (dropped by the gateway)
# Usage: bash tls_idle.sh <idle|gap> <tc|ctmark> <ids|ips>   result written as one line to $OUT (default ./tls_idle.kvl), progress printed to stdout
HERE=$(cd "$(dirname "$0")" && pwd)
TARGET=${TARGET:-docker}; OUT=${OUT:-$PWD/tls_idle.kvl}
D=/tmp/tlsidle; SLOG=/var/log/wnc-gw/suricata; PORT=4443; SPORT=$((20000 + RANDOM % 20000))
case_=$1; backend=$2; prot=$3; WHEN=${WHEN:-accept}
case "$case_:$backend:$prot" in idle:tc:i[dp]s|idle:ctmark:i[dp]s|gap:tc:i[dp]s|gap:ctmark:i[dp]s) ;; *) sed -n '2,13p' "$0"; exit 2 ;; esac

if [ $TARGET = docker ]; then
  G="docker exec wnc-gw"; C="docker exec wnc-cli"; S="docker exec wnc-srv"; B=/opt/sg/wnc-gw; CIF=eth0; SIF=eth0
  SIP=10.0.2.2; CIP=10.0.1.2; MODE=routed; LAN=02:00:00:00:01:01; WAN=02:00:00:00:02:01
  put() { docker exec -i $1 sh -c "mkdir -p $(dirname $3); cat > $3" < $2; }   # put <container> <file> <path>
  gw_bg() { docker exec -d wnc-gw sh -c "$1"; }
  srv_bg() { docker exec -d wnc-srv sh -c "$1"; }
  WGW=wnc-gw; WCLI=wnc-cli; WSRV=wnc-srv
else
  G="ip netns exec wgw"; C="ip netns exec fcli"; S="ip netns exec fsrv"; B=${GW:-/tmp/wncgw/wnc-gw}; CIF=c-lan; SIF=s-wan
  SIP=10.9.0.2; CIP=10.9.0.1; MODE=bridge; LAN=x-lan; WAN=x-wan
  put() { mkdir -p $(dirname $3); cp $2 $3; }
  gw_bg() { $G sh -c "$1" > /dev/null 2>&1 & }
  srv_bg() { $S sh -c "$1" > /dev/null 2>&1 & }
  WGW=; WCLI=; WSRV=
fi
TUPLE="tcp $CIP $SPORT $SIP $PORT"

prepare() {
  local t; t=$(mktemp -d)
  printf 'alert icmp any any -> any any (msg:"tls idle icmp"; sid:1000301; rev:1;)\n' > $t/test.rules
  printf '%%YAML 1.1\n---\ninclude: /etc/suricata/suricata.yaml\ndefault-rule-path: %s\nrule-files:\n  - test.rules\nstats:\n  enabled: yes\n  interval: 8\n  stream-events: true\n' $D > $t/s.yaml
  printf 'mode = "%s"\nprotection = "%s"\n\n[ports]\nlan = "%s"\nwan = "%s"\n\n[suricata]\nconfig = "%s/s.yaml"\nwhen_unavailable = "%s"\n\n[trust]\nbackend = "%s"\nauto = true\n' \
    $MODE $prot $LAN $WAN $D $WHEN $backend > $t/setting.toml
  for f in test.rules s.yaml setting.toml; do put "$WGW" $t/$f $D/$f; done
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=tls-idle -keyout $t/key.pem -out $t/cert.pem 2> /dev/null
  put "$WSRV" $t/key.pem $D/key.pem; put "$WSRV" $t/cert.pem $D/cert.pem
  put "$WCLI" $HERE/tls_idle.py $D/tls_idle.py
  put "$WSRV" $HERE/tls_idle.py $D/tls_idle.py
  rm -rf $t
  $S pkill -f "tls_idle.py server"; srv_bg "python3 $D/tls_idle.py server $PORT $D/cert.pem $D/key.pem > /dev/null 2>&1"; sleep 1
  $C rm -f $D/mark $D/client.out
}

start() {
  $G sh -c "rm -f $SLOG/eve.json $SLOG/stats.log $D/run.log $D/exit $D/timeline"
  gw_bg "$B --log-level debug -c $D/setting.toml run > /dev/null 2> $D/run.log & echo \$! > $D/pid; wait \$!; echo \$? > $D/exit"
  for i in $(seq 1 300); do
    $G grep -q "traffic is inspected" $D/run.log 2> /dev/null && return 0
    $G test -e $D/exit && break; sleep 1
  done
  echo "wnc-gw did not start"; $G tail -5 $D/run.log; return 1
}
stop() { $G sh -c "kill -INT \$(cat $D/pid)"; until $G test -e $D/exit; do sleep 0.5; done; }
ids_count() { $G nft list chain inet wnc_gw ids | grep -o "packets [0-9]*" | head -1 | cut -d" " -f2; }
trusted() { $G $B trust list 2> /dev/null | grep -c " $CIP:$SPORT "; }
counters() {
  $G awk '/^Date/{b = ""} {b = b "\n" $0} END{print b}' $SLOG/stats.log \
    | awk -F'|' '/^(ips\.|exception_policy\.|app_layer\.error\.tls|app_layer\.flow\.tls|tcp\.(midstream_pickups|reassembly_gap|pkt_on_wrong_thread|ack_unseen_data|sessions)|flow\.end\.state|stream\.)/ && $3 + 0 > 0 {gsub(/ /, "", $1); printf "%s=%d ", $1, $3}'
}
eve_events() {
  $G sh -c "grep -h '\"src_port\":$SPORT,' $SLOG/eve.json 2> /dev/null; grep -h '\"dest_port\":$SPORT,' $SLOG/eve.json 2> /dev/null" \
    | python3 -c '
import json, sys
for line in sys.stdin:
    e = json.loads(line)
    kind = e.get("event_type")
    if kind == "tls":
        print("   eve tls", e["timestamp"][11:19], e["tls"].get("version"), e["tls"].get("sni", ""))
    elif kind == "anomaly":
        print("   eve anomaly", e["timestamp"][11:19], json.dumps(e["anomaly"]))
    elif kind == "flow":
        f = e["flow"]
        print("   eve flow", f.get("start", "")[11:19], "to", f.get("end", "")[11:19], "app_proto", e.get("app_proto"),
              "state", f.get("state"), "reason", f.get("reason"), "action", f.get("action"), "pkts", f.get("pkts_toserver"), f.get("pkts_toclient"))
    elif kind in ("drop", "alert"):
        print("   eve", kind, e["timestamp"][11:19], json.dumps(e.get(kind, {}))[:160])'
}
timeline() {  # background: one line every 10 s "seconds trusted-count ids-chain-counter" until the client exits
  local t0=$(date +%s)
  while ! $C test -e $D/client.done; do
    echo "$(( $(date +%s) - t0 )) $(trusted) $(ids_count)" >> $D/timeline.local; sleep 10
  done
}

prepare; start || exit 1
echo "$(date -u +%T) $case_ backend=$backend protection=$prot when=$WHEN target=$TARGET connection=\"$TUPLE\""
rm -f $D/timeline.local; mkdir -p $D; $C rm -f $D/client.done
case $case_ in
idle) phases="20:0.2 640:0 330:1" ;;
gap) phases="20:0.2 mark:$D/mark 30:0.2" ;;
esac
if [ "${CAPTURE:-0}" = 1 ]; then
  # neither side coalesces or splits segments, so packets captured on both sides can be matched one to one
  $C ethtool -K $CIF tso off gso off gro off 2> /dev/null; $S ethtool -K $SIF tso off gso off gro off 2> /dev/null
  $C sh -c "rm -f $D/cap-c.pcap; tcpdump -S -U -i $CIF -w $D/cap-c.pcap tcp port $PORT and port $SPORT > /dev/null 2>&1 &"
  $S sh -c "rm -f $D/cap-s.pcap; tcpdump -S -U -i $SIF -w $D/cap-s.pcap tcp port $PORT and port $SPORT > /dev/null 2>&1 &"
  sleep 2
fi
( $C sh -c "python3 $D/tls_idle.py client $SIP $PORT $CIP $SPORT $phases > $D/client.out 2>&1; touch $D/client.done" ) &
client=$!
timeline &
if [ $case_ = gap ]; then
  until $C test -e $D/mark || $C test -e $D/client.done; do sleep 0.2; done
  echo "   trusted before del: $(trusted)"; $G $B trust del $TUPLE && echo "   trust del: ok"
fi
wait $client; sleep 10
result=$($C tail -1 $D/client.out)
got=$(counters)
$C cat $D/client.out | sed 's/^/   client: /'
echo "   timeline (s trusted ids_chain):"; awk '{printf "     %s", $0; n++; if (n % 4 == 0) print ""} END{if (n % 4) print ""}' $D/timeline.local
echo "   suricata: $got"
eve_events
stop
if [ "${CAPTURE:-0}" = 1 ]; then
  $C pkill -x tcpdump; $S pkill -x tcpdump; sleep 1
  { $C tcpdump -S -nn -tt -r $D/cap-c.pcap 2> /dev/null | sed 's/^/c /'; $S tcpdump -S -nn -tt -r $D/cap-s.pcap 2> /dev/null | sed 's/^/s /'; } \
    | python3 -c '
import collections, re, sys
side = {"c": collections.Counter(), "s": collections.Counter()}
first = {}
lines = {}
for line in sys.stdin:
    who, ts, rest = line.split(" ", 2)
    m = re.match(r"IP (\S+) > (\S+): Flags \[([^]]*)\](?:, seq ([\d:]+))?(?:, ack (\d+))?.*length (\d+)", rest)
    if not m:
        continue
    key = m.groups()
    side[who][key] += 1
    first.setdefault(who, float(ts))
    lines.setdefault((who, key), float(ts))
t0 = min(first.values())
for sender, receiver, name in (("c", "s", "client to server"), ("s", "c", "server to client")):
    sent = collections.Counter({k: n for k, n in side[sender].items() if k[0].startswith("'$CIP'" if sender == "c" else "'$SIP'")})
    missing = sent - side[receiver]
    print(f"   capture {name}: sent {sum(sent.values())}, not received {sum(missing.values())}")
    for k in sorted(missing, key=lambda k: lines[(sender, k)])[:12]:
        print(f"     t={lines[(sender, k)] - t0:.1f} flags [{k[2]}] seq {k[3]} ack {k[4]} length {k[5]} ×{missing[k]}")'
fi
$G grep -E "connection trusted|trust expired|idle connection|no longer trusted|revoked|will not be trusted|automatic trust" $D/run.log | grep -E "$SPORT|automatic trust is" | cut -c28-220 | sed 's/^/   /'
echo "case=$case_ backend=$backend protection=$prot when=$WHEN target=$TARGET sport=$SPORT $(echo $result | sed 's/^result //; s/ error=.*//') $got" >> $OUT
