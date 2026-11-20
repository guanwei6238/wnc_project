#!/bin/bash
# live_docker.sh — exp 3b: a real TCP connection (Docker testbed, routed, wnc-gw run); send a large file while trusted, then GET /evil after trust is removed
#   order: GET /small → wnc-gw trust add → GET /big (SIZE MB, trusted) → wnc-gw trust del → GET /evil?q=EVIL → GET /small
#   check: whether the /evil request completes and how long it takes; whether Suricata alerts (R1 http.uri, R3 stream content); packet loss and invalid ack in stats
#   NOTRUST=1: no trust add/del (control group)
#   TIMEOUT=<sec>: Suricata's flow-timeouts.tcp.established; HOLD=<sec>: after the large file finishes and before trust is removed, how many seconds the connection stays trusted and idle
#   ACKSYNC=1: also install a table (forward, priority -10) that sends 1 in 10 trusted pure ACKs (ip length ≤ 64) to Suricata (queue 0 for ips, log group 10 for ids)
# Usage: PROTECTION=ips|ids SIZE=<MB> ACKSYNC=0|1 bash live_docker.sh run    prints one key=value result line
#       bash live_docker.sh clean
# Prerequisites: cd docker && ./up.sh; x86_64 musl debug build of wnc-gw ready (mounted by compose at /opt/sg)
G="docker exec wnc-gw"; GI="docker exec -i wnc-gw"; C="docker exec wnc-cli"; CI="docker exec -i wnc-cli"; S="docker exec wnc-srv"; SI="docker exec -i wnc-srv"
D=/tmp/live; SLOG=/var/log/wnc-gw/suricata
PROTECTION=${PROTECTION:-ips}; SIZE=${SIZE:-64}; ACKSYNC=${ACKSYNC:-0}
SPORT=$((20000 + RANDOM % 20000))

setup() {
  $G mkdir -p $D
  $GI sh -c "cat > $D/test.rules" <<'EOF'
alert http any any -> any any (msg:"R1 uri est"; flow:established,to_server; http.uri; content:"/evil"; sid:1; rev:1;)
alert http any any -> any any (msg:"R2 uri"; flow:to_server; http.uri; content:"/evil"; sid:2; rev:1;)
alert tcp any any -> any any (msg:"R3 stream est"; flow:established,to_server; content:"EVIL"; sid:3; rev:1;)
alert tcp any any -> any any (msg:"R7 est_invalid_ack"; stream-event:est_invalid_ack; sid:7; rev:1;)
alert tcp any any -> any any (msg:"R10 seq gap"; stream-event:reassembly_seq_gap; sid:10; rev:1;)
EOF
  $GI sh -c "cat > $D/s.yaml" <<EOF
%YAML 1.1
---
include: /etc/suricata/suricata.yaml
default-rule-path: $D
rule-files:
  - test.rules
EOF
  if [ -n "${TIMEOUT:-}" ]; then
    $GI sh -c "cat >> $D/s.yaml" <<EOF
flow-timeouts:
  tcp:
    new: 60
    established: $TIMEOUT
    closed: 0
    bypassed: 100
    emergency-new: 10
    emergency-established: 5
    emergency-closed: 0
    emergency-bypassed: 50
EOF
  fi
  $GI sh -c "cat > $D/setting.toml" <<EOF
mode = "routed"
protection = "$PROTECTION"

[ports]
lan = "02:00:00:00:01:01"
wan = "02:00:00:00:02:01"

[suricata]
config = "$D/s.yaml"
EOF
  $SI sh -c "cat > /tmp/srv.py" <<'EOF'
import http.server, socketserver, sys
SIZE = int(sys.argv[1]) << 20
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        n = SIZE if self.path.startswith("/big") else 2000
        self.send_response(200)
        self.send_header("Content-Length", str(n))
        self.end_headers()
        chunk = b"x" * 65536
        left = n
        while left:
            k = min(left, len(chunk))
            self.wfile.write(chunk[:k])
            left -= k
    def log_message(self, *a):
        pass
class T(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
T(("0.0.0.0", 80), H).serve_forever()
EOF
  $S sh -c "pkill -f 'python3 /tmp/[s]rv.py'"; sleep 0.5
  docker exec -d wnc-srv python3 /tmp/srv.py $SIZE
  $CI sh -c "cat > /tmp/cli.py" <<'EOF'
import http.client, socket, sys, time, os
sport = int(sys.argv[1])
def step(name):
    open("/tmp/cli.step", "w").write(name)
def wait(name):
    while not os.path.exists("/tmp/go." + name):
        time.sleep(0.05)
c = http.client.HTTPConnection("10.0.2.2", 80, timeout=15, source_address=("10.0.1.2", sport))
def get(path):
    t = time.time()
    try:
        c.request("GET", path)
        r = c.getresponse()
        n = len(r.read())
        return f"ok:{n}:{time.time() - t:.2f}"
    except Exception as e:
        return f"fail:{type(e).__name__}:{time.time() - t:.2f}"
out = []
out.append("small1=" + get("/small1"))
step("trust"); wait("trust")
out.append("big=" + get("/big"))
step("untrust"); wait("untrust")
out.append("evil=" + get("/evil?q=EVIL"))
out.append("small2=" + get("/small2"))
print(" ".join(out))
step("done")
EOF
  sleep 1
}

start() {
  $G sh -c "rm -f $SLOG/* $D/run.log $D/exit"
  docker exec -d wnc-gw sh -c "/opt/sg/wnc-gw -c $D/setting.toml run > /dev/null 2> $D/run.log & echo \$! > $D/pid; wait \$!; echo \$? > $D/exit"
  for i in $(seq 1 150); do
    $G grep -q "traffic is inspected" $D/run.log 2>/dev/null && return 0
    $G test -e $D/exit && break; sleep 0.2
  done
  echo "wnc-gw did not start"; $G tail -5 $D/run.log; return 1
}

stop() { $G sh -c "kill -INT \$(cat $D/pid)"; until $G test -e $D/exit; do sleep 0.2; done; }

acksync() {
  local act="queue num 0 bypass"; [ $PROTECTION = ids ] && act="log group 10"
  $G nft add table inet acksync
  $G nft add chain inet acksync f '{ type filter hook forward priority -10; policy accept; }'
  $G nft add rule inet acksync f ct mark and 0x80000000 == 0x80000000 tcp flags == ack ip length le 64 numgen inc mod 10 == 0 counter $act
}

waitstep() { for i in $(seq 1 600); do [ "$($C cat /tmp/cli.step 2>/dev/null)" = "$1" ] && return 0; sleep 0.1; done; return 1; }

case "$1" in
run)
  setup
  start || exit 1
  [ "$ACKSYNC" = 1 ] && acksync
  $C sh -c "rm -f /tmp/cli.step /tmp/go.* /tmp/cli.out"
  docker exec -d wnc-cli sh -c "python3 /tmp/cli.py $SPORT > /tmp/cli.out 2>&1"
  waitstep trust || { echo "client stuck before trust"; }
  [ "${NOTRUST:-0}" = 1 ] || $G /opt/sg/wnc-gw trust add tcp 10.0.1.2 $SPORT 10.0.2.2 80 > /dev/null 2>&1
  $C touch /tmp/go.trust
  waitstep untrust || echo "client stuck in big"
  sleep ${HOLD:-0}
  ids0=$($G nft list chain inet wnc_gw ids 2>/dev/null | grep -o "packets [0-9]*" | head -1 | cut -d' ' -f2)
  [ "${NOTRUST:-0}" = 1 ] || $G /opt/sg/wnc-gw trust del tcp 10.0.1.2 $SPORT 10.0.2.2 80 > /dev/null 2>&1
  $C touch /tmp/go.untrust
  waitstep done || echo "client stuck after untrust"
  sleep 1
  res=$($C cat /tmp/cli.out)
  as=$($G nft list table inet acksync 2>/dev/null | grep -o "packets [0-9]*" | head -1 | cut -d' ' -f2)
  stop
  st() { $G sh -c "grep -E '^$1 ' $SLOG/stats.log | tail -1 | awk '{print \$NF}'"; }
  al=$($G sh -c "grep -o '\[1:[0-9]*:1\]' $SLOG/fast.log 2>/dev/null | sort | uniq -c | awk '{printf \"%s×%s \", \$2, \$1}'")
  echo "protection=$PROTECTION size_mb=$SIZE acksync=$ACKSYNC notrust=${NOTRUST:-0} timeout_s=${TIMEOUT:-600} hold_s=${HOLD:-0} sport=$SPORT $res alerts=[${al% }] ids_pkts_before_untrust=$ids0 acksync_pkts=${as:-0} drop_stream_err=$(st ips.drop_reason.stream_error) ips_blocked=$(st ips.blocked) ack_unseen=$(st tcp.ack_unseen_data) gaps=$(st tcp.reassembly_gap) midstream=$(st tcp.midstream_pickups) http_tx=$(st app_layer.tx.http)"
  $G nft delete table inet acksync 2>/dev/null
  ;;
clean)
  $G nft delete table inet acksync 2>/dev/null
  $S sh -c "pkill -f 'python3 /tmp/[s]rv.py'"
  ;;
*) sed -n '2,9p' "$0"; exit 2 ;;
esac
