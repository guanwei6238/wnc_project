#!/bin/bash
# trust_cost.sh — 3a: per-packet savings after trust (ct mark), and the cost of L2 (SYN/FIN/RST always to Suricata)
#   C0 counters only (no conntrack); C1 ct mark accept + queue (no trust → everything to Suricata)
#   C2 prerouting sets a mark on every connection (everything trusted); C3 = C2 + L2
#   C4 = C3 + a rule clearing the trust bit on pure SYN (before L2, as in wnc-gw); C5 = C3 + K identical rules (amplified, to get the per-rule cost)
#   netns rebuilt each time (conntrack table starts empty); Suricata runs NFQ directly (full, same forced settings as wnc-gw), pinned to CPU 2,3; tcpreplay pinned to CPU 1
#   tcpreplay uses -T nano: the default gtod busy-waits and saturates CPU 1, hiding the kernel's forwarding cost on CPU 1
#   CPU from per-CPU rq_cpu_time in /proc/schedstat (ns, exact at context switch); /proc/stat is tick-sampled and misses work that wakes for a dozen µs and sleeps again
#   kernel lacks IRQ_TIME_ACCOUNTING, so forwarding and NFQ softirq time is counted in tcpreplay's or Suricata's run time
#   cpu_us_per_pkt = increase of rq_cpu_time over all CPUs ÷ packets through forward; suricata_us_per_pkt counts only the Suricata process
# Prerequisites: pi_lab_mode.sh up 1000, system suricata service stopped, sh make_configs.sh
# Usage: sudo nohup bash -c 'for r in 1 2; do ROUND=$r bash trust_cost.sh; done' > /home/wnc/ids_inline/trust.log 2>&1 < /dev/null &
cd "$(dirname "$0")" || exit 1
TAG=${TAG:-trust1}; ROUND=${ROUND:-1}; RATE=${RATE:-10000}; RULESET=${RULESET:-full}
OUT=${OUT:-/home/wnc/ids_inline/results}; M=${M:-/tmp/wncgw/m}; PCAPS=/home/wnc/ids_throughput/data/pcaps
LOG=/var/log/wnc-gw/suricata
PCS=${PCS:-"S_h5 S_somfy02 S_m1 S_m44 S_m39"}; CFGS=${CFGS:-"C0 C1 C2 C3"}; K=${K:-500}
mkdir -p "$OUT"
pgrep -x Suricata-Main > /dev/null && { echo "another suricata is running"; exit 1; }
for pc in $PCS; do bash trial.sh empty "$pc" cache /tmp/x || exit 1; done

busy() { awk '/^cpu[0-9]/{s += $8} END{printf "%d", s / 1000}' /proc/schedstat; }
scpu() { cat /proc/$1/task/*/schedstat 2>/dev/null | awk '{s += $1} END{printf "%d", s / 1000}'; }
counters() { ip netns exec wgw nft list counters table inet tc | awk '/counter /{n=$2} /packets/{printf "%s=%s ", n, $2}'; }
nfq_pending() { ip netns exec wgw cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null | awk '{s += $3} END{print s + 0}'; }

table() {  # table <C0|C1|C2|C3|C4|C5>
  local mark="" l2="" clear="" ids='ct mark & 0x1 == 0x1 counter name "trusted" accept
    counter name "queued" queue num 0'
  local rule='meta l4proto tcp tcp flags & (syn | ack) == syn ct mark & 0x1 == 0x1 counter name "cleared" ct mark set ct mark & 0xfffffffe'
  case $1 in
  C0) ids='counter name "passed" accept' ;;
  C2) mark='chain pre { type filter hook prerouting priority 0; policy accept; ct mark set ct mark | 0x1; }' ;;
  C3) mark='chain pre { type filter hook prerouting priority 0; policy accept; ct mark set ct mark | 0x1; }'
      l2='meta l4proto tcp tcp flags & (fin | syn | rst) != 0 counter name "l2" queue num 0' ;;
  C4|C5) mark='chain pre { type filter hook prerouting priority 0; policy accept; ct mark set ct mark | 0x1; }'
      l2='meta l4proto tcp tcp flags & (fin | syn | rst) != 0 counter name "l2" queue num 0'
      clear=$(for i in $(seq $(cfg_k $1)); do printf '    %s\n' "$rule"; done) ;;
  esac
  ip netns exec wgw nft -f - <<NFT
table inet tc {
  counter passed {}
  counter trusted {}
  counter queued {}
  counter l2 {}
  counter cleared {}
  $mark
  chain forward {
    type filter hook forward priority 0; policy accept;
$clear
    $l2
    $ids
  }
}
NFT
}

cfg_k() { case $1 in C4) echo 1 ;; C5) echo $K ;; *) echo 0 ;; esac; }

seq=0
for pc in $PCS; do
  for cfg in $(printf '%s\n' $CFGS | shuf); do
    seq=$((seq + 1)); echo "$(date -u +%T) #$seq $pc $cfg"
    sh env.sh down; sh env.sh up
    rm -f $LOG/*
    taskset -c 2,3 ip netns exec wgw suricata -c $M/suricata-$RULESET.yaml -q 0 -l $LOG --set unix-command.enabled=no \
      --set coredump.max-dump=0 --set stream.midstream=true --set stream.midstream-policy=ignore > /tmp/wncgw/tc-suricata.txt 2>&1 &
    sp=$!
    until grep -q "Engine started" /tmp/wncgw/tc-suricata.txt; do sleep 0.5; kill -0 $sp 2>/dev/null || { echo "  suricata failed"; continue 2; }; done
    table $cfg || { echo "  nft failed"; kill $sp; continue; }
    sleep 2
    s0=$(scpu $sp); b0=$(busy); t0=${EPOCHREALTIME/./}
    ip netns exec wtest taskset -c 1 tcpreplay -T nano -i t-wan -I t-lan -c $M/cache/$pc.cache --pps=$RATE $PCAPS/$pc.pcap > /tmp/wncgw/tc-replay.txt 2>&1
    sleep 0.3; until [ "$(nfq_pending)" = 0 ]; do sleep 0.05; done
    t1=${EPOCHREALTIME/./}; b1=$(busy); s1=$(scpu $sp)
    c=$(counters); ct=$(ip netns exec wgw cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
    kill -TERM $sp; wait $sp 2>/dev/null
    treated=$(grep -o "Treated: Pkts [0-9]*" /tmp/wncgw/tc-suricata.txt | awk '{s += $3} END{print s + 0}')
    sent=$(grep -o "Actual: [0-9]* packets" /tmp/wncgw/tc-replay.txt | cut -d" " -f2)
    line=$(awk -v tag=$TAG -v round=$ROUND -v seq=$seq -v pc=$pc -v cfg=$cfg -v k=$(cfg_k $cfg) -v sent=$sent -v c="$c" -v ct=$ct -v b=$((b1 - b0)) -v sc=$((s1 - s0)) -v tr=$treated -v dt=$((t1 - t0)) 'BEGIN{
      n = split(c, kv, " "); for (i = 1; i <= n; i++) { split(kv[i], p, "="); v[p[1]] = p[2] }
      fwd = v["passed"] + v["trusted"] + v["queued"] + v["l2"]; ids = v["queued"] + v["l2"]
      printf "tag=%s round=%d seq=%d pcap=%s cfg=%s k=%d sent=%d forwarded=%d passed=%d trusted=%d queued=%d l2=%d to_ids_pct=%.2f suricata_treated=%d conntrack=%d cpu_s=%.3f suricata_cpu_s=%.3f wall_s=%.2f cpu_us_per_pkt=%.2f suricata_us_per_pkt=%.2f",
        tag, round, seq, pc, cfg, k, sent, fwd, v["passed"], v["trusted"], v["queued"], v["l2"], (fwd ? 100 * ids / fwd : 0), tr, ct, b / 1e6, sc / 1e6, dt / 1e6, (fwd ? b / fwd : 0), (fwd ? sc / fwd : 0) }')
    echo "$line" >> "$OUT/$TAG.kvl"; echo "  $(echo "$line" | grep -o -E 'forwarded=[^ ]*|to_ids_pct=[^ ]*|suricata_treated=[^ ]*|cpu_us_per_pkt=[^ ]*|suricata_us_per_pkt=[^ ]*' | tr '\n' ' ')"
  done
done
sh env.sh down; sh env.sh up
echo "ALL DONE $(date -u +%FT%TZ)"
