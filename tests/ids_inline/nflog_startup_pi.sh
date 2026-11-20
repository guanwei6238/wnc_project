#!/bin/bash
# does Suricata --nflog crash when started under traffic (Pi, env.sh's wgw/wtest)
#   install the log group 10 rule first, wtest keeps sending 60-1 (10,000 pps) with tcpreplay, then start and stop Suricata N times, getting the exit status with wait
#   baseline: Docker 8.0.7 segfaulted 5/20 times (ReceiveNFLOGThreadInit)
# Prerequisites: sudo sh env.sh up; sh make_configs.sh; one trial.sh run with IMPL=nflog (uses the suricata.yaml it generates)
# Usage: sudo bash nflog_startup_pi.sh <suricata.yaml> [count, default 20]
Y=${1:?usage: nflog_startup_pi.sh <suricata.yaml> [runs]}; N=${2:-20}
M=${M:-/tmp/wncgw/m}; PCAP=/home/wnc/ids_throughput/data/pcaps/S_m60.pcap; L=/tmp/wncgw/nflstart
rm -rf $L; mkdir -p $L
echo "table inet sq { chain f { type filter hook forward priority 0; policy accept; counter log group 10; }; }" | ip netns exec wgw nft -f - || exit 1
ip netns exec wtest taskset -c 1 tcpreplay -i t-wan -I t-lan -c $M/cache/S_m60.cache --pps=10000 --loop=0 $PCAP > /dev/null 2>&1 &
tr=$!
crashed=0; ok=0
for run in $(seq 1 $N); do
  taskset -c 2,3 ip netns exec wgw suricata -c $Y --nflog -l $L --set unix-command.enabled=no --set coredump.max-dump=0 > $L/run.log 2>&1 &
  sp=$!
  for i in $(seq 1 100); do grep -q "Engine started" $L/run.log && break; kill -0 $sp 2>/dev/null || break; sleep 0.1; done
  sleep 1; kill -TERM $sp 2>/dev/null; wait $sp; st=$?
  if [ $st -gt 128 ]; then
    crashed=$((crashed + 1)); echo "run $run: signal $((st - 128)) $(grep -o "stacktrace:sig [0-9]*:.*Init[^;]*" $L/run.log | cut -c1-120)"
  else
    ok=$((ok + 1))
  fi
done
kill -INT $tr; wait $tr 2>/dev/null
echo "nflog under 10,000 pps: clean $ok/$N, crashed $crashed/$N; log rule $(ip netns exec wgw nft list table inet sq | grep -o 'packets [0-9]*')"
ip netns exec wgw nft delete table inet sq
