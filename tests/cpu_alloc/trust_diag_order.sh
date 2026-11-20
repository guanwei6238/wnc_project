#!/bin/bash
# First 15,000 packets of S_h5, 5,000 pps vs 500 pps: is out-of-order sending across the two NICs the cause of stream errors/TLS gaps (bridge, U, ips)
# Results go to $O/probe3.kvl (bridge topology)
LAN=enx9c69d3241bd9; WAN=eno2; PI=wnc@10.254.254.2; G="docker exec wnc-gen"; O=/home/sixsquare/datasets/throughput/cpu_alloc
for rate in 5000 500 5000 500; do
  ssh $PI "sudo PROTECTION=ips bash ~/ids_inline/planb_pi.sh start full 1 0" | tail -1
  $G tcpreplay -i $LAN -I $WAN.20 -c /out/trust/S_h5.gw.cache --pps=$rate --limit=15000 /out/trust/S_h5.gw.pcap > $O/tcpreplay.txt 2>&1
  sleep 10
  c=$(ssh $PI "sudo awk '/^Date/{b = \"\"} {b = b \"\\n\" \$0} END{print b}' /var/log/wnc-gw/suricata/stats.log" \
    | awk -F'|' '/^(ips\.|exception_policy\.|app_layer\.error\.|tcp\.(sessions|midstream_pickups|ack_unseen_data|reassembly_gap))/ && $3 + 0 > 0 {gsub(/ /, "", $1); printf "%s=%d ", $1, $3}')
  echo "pps=$rate sent=$(grep -o 'Actual: [0-9]*' $O/tcpreplay.txt | cut -d' ' -f2) $c" | tee -a $O/probe3.kvl
  ssh $PI "sudo bash ~/ids_inline/planb_pi.sh stop" > /dev/null
done
echo "PROBE3 DONE"
