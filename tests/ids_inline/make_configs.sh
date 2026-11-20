#!/bin/sh
# make_configs.sh — generate Suricata and wnc-gw configs for three rule sets (in $M)
#   Suricata config = system /etc/suricata/suricata.yaml with only these lines changed (aligned with the offline measurement):
#     runmode workers (1 queue = 1 worker, matching offline's --runmode single)
#     mpm-algo ac-ks, spm-algo bm (offline's --set)
#     capture.checksum-validation none (same as offline's -k none)
#     exception-policy ignore (auto in IPS mode means drop-flow, which drops midstream flows; offline is IDS mode, where auto means ignore)
#     rule-files: full, gw_corp use the same files as offline; empty uses one rule that never matches (doctor refuses to start with 0 rules)
#   wnc-gw config: bridge mode, protection = "ips" (NFQ; the default ids is NFLOG), when_unavailable = "drop" (drop instead of pass when it cannot keep up, so loss is measurable)
# Usage: sh make_configs.sh   then diff suricata --dump-config against the system config to confirm only the items above differ
M=${M:-/tmp/wncgw/m}
RULES=${RULES:-/home/wnc/ids_throughput/data/rules}
set -e
mkdir -p $M/rules $M/cache
echo 'alert ip any any -> 192.0.2.1 any (msg:"never matches"; sid:9000001; rev:1;)' > $M/rules/never.rules
for rs in empty full gw_corp; do
  if [ $rs = empty ]; then rf=$M/rules/never.rules; else rf=suricata_$rs.rules; fi
  sed -e "s|^#runmode: autofp|runmode: workers|" \
      -e "s|^mpm-algo: auto|mpm-algo: ac-ks|" -e "s|^spm-algo: auto|spm-algo: bm|" \
      -e "s|^  #checksum-validation: none|  checksum-validation: none|" \
      -e "s|^exception-policy: auto|exception-policy: ignore|" \
      -e "s|^default-rule-path: .*|default-rule-path: $RULES|" -e "s|^  - suricata.rules\$|  - $rf|" \
      /etc/suricata/suricata.yaml > $M/suricata-$rs.yaml
  printf 'mode = "bridge"\nxdp = "off"\nprotection = "ips"\n\n[ports]\nlan = "g-lan"\nwan = "g-wan"\n\n[suricata]\nconfig = "%s"\nwhen_unavailable = "drop"\n' \
    "$M/suricata-$rs.yaml" > $M/setting-$rs.toml
  for n in 2 3 4; do  # multiple queues: setting-<rules>-qN.toml
    { cat $M/setting-$rs.toml; printf 'queue = "0-%d"\n' $((n - 1)); } > $M/setting-$rs-q$n.toml
  done
done
# af-packet IPS mode (baseline): Suricata moves packets between g-lan and g-wan itself, bypassing the bridge and nft
#   redefining af-packet after include replaces the whole system list; IPS mode cannot use tpacket-v3
for rs in empty full gw_corp; do
  printf '%%YAML 1.1\n---\ninclude: %s\n\naf-packet:\n' "$M/suricata-$rs.yaml" > $M/suricata-$rs-afp.yaml
  for pair in "g-lan g-wan 98" "g-wan g-lan 97"; do
    set -- $pair
    printf '  - interface: %s\n    threads: 1\n    cluster-id: %s\n    cluster-type: cluster_flow\n    defrag: no\n    use-mmap: yes\n    tpacket-v3: no\n    copy-mode: ips\n    copy-iface: %s\n' "$1" "$3" "$2" >> $M/suricata-$rs-afp.yaml
  done
done
suricata --dump-config -c /etc/suricata/suricata.yaml 2>/dev/null > $M/system.dump
for rs in empty full gw_corp; do
  echo "== $rs"; suricata --dump-config -c $M/suricata-$rs.yaml 2>/dev/null | diff $M/system.dump - | grep '^>' || true
done
