#!/bin/sh
# make_configs.sh — 產生三組 rule set 的 Suricata 設定與 wnc-gw 設定（放在 $M）
#   Suricata 設定 = 系統的 /etc/suricata/suricata.yaml 只改這幾行（和 offline 量測對齊）：
#     runmode workers（1 個 queue = 1 個 worker，對應 offline 的 --runmode single）
#     mpm-algo ac-ks、spm-algo bm（offline 的 --set）
#     capture.checksum-validation none（等同 offline 的 -k none）
#     exception-policy ignore（IPS 模式的 auto 等於 drop-flow，會丟掉 midstream 的 flow；offline 是 IDS 模式，auto 等於 ignore）
#     rule-files：full、gw_corp 用 offline 的同一份檔案；empty 用一條不會命中的 rule（doctor 不讓 0 條 rule 啟動）
#   wnc-gw 設定：bridge 模式、when_unavailable = "drop"（跟不上時丟掉，不放行，丟失才算得出來）
# 用法: sh make_configs.sh   之後用 suricata --dump-config 和系統設定 diff，確認只差上面幾項
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
  printf 'mode = "bridge"\nxdp = "off"\n\n[ports]\nlan = "g-lan"\nwan = "g-wan"\n\n[suricata]\nconfig = "%s"\nwhen_unavailable = "drop"\n' \
    "$M/suricata-$rs.yaml" > $M/setting-$rs.toml
  for n in 2 3 4; do  # 多個 queue：setting-<rules>-qN.toml
    { cat $M/setting-$rs.toml; printf 'queue = "0-%d"\n' $((n - 1)); } > $M/setting-$rs-q$n.toml
  done
done
# af-packet IPS 模式（對照組）：Suricata 自己在 g-lan、g-wan 之間搬封包，不經過 bridge 與 nft
#   include 之後重新定義 af-packet 會整個取代系統的清單；IPS 模式不能用 tpacket-v3
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
