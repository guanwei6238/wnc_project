#!/usr/bin/env bash
# 第 3 關：資料集的封包能不能「穿過」gateway，並看到 gateway 依規則處置？
#
# 對每個 cases/*.env：
#   1. tcprewrite 把原始位址改成 lab 的 cli(10.0.1.2) / srv(10.0.2.2)，MAC 改成對應的下一跳
#   2. 依方向拆成 c2s / s2c，分別從 cli 端、srv 端送進 gw（gw 兩側各一個介面）
#   3. gw 的 LAN / WAN 兩側同時抓包，加上 nft 規則計數器
#   4. 規則「停用」跑 N 次當對照，「啟用」再跑 N 次
#
# 判定依據 —— 三樣證據要同時成立：
#   入口收到（gw 入口介面抓到）、規則計數器增加、出口有／沒有轉送
#
# 對應實機（Pi）：
#   cli 端 = 筆電上的 lan netns（scripts/netns.sh），srv 端 = 筆電 root ns 的 eno2
#   gw 上的 nft 表格、tcpdump 指令可以原封不動搬到 Pi 上執行
#   不等價：Docker veth 沒有 USB 網卡的 offload / MTU 行為
#
# 用法：./03_replay.sh [重複次數，預設 3] [cases/xx.env ...]
# 前提：lab 已啟動（docker/up.sh）
set -euo pipefail
cd "$(dirname "$0")"
HERE=$PWD

REPEAT=${1:-3}
shift || true
CASES=("$@")
[[ ${#CASES[@]} -gt 0 ]] || CASES=(cases/*.env)

CLI_IP=10.0.1.2
SRV_IP=10.0.2.2
TABLE="inet ds_test"          # 只動這張自己的表，不碰 gw 上其他規則

# ---------- 前置檢查 ----------
for c in wnc-cli wnc-gw wnc-srv; do
  docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true \
    || { echo "容器 $c 沒有在跑，先執行 docker/up.sh" >&2; exit 1; }
done
if ! docker image inspect wnc-tools >/dev/null 2>&1; then
  echo "==> 建立重播工具 image（第一次需要網路）"
  docker build -q -t wnc-tools -f Dockerfile.tools . >/dev/null
fi

# 介面名稱用 IP 反查（跟 entrypoint.sh 同樣的做法）
if_of() { docker exec "$1" ip -o -4 addr show | awk -v ip="$2" '$4 ~ "^"ip"/" {print $2; exit}'; }
mac_of() { docker exec "$1" cat "/sys/class/net/$2/address"; }

CLI_IF=$(if_of wnc-cli $CLI_IP);  CLI_MAC=$(mac_of wnc-cli "$CLI_IF")
SRV_IF=$(if_of wnc-srv $SRV_IP);  SRV_MAC=$(mac_of wnc-srv "$SRV_IF")
GW_LAN=$(if_of wnc-gw 10.0.1.1);  GW_LAN_MAC=$(mac_of wnc-gw "$GW_LAN")
GW_WAN=$(if_of wnc-gw 10.0.2.1);  GW_WAN_MAC=$(mac_of wnc-gw "$GW_WAN")

RUN_ID=$(date +%Y%m%d-%H%M%S)
OUT="$HERE/out/$RUN_ID"
mkdir -p "$OUT"
REPORT="$OUT/summary.txt"

tools() {   # 在工具容器裡跑指令；$1 = 借用哪個容器的網路（none = 不需要網路）
  local net=$1; shift
  local netopt=(--network none)
  [[ $net != none ]] && netopt=(--network "container:$net" --cap-add NET_RAW --cap-add NET_ADMIN)
  docker run --rm "${netopt[@]}" -v "$HERE:/w" -w /w wnc-tools "$@"
}

count() {   # 數 pcap 裡符合 BPF 的封包數
  tools none tcpdump -nr "$1" "$2" 2>/dev/null | wc -l
}

load_rules() {   # $1 = on / off
  local rule=""
  [[ $1 == on ]] && rule="$RULE_MATCH counter name hit $RULE_VERDICT"
  docker exec -i wnc-gw nft -f - <<NFT
table $TABLE
delete table $TABLE
table $TABLE {
  counter hit {}
  chain forward {
    type filter hook forward priority filter - 10; policy accept;
    $rule
  }
}
NFT
}

hit_count() {
  docker exec wnc-gw nft list counter $TABLE hit | awk '/packets/ {print $2}'
}

{
echo "Dataset 重播測試  $RUN_ID"
echo "gw: LAN=$GW_LAN($GW_LAN_MAC)  WAN=$GW_WAN($GW_WAN_MAC)"
echo "tcpreplay: $(tools none tcpreplay -V 2>&1 | head -1)"
echo "重複次數：規則停用 ×$REPEAT、規則啟用 ×$REPEAT"
} | tee "$REPORT"

for case_file in "${CASES[@]}"; do
  # shellcheck disable=SC1090
  source "$case_file"
  name=$(basename "$case_file" .env)
  dir="$OUT/$name"; mkdir -p "$dir"
  rel=${dir#"$HERE"/}

  # ---------- 1. 改寫位址與 MAC，依方向拆檔 ----------
  tools none tcprewrite --fixcsum \
    --pnat="$ORIG_CLIENT/32:$CLI_IP/32,$ORIG_SERVER/32:$SRV_IP/32" \
    -i "$PCAP" -o "$rel/mapped.pcap"
  tools none tcpdump -r "$rel/mapped.pcap" -w "$rel/c2s_ip.pcap" "src host $CLI_IP" 2>/dev/null
  tools none tcpdump -r "$rel/mapped.pcap" -w "$rel/s2c_ip.pcap" "src host $SRV_IP" 2>/dev/null
  tools none tcprewrite --enet-smac="$CLI_MAC" --enet-dmac="$GW_LAN_MAC" -i "$rel/c2s_ip.pcap" -o "$rel/c2s.pcap"
  tools none tcprewrite --enet-smac="$SRV_MAC" --enet-dmac="$GW_WAN_MAC" -i "$rel/s2c_ip.pcap" -o "$rel/s2c.pcap"
  n_c2s=$(count "$rel/c2s.pcap" "")
  n_s2c=$(count "$rel/s2c.pcap" "")

  {
  echo
  echo "================================================================"
  echo "案例 $name：$DESC"
  echo "  PCAP   $PCAP"
  echo "  sha256 $(sha256sum "$PCAP" | cut -c1-16)…"
  echo "  位址   $ORIG_CLIENT → $CLI_IP (cli)   $ORIG_SERVER → $SRV_IP (srv)"
  echo "  規則   $RULE_MATCH  →  $RULE_VERDICT"
  echo "  封包   cli→srv $n_c2s 個，srv→cli $n_s2c 個"
  echo "----------------------------------------------------------------"
  echo "             │    cli → srv     │    srv → cli     │"
  echo "規則   輪    │  送  入口  出口  │  送  入口  出口  │ 規則命中"
  } | tee -a "$REPORT"

  for mode in off on; do
    for i in $(seq "$REPEAT"); do
      tag="${mode}_$i"
      cap="/tmp/ds_${name}_${tag}"     # 每個案例、每輪用不同檔名，避免讀到上一輪的抓包
      docker exec wnc-gw rm -f "${cap}_lan.pcap" "${cap}_wan.pcap"
      load_rules "$mode"
      # 每輪初始化：只清掉 cli 相關的 conntrack，不影響其他連線
      docker exec wnc-gw conntrack -D -s $CLI_IP >/dev/null 2>&1 || true

      # ---------- 2. gw 兩側抓包 ----------
      docker exec -d wnc-gw tcpdump -U -ni "$GW_LAN" -w "${cap}_lan.pcap" "$CAPTURE"
      docker exec -d wnc-gw tcpdump -U -ni "$GW_WAN" -w "${cap}_wan.pcap" "$CAPTURE"
      sleep 1

      # ---------- 3. 重播（保留原始時間間隔）----------
      tools wnc-cli tcpreplay -q -i "$CLI_IF" "$rel/c2s.pcap" >/dev/null 2>&1
      [[ $n_s2c -gt 0 ]] && tools wnc-srv tcpreplay -q -i "$SRV_IF" "$rel/s2c.pcap" >/dev/null 2>&1
      sleep 1
      docker exec wnc-gw pkill tcpdump || true
      sleep 0.5
      docker cp -q "wnc-gw:${cap}_lan.pcap" "$dir/${tag}_lan.pcap"
      docker cp -q "wnc-gw:${cap}_wan.pcap" "$dir/${tag}_wan.pcap"
      docker exec wnc-gw rm -f "${cap}_lan.pcap" "${cap}_wan.pcap"

      # ---------- 4. 數證據 ----------
      c_in=$(count "$rel/${tag}_lan.pcap" "src host $CLI_IP")
      c_out=$(count "$rel/${tag}_wan.pcap" "src host $CLI_IP")
      s_in=$(count "$rel/${tag}_wan.pcap" "src host $SRV_IP")
      s_out=$(count "$rel/${tag}_lan.pcap" "src host $SRV_IP")
      hit=$([[ $mode == on ]] && hit_count || echo "-")
      label=$([[ $mode == on ]] && echo "啟用" || echo "停用")
      printf '%s   #%-4s │ %4s %5s %5s │ %4s %5s %5s │ %5s\n' \
        "$label" "$i" "$n_c2s" "$c_in" "$c_out" "$n_s2c" "$s_in" "$s_out" "$hit" | tee -a "$REPORT"
    done
  done
done

docker exec wnc-gw nft delete table $TABLE
{
echo
echo "停用 = 對照組（規則不載入），啟用 = 載入待驗證規則"
echo "入口 = gw 收到的封包（LAN 側看 cli→srv，WAN 側看 srv→cli）"
echo "出口 = gw 轉送出去的封包"
echo "srv→cli 入口可能多於「送」：srv 是真實主機，會對收到的封包回應（例如回 RST），"
echo "      這些不是重播的封包 —— tcpreplay 只送歷史封包，不會跟 srv 建立新連線"
echo "證據檔：out/$RUN_ID/<案例>/{off,on}_N_{lan,wan}.pcap"
} | tee -a "$REPORT"
