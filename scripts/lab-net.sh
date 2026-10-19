#!/bin/bash
# lab-net.sh — 實驗室有線網卡的「開機設定」（只管這台電腦這一側）
#
# 為什麼需要它：
#   開機後這兩張網卡會被 NetworkManager 接管：它會一直 DHCP 要位址，還會把 IPv6 link-local
#   設成「不自動產生」(addr_gen_mode=1)，手動下的 ip 指令重開機就消失。
#   這支腳本把「我們手動做過的事」變成開機自動做，而且可以完整移除，不影響未來的架構。
#
# 它只做三件事（只動下面 NICS 列的兩張網卡，不碰預設路由、Wi-Fi、Docker）：
#   1. 讓 NetworkManager 不要管這兩張卡
#   2. 讓核心自動產生 IPv6 link-local（fe80::）— SSH 用 fe80:: 連 Pi 就靠它
#   3. 設定 IPv4 位址（與 scripts/net.sh 相同的網段）
#
# 用法：
#   lab-net.sh status           看目前狀態（不需要 root）
#   sudo lab-net.sh up          立刻套用（可重複執行，不會重複加）
#   sudo lab-net.sh down        只移除我們加的 IPv4 位址
#   sudo lab-net.sh install     安裝成開機自動執行（NetworkManager 設定 + systemd + udev）
#   sudo lab-net.sh uninstall   完整移除 install 做的所有事，網卡還給 NetworkManager
#   DRY=1 lab-net.sh <指令>     只印出會做什麼，不真的做（不需要 root，用來先檢查）
#
# 注意：install 會把這支腳本「複製」到 /usr/local/sbin/wnc-lab-net。
#       之後改了這個檔案，要再跑一次 sudo ./lab-net.sh install 才會生效。
#       （為什麼複製：讓 root 直接執行放在家目錄、使用者可改的檔案，等於讓你的任何程式都能取得 root。）

set -u

# ---- 設定區：只改這裡 --------------------------------------------------------
# 格式："標籤 MAC IPv4位址/長度"。用 MAC 認網卡，因為介面名稱（eno2、enx…）會變，MAC 不會。
NICS=(
  "WAN 04:42:1a:85:7f:e7 10.254.254.1/24"   # 內建網卡 eno2   ↔ Pi 的 USB 網卡（WAN 側）
  "LAN 9c:69:d3:2a:11:54 10.254.127.1/24"   # USB 網卡 enx…   ↔ Pi 的內建網口（LAN 側）。2026-10-16 換了另一張 USB 網卡；舊的是 9c:69:d3:24:1b:d9
)
# 對端（Pi）位址，只給 status 用來提示，不會設定到 Pi 上：
PEERS="10.254.254.2 10.254.127.2"

INSTALLED_BIN=/usr/local/sbin/wnc-lab-net
NM_CONF=/etc/NetworkManager/conf.d/90-wnc-lab.conf
UDEV_RULE=/etc/udev/rules.d/90-wnc-lab-net.rules
UNIT=/etc/systemd/system/wnc-lab-net.service
# ------------------------------------------------------------------------------

# run：DRY=1 時只印出指令，否則真的執行
run() {
  if [ -n "${DRY:-}" ]; then echo "[DRY] $*"; else "$@"; fi
}

# put <檔案>：把 stdin 寫進檔案（DRY=1 時只印出內容）
put() {
  local f=$1 content
  content=$(cat)
  if [ -n "${DRY:-}" ]; then
    echo "[DRY] 將寫入 $f ："
    printf '%s\n' "$content" | sed 's/^/        | /'
  else
    printf '%s\n' "$content" > "$f"
  fi
}

need_root() {
  [ "$(id -u)" = 0 ] || [ -n "${DRY:-}" ] || { echo "需要 root：請用 sudo 執行"; exit 1; }
}

# 用 MAC 找出目前的介面名稱；找不到（沒插、或已被搬進 netns）就回傳失敗
find_if() {
  local m=${1,,} d
  for d in /sys/class/net/*; do
    [ "$(cat "$d/address" 2>/dev/null)" = "$m" ] && { basename "$d"; return 0; }
  done
  return 1
}

cmd_up() {
  need_root
  local entry tag mac ip ifn
  for entry in "${NICS[@]}"; do
    read -r tag mac ip <<<"$entry"
    if ! ifn=$(find_if "$mac"); then
      echo "[$tag] 找不到 MAC=$mac 的網卡（沒插，或已被 netns.sh 搬進 namespace），略過"
      continue
    fi
    echo "[$tag] $ifn  MAC=$mac  → $ip"
    # 1. 若 NetworkManager 還在管，就取消（正式的做法是 install 寫的 conf.d，這裡是保險）
    if command -v nmcli >/dev/null 2>&1 &&
       nmcli -t -f DEVICE,STATE dev status 2>/dev/null | grep "^$ifn:" | grep -qv ":unmanaged"; then
      run nmcli device set "$ifn" managed no
    fi
    # 2. 讓核心自動產生 link-local（0 = 依 MAC 產生）。NetworkManager 之前可能把它設成 1（不產生）
    run sysctl -qw "net.ipv6.conf.$ifn.addr_gen_mode=0"
    # 3. 起網卡；如果還沒有 fe80:: 位址，開關一次讓核心重新產生
    run ip link set "$ifn" up
    if ! ip -6 addr show dev "$ifn" scope link 2>/dev/null | grep -q inet6; then
      run ip link set "$ifn" down
      run ip link set "$ifn" up
    fi
    # 4. IPv4 位址。replace：已經有就不會報錯，也不會重複加
    run ip addr replace "$ip" dev "$ifn"
  done
}

cmd_down() {
  need_root
  local entry tag mac ip ifn
  for entry in "${NICS[@]}"; do
    read -r tag mac ip <<<"$entry"
    ifn=$(find_if "$mac") || { echo "[$tag] 找不到網卡，略過"; continue; }
    echo "[$tag] $ifn  移除 $ip"
    run ip addr del "$ip" dev "$ifn" 2>/dev/null || true
  done
}

cmd_status() {
  local entry tag mac ip ifn
  for entry in "${NICS[@]}"; do
    read -r tag mac ip <<<"$entry"
    echo "=== [$tag] 期望 MAC=$mac 位址=$ip"
    if ! ifn=$(find_if "$mac"); then
      echo "    找不到這張網卡（沒插，或在 netns 裡：用 'ip netns exec lan ip -br addr' 看）"
      continue
    fi
    printf '    介面名稱   : %s\n' "$ifn"
    printf '    連線狀態   : %s  carrier=%s  速度=%s Mb/s\n' "$(cat /sys/class/net/$ifn/operstate)" \
           "$(cat /sys/class/net/$ifn/carrier 2>/dev/null)" "$(cat /sys/class/net/$ifn/speed 2>/dev/null)"
    printf '    addr_gen   : %s   （0=自動產生 fe80::，1=不產生）\n' "$(cat /proc/sys/net/ipv6/conf/$ifn/addr_gen_mode)"
    printf '    NetworkMgr : %s\n' "$(nmcli -t -f DEVICE,STATE dev status 2>/dev/null | grep "^$ifn:" | cut -d: -f2)"
    printf '    位址       : %s\n' "$(ip -br addr show dev "$ifn" | awk '{for(i=3;i<=NF;i++) printf $i" "}')"
    if ip addr show dev "$ifn" 2>/dev/null | grep -q "inet ${ip%/*}/"; then echo "    → 期望的 IPv4 已設定"; else echo "    → 期望的 IPv4 尚未設定（執行 sudo $0 up）"; fi
  done
  echo
  echo "=== 開機自動執行是否已安裝"
  printf '    systemd 服務 : %s\n' "$(systemctl is-enabled wnc-lab-net.service 2>&1 | head -1)"
  for f in "$INSTALLED_BIN" "$NM_CONF" "$UDEV_RULE" "$UNIT"; do
    [ -e "$f" ] && echo "    存在 $f" || echo "    沒有 $f"
  done
  echo
  echo "=== 對端（Pi）位址提示：$PEERS  （Pi 那一側要另外設定，這支腳本不會碰 Pi）"
}

cmd_install() {
  need_root
  local entry tag mac ip macs="" rules=""
  for entry in "${NICS[@]}"; do
    read -r tag mac ip <<<"$entry"
    macs="${macs:+$macs;}mac:$mac"
    rules="$rules
ACTION==\"add\", SUBSYSTEM==\"net\", ATTR{address}==\"$mac\", TAG+=\"systemd\", ENV{SYSTEMD_WANTS}+=\"wnc-lab-net.service\""
  done

  # 1. 複製腳本到系統目錄（擁有者 root，其他人不能改）
  run install -m 0755 -o root -g root "$(readlink -f "$0")" "$INSTALLED_BIN"

  # 2. 讓 NetworkManager 永遠不要管這兩張卡（用 MAC 指定，換介面名稱也有效）
  put "$NM_CONF" <<EOF
# 由 lab-net.sh install 產生。移除請用 lab-net.sh uninstall。
[keyfile]
unmanaged-devices=$macs
EOF

  # 3. udev：這兩張卡「出現」時（開機稍晚、或 USB 重新插上）就再套用一次
  put "$UDEV_RULE" <<EOF
# 由 lab-net.sh install 產生。USB 網卡可能比開機服務晚出現，出現時再跑一次 wnc-lab-net up。$rules
EOF

  # 4. systemd 服務：開機時套用一次。沒有 RemainAfterExit，所以 udev 可以重複觸發
  put "$UNIT" <<EOF
# 由 lab-net.sh install 產生。
[Unit]
Description=WNC lab: 設定實驗室有線網卡（位址、IPv6 link-local、不讓 NetworkManager 接管）
After=NetworkManager.service

[Service]
Type=oneshot
ExecStart=$INSTALLED_BIN up

[Install]
WantedBy=multi-user.target
EOF

  run systemctl daemon-reload
  run udevadm control --reload
  run nmcli general reload conf
  run systemctl enable --now wnc-lab-net.service
  echo "完成。重開機後用 'lab-net.sh status' 驗證。要還原：sudo $0 uninstall"
}

cmd_uninstall() {
  need_root
  run systemctl disable --now wnc-lab-net.service 2>/dev/null || true
  cmd_down
  run rm -f "$UNIT" "$UDEV_RULE" "$NM_CONF" "$INSTALLED_BIN"
  run systemctl daemon-reload
  run udevadm control --reload
  run nmcli general reload conf
  echo "已移除。這兩張網卡會回到 NetworkManager 的管理（可能要拔插網線或重開機才會重新 DHCP）。"
}

case "${1:-}" in
  up)        cmd_up ;;
  down)      cmd_down ;;
  status)    cmd_status ;;
  install)   cmd_install ;;
  uninstall) cmd_uninstall ;;
  *) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
