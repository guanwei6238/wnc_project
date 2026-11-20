#!/bin/bash
# lab-net.sh — boot-time setup for the lab wired NICs (this machine's side only)
#
# Why:
#   After boot NetworkManager takes over these two NICs: it keeps asking for DHCP and sets IPv6 link-local
#   to not auto-generate (addr_gen_mode=1), and manual ip commands are lost on reboot.
#   This script turns what we did by hand into boot-time setup, and can be fully removed without affecting the future architecture.
#
# It does only three things (only on the two NICs listed in NICS below; no default route, Wi-Fi or Docker):
#   1. Keep NetworkManager off these two NICs
#   2. Let the kernel auto-generate the IPv6 link-local (fe80::) - SSH to the Pi over fe80:: depends on it
#   3. Set the IPv4 addresses (same subnets as scripts/net.sh)
#
# Usage:
#   lab-net.sh status           show current state (no root needed)
#   sudo lab-net.sh up          apply now (idempotent, never adds twice)
#   sudo lab-net.sh down        remove only the IPv4 addresses we added
#   sudo lab-net.sh install     install to run at boot (NetworkManager config + systemd + udev)
#   sudo lab-net.sh uninstall   undo everything install did and hand the NICs back to NetworkManager
#   DRY=1 lab-net.sh <cmd>      only print what would be done (no root needed; for checking first)
#
# Note: install copies this script to /usr/local/sbin/wnc-lab-net.
#       After editing this file, rerun sudo ./lab-net.sh install for the change to take effect.
#       (Why copy: having root run a user-writable file in the home directory would let any of your programs get root.)

set -u

# ---- Settings: edit only here --------------------------------------------------------
# Format: "label MAC IPv4/prefix". NICs are matched by MAC because interface names (eno2, enx…) change and MACs do not.
NICS=(
  "WAN 04:42:1a:85:7f:e7 10.254.254.1/24"   # built-in NIC eno2   ↔ Pi's USB NIC (WAN side)
  "LAN 9c:69:d3:2a:11:54 10.254.127.1/24"   # USB NIC enx…   ↔ Pi's built-in port (LAN side). Switched to another USB NIC on 2026-10-16; the old one was 9c:69:d3:24:1b:d9
)
# Peer (Pi) addresses, only used as hints by status; nothing is configured on the Pi:
PEERS="10.254.254.2 10.254.127.2"

INSTALLED_BIN=/usr/local/sbin/wnc-lab-net
NM_CONF=/etc/NetworkManager/conf.d/90-wnc-lab.conf
UDEV_RULE=/etc/udev/rules.d/90-wnc-lab-net.rules
UNIT=/etc/systemd/system/wnc-lab-net.service
# ------------------------------------------------------------------------------

# run: with DRY=1 only print the command, otherwise run it
run() {
  if [ -n "${DRY:-}" ]; then echo "[DRY] $*"; else "$@"; fi
}

# put <file>: write stdin to the file (with DRY=1 only print the content)
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

# Find the current interface name by MAC; fail if not found (unplugged, or moved into a netns)
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
    # 1. If NetworkManager still manages it, unmanage it (the real fix is the conf.d written by install; this is a fallback)
    if command -v nmcli >/dev/null 2>&1 &&
       nmcli -t -f DEVICE,STATE dev status 2>/dev/null | grep "^$ifn:" | grep -qv ":unmanaged"; then
      run nmcli device set "$ifn" managed no
    fi
    # 2. Let the kernel auto-generate link-local (0 = derive from MAC). NetworkManager may have set it to 1 (none)
    run sysctl -qw "net.ipv6.conf.$ifn.addr_gen_mode=0"
    # 3. Bring the NIC up; if there is no fe80:: address yet, toggle it once so the kernel regenerates it
    run ip link set "$ifn" up
    if ! ip -6 addr show dev "$ifn" scope link 2>/dev/null | grep -q inet6; then
      run ip link set "$ifn" down
      run ip link set "$ifn" up
    fi
    # 4. IPv4 address. replace: no error if it already exists, and never added twice
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

  # 1. Copy the script into a system directory (owned by root, not writable by others)
  run install -m 0755 -o root -g root "$(readlink -f "$0")" "$INSTALLED_BIN"

  # 2. Keep NetworkManager off these two NICs for good (matched by MAC, so renaming does not matter)
  put "$NM_CONF" <<EOF
# Generated by lab-net.sh install. Remove with lab-net.sh uninstall.
[keyfile]
unmanaged-devices=$macs
EOF

  # 3. udev: reapply when either NIC appears (late in boot, or USB replugged)
  put "$UDEV_RULE" <<EOF
# Generated by lab-net.sh install. The USB NIC may appear after the boot service; run wnc-lab-net up again when it does.$rules
EOF

  # 4. systemd service: apply once at boot. No RemainAfterExit, so udev can trigger it repeatedly
  put "$UNIT" <<EOF
# Generated by lab-net.sh install.
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
