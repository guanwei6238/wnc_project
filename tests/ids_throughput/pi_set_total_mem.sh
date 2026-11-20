#!/bin/bash
# pi_set_total_mem.sh - set or remove total_mem in /boot/firmware/config.txt (run on the Pi, needs sudo)
#
# Why: the firmware option total_mem makes a 4 GB Pi 4 behave like a smaller-memory model (the official docs' example is a 4 GB board set to
# total_mem=1024 to emulate 1 GB). This measures, on one board, how memory size affects whether the engine can load rules and whether speed drops.
# Limitation: only usable RAM is limited; CPU, memory bandwidth and NIC stay the same, so it is not the same as the real model.
# Per the official docs: unit is MB, clamped between 128 MB and the board's real memory; must be set directly in config.txt (has no effect in an included file).
#
# Usage: pi_set_total_mem.sh <MB>     e.g. pi_set_total_mem.sh 1024
#        pi_set_total_mem.sh off      remove (back to the board's real memory)
# Takes effect only after a reboot. The first run backs up the original config.txt to config.txt.bak_wnc_orig (never overwritten).
# Idempotent: deletes any existing total_mem= line, then adds one if needed (at the end of the file; the last section is currently [all], which applies to all models).

C=/boot/firmware/config.txt
usage() { echo "用法: $0 <MB|off>   （MB 範圍 128–4096）"; exit 2; }
[ $# -eq 1 ] || usage
if [ "$1" != off ]; then
  case "$1" in ''|*[!0-9]*) usage ;; esac
  [ "$1" -ge 128 ] && [ "$1" -le 4096 ] || usage
fi

[ -f "$C.bak_wnc_orig" ] || { sudo cp -p "$C" "$C.bak_wnc_orig" && echo "已備份原始檔 -> $C.bak_wnc_orig"; }
sudo sed -i '/^total_mem=/d' "$C"
[ "$1" = off ] || echo "total_mem=$1" | sudo tee -a "$C" >/dev/null
echo "--- $C 目前的 total_mem ---"
grep -n '^total_mem=' "$C" || echo "(沒有 total_mem，重開機後使用板子的實際記憶體)"
echo "（需要重開機才會生效；目前 MemTotal = $(awk '/MemTotal/{printf "%d MB", $2/1024}' /proc/meminfo)）"
