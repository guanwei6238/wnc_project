#!/bin/bash
# pi_set_total_mem.sh — 設定或移除 /boot/firmware/config.txt 的 total_mem（在 Pi 上執行，需要 sudo）
#
# 為什麼：用韌體選項 total_mem 讓 4 GB 的 Pi 4「表現得像」較小記憶體的機型（官方文件的範例就是 4 GB 設
# total_mem=1024 模擬 1 GB）。這是為了在同一塊板子上量「記憶體容量對引擎能不能載入規則、速度會不會掉」的影響。
# 限制：只限制可用 RAM 容量；CPU、記憶體頻寬、網卡都不變，所以不等於真的那一款機型。
# 官方文件說明：單位 MB，範圍夾在 128 MB 到板子實際記憶體之間；必須直接寫在 config.txt（寫在 include 的檔案裡不會生效）。
#
# 用法： pi_set_total_mem.sh <MB>     例：pi_set_total_mem.sh 1024
#        pi_set_total_mem.sh off      移除（還原成板子的實際記憶體）
# 改完要「重開機」才會生效。第一次執行時會把原始 config.txt 備份成 config.txt.bak_wnc_orig（之後不覆蓋）。
# 這支腳本是冪等的：先刪掉既有的 total_mem= 行，再視需要加一行（加在檔案最後；目前最後一個區段是 [all]，對所有機型生效）。

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
