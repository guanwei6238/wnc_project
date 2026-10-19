#!/bin/bash
# measure.sh -- 「一次量測」：讓一個引擎讀一個 pcap，留下原始 log。MODE=docker 或 native 都跑這支（同一套邏輯）。
#   docker 模式: 由 run_matrix.py 用 `docker run ... /scripts/measure.sh` 呼叫（容器內就是 native 環境）
#   native 模式: run_matrix.py 直接呼叫（在 Pi 上）
#
# 用法: measure.sh <suricata|snort> <empty|規則集名稱> <pcap 路徑> <輸出目錄>      規則集名稱例如 full、sel、gw_corp、common
# 環境變數（都有預設值）:
#   WORK          放 pcap 副本與引擎輸出的暫存目錄，必須是 tmpfs/記憶體檔案系統（避免磁碟 I/O 影響）。docker: /work；Pi: /dev/shm/ids_tp
#   RULES_DIR     規則檔目錄（內有 <引擎>_<規則集>.rules，例如 suricata_full.rules、snort_gw_corp.rules）
#   THREADS       封包處理執行緒數。本步驟只支援 1（參數照樣記錄，之後要擴充才不用改介面）
#   CPUSET        native 模式才用：例如 "2,3" -> taskset -c 2,3。docker 模式由 --cpuset-cpus 負責
#   SNORT_ETC     Snort 3 官方 snort.lua 所在目錄；SURICATA_YAML  Suricata 設定檔
# 輸出（<輸出目錄>）: engine.log  time.txt(/usr/bin/time -v)  timing.kv(外部量到的牆鐘 µs、exit code)  stats.log(Suricata)  sids.txt(alert 的 sid 次數)

set -u
engine=$1; rset=$2; pcap=$3; out=$4
WORK=${WORK:-/work}
RULES_DIR=${RULES_DIR:-/rules}
THREADS=${THREADS:-1}
SNORT_ETC=${SNORT_ETC:-/opt/snort/etc/snort}
SURICATA_YAML=${SURICATA_YAML:-/etc/suricata/suricata.yaml}

[ "$THREADS" = "1" ] || { echo "THREADS=$THREADS 尚未支援（本步驟固定單一封包處理執行緒）"; exit 97; }
mkdir -p "$out" || exit 99
run=$(mktemp -d "$WORK/run.XXXXXX") || exit 99
trap 'rm -rf "$run"' EXIT

# 1. 規則檔。empty = 空規則 baseline（Suricata 依規格用 /dev/null；Snort 用 /dev/null 也可以，已實測）
if [ "$rset" = empty ]; then rf=/dev/null; else rf="$RULES_DIR/${engine}_${rset}.rules"; fi
[ -r "$rf" ] || { echo "找不到規則檔 $rf"; exit 98; }

# 2. pcap 先複製進 tmpfs。這一步不計入引擎時間。（引擎之後讀的是記憶體檔案系統，不是磁碟）
cp "$pcap" "$run/in.pcap" || exit 99

# 3. 組指令。共同原則：只改「必要」的設定，其餘維持各引擎的預設/官方設定檔。
pin=(); [ -n "${CPUSET:-}" ] && pin=(taskset -c "$CPUSET")
case $engine in
  suricata)
    # --runmode single  : 單一 worker thread（收封包+解碼+偵測都在同一條 thread）。log 會印 "Threads created -> W: 1"
    # -k none           : 忽略 checksum（IoT-23 有些封包 checksum 是錯的，不忽略會被丟掉）
    # mpm ac-ks / spm bm: Pi 的 Debian 套件沒有 Hyperscan，所以 x86 也用 Pi 能用的 matcher
    # unix-command=no   : 關掉 unix socket 管理執行緒（非 root 時本來就會失敗，這樣各環境一致）
    # -v                : 才會印 "time elapsed"（引擎自己量的處理時間）
    cmd=("${pin[@]}" suricata -v -c "$SURICATA_YAML" -S "$rf" -l "$run" --runmode single
         --set mpm-algo=ac-ks --set spm-algo=bm --set unix-command.enabled=no -k none -r "$run/in.pcap")
    ;;
  snort)
    # Snort 3 預設 HOME_NET=any 會讓 ET 的 !$HOME_NET 被拒絕，這裡與 Suricata 預設一致（同 tests/ids_rules/ids.sh）
    sed -e "s|^HOME_NET = 'any'|HOME_NET = '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]'|" \
        -e "s|^EXTERNAL_NET = 'any'|EXTERNAL_NET = '!\$HOME_NET'|" "$SNORT_ETC/snort.lua" > "$run/snort.lua"
    # alert_fast.file=true: alert 寫到 $run/alert_fast.txt（否則會灌到 stdout，I/O 方式就和 Suricata 不一樣）
    # -k none: 忽略 checksum；--max-packet-threads: 封包處理執行緒數
    # -s 65535: snaplen。Snort 3 預設只看每個封包前 1518 bytes，超過會被截斷；pcap 若有更大的封包，量到的就不是同樣的資料
    cmd=("${pin[@]}" snort -c "$run/snort.lua" --include-path "$SNORT_ETC" -R "$rf"
         --lua "search_engine = { search_method = 'ac_bnfa' } alert_fast = { file = true }"
         -r "$run/in.pcap" -A alert_fast -l "$run" -k none -s 65535 --max-packet-threads "$THREADS")
    ;;
  *) echo "unknown engine $engine"; exit 98 ;;
esac

# 4. 執行。外部牆鐘用 bash 內建的 $EPOCHREALTIME（微秒），比 time -v 的 10 ms 解析度細。
#    /usr/bin/time -v 提供 user/sys CPU 與峰值 RSS（含子行程）。
t0=${EPOCHREALTIME/./}
/usr/bin/time -v -o "$out/time.txt" "${cmd[@]}" > "$out/engine.log" 2>&1
rc=$?
t1=${EPOCHREALTIME/./}
{ echo "wall_us=$((t1 - t0))"; echo "exit_code=$rc"; echo "threads=$THREADS"; echo "cmd=${cmd[*]}"; } > "$out/timing.kv"

# 5. 事後整理（不在計時範圍內）：Suricata 的 stats.log、alert 的 sid 次數
[ -f "$run/stats.log" ] && cp "$run/stats.log" "$out/stats.log"
alertfile="$run/fast.log"; [ "$engine" = snort ] && alertfile="$run/alert_fast.txt"
if [ -f "$alertfile" ]; then
  # 兩個引擎的 fast 格式都有 "[**] [gid:sid:rev]"，用同一條 grep 取 sid
  grep -o '\[\*\*\] \[[0-9]*:[0-9]*:[0-9]*\]' "$alertfile" | cut -d: -f2 | sort | uniq -c | sort -rn > "$out/sids.txt"
else
  : > "$out/sids.txt"
fi
exit $rc
