#!/bin/bash
# eve_cost_pi.sh — EVE 寫檔案和 unix_stream 各花 Suricata 多少 CPU（Pi，Suricata 8.0.7，offline -r，沒有規則、只輸出 flow 事件）
#   none（不開 eve-log）／regular（寫在 SD 卡上的檔案）／unix（unix_stream，讀取端 reader.py fast 綁 CPU 3）
#   Suricata 綁 CPU 2；每種 5 次、順序每輪打亂
#   suricata_cpu_s = Suricata 的 user+sys（bash 的 time）；machine_busy_s = 4 顆 CPU 的經過時間 − idle − iowait（/proc/stat，NO_HZ 下 idle 是精確的）
#   offline 模式下 unix socket 是 blocking（live 模式才是 non-blocking、會丟事件，見 eve_sock_docker.sh），所以這裡量的是全部寫出去的成本
# 前置：pi_lab_mode.sh up 1000、系統的 suricata 服務已停；reader.py 和本檔放在同一個目錄
# 用法: sudo bash eve_cost_pi.sh <pcap> [輪數，預設 5]，結果一行一次寫到 stdout
HERE=$(cd "$(dirname "$0")" && pwd); W=/home/wnc/eo; PC=$1; N=${2:-5}
mkdir -p $W/log; : > $W/empty.rules
yaml() {  # yaml <檔名> <none|regular|unix>
  { printf '%%YAML 1.1\n---\ninclude: /etc/suricata/suricata.yaml\noutputs:\n'
    case $2 in
    regular) printf '  - eve-log:\n      enabled: yes\n      filetype: regular\n      filename: eve.json\n      types:\n        - flow\n' ;;
    unix) printf '  - eve-log:\n      enabled: yes\n      filetype: unix_stream\n      filename: %s/eve.sock\n      types:\n        - flow\n' $W ;;
    none) printf '  - stats:\n      enabled: no\n' ;;
    esac; } > $W/$1
}
idle() { awk '/^cpu[0-9]/{s += $5 + $6} END{print s}' /proc/stat; }
for m in none regular unix; do yaml y-$m.yaml $m; done
for r in $(seq 1 $N); do
  for m in $(printf 'none\nregular\nunix\n' | shuf); do
    rm -rf $W/log/*; rm -f $W/eve.sock $W/reader.out
    if [ $m = unix ]; then
      taskset -c 3 python3 $HERE/reader.py $W/eve.sock fast $W/reader.out &
      for i in $(seq 1 50); do [ -S $W/eve.sock ] && break; sleep 0.1; done
    fi
    sync; i0=$(idle); t0=$(date +%s.%N)
    cpu=$( { TIMEFORMAT='%U %S'; time taskset -c 2 suricata -c $W/y-$m.yaml -r $PC -S $W/empty.rules -l $W/log --runmode single -k none > $W/suri.txt 2>&1; } 2>&1 )
    t1=$(date +%s.%N); i1=$(idle)
    wait
    case $m in
    regular) ev=$(wc -l < $W/log/eve.json) ;;
    unix) ev=$(grep -o 'lines=[0-9]*' $W/reader.out | cut -d= -f2) ;;
    none) ev=0 ;;
    esac
    awk -v r=$r -v m=$m -v cpu="$cpu" -v t0=$t0 -v t1=$t1 -v i0=$i0 -v i1=$i1 -v ev=$ev 'BEGIN{
      split(cpu, c, " "); dt = t1 - t0
      printf "round=%d mode=%s events=%d wall_s=%.2f suricata_cpu_s=%.3f machine_busy_s=%.3f\n", r, m, ev, dt, c[1] + c[2], 4 * dt - (i1 - i0) / 100 }'
  done
done
