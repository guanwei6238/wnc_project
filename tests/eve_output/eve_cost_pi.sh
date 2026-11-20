#!/bin/bash
# eve_cost_pi.sh — how much CPU Suricata spends writing EVE to a file vs unix_stream (Pi, Suricata 8.0.7, offline -r, no rules, flow events only)
#   none (no eve-log) / regular (a file on the SD card) / unix (unix_stream, reader is reader.py fast pinned to CPU 3)
#   Suricata pinned to CPU 2; 5 runs each, order shuffled every round
#   suricata_cpu_s = Suricata's user+sys (bash time); machine_busy_s = elapsed time of the 4 CPUs − idle − iowait (/proc/stat; idle is exact under NO_HZ)
#   In offline mode the unix socket is blocking (only live mode is non-blocking and drops events, see eve_sock_docker.sh), so this measures the cost of writing everything out
# Prerequisite: pi_lab_mode.sh up 1000, system suricata service stopped; reader.py in the same directory as this file
# Usage: sudo bash eve_cost_pi.sh <pcap> [rounds, default 5]; results go to stdout, one line per run
HERE=$(cd "$(dirname "$0")" && pwd); W=/home/wnc/eo; PC=$1; N=${2:-5}
mkdir -p $W/log; : > $W/empty.rules
yaml() {  # yaml <file name> <none|regular|unix>
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
