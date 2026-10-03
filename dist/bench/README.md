# bench/ - Suricata vs Snort 3 vs Zeek on a Raspberry Pi 3B+

A small, reproducible harness that runs **on the Pi** and measures three network
engines, one CSV row per run. A separate traffic-generator host replays pcaps
towards the Pi; the harness either triggers it over ssh (`GEN_CMD`) or waits for
the operator.

| file | purpose |
|---|---|
| `run.sh` | one run of one engine (offline pcap or live af_packet), appends one CSV row |
| `sweep.sh` | outer loop over engines x pcaps x rules x threads x rates x repeats; `--find-ndr` binary search |
| `sweep.conf.example` | config for `sweep.sh` |
| `report.py` | median / p95 Markdown (or CSV) tables from the results CSV (stdlib only) |
| `inline.sh` | Tier 3: one inline (IPS) run of Suricata / Snort 3 / kernel-bridge baseline, long-format CSV |
| `sweep-inline.sh`, `sweep-inline.conf.example` | outer loop around `inline.sh` (engines x rules x threads x tests x repeats, NDR searches) |
| `lib.sh` | helpers shared by `inline.sh` and `sweep-inline.sh` (`run.sh` keeps its own copies) |
| `client/run-client.sh`, `client/setup-client.sh` | run ON the client host: the tests (latency, tcp, udp, http, cps, tls, ttfb) and tool install |
| `server/setup-server.sh` | server host: nginx (:80/:443), iperf3 -s, sockperf server |
| `make-pcaps.py` | deterministic synthetic pcaps (fixed-size UDP, IMIX, HTTP-like TCP) |

## Three-tier method

1. **Tier 1 - offline, all engines.** `--mode offline`: the engine reads a pcap
   (`suricata -r`, `snort -r`, `zeek -r`). Page cache is dropped first. Measures
   pure processing cost (CPU seconds, peak RSS, packets/s) with no NIC or kernel
   capture path involved.
2. **Tier 2 - live passive, all engines.** `--mode live`: engine captures on a
   mirror/tap/direct link with af_packet while the generator replays at a fixed
   rate. Measures drops (kernel and engine), CPU utilisation and the no-drop
   rate (NDR) via `sweep.sh --find-ndr`.
3. **Tier 3 - inline (IPS), Suricata/Snort only** (Zeek cannot run inline): see
   [Tier 3](#tier-3---inline-tests-inlinesh) below.

Synthetic pcaps from `make-pcaps.py` are for smoke tests and frame-size sweeps.
**Use realistic captures for detection-heavy comparisons** (real protocol mixes,
real payloads, a real rule set): synthetic UDP/HTTP traffic exercises almost no
protocol parsers and trips few rules.

## Installing the engines on the Pi (64-bit Raspberry Pi OS bookworm)

```sh
sudo apt-get update
sudo apt-get install -y time ethtool tcpdump wireshark-common python3   # time: /usr/bin/time; capinfos is optional
```

### Suricata
Debian bookworm's `suricata` package is only in `bookworm-backports` (7.0.x);
the harness works with 6.0 and 7.0 (`stats.log` format is the same).
```sh
echo 'deb http://deb.debian.org/debian bookworm-backports main' | sudo tee /etc/apt/sources.list.d/bp.list
sudo apt-get update && sudo apt-get install -y -t bookworm-backports suricata suricata-update
sudo suricata-update            # fetches ET Open into /var/lib/suricata/rules/suricata.rules
```
`--rules full` uses the `rule-files` of `/etc/suricata/suricata.yaml`; to use a
different file export `SURICATA_RULES=/path/file.rules` (passed as `-S`).
`--rules none` uses `-S /dev/null`.

### Snort 3
Install the `libdaq3` and `snort3` debs built from this repo, then convert ET Open:
```sh
sudo apt-get install -y ./libdaq3_*_arm64.deb ./snort3_*_arm64.deb
sudo mkdir -p /etc/snort/rules
sudo scripts/et-open-to-snort3.sh -o /etc/snort/rules/et-open.rules -n 192.168.0.0/16
```
`run.sh` generates `bench.lua` per run: it `include`s `/etc/snort/snort.lua`, overrides
`HOME_NET`/`EXTERNAL_NET` (env `HOME_NET`, default `192.168.0.0/16`) and sets `ips.rules`
to `include /etc/snort/rules/et-open.rules` (`full`) or nothing (`none`).
Override with `SNORT_CONF`, `SNORT_RULES`.
Note: Snort's default `file_id` magic rules (about 219) are loaded even for `none`.

### Zeek
```sh
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | sudo tee /etc/apt/keyrings/security_zeek.gpg >/dev/null
echo 'deb [signed-by=/etc/apt/keyrings/security_zeek.gpg] http://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' | sudo tee /etc/apt/sources.list.d/zeek.list
sudo apt-get update && sudo apt-get install -y zeek-lts      # or: zeek
```
Binary: `/opt/zeek/bin/zeek` (override with `ZEEK_BIN`). Scripts loaded:
`local policy/misc/stats policy/misc/capture-loss` (override with `ZEEK_SCRIPTS`).
Zeek has no rules: `--rules` is recorded as `n/a`. Live capture uses the built-in
`af_packet::IF` plugin (checked with `zeek -N`); without it, plain `-i IF` is used.

## CPU governor

`run.sh` and `inline.sh` set every core's `scaling_governor` to `performance` for the run (needs root), and put each core back
to the governor it had before on every exit path: normal end, `die`, SIGINT and SIGTERM (the log says `CPU governor restored: cpu0:ondemand ...`).
SIGKILL or a power cut cannot be caught, so the governor stays `performance` then. `GOVERNOR=performance|keep` (default
`performance`): `keep` does not touch the governor at all (logged as `GOVERNOR=keep`), any other value is an error. The sweep scripts
start `run.sh`/`inline.sh` once per run, so the restore happens per run (the governor is back to the old value during
`COOLDOWN`); they add no governor logic, just `export GOVERNOR=keep` in the shell or the sweep config. `CPUFREQ_ROOT` (default
`/sys/devices/system/cpu`) is only there for tests with a fake tree.

On a Pi that is undervoltage-throttled (see the `get_throttled` warning), the firmware caps the clock whatever the governor says, so
`performance` mostly costs extra power draw without extra speed: `GOVERNOR=keep` is reasonable until the power supply is fixed
(results from such runs are unreliable anyway).

## Logs on tmpfs

An SD card will distort every result, so engine logs go to a tmpfs. `run.sh` mounts
`--logdir` (default `/run/bench-logs`, 256 MB) as tmpfs if it is not already one. To make
it permanent: `tmpfs /run/bench-logs tmpfs size=256M,mode=0755 0 0` in `/etc/fstab`.
Each run's raw output is kept in `$LOGDIR/<timestamp>-<engine>-<pid>/` (`engine.out`,
`work/` with stats.log / conn.log / ..., `time.txt`, `bench.lua`, `gen.out`) and the path
is the last CSV column. Files over 20 MB are deleted after the run and only the
newest `KEEP_RUNS` (30) directories are kept; copy what you need off the Pi.
Suricata's fast/eve outputs are disabled for speed (`KEEP_OUTPUTS=1` keeps them), Snort
runs with `-A none`; alert *counts* still come from engine counters. Zeek's logs stay on
(that is its job) but are on tmpfs.

## Per-run preparation (done by run.sh)

* CPU governor set to `performance` where writable (prints the old value; restored on exit; `GOVERNOR=keep` skips it, see [CPU governor](#cpu-governor)).
* Live: `ethtool -K IF gro off lro off gso off tso off` (printed, not restored).
* Offline: `sync; echo 3 > /proc/sys/vm/drop_caches`.
* Warns if `vcgencmd get_throttled` is non-zero at start.

## run.sh

```
sudo ./run.sh --engine {suricata|snort3|zeek} --mode {offline|live} --pcap FILE \
     [--iface IF] [--pps N] [--duration S] [--threads N] [--rules {full|none}] \
     [--label STR] [--out results.csv] [--logdir DIR]
```
Defaults: `--threads 1`, `--rules full`, `--duration 30` (live), `--out results.csv`.
Environment: `GEN_CMD`, `SETTLE` (5 s after the engine reports ready), `DRAIN` (5 s after replay),
`READY_TIMEOUT` (300 s; rule loading is slow on a Pi), plus the engine variables above.

* **offline**: `suricata -c CONF -r PCAP` (`--runmode single` when `--threads 1`, otherwise
  Suricata's default autofp with one worker per core), `snort -c bench.lua -r PCAP -k none -A none`,
  `zeek -C -r PCAP SCRIPTS`. `--threads` does not change Snort/Zeek offline.
* **live**: `suricata --af-packet --runmode workers --set af-packet.0.interface=IF --set af-packet.0.threads=N`,
  `snort --daq afpacket -i IF -z N --daq-var fanout_type=hash -k none -A none`,
  `zeek -C -i af_packet::IF SCRIPTS` (single process; `--threads` only recorded).
  The engine is started, run.sh waits until it is ready (+SETTLE), snapshots NIC counters,
  runs the generator, waits DRAIN, snapshots NIC counters again and stops the engine with SIGTERM.

Timing definitions: `wall_s` and `cpu_s` / `peak_rss_kb` are from `/usr/bin/time` on the engine
process, so they include start-up and rule loading (large with ET Open on a Pi). `replay_s` is the
duration of the generator command (live). `cpu_util_pct` is the average over all cores from
`/proc/stat` deltas: for offline over the whole engine run, for live over the replay window only.
`proc_pps = eng_proc_pkts / wall_s` offline and `/ replay_s` live.
Offline `proc_pps` therefore includes start-up; use `cpu_s` and compare big pcaps for steady state.

### GEN_CMD contract (generator side)

`GEN_CMD` is run locally with `bash -c` after `$PPS`, `$DURATION`, `$PCAP` (the local
path given with `--pcap`) and `$PCAP_BASENAME` are substituted (also exported as env vars).
Single-quote it so your shell does not expand them early. It must return when the replay is
finished. Example (pcap pre-copied to the same directory on the generator):
```sh
export GEN_CMD='ssh gen tcpreplay -i eth1 --loop=0 --pps=$PPS --duration=$DURATION /srv/pcaps/$PCAP_BASENAME'
```
`--loop=0` repeats the pcap until `--duration` ends (tcpreplay 4.x). If the command prints
tcpreplay's `Actual: N packets ...` line, N is stored as `gen_sent_pkts` and used as the
reference for `total_drop_pct`. Without `GEN_CMD`, run.sh prints
`Start replay now, press Enter when finished` and waits.

## CSV columns (fixed order; empty = not applicable/unavailable; commas are stripped from fields)

| column | meaning |
|---|---|
| timestamp, hostname | UTC end time, `hostname` |
| engine, version | suricata/snort3/zeek and parsed version (`suricata -V`, `snort -V`, `zeek --version`) |
| mode, pcap | offline/live, pcap basename |
| pcap_pkts, pcap_bytes | packets and wire bytes in the pcap (`capinfos` if present, else built-in pcap/pcapng reader) |
| pps_req, duration_req | requested rate and replay duration (live) |
| threads, rules, label | threads, `full`/`none`/`n/a` (zeek), free label |
| wall_s, replay_s | engine wall time; generator command duration (live) |
| cpu_s | engine user+sys CPU seconds (process tree, `time -f %U %S`) |
| cpu_util_pct | average CPU utilisation over all cores (see above) |
| peak_rss_kb | max resident set size (`time -f %M`) |
| nic_rx_packets, nic_rx_bytes, nic_rx_dropped, nic_rx_missed, nic_rx_fifo | delta of `/sys/class/net/IF/statistics/{rx_packets,rx_bytes,rx_dropped,rx_missed_errors,rx_fifo_errors}` (live; empty if the driver lacks the counter) |
| gen_sent_pkts | packets reported sent by tcpreplay (live, if GEN_CMD output has the `Actual:` line) |
| eng_rx_pkts | packets seen by the capture layer (see below) |
| eng_proc_pkts | packets decoded/analysed by the engine |
| eng_drop_pkts | packets dropped by the capture layer (kernel) |
| eng_flows, eng_alerts | flows/sessions seen; alerts (Zeek: `notice.log` rows) |
| proc_pps | processed packets per second |
| eng_drop_pct | `100 * max(0, rx - drop - proc) / rx`: lost inside the engine |
| kernel_drop_pct | `100 * drop / rx`: lost in the kernel capture path |
| total_drop_pct | `100 * max(0, ref - proc) / ref`; ref = `gen_sent_pkts`, else NIC `rx_packets+missed+fifo` (live), else `pcap_pkts` (offline) |
| temp_start_c, temp_end_c, throttled_start, throttled_end | `vcgencmd measure_temp` / `get_throttled` (empty without vcgencmd) |
| exit_code | engine exit status (live: SIGTERM stop counts as 0) |
| logdir | per-run raw output directory |

Engine counter sources:

| engine | eng_rx_pkts | eng_proc_pkts | eng_drop_pkts | eng_flows | eng_alerts |
|---|---|---|---|---|---|
| Suricata | `capture.kernel_packets` (else `decoder.pkts`) | `decoder.pkts` | `capture.kernel_drops` (absent = 0) | `flow.total` (else tcp+udp) | `detect.alert` |
| Snort 3 | `daq: received` | `daq: analyzed` | `daq: dropped` (absent = 0) | `stream: flows` | `detection: total_alerts` |
| Zeek | proc + dropped | sum of `pkts_proc` in `stats.log` | sum of `pkts_dropped` (`-` = 0) | rows in `conn.log` | rows in `notice.log` |

Suricata uses the last block of `stats.log`; Zeek's `stats.log` rows are per-interval deltas, so they
are summed. Zeek drops are only what the capture plugin reports; Zeek has no separate "engine drop".
`eng_alerts` is not comparable across engines (different rule sets, Zeek notices are not signatures).

## sweep.sh

```sh
cp sweep.conf.example sweep.conf; $EDITOR sweep.conf
sudo ./sweep.sh -c sweep.conf                 # full cross product
sudo ./sweep.sh -c sweep.conf --find-ndr      # no-drop-rate search (live only)
```
The config is a sourced bash file (`ENGINES PCAPS PPS_RATES REPEATS THREADS RULES MODE IFACE GEN_CMD
DURATION OUT LOGDIR LABEL COOLDOWN TEMP_MAX PPS_MIN PPS_MAX RESOLUTION LOSS_TOLERANCE`).
Between live runs it sleeps `COOLDOWN` s and, if `vcgencmd` exists, waits until the SoC is below
`TEMP_MAX` (55 C). Zeek runs once per combination regardless of `RULES`.

`--find-ndr`: for each engine/pcap/rules/threads it probes `PPS_MAX`; if that passes it is the NDR,
otherwise it checks `PPS_MIN` and bisects until `hi - lo <= RESOLUTION`. A probe passes when
`total_drop_pct <= LOSS_TOLERANCE` (default 0.1) **and** the generator really sent at least 95 % of the
requested rate (otherwise the result would be generator-limited, which is logged and counted as a fail).
Each probe is a normal CSV row with label `ndr-search`; a final extra run at the found rate is labelled
`ndr-result`.

## report.py

```sh
./report.py results.csv          # Markdown tables
./report.py results.csv --csv    # aggregated CSV
```
Groups by engine, mode, pcap, pps, threads, rules and prints n, median and p95 of processed pps, engine
drop %, kernel drop %, CPU %, peak RSS (MB), wall s and alerts; a second table lists `ndr-result` rows.
`ndr-search` probes are excluded from the first table.

## Tier 3 - inline tests (inline.sh)

The Pi forwards real traffic between two hosts while an engine inspects it, so latency, throughput,
connection rate and loss *through the engine* can be measured.

```
  client host                          Raspberry Pi 3B+                          server host
 +------------+   cable   +--------------------------------------------+  cable  +------------+
 | test NIC   |-----------| IF_A  [ engine inline (or kernel bridge) ] IF_B |---------| test NIC   |
 | 10.10.0.2  |           |  (no IP, promisc)                (no IP)    |         | 10.10.0.3  |
 | run-client |           |  inline.sh (driver)                         |         | nginx      |
 +------------+           |  wlan0 = management (ssh), NOT in the path  |         | iperf3 -s  |
        ^                 +--------------------------------------------+         | sockperf   |
        |  CLIENT_CMD (ssh) triggers run-client.sh, reads metric=value lines      +------------+
        +------------------------- management network (Wi-Fi) -----------------------------+
```

* Addressing: client `10.10.0.2/24`, server `10.10.0.3/24` (`SERVER_IP`, default `10.10.0.3`) on their test NICs.
  IF_B on the Pi carries **no IP** (`inline.sh` refuses to run if it does), IF_A carries none either unless you use in-band
  management (below). IPv6 is disabled on both (router solicitations would pollute the counters) and both go promiscuous
  for the engine.
* The Pi is managed either over **Wi-Fi / a third interface** (IF_A and IF_B stay address-less, `MGMT_NET` unset) or **in-band over the
  test cable on IF_A**, see [In-band management](#in-band-management-mgmt_net). Keep ssh and the CSV on that path.
* The Pi 3B+ has one NIC on the USB 2.0 bus. Use two USB Ethernet adapters for IF_A/IF_B (and the
  built-in one for management if you prefer), e.g. **Realtek RTL8153** or **ASIX AX88179** (gigabit chips;
  the link is limited by USB). Both adapters and the on-board NIC **share one USB 2.0 bus** (480 Mbit/s raw),
  so expect a ceiling of about **150 Mbit/s per direction in total** when forwarding. That is the baseline
  limit, not the engine.
* Offloads are disabled on **all four NICs** (client, IF_A, IF_B, server): `ethtool -K IF gro off lro off
  gso off tso off`. `inline.sh` does this for IF_A/IF_B; do it by hand on the two hosts (the setup scripts
  print the command). With GRO/LRO on, the engine would see super-packets and forwarding would break
  or look unrealistically fast.

### In-band management (MGMT_NET)

When the Pi has no Wi-Fi and no third NIC, IF_A can carry a management address in a **separate subnet** (not the
test subnet), so the client reaches the Pi over the test cable and `CLIENT_CMD`'s ssh (Pi -> client) uses the same link:

```
 client test NIC: 10.10.0.2/24 (test) + 192.168.99.2/24 (management)  --cable-->  IF_A: 192.168.99.1/24   [engine / bridge]  IF_B (no IP) --> server
```
`inline.sh` decides by itself, there is no switch:

| IF_A | `MGMT_NET` | behaviour |
|---|---|---|
| no IPv4 address | unset | exactly the classic mode (address-less, no filter, no counters) |
| has IPv4 address(es) | unset | management mode, `MGMT_NET` derived from the configured prefix (logged); several prefixes: error, set `MGMT_NET` |
| any | set (e.g. `192.168.99.0/24`) | management mode with that prefix; every IPv4 address on IF_A must lie inside it, else error |

IF_B must still have no IP. Manual setup with plain `ip` (no NetworkManager assumed; persisting it is up to you):

```sh
# Pi (IF_A = eth1)
sudo ip addr add 192.168.99.1/24 dev eth1 ; sudo sysctl -w net.ipv6.conf.eth1.disable_ipv6=1 ; sudo ip link set eth1 up
# IF_B (eth2): nothing, no address
# client (test NIC = enx...): second address next to 10.10.0.2/24, IPv6 off on that NIC
sudo ip addr add 192.168.99.2/24 dev enx... ; sudo sysctl -w net.ipv6.conf.enx....disable_ipv6=1
export CLIENT_HOST=192.168.99.2          # the Pi reaches the client over the test cable
```
IPv6 must be off on the client's test NIC: its router solicitations and MLD reports are not in `MGMT_NET`, so the filters
below do not exclude them and they would cross the engine to the server side (seen in the idle counters of the experiment).

What the Pi/engine do in management mode, and why it is needed. af_packet does not take packets away from the kernel (the kernel
still answers ssh on IF_A), but an inline engine **also captures frames the Pi itself transmits on IF_A** and copies everything it
captured to the other port. Measured in the Docker testbed with Suricata IPS copy mode and no filter, during an ssh session
cli <-> Pi: the client's frames to the Pi's address (SYN, data, ACKs), the Pi kernel's own replies (`gw MAC > client MAC ... Flags
[S.]`) and the ARP request/reply for the management addresses all appeared on IF_B and at the server (every one of the 97 frames of a
short session). So:

* **Suricata**: `bpf-filter=not net $MGMT_NET` on **both** af-packet entries (the plain form: libpcap's unqualified `net`
  matches IPv4 source/destination and ARP sender/target). Suricata warns that non-matching packets are dropped in IPS mode;
  here that means management frames are simply not captured, hence not forwarded. Verified: 0 management frames on IF_B and
  at the server, and the engine's `rx` counter is the same with and without ssh activity (5002 vs 5002 packets for the same test,
  versus 5477 without the filter).
* **`--engine none`**: an IP cannot sit on a bridge port. For the run `inline.sh` gives `br0` IF_A's MAC (the client's ARP
  cache stays valid), moves IF_A's address(es) and non-kernel routes to `br0` and installs an nftables table
  `bridge inline_mgmt_br` on the **postrouting** hook that drops `MGMT_NET` IPv4 and its ARP going out of IF_B (postrouting
  also covers the bridge's own flooded broadcast ARP requests, which `forward` would miss). The addresses move back on exit.
  Without the rule only the broadcast ARP requests leaked (2 frames); with it, 0. An ssh session opened before the run survives the
  move (no gap in a 5 Hz heartbeat). Cleanup (nft tables, bridge, addresses, routes) runs on every exit path (normal, die,
  SIGINT/SIGTERM) and is idempotent; SIGKILL cannot be caught (then remove `br0`, the nft table and re-add the address by hand).
* **Snort 3** + management mode is a **stub**: `inline.sh` stops with "in-band management not yet verified for Snort 3 / DAQ
  afpacket" (function `mgmt_snort3_stub`). Without management mode (IF_A address-less) Snort 3 is unchanged. Not verified yet
  (from reading the sources, to be checked when Snort 3 is built): a filter would go in via `-F`/`bpf_file` or the DAQ's
  `set_filter` (libdaq afpacket attaches it with `SO_ATTACH_FILTER`), and whether DAQ afpacket sees the Pi's outgoing frames.

**Management traffic accounting.** `inline.sh` creates an nftables `netdev` table (`inline_mgmt_ctr`: ingress and egress hooks on IF_A, IPv4
`MGMT_NET` src/dst and its ARP), reads it before/after the measurement and deletes it on exit. Metric rows (CSV schema
unchanged): `mgmt_ifa_rx_pkts`, `mgmt_ifa_rx_bytes`, `mgmt_ifa_tx_pkts`, `mgmt_ifa_tx_bytes`. nft counts bytes from the IP header on, so they are
about 14 B per packet below the sysfs counters. If `nft` or the egress hook (kernel >= 5.16) is missing it warns and skips. Caveat: the
`ifa_*` sysfs columns still include management frames (the filter keeps them from the engine, not from the NIC counters), so
`ifa_rx ~ ifb_tx` is off by about the management counts; compare with the `mgmt_*` rows. Idle cost measured over 60 s: no session
about 2 frames, an idle ssh session without keepalive about 1 ARP pair, with `ServerAliveInterval=5` about 37 frames (about 3 KB), a new
ssh login about 54 frames (about 11 KB).

**ssh ControlMaster.** The default `CLIENT_CMD` is `ssh $CLIENT_SSH_OPTS $CLIENT_HOST ...` with `CLIENT_SSH_OPTS` = `-o ControlMaster=auto -o
ControlPath=/run/bench-ssh/%C -o ControlPersist=10m` (`/run/bench-ssh` is on tmpfs, mode 700), so consecutive runs (and the sweeps) reuse one connection.
Measured with the mgmt counters (`--engine none`, 100-connection cps run): without it 55 frames / 11.7 KB per run; with it the first run
46 frames (it opens the master), later runs 21-23 frames / about 2 KB. Override `CLIENT_SSH_OPTS` (set it to a single space to turn it off) or the whole `CLIENT_CMD`; `ssh -O exit` stops
the master.

### Setup

```sh
# server host
sudo bench/server/setup-server.sh            # nginx :80/:443 (HTTP/1.1, keepalive, sendfile, self-signed cert),
                                             # /var/www/bench/{1k,100k,1m}; systemd units if systemd runs
sudo bench/server/setup-server.sh --start    # no systemd: start nginx, iperf3 -s, sockperf server (udp+tcp :11111)
# client host
sudo bench/client/setup-client.sh            # iperf3 sockperf nghttp2-client curl openssl
# Pi: needs ethtool, time, the engines (see above), ssh access to the client
export CLIENT_HOST=client.local              # default CLIENT_CMD runs: ssh $CLIENT_HOST bench/client/run-client.sh ...
sudo -E ./inline.sh --engine snort3 --rules full --threads 2 --ifa eth1 --ifb eth2 --test tcp --duration 30
```
Both setup scripts are idempotent. `bench/` must exist on the client at the path the `CLIENT_CMD` uses
(default: relative to the ssh login directory, i.e. `~/bench`).

### How each engine is run inline

| engine | mechanism |
|---|---|
| `none` | **Baseline / floor.** Creates a kernel bridge (`ip link add br0 type bridge`, IF_A and IF_B as ports, offloads off), removes it afterwards. This is the in-kernel L2 forwarding path, which is *different* from the engines' userspace af_packet forwarding (packet copied to userspace and written back by `sendto`/TX ring): the bridge is the best case, not "an engine that does nothing". |
| `suricata` | af-packet **IPS copy mode**, two entries passed with `--set` (verified on Suricata 7.0.10): `af-packet.0` = `IF_A` -> copy-iface `IF_B` (cluster-id 98), `af-packet.1` = `IF_B` -> `IF_A` (cluster-id 99), `copy-mode=ips`, `threads=N` **per interface**, `cluster-type=cluster_flow`, **`tpacket-v3=no`** (v3 is not supported in copy mode), `use-mmap=yes`, `defrag=yes` (Suricata warns that defrag is not recommended inline; set `SURICATA_DEFRAG=no` to turn it off), plus `--runmode workers --af-packet`, `stats.enabled=yes`, fast/eve outputs disabled (`KEEP_OUTPUTS=1` keeps them). Rules `none` = `-S /dev/null`, `full` = rule-files of the config or `SURICATA_RULES`. |
| `snort3` | `snort -c bench.lua --daq afpacket -i IF_A:IF_B -Q -z N -k none -A none --daq-var fanout_type=hash` (colon = inline pair, `-Q` = inline mode). `bench.lua` is generated as in `run.sh` (`HOME_NET` default here `10.10.0.0/24`). Multiple packet threads work with the inline pair on DAQ afpacket v7 (`-z 2` verified: two `s3.pkt-iN` threads, traffic forwarded); if the engine fails to start with `-z N > 1`, `inline.sh` falls back to `-z 1`, warns and records it in the `note` column. |

**Rules only alert; nothing is ever set to drop**, so the engines forward every packet and the measured cost is
inspection, not blocking. Logs go to the tmpfs `--logdir` as for the other tiers; engine counters, SIGTERM stop,
readiness detection (`Engine started` / `Commencing packet processing`), CPU governor and temperature handling
are the same as `run.sh`.

### inline.sh

```
sudo ./inline.sh --engine {none|suricata|snort3} --test {latency|tcp|udp|http|cps|tls|ttfb}
     [--ifa IF] [--ifb IF] [--threads N] [--rules {full|none}] [--label STR] [--out inline.csv] [--logdir DIR]
     [test args: --duration --streams --conns --reqs --rate --frame --object --count --port --proto --client-threads]
     [--find-ndr --frame SIZE]
     [cps RFC 9411 mode: --target-cps N --init-s --ramp-s --sustain-s --slice-s --fail-txn-max-pct --rst-max-pct --rate-dev-max-pct]
```
`--threads` is the **engine's** thread count; the load generator's thread count is `--client-threads`.
Environment: `CLIENT_CMD`, `CLIENT_HOST`, `SERVER_IP`, `CLIENT_TIMEOUT` (900 s; with `--target-cps` the default is raised to at least init+ramp+sustain+120 s), `GOVERNOR` (`performance`|`keep`, see [CPU governor](#cpu-governor)), `SETTLE`/`DRAIN` (5/5 s), `READY_TIMEOUT`,
`BRIDGE`, `HOME_NET`, `SNORT_CONF`, `SNORT_RULES`, `SURICATA_CONF`, `SURICATA_RULES`, `SURICATA_DEFRAG`, and for
`--find-ndr`: `PDR_LOSS`, `NDR_LOSS`, `RATE_MIN`, `RATE_MAX`, `RATE_RES`.

Flow: prepare interfaces -> start engine (or bridge) -> wait ready + `SETTLE` -> run the client test
-> `DRAIN` -> stop the engine with SIGTERM -> read counters -> append rows.

`CLIENT_CMD` is a shell template run on the Pi with `$TEST`, `$SERVER_IP` and `$ARGS` substituted; it must end up
running `run-client.sh` on the client host and print its stdout. Default (when `CLIENT_HOST` is set):
`ssh $CLIENT_SSH_OPTS $CLIENT_HOST bench/client/run-client.sh $TEST $SERVER_IP $ARGS` (ControlMaster options, see [In-band management](#in-band-management-mgmt_net)). With neither set, `inline.sh` prints the
command to run by hand and reads the `metric=value` lines from stdin until EOF.

### Tests (client/run-client.sh TEST SERVER_IP [args]; stdout = `metric=value` lines)

| test | what | metrics |
|---|---|---|
| `latency` | `sockperf ping-pong -i SERVER -p 11111 -t DURATION --full-rtt` (UDP, 14-byte messages; `--proto tcp` for TCP). Without sockperf: `ping -i 0.01 -c COUNT` (root needed for 10 ms) with percentiles from the per-packet times | `tool`, `rtt_p50_us`, `rtt_p99_us`, `rtt_p999_us`, `rtt_avg_us`, `rtt_min_us`, `rtt_max_us`, `rtt_samples`, `rtt_lost` |
| `tcp` | `iperf3 -c SERVER -J -t DURATION -P STREAMS` | `tcp_mbps` (receiver), `tcp_retransmits`, `tcp_streams` |
| `udp` | `iperf3 -J -u -b RATE -l PAYLOAD -t DURATION`; `--frame` F gives PAYLOAD = F - 42 (14 Ethernet + 20 IP + 8 UDP, no FCS), clamped to [16, 1472] | `udp_offered_mbps` (requested), `udp_sent_mbps` (actual), `udp_recv_mbps`, `udp_pps`, `udp_loss_pct`, `udp_jitter_ms`, `frame_bytes_actual`. iperf3's rate counts UDP *payload* bits. |
| `http` | `h2load --h1 -c CONNS -n REQS -t THREADS http://SERVER/OBJECT` (keepalive; default object `100k`). h2load prints only min/max/mean/sd, so percentiles are computed from `--log-file` (per-request time) | `http_rps`, `http_succeeded`, `http_failed`, `http_req_p50_ms`, `http_req_p99_ms`, `http_req_mean_ms`, `http_ttfb_mean_ms` (summary) |
| `cps` | connections per second. **Legacy burst** (no `--target-cps`): `h2load --h1 -c N -n N` = one request per connection, so each is a new TCP connection (default 500 x 1k object). `--rate R` adds `-r R` (connections/s pacing). If `--reqs` > `--conns` it sends `Connection: close` so h2load reconnects for every request. **RFC 9411 mode** (`--target-cps N`): phased load with pass/fail criteria, see [cps RFC 9411 mode](#cps-rfc-9411-mode---target-cps) | legacy: `cps_achieved`, `cps_succeeded`, `cps_failed`, `connect_time_mean_ms`, `rfc9411_conformant=no`, `rfc9411_deviations=legacy-burst`. RFC mode: see below |
| `tls` | `openssl s_time -connect SERVER:443 -new -time DURATION` (new full handshake per connection; rate = connections / wall-clock, not openssl's per-"user sec" figure) and `h2load --h1 https://...` with `-c N -n N` | `tls_handshakes_total`, `tls_handshakes_per_s`, `tls_handshakes_per_user_s`, `tls_cps`, `tls_failed`, `tls_connect_mean_ms`, `tls_protocol`, `tls_cipher` |
| `ttfb` | `curl -s -o /dev/null -w '%{time_connect} %{time_starttransfer} %{time_total}'` COUNT times (default 200, object `1m`), sequential, new connection each time. TTFB is measured from the start of the request (includes connect) | `ttfb_p50_ms`, `ttfb_p99_ms`, `ttlb_p50_ms`, `ttlb_p99_ms`, `connect_p50_ms`, `ttfb_failed` |

Arguments: `--duration` (10) `--streams` (1) `--conns` `--reqs` `--client-threads` (h2load, 2) `--rate` (Mbit/s, udp default 10)
`--frame` (512) `--object` `--count` `--port` (sockperf, 11111) `--proto`. All tools are checked with `command -v` and the script
fails with a clear message when one is missing. Diagnostics go to stderr, so only metrics reach the CSV.

### cps RFC 9411 mode (--target-cps)

`--test cps --target-cps N` runs the load profile of RFC 9411 (benchmarking methodology for network security devices:
the "TCP/HTTP connections per second" test) and checks the RFC's acceptance criteria. Without `--target-cps` the
legacy burst runs unchanged (and only adds `rfc9411_conformant=no`).

Phases (the defaults are the RFC values; every value can be set by flag, else env var, else default):

| phase | default | flag / env | what happens |
|---|---|---|---|
| Init | 5 s | `--init-s` / `INIT_S` (falls back to `SETTLE`) | idle time after the engine is ready, no traffic. It is the same wait `inline.sh` already did as `SETTLE`, not a second sleep. The value is passed to the client only so it is recorded and checked for conformance |
| Ramp-up | 30 s | `--ramp-s` / `RAMP_S` | three steps of RAMP_S/3 at 25 %, 50 %, 75 % of the target. **Not measured**: only logged (`#ramp` lines), results discarded |
| Sustain | 300 s | `--sustain-s` / `SUSTAIN_S` | 100 % of the target. **All KPIs are measured here only** |
| Sampling | 1 s | fixed | one bucket per second (the RFC requires < 2 s) |

Thresholds: `--fail-txn-max-pct` / `FAIL_TXN_MAX_PCT` (0.001), `--rst-max-pct` / `RST_MAX_PCT` (0.001),
`--rate-dev-max-pct` / `RATE_DEV_MAX_PCT` (5). `--slice-s` / `SLICE_S` (10) sets the load-generator slice length (below).
Env-only: `SLICE_GRACE_S` (15), `SLICE_MAX_ALIVE` (4), `TXN_TIMEOUT_S` (10, h2load `-T`: a connection open longer
than that is a failed transaction). `--conns` is rejected in this mode. Example:

```sh
sudo -E ./inline.sh --engine suricata --rules full --threads 2 --ifa eth1 --ifb eth2 --test cps --target-cps 1000
# shortened, NOT conformant:  ... --test cps --target-cps 1000 --ramp-s 6 --sustain-s 20
```

**How the load is generated.** h2load's `--rps` is silently ignored with `--h1` (measured: `-c 50 --rps 20` ran at
about 39000 req/s) and `-r` and `-D` are mutually exclusive, so a single `-D` run cannot hold a fixed connection rate.
Instead every phase is cut into slices of `SLICE_S` seconds, each one
`h2load --h1 -r R --rate-period=P -c N -n N -t 1 -H "Connection: close" --log-file=slice-K.log`
(N clients with one request each = N new TCP connections, R opened every P ms, N = R x slices' periods). h2load accepts
the period only as an integer number of ms, so R/P is chosen for the target: the largest P <= 10 ms within 0.5 % of the
target, else the closest R/P with P up to 20 ms; below 100/s R = 1 and P = 1000/target. The nominal rate actually used
is reported as `cps_nominal` (and the pair as `cps_pacing`, e.g. `10/10ms`); it can differ slightly from the target,
`cps_sustain_mean` is what was really achieved. Pacing is smooth inside a slice (checked: 1 s buckets of 1000.0 +/- 0 and
per-10 ms buckets of exactly R). Slices start on an **absolute schedule** (slice K at t0 + its offset, in the
background), so a slow tail overlaps the next slice instead of opening a gap. A slice still running `SLICE_GRACE_S`
after its window is killed and counted as a failure signal (`slices_overrun`, its unfinished transactions count as failed);
if `SLICE_MAX_ALIVE` h2load processes are already alive the slice is not started (`slices_skipped`, all its transactions
failed). One h2load thread (`-t 1`) is used: with several threads h2load divides the rate per thread. Practical
limits (x86 client, tested): 10 000 connections/s used about 24 MB RSS and 5 file descriptors per slice (connections are
short-lived); on a slow path open connections = rate x latency, `ulimit -n` is raised to the hard limit. The
client's ephemeral port range (about 28 000 ports) is the next limit if the server holds TIME_WAIT. Rate quantisation: a
1 s bucket holds R-sized bursts, so at very low targets (about 20/s) 1 s buckets alone exceed 5 %.

**Failures in h2load output.** A connection that fails (refused, reset, timeout) does **not** appear in `--log-file`
(only completed requests, any HTTP status, are logged); it shows only in the summary line (`failed`, `errored`,
`timeout`; `failed` already includes the other two). `txn_total` is therefore the sum of the slices' N and
`txn_failed` = N - succeeded, so slices that were killed or skipped count too. The per-second series comes from the
merged sustain logs, by **completion** time (start + duration) of requests with status < 400.

**Acceptance criteria** (all over the sustain phase; the verdict metrics are `pass` or `fail`):

| criterion | rule | source |
|---|---|---|
| `crit_failed_txn` | `txn_failed_pct` < `FAIL_TXN_MAX_PCT` | h2load summaries |
| `crit_rst` | `rst_pct` < `RST_MAX_PCT`, `rst_count` = delta of `TcpEstabResets` + `TcpAttemptFails`, `rst_pct` = that / delta of `TcpActiveOpens` | `nstat -az` on the client, snapshots at the start and end of the sustain window |
| `crit_rate_dev` | every 1 s bucket within +/- `RATE_DEV_MAX_PCT` of the mean of the buckets; the first and last second are dropped | merged sustain logs |
| `crit_all` | all three pass | |

`TcpEstabResets` counts established connections killed by a received RST, `TcpAttemptFails` counts connection attempts
that ended in a RST (refused) or time-out; both are connection-level and cannot be mixed up with RSTs the client sent
itself (`TcpOutRsts` is recorded as `nstat_tcpoutrsts` for information only). The denominator is the client's
connection count in the same window. A client-side counter sees an engine's RST injection or a middlebox reset, which
h2load alone may report as a generic error.

Metrics (long-format rows, schema unchanged): `cps_target`, `cps_nominal`, `cps_pacing`, `cps_sustain_mean`,
`cps_sustain_min`, `cps_sustain_max`, `cps_samples` (buckets used), `cps_dev_max_pct`, `cps_dev_violations` (buckets
outside the band), `txn_total`, `txn_failed`, `txn_failed_pct`, `rst_count`, `rst_pct`, `nstat_tcpactiveopens`,
`nstat_tcpattemptfails`, `nstat_tcpestabresets`, `nstat_tcpoutrsts`, `slices_total`, `slices_overrun`, `slices_skipped`,
`crit_failed_txn`, `crit_rst`, `crit_rate_dev`, `crit_all`, the thresholds in force (`fail_txn_max_pct`, `rst_max_pct`,
`rate_dev_max_pct`), the phase lengths used (`init_s`, `ramp_s`, `sustain_s`, `slice_s`), `rfc9411_conformant`
(`yes`/`no`) and `rfc9411_deviations` (`none` or e.g. `sustain=20s<300s;ramp=none`). **Conformant = yes** only if
init >= 5 s, a ramp is present, sustain >= 300 s and no threshold is looser than the default; this is decided in one place
(`rfc_report` in `client/run-client.sh`). Per-second series and per-slice lines are written to the client's stdout as
`#series sustain_s=K conn_per_s=C` (first/last second marked `dropped`), `#slice ...` and `#ramp ...`; the metric
parser ignores `#` lines, so they stay in `$RUN/client-N.out` in the tmpfs log directory (never on the SD card; copy them off
with the rest of the run directory). Each run writes one set of rows; `report.py` shows `rfc9411_conformant` etc. as text metrics.

### Docker testbed (docker/bench, outside this tarball)

`docker/bench/` (in the repository, next to `bench/`; see its README for up/down, hub mode and the checksum-offload note) gives an
L2-transparent lab on one machine: `cli` (10.10.0.2/24, h2load/iperf3/sockperf/nstat, sshd) -- `gw` (privileged; `IF_A`/`IF_B` without
IP; suricata, nftables, `bench/` mounted at `/opt/bench`, `/run/bench-logs` is tmpfs) -- `srv` (10.10.0.3/24,
`bench/server/setup-server.sh`). `gw` drives the client over ssh, exactly the default `CLIENT_HOST` flow. `docker/bench/mgmt.sh on`
adds the in-band management addresses (192.168.99.0/24) so the management mode above can be exercised.

What it proves and what it does not: the orchestration, parsing, criteria, conformance and management logic, and the engines' IPS
wiring behave as on the Pi (same Debian trixie packages, same af-packet copy mode, same tmpfs log dir). Not equivalent:
veth has no USB 2.0 bus ceiling (about 150 Mbit/s on the Pi), the x86 CPU is much faster (so the target CPS that fails on the
Pi passes here) and there are no real NIC drivers/offloads. Docker numbers validate the logic, not the Pi's performance.
**Snort 3 was not tested in Docker** (not packaged for trixie; building it from `packaging/` was skipped);
only `none` and `suricata` were exercised.

### NDR / PDR search (`--find-ndr --frame SIZE`, udp test only)

One engine session, many probes: the engine is started once and `iperf3 -u` is run at a series of offered rates
(Mbit/s of UDP payload). **PDR** = highest rate with loss <= `PDR_LOSS` (default 0.5 %), **NDR** = highest with loss
<= `NDR_LOSS` (default 0.01 %). Search range `RATE_MIN`..`RATE_MAX` (5..100), resolution `RATE_RES` (2) Mbit/s, integer rates:
`RATE_MAX` is probed first (pass = result), then `RATE_MIN` (fail = result 0), then bisection; PDR is searched first and NDR
below it. Loss is iperf3's receiver-side `lost_percent` from the client. A probe counts as a **failure** if the client could not
send 95 % of the requested rate (generator-limited; warning printed). Every probe is stored as rows labelled `ndr-search`; the result as rows
`metric=ndr_mbps / pdr_mbps / ndr_pps / pdr_pps` labelled `ndr-result` (pps = rate / (8 x payload bytes), `test_args` holds the frame
size, thresholds and range).

Caveats: iperf3 paces UDP in userspace and small frames need very high packet rates (64 B at 100 Mbit/s of payload
is about 570 kpps), so **results at 64 B are generator-limited unless the client is strong**: check for the
generator-limited warnings and `udp_sent_mbps`. Loss is end-to-end (client to server), so it includes anything the NICs,
the USB bus and the host drop, not only the engine; compare against the `none` baseline measured with the same frame size.
A single probe is `--duration` seconds (default 10); short probes make NDR noisy.

### Long-format CSV (inline.csv)

One row per metric per measurement; empty = not applicable.

| column | meaning |
|---|---|
| run_id | `<timestamp>-inline-<engine>-<pid>`, also the log directory name; groups the rows of one invocation |
| timestamp | UTC time the rows were written |
| engine, engine_version | `none`/`suricata`/`snort3`; parsed version (`kernel-<uname -r>` for the bridge) |
| rules, threads | `full`/`none` (`n/a` for the baseline); effective engine threads (after a Snort fallback) |
| test, test_args | test name; the args sent to the client (`--find-ndr` rows: `frame=.. duration=..` etc.) |
| label | free label; `ndr-search` for probes, `ndr-result` for the result rows |
| metric, value, unit | the client's `metric=value`; unit derived from the name (`us ms Mbps % pps /s`); values may be text (`tool`, `tls_cipher`) |
| cpu_util_pct | average CPU over all cores during the client command (`/proc/stat`) |
| peak_rss_kb | engine peak RSS over the whole run (`/usr/bin/time`) |
| eng_rx, eng_drop, eng_flows, eng_alerts | engine counters for the whole run (same sources as Tier 2; `eng_rx` is both directions) |
| ifa_rx, ifa_tx, ifb_rx, ifb_tx | `rx_packets`/`tx_packets` deltas of IF_A and IF_B during that measurement. Forwarding is healthy when `ifa_rx ~ ifb_tx` and `ifb_rx ~ ifa_tx` |
| temp_start, temp_end, throttled | `vcgencmd` SoC temperature at start/end and `get_throttled` at the end |
| note | e.g. Snort thread fallback |
| logdir | per-run raw output (`engine.out`, `work/`, `client-N.out`, `metrics.tsv`, `bench.lua`) |

### report.py --tier3

```sh
./report.py --tier3 inline.csv           # Markdown
./report.py --tier3 inline.csv --csv     # aggregated CSV
```
Groups by engine, rules, threads, test, test_args, metric and prints n, median, p95, min and max (text metrics show their
values); a second table lists the `ndr-result` rows per engine / rules / threads / frame (NDR and PDR in Mbit/s and pps).
`ndr-search` probes are excluded.

### sweep-inline.sh

```sh
cp sweep-inline.conf.example sweep-inline.conf; $EDITOR sweep-inline.conf
sudo -E ./sweep-inline.sh -c sweep-inline.conf
```
Loops engines (the `none` baseline once, first) x `RULES` x `THREADS` x `TESTS` (each entry `"TEST args..."`) x `REPEATS`, then the optional
NDR search per frame in `NDR_FRAMES`. Between runs: `COOLDOWN` seconds, then wait until the SoC is below `TEMP_MAX` (as `sweep.sh`).

### Order of operations

1. Cable it, set the addresses, disable offloads on the client and server NICs, run the setup scripts, check `ping` client -> server through the Pi
   (with `--engine none` running, or a manual bridge). Confirm `throttled=0x0`, heatsink/fan on, tmpfs for logs.
2. **Baseline first**: `--engine none` for every test (and NDR frames). This is the floor and shows what the USB NICs and generator can do.
3. Each engine with `--rules none` (engine overhead alone), for 1 and N threads.
4. Then each engine with `--rules full` (the same thread counts).
5. Repeat every combination **5 times**; take the median (`report.py --tier3`).
6. Cool down between runs (`COOLDOWN`, `TEMP_MAX`), one engine at a time (RAM), reboot or at least drop caches if memory gets tight.
7. Compare engines only at equal threads and rules; compare each to the baseline at the same test arguments.

## make-pcaps.py

```sh
./make-pcaps.py --outdir pcaps [--packets 20000] [--flows 500] [--seed 1]
```
`udp-{64,128,256,512,1024,1518}.pcap` (fixed frame size, varying src ports/addresses so flows differ),
`imix.pcap` (7:4:1 of 64/570/1518 byte frames) and `http.pcap` (full TCP handshake, GET, 200 response in
1400-byte segments, FIN teardown per flow). Seeded and deterministic; valid IP/TCP/UDP checksums.

## Raspberry Pi 3B+ caveats

* The Ethernet NIC hangs off the **USB 2.0 bus** shared with everything else: practical ceiling is about
  300 Mbit/s (~25-30 kpps at 1518 B is not the limit, small-frame rates are limited by the USB/CPU path
  at far lower pps than a PCIe NIC). A NDR found with a USB NIC mostly measures that path.
* **Thermal throttling** starts at 60 C (soft limit 60, hard 80); use a heatsink/fan, keep the governor on
  `performance`, and keep `TEMP_MAX` below 60. Check `throttled_*` columns: anything but `0x0` taints a run.
  Undervoltage (bit 0) also taints it - use a proper power supply.
* **Logs must be on tmpfs** (SD card writes would dominate).
* **1 GB RAM**: Snort 3 with the full ET Open rule set and Suricata with ET Open need hundreds of MB each;
  run one engine at a time, no swap, and watch `peak_rss_kb`. Suricata's default `max-pending-packets`/flow
  memcaps may need lowering. Rule loading takes minutes (hence `READY_TIMEOUT`).
* The generator must be able to reach the target rate (check `gen_sent_pkts / replay_s`) and the link should
  be dedicated: ARP/mDNS/ssh on the capture interface count towards NIC counters.
