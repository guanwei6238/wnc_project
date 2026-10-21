# 平台後端：Debian / Pi OS、OpenWrt

查證日期 2026-10-20。出處縮寫：
- `K`：linux master 的 `net/netfilter/` 和 `Documentation/networking/nf_flowtable.rst`
- `FW4`：git.openwrt.org 的 firewall4
- `OW`：openwrt.org 文件與 downloads.openwrt.org

標「主 agent 核對」的已讀過原始碼或清單，其他來自 subagent 調查。

## 目錄
1. 要抽象的介面
2. Fast path 後端比較
3. nftables flowtable 細節
4. OpenWrt
5. Debian / Pi OS
6. IDS engine adapter

## 1. 要抽象的介面 [建議]

下面只是介面草圖，不是要照抄的程式碼：

```rust
trait FirewallBackend { fn install_base(&self); fn ban(..); fn unban(..); fn persist(&self); }
trait FastPathBackend {
    fn probe(&self) -> FastPathCaps;        // 模組是否存在、L2/L3、BTF、硬體 offload
    fn trust(&self, flow: &FlowKey, ttl: Duration);
    fn revoke(&self, flow: &FlowKey);       // 不同後端的撤銷語意不同，見 §2
    fn stats(&self, flow: &FlowKey) -> Option<Counters>;
}
trait ServiceManager { /* 從同一份權限清單產生 systemd unit 或 procd init + ujail JSON */ }
trait ConfigSource   { /* Debian 讀 /etc 下的檔案；OpenWrt 讀 UCI；都轉成同一個 config struct */ }
trait XdpProbe       { /* 見 ebpf-plugins.md §7 */ }
trait IdsEngine      { /* 見 §6 */ }
```

- 依兩件事選出可用的組合：`{bridge, routed}` 模式（SYNTHESIS §11 D3）和 `probe()` 的結果。
- probe 失敗時，退回「只有 ct mark accept、不加速」。這個做法在每個平台都能用。

## 2. Fast path 後端比較

| 後端 | 模式 | 協定 | 怎麼撤銷 | 計數 | 需要什麼 | Pi 4 |
|---|---|---|---|---|---|---|
| ct mark accept（階段 1） | L2/L3 | 全部 | 改 ct mark | conntrack acct | nftables | 可用 |
| nft flowtable（software） | **只有 L3 路由** | 只有 TCP/UDP | **刪 conntrack entry**；改 mark 沒有用 | 開 `counter` + `nf_conntrack_acct=1` | `nf_flow_table` 模組 | 有模組（主 agent 核對 bcm2711_defconfig） |
| tc eBPF redirect（階段 3） | L2/L3 | 自訂 | 刪 BPF map entry | 自己在 map 裡算 | TCX（6.6+） | 可用；但沒有 BTF，conntrack 逾時要自己管 |
| 硬體 offload（flowtable `flags offload`） | L3 | TCP/UDP | 同 flowtable | 同 flowtable | 支援的 SoC driver | **沒有**（bcmgenet、r8152、ax88179 都沒有 `ndo_setup_tc`） |

[推測] flowtable 適合當 L3 模式的預設 fast path，尤其在 OpenWrt 上：
- conntrack 生命週期、VLAN/PPPoE、路由失效都由 kernel 處理，不用自己寫 BPF。
- 之後換到 MediaTek 設備可以直接開硬體 offload。

L2 bridge 模式，或需要細粒度撤銷和抽樣時，改用 tc eBPF。

## 3. nftables flowtable 細節

- **原理**：flowtable 掛在 netdev ingress hook。命中的封包直接用 `neigh_xmit()` 送出，不再經過後面任何 netfilter hook（prerouting、forward、postrouting），**也就不會進 NFQUEUE**；沒命中的封包照原路走 [K: nf_flowtable.rst]。
- **版本**：software flowtable 從 4.16 開始，counter 從 5.7。不限 OpenWrt，Debian 6.12 和 Pi 的 rpi-6.12.y 都編成模組。
- **怎麼建立 entry**：在 forward chain 寫 `flow add @ft`，前面可以加條件。限制如下 [K: `nft_flow_offload.c`]：
  - TCP 必須是 established，而且不是 FIN 或 RST；conntrack 要已經 confirmed。
  - 只支援 TCP 和 UDP。
  - 有 conntrack helper、SEQ_ADJUST、IP options 或 IPsec 的 flow 不會被 offload。
- **`flow add` 不會結束規則比對**：觸發 offload 的那個封包會繼續往下比對 rule。所以信任 flow 的規則要寫成「條件 + `flow add @ft` + `accept`」，而且放在 queue 規則前面。[推測，待實測]
- **逾時**：
  - 加進 flowtable 時，conntrack entry 被 refresh 成 1 天。
  - flowtable entry 自己的逾時由 sysctl `nf_flowtable_tcp_timeout` 和 `nf_flowtable_udp_timeout` 控制，預設 30 秒，每個命中的封包都會 refresh。
  - gc 每秒跑一次；entry 過期、ct 被刪或路由失效時 teardown，把 ct 交還給 conntrack。
- **計數**：flowtable 宣告加 `counter`，會把 bytes 和 packets 同步回 ct。但只有 ct 已經有 acct extension 時才會累加，所以要同時開 `net.netfilter.nf_conntrack_acct=1`。[推測，從原始碼推論]
- **撤銷**：
  - flowtable 程式碼**完全不讀 mark**（主 agent 核對 master 的 `nft_flow_offload.c`、`nf_flow_table_core.c`、`nf_flow_table_ip.c`），所以改 ct mark 沒有用。
  - 要撤銷就用 `conntrack -D` 刪掉 ct，下一輪 gc（約 1 秒內）會 teardown。之後的封包會建立新的 ct，mark 是 0。
  - 因為 `nf_conntrack_tcp_loose=1`，新的 ct 會以 established 狀態接續追蹤，封包回到 queue。這時 **Suricata 看到的是連線中段（midstream）**。
  - nft 沒有刪除單一 flowtable entry 的指令（未能確認）。
- **FIN/RST**：文件說會交回一般路徑，但 master 的程式碼只標記 `NF_FLOW_CLOSING`，封包仍由 fast path 轉送，之後才 teardown。文件和程式碼不一致，[待查證] 6.12 的實際行為。
- **不支援 bridge**：nft 的 flowtable 只接受 ip、ip6、inet family。5.13 加入的「bridge port」指的是 bridge port 和 L3 轉發之間的 fast path，不是 L2 port 到 port。bridge 原生支援的 patch 還沒合併。**L2 bridge 模式下，flowtable 對純橋接流量沒有作用。**
- **和 tc 特徵計算的關係**：tc ingress 早於 netfilter ingress [K: `net/core/dev.c`]，所以就算用 flowtable 當 fast path，階段 2 的 tc 特徵計算仍然看得到所有封包。

## 4. OpenWrt

- **版本** [OW]：
  - 24.10.8（2026-07-25）：kernel 6.6.144，opkg。
  - 25.12.6（2026-10-18）：kernel 6.12.112，從 25.12.0 開始用 apk。
  - 兩版都用 musl。
- **在 Pi 4 上跑 OpenWrt**：target 是 bcm27xx/bcm2711，profile 是 rpi-4，arch 是 aarch64_cortex-a72。第二個 port 用 USB 網卡（例如 kmod-usb-net-rtl8152）。
- **可裝的套件** [OW downloads]：
  - kernel 模組：nft-queue、nfnetlink-queue、nf-flow、sched-bpf、nf-conntrack-netlink
  - 函式庫和工具：libnetfilter-queue1、libmnl0、libnftnl11、libbpf1、tc-bpf、bpftool、conntrack
- **Suricata 不在官方 feed 裡**。25.12.6 的 aarch64_cortex-a72 有 `snort3-3.10.0.0-r1.apk`，但沒有 suricata（主 agent 核對整份套件清單）。openwrt/packages 只有一個已關閉的舊 PR「Suricata6 initial commit」。走 OpenWrt 就得自己寫 package Makefile，這是 OpenWrt 路線最大的成本（`decisions.md` O6）。
- **fw4 的行為** [FW4]：
  - `fw4 reload` 會重新產生整份 ruleset：先 `flush table inet fw4`，再 `delete flowtable inet fw4 ft`。
  - `fw4 stop` 只刪 `inet fw4`。
  - `fw4 flush`（init script 的 stop_service 會呼叫）會**刪光所有 table，包括第三方的**。
  - 自訂規則可以這樣加：
    - `/etc/nftables.d/*.nft`：被 include 在 fw4 table 裡面。
    - `/usr/share/nftables.d/{ruleset-pre,ruleset-post,table-pre,table-post,chain-pre/<chain>,chain-post/<chain>}/*.nft`：依路徑決定插入位置。
    - UCI `config include`：type 可以是 nftables，也可以是 script。type script 會在每次 start 或 reload 之後執行（逾時 30 秒），可以當 reload hook。
  - [建議] 用自己的 table，加上 UCI script include 當 reload hook，被 `fw4 flush` 刪掉後再重建。
- **不要開 fw4 的全域 flow offloading**（`firewall.@defaults[0].flow_offloading=1`）。它會在 forward chain、`ct state vmap` 之前，替**所有** TCP/UDP flow 加上 `flow offload @ft`，連雲端還沒判定的 flow 也會繞過 NFQUEUE 和 Suricata。要 offload 只能在自己的 table 定義 flowtable，加上信任條件。兩個 flowtable 能不能共用同一個 device，[待查證]。
- **硬體 offload**：
  - OpenWrt 文件寫的主要是 MediaTek Filogic：約 64 條 entry，超過的退回軟體；和 SQM/QoS 不相容。
  - kernel 裡有實作的：mtk_eth_soc（MT7621、MT7622、MT7623、MT7981、MT7986、MT7988）、airoha_eth、DSA。
  - fw4 偵測到硬體 offload 失敗時，會降為 software 並發出警告。
- **procd + ujail** [OW procd-init-scripts]：
  - `procd_add_jail <name> [log ubus procfs sysfs ronly ...]`
  - `procd_set_param user`、`seccomp <OCI JSON>`、`capabilities <OCI JSON>`、`no_new_privs 1`
  - [推測] 不能用 netns，因為服務要看得到實體網卡。
- **BTF**：`KERNEL_DEBUG_INFO_BTF` 預設是 n。
- **Rust 交叉編譯**：
  - feed 裡的 `lang/rust` 只提供 host 工具鏈（25.12 分支是 1.96.0）。套件 Makefile 寫 `PKG_BUILD_DEPENDS:=rust/host`，再 `include ../../lang/rust/rust-package.mk`；可以參考 `utils/librespeed-cli-rust`。
  - target 是 `aarch64-unknown-linux-musl`（Rust Tier 2 with host tools）。
  - 另一條路是用 rustup 的 musl target，搭配 OpenWrt SDK 的 gcc 當 linker。純 Rust、靜態連結最簡單；只有要動態連結 OpenWrt 的 C 函式庫時才需要 SDK。[推測]

## 5. Debian / Pi OS

- **防火牆**：用自己的 `table inet wnc_gw`，由自己的 systemd unit 載入和持久化，不改發行版的 `/etc/nftables.conf`。[建議]
- **systemd 權限限制**（`systemd.exec(5)`、`seccomp-util.c`）：
  - `User=gw`
  - `AmbientCapabilities=CAP_NET_ADMIN CAP_BPF`，`CapabilityBoundingSet` 設成一樣。只用 nft、NFQUEUE、ctnetlink 時只留 `CAP_NET_ADMIN`。
  - `NoNewPrivileges=yes`
  - `RestrictAddressFamilies=AF_NETLINK AF_UNIX`：privd 不需要 AF_INET；只有 agent 要連雲端，才加 AF_INET/AF_INET6。
  - `ProtectSystem=strict`、`ProtectHome=yes`、`PrivateTmp=yes`、`RestrictNamespaces=yes`、`MemoryDenyWriteExecute=yes`
  - `SystemCallFilter=@system-service bpf`：`bpf` 不在 `@system-service` 裡。
  - 不要用 `PrivateNetwork`，因為服務要看得到實體網卡。
- **L2 bridge 模式要注意**（和 SYNTHESIS §11 D3 有關）：
  - Pi 的 bcm2711_defconfig 有 `BRIDGE_NETFILTER=m`、`NF_TABLES_BRIDGE=m`，但沒有列 `NF_CONNTRACK_BRIDGE`（主 agent 核對）。bridge family 的 conntrack 可能要改用 br_netfilter，或自己編 kernel。
  - [待查證] 在 Pi 上用 `modinfo nf_conntrack_bridge` 或 `/proc/config.gz` 確認。

## 6. IDS engine adapter

- **契約**：
  - 輸入事件：alert 和 flow，有固定 schema。
  - 輸出操作：套用規則集、dataset add、reload、取統計。
- **Suricata**：走 EVE + unix socket（`suricata-integration.md` 方案 A）。安全要求見 `rules-nft-suricata.md`。
- **Snort 3**：OpenWrt 官方 feed 有 3.10.0.0。它的介面（輸出格式、reload、inline 模式）[待查證]。
- **自製 engine**：專案記憶裡有記錄 IDS 之後可能自己做。只要它輸出同樣的事件、接受同樣的寫入操作，就能替換掉 Suricata。
