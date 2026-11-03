# Suricata 對外整合介面調查：要把 Suricata 接進我們的 gateway，有哪些「接口」

調查日期 2026-10-20。對應 `SYNTHESIS.md` §4（信任狀態放 ct mark、稽核窗、撤銷、conntrack 匯出 flow record）與 `mechanisms.md` §7。
`mechanisms.md` 已查過的 bypass、NFQ mark、`nfq_set_mark` 這裡不重複，只在需要處直接引用。

---

## 0. 先講結論

開發者記得的「SDK」，官方並沒有叫 SDK 的東西。最接近的有兩個，**兩個都是官方自己標示「進行中／實驗性」的功能**：

- **libsuricata（library mode）**：把 Suricata 引擎當函式庫，由我們的程式自己收封包、自己餵進去。**8.0 才有可用版本**，7.0.x 沒有。
- **Plugin 系統**：以 `.so` 形式載入 capture、EVE 輸出、（8.0 起）app-layer、EVE callback、flow callback。沒有穩定 ABI 承諾。

幾個會影響決策的事實：

1. **Debian 套件完全不帶這兩者需要的東西。** trixie 的 `suricata 1:7.0.10-1+deb13u4` 與 trixie-backports 的 `1:8.0.7-1~bpo13+1`（兩者都有 arm64）的檔案清單裡沒有 `libsuricata*.so/.a`、沒有 `/usr/include/suricata`、沒有任何 plugin `.so`。要用 library mode 或寫 plugin，就得自己用原始碼編。[已驗證-清單]
2. **Debian 套件上現成可用、又穩定的只有三個**：EVE JSON 輸出（含 `unix_dgram`／`unix_stream`／`redis`）、unix socket 指令、datasets／hostbits。這三者的指令集在 7.0.10、8.0.7、main 之間幾乎沒變。[已驗證-讀碼]
3. **沒有任何介面能對「單一 flow」下指令**（撤銷 bypass、叫 Suricata 忘掉某條 flow、改它的 verdict）。unix socket 對 flow 只有唯讀的 `get-flow-stats-by-id`。這和 `mechanisms.md` §7.6 的結論一致：信任與撤銷要放在 kernel 與我們的控制程式。[已驗證-讀碼]
4. **版本風險比想像中大。** Suricata 7.0 上游已在 **2026-07-07 EOL**，最後一版 7.0.17（2026-07-09 公告）。Debian trixie 的 7.0.10 仍由 Debian 自己 backport 修補（`debian/patches` 內有 23 個 CVE patch 檔），但上游不會再出 7.0.x。trixie-backports 已有 8.0.7 的 arm64 套件。[已驗證-文件／清單]
5. `mechanisms.md` §M4 的結論（NFQ 的 bypass 只貼單一封包的 mark、Suricata 不碰 conntrack）在 **8.0.7 與 main 仍成立**：這兩版的 `src/source-nfq.c` 一樣沒有任何 conntrack／connmark 操作（我 grep 過）。[已驗證-讀碼]

### 證據標記（本檔專用）

我沒有在 Pi 或任何機器上執行 Suricata、沒有編譯、沒有安裝任何東西。所以「已驗證」的意思是**對照官方文件、原始碼或 Debian 套件中繼資料確認**，不是實機跑過。

| 標記 | 意思 |
|---|---|
| [已驗證-文件] | 官方文件原文 |
| [已驗證-讀碼] | 讀 git tag 原始碼確認（未編譯、未執行） |
| [已驗證-清單] | Debian `Packages` 索引或 packages.debian.org 檔案清單確認 |
| [二手] | crates.io 描述、論壇、搜尋摘要等非官方來源 |
| [推測] | 我的判斷，不是來源寫的 |

### 讀了哪些版本

| 代號 | 內容 |
|---|---|
| 7.0.10 | tag `suricata-7.0.10`；就是 Debian trixie 套件的上游版本（專案 `tests/ids_throughput` 也用它） |
| 7.0.17 | 7.0 最後一版；只用 GitHub contents API 確認檔案有無 |
| 8.0.7 | tag `suricata-8.0.7`（8.0 目前最新，commit `95130303`）；8.0.0 是 2025-07-08 |
| main | `OISF/suricata` 預設分支是 `main`（不是 master），`AC_INIT` 為 `9.0.0-dev`，我讀的 commit `9451642a`（2026-10-19）。crates.io 上對應 `9.0.0-alpha.20261013.1` |
| Debian | trixie `7.0.10-1+deb13u4`（arm64，2,616,824 bytes）；trixie-backports `8.0.7-1~bpo13+1`（arm64，3,851,888 bytes）；sid `8.0.7-2` |

---

## 1. Library mode／libsuricata

### 是什麼
把 Suricata 引擎編成函式庫（`libsuricata.so`，或 `libsuricata_c.a` 加 `libsuricata_rust.a`）。我們的程式自己呼叫 `SuricataPreInit → SuricataInit → SuricataPostInit → SuricataMainLoop → SuricataShutdown`，**自己開執行緒、自己產生 `Packet` 餵進引擎**，取代 Suricata 內建的 capture 模組（NFQ、AF_PACKET 等）。

### 版本狀態

| 版本 | 狀態 |
|---|---|
| 7.0.10／7.0.17 | **不能餵封包。** 有「編出 libsuricata」的建置目標（`Makefile.am` 的 `install-library`、`install-headers`，以及 `libsuricata-config.in`），但引擎入口只有 `SuricataMain(argc, argv)`（`src/suricata.h:194`）。沒有 `RUNMODE_LIB`、沒有 `DecodeLib` 模組、沒有 `runmode-lib.c`（7.0.17 tag 用 GitHub contents API 查 `src/runmode-lib.c` 回 404）。官方 devguide 也沒有 libsuricata 頁（`docs.suricata.io/en/suricata-7.0.10/devguide/libsuricata/` 回 404）。 |
| 8.0.0–8.0.7 | **有。** `src/runmode-lib.[ch]`、`src/source-lib.c`（`DecodeLib` 模組）、`examples/lib/custom`（8.0.0 起）、`examples/lib/live`（8.0.4 起確認有，8.0.1 沒有）、`examples/lib/simple`、`examples/lib/cplusplus`（8.0.7 有）。8.0.0 發佈說明：「making it easy for library users to bring their own packets and threads」。 |
| main (9.0.0-dev) | API 還在改。與 8.0.7 相比：`SCFinalizeRunMode()` 變成 `SCFinalizeRunMode(int argc)`；`EngineModeSetIPS()` 變成 `EngineModeSetIPS(enum EngineHostMode)`；`SCDetectEngineRegisterRateFilterCallback()` 改成要檢查回傳值；`SC_API_VERSION` 從 0x0800 變 0x0900。 |

### 官方文件／原始碼位置
- 文件（`latest` 與 `suricata-8.0.7` 內容相同）：https://docs.suricata.io/en/latest/devguide/libsuricata/index.html
  原文：「The ability to turn Suricata into a library that can be utilized in other tools is **currently a work in progress**, tracked by Redmine Ticket #2693」。
- 追蹤票 https://redmine.openinfosecfoundation.org/issues/2693：狀態 In Progress，**target 9.0.0-beta1**。已知未完成項目：移除全域變數（#4682、#4684、#8106 SCInstance）、ruleset reload API（#8095 Assigned）、「stream input without synthetic packets」（#9150 New）。
- 原始碼：`src/runmode-lib.[ch]`、`src/source-lib.c`、`src/suricata.h`、`src/packet.h`（`SCPacketSet*`）。
  https://github.com/OISF/suricata/tree/suricata-8.0.7/examples/lib
- 8.0.0 發佈說明：https://forum.suricata.io/t/suricata-8-0-0-released/5854

### 呼叫流程（從 `examples/lib/custom/main.c`、`live/main.c` 摘）
1. `SuricataPreInit(argv[0])`，選用 `SCParseCommandLine()`。
2. `SCRunmodeSet(RUNMODE_LIB)`、`SCFinalizeRunMode()`、`SCLoadYamlConfig()`。
3. `RunModeRegisterNewRunMode(RUNMODE_LIB, "custom", …, AppRunModeSetup, NULL)`；在 callback 內用 `SCRunModeLibCreateThreadVars(id)` 建 worker 的 `ThreadVars`（必須在 thread sealing 之前）。
4. `LiveRegisterDevice("lib0")`、`SuricataInit()`。
5. 我們的執行緒：`SCRunModeLibSpawnWorker(tv)`，然後迴圈：`PacketGetFromQueueOrAlloc()` → `SCPacketSetSource/Time/Datalink/LiveDevice/ReleasePacket` → `PacketSetData(p, data, len)` → `TmThreadsSlotProcessPkt(tv, tv->tm_slots, p)`。
6. `SuricataPostInit()`、`SuricataMainLoop()`、`SuricataShutdown()`；收尾時 worker 要呼叫 `EngineStop()` 與 `SCTmThreadsSlotPacketLoopFinish(tv)`（官方註解說這兩邊必須**同時**進行）。

### 能做什麼
- **我們擁有封包迴圈。** 現有 `security_gateway`（Rust `nfq` crate）收到的 NFQ 封包是 L3（沒有 Ethernet header），可用 `SCPacketSetDatalink(p, DLT_RAW)` 餵進去；`DecodeLinkLayer` 有處理 `LINKTYPE_RAW`（`src/decode.h:1440`）。[已驗證-讀碼；整體可行性是推測]
- **verdict 由我們掌握。** `SCPacketSetReleasePacket(p, ReleasePacket)` 設的 callback 會在 Suricata 處理完時被呼叫，裡面可用 `PacketCheckAction(p, ACTION_DROP)` 得知規則要不要 drop。官方範例註解：「Optionally this is where you would handle IPS like functionality such as forwarding the packet」。
- 同一個 process 內可直接呼叫內部 API（例如 flow 查詢、dataset），因為 `make install-headers` 會把**全部內部標頭**（`src/Makefile.am` 的 `noinst_HEADERS`）裝出去。[已驗證-讀碼]

### 不能做什麼／風險
- **沒有穩定 API／ABI。** 文件自述 WIP；`install-headers` 裝的是整個內部標頭集合，等於整份引擎內部都是「API」；8.0.7 → main 已經有上面那些簽名變動。
- 全域變數還沒清完，所以**一個 process 只能一個引擎實例**。[推測，依 #4682／#8106 未關]
- 規則重載沒有專用 API（#8095 未完成）；只能走 `SCEnableDefaultSignalHandlers()` 啟用的 SIGUSR2 或 unix socket。
- **沒有 Rust 綁定。** `suricata-sys`（Rust bindgen crate）的輸入 `src/bindgen.h` 只包含 plugin 用到的標頭（app-layer、detect、EVE、flow callback、datasets 等），**沒有** `runmode-lib.h`、`suricata.h`、`packet.h`。Rust 要呼叫 library mode，得自己對內部標頭跑 bindgen，或寫一層 C shim。[已驗證-讀碼]
- IPS 的 drop 語意（lib runmode 下怎麼讓 engine 進入 IPS 模式）我沒查清楚。`--simulate-ips`（「force engine into IPS mode. Useful for QA」，`src/suricata.c:744`）存在，但 lib 路徑怎麼設未確認。[未確認]

### 在 Pi arm64 + Debian 套件上能不能直接用
- **不能直接用。** 兩個 Debian 套件都沒有 libsuricata 與 headers。[已驗證-清單]
- 從原始碼編：Linux 目標會設 `can_build_shared_library="yes"`（`configure.ac:282`）。trixie 的 `rustc` 是 1.85.1，滿足 8.0.7 的 `rust-version = 1.75.0`（main 的 9.0.0-alpha 要 1.85.0）。[已驗證-讀碼／清單]
- Pi 上編譯要多久、記憶體夠不夠：未測。[推測] 建議在筆電用 arm64 container 或 cross build，再把產物放進 Pi。

---

## 2. Plugin 系統

### 是什麼
Suricata 在啟動時對 `suricata.yaml` 的 `plugins:` 列的檔案或目錄做 `dlopen`，找符號 `SCPluginRegister`，取得一個 `SCPlugin`，呼叫它的 `Init()`，plugin 在 `Init()` 裡註冊自己的功能。`configure` 摘要印的是 **"Plugin support (experimental)"**，yaml 註解也是 "Plugins -- Experimental"。

### 版本與型別支援

| 型別 | 7.0.10 | 8.0.7 | main |
|---|---|---|---|
| Capture plugin（`SCCapturePlugin`，`--capture-plugin=NAME`） | 有（`suricata-plugin.h:66`） | 有；PF_RING 與 Napatech 在 8.0 改成 capture plugin（`plugins/`） | 有 |
| EVE filetype plugin（`SCEveFileType`，yaml `filetype: <name>`） | 有（`suricata-plugin.h:47`） | 有（`output-eve.h`；文件 devguide/extending/output/eve-filetypes） | 有 |
| EVE callback（`SCEveRegisterCallback`，只能追加欄位） | 無 | 有（8.0.0 tag 就有 `output-eve.h`） | 有 |
| Flow init／update／finish callback、thread init callback、flow／thread storage | 無 | 有（8.0.0 tag 有 `flow-callbacks.h`、`thread-callbacks.h`） | 有 |
| App-layer plugin（`SCAppLayerPlugin`、`SCPluginRegisterAppLayer`） | 無 | 有（範例 `examples/plugins/altemplate`，Rust） | 有 |
| Rust safe wrapper `suricata-ffi` | 無 | 無 | 有（只在 9.0.0-alpha） |

### ABI 穩定嗎？不穩
- **7.0.10**：`SCPlugin` 結構只有 `{name, license, author, Init}`，**沒有版本欄位，載入時完全不檢查**（`src/util-plugin.c:48` 起的 `RegisterPlugin`）。
- **8.0.7**：`SCPlugin` 前面多了 `version`、`suricata_version`、`plugin_version`；載入時 `plugin->version != SC_API_VERSION` 就拒絕載入（`src/util-plugin.c:54`）。`SC_API_VERSION = 0x0800`，只編碼 major.minor；main 是 `0x0900`。
- 所以 8.0 的做法是「**major.minor 一致才載入**」，不是「ABI 穩定」。plugin 用的是 Suricata 內部型別（`Packet`、`ThreadVars`、`Flow`），同一個 8.0.x 內 patch 版之間官方沒有相容承諾。7.0 編的 plugin 和 8.0 的結構佈局不同，不能共用。[已驗證-讀碼；patch 版相容性是推測]
- 文件另有一個 Rust plugin 的警告：「A plugin should not use rust structures from suricata crate if they are not repr(C)」，並要求純 Rust plugin 以 `RUSTFLAGS=-Clink-args=-Wl,-undefined,dynamic_lookup` 編譯（`devguide/libsuricata/index.rst`）。

### 用什麼語言寫
- C 為主：`examples/plugins/c-json-filetype`、`c-custom-loggers`、`ci-capture`（8.0.7）。
- Rust：8.0 的 app-layer 範例（`altemplate`，用 `suricata` crate，要呼叫 `suricata::plugin::init()`）；main 另有純 Rust 範例 `examples/plugins/rust`（用 `suricata-sys` 加 `suricata-ffi`，示範 EVE callback、flow／thread callback 與 per-flow／per-thread storage）。

### 官方文件／原始碼位置
- 文件：https://docs.suricata.io/en/latest/devguide/libsuricata/index.html（Plugins 段）、https://docs.suricata.io/en/latest/devguide/extending/output/eve-filetypes.html 、https://docs.suricata.io/en/latest/devguide/extending/output/eve-hooks.html 、https://docs.suricata.io/en/latest/plugins/index.html
- 7.0 的 devguide `extending/capture/index.rst` 只有標題、沒有內容；7.0.10 tag 本身**沒有 `examples/` 目錄**（GitHub contents API 的 tag 根目錄清單裡沒有）。7.0 的 plugin 只能靠 `src/suricata-plugin.h` 與 `src/util-plugin.c` 自學。
- 原始碼：`src/suricata-plugin.h`、`src/util-plugin.c`、`src/output-eve.h`（8.0+）、`src/flow-callbacks.h`（8.0+）、`examples/plugins/*`。

### 能做什麼（對我們）
- **EVE filetype plugin**：每筆 EVE JSON 序列化好的 buffer 直接交給 plugin 的 `Write()`，不經檔案或 socket。我們可以在裡面把它丟進自己的 queue 再送給控制程式。官方警告：`Write` 跑在 packet processing thread，**不要阻塞**，否則掉封包。[已驗證-文件]
- **Capture plugin**：自訂封包來源，是 library mode 的「plugin 版」。範例 `ci-capture/source.c` 顯示它用的是內部 `TmModule` API。
- **Flow callback（8.0+）**：每個封包更新 flow 時、flow 建立與結束時被呼叫，可讀 flow 的 5-tuple、封包計數，並掛 per-flow storage。理論上可用來記錄「稽核窗內看到幾個封包」。[推測]

### 不能做什麼
- 官方公開的 plugin 型別裡**沒有「改 verdict」或「改 flow 的 bypass 狀態」的 hook**。callback 拿得到 `Flow *`／`Packet *`，用內部標頭理論上可以改欄位，但那不是公開承諾。[推測]
- capture plugin 要自己處理 IPS 的 verdict 路徑（Suricata 內建 NFQ 的那套不會幫你做）。[推測]

### 在 Pi arm64 + Debian 套件上能不能直接用
- Suricata 本體：兩個 Debian 套件都能載入 plugin 的可能性高（`configure.ac:394-413` 的 `-rdynamic` 連結測試在 Linux 通過就會定義 `HAVE_PLUGINS`），但**沒有 `suricata --build-info` 的實測輸出**。[已驗證-讀碼；實際 build 結果未確認]
- 寫 plugin：Debian 套件沒有 headers，也沒有範例。要編 plugin 需要**對應版本的官方 release tarball**（含 `autoconf.h`、`rust/dist/rust-bindings.h`）加 `libsuricata-config`。純 git tag 的 tarball 沒有預先產生的 `rust-bindings.h`，要靠 cbindgen。[推測]
- 實際可行的做法：用 backports 的 8.0.7 binary，加上自己編的 8.0.7 plugin `.so`，在 yaml `plugins:` 指過去。這比 library mode 輕，但仍要一套 8.0.7 的建置環境。[推測]

---

## 3. Unix socket（suricatasc）

### 是什麼
Suricata 在一個 unix domain socket 上開 JSON 指令介面。`suricatasc` 只是它的命令列客戶端。協定是**按行的 JSON**：先送 `{"version": "0.2"}` 握手，回 `{"return": "OK"}`，之後送 `{"command": "...", "arguments": {...}}`，回 `{"return": "OK"|"NOK", "message": ...}`。

### 版本狀態
- 指令集：7.0.10、8.0.7、main 幾乎一致（`src/unix-manager.c` 的 `UnixManagerInit()`，7.0.10 第 1076 行起、8.0.7 第 1084 行起）。8.0 多了 `dataset-add-json`。`ruleset-profile*` 只在編譯時開 `PROFILE_RULES` 才有。
- 客戶端：7.0.10 的 `suricatasc` 是 Python（Debian 套件裝在 `/usr/lib/suricata/python/suricatasc`）；**8.0 起改用 Rust 重寫**（`rust/suricatasc`，upgrade 註記「have been rewritten in Rust」）。
- Debian 7.0.10 的預設：`debian-default-cfg.patch` 把 `unix-command` 設成 `enabled: yes`，socket 路徑為 `suricata-command.socket`，放在 `@e_localstatedir@`（`/run/` 之下，實際路徑為 `/run/suricata-command.socket` 或 `/var/run/…`）。[已驗證-讀碼；路徑未在實機確認]

### 官方文件
- https://docs.suricata.io/en/suricata-7.0.10/unix-socket.html 、https://docs.suricata.io/en/latest/unix-socket.html
- 協定說明在 Redmine wiki（文件內連結）。文件警告：「a Suricata message is sent in multiple send operations. This result in possible incomplete read on client side」，客戶端要自己處理分段讀取。

### 執行期能做什麼（依 `UnixManagerInit` 註冊的指令）

| 類別 | 指令 | 備註 |
|---|---|---|
| 生命週期 | `shutdown`、`version`、`uptime`、`running-mode`、`capture-mode`、`conf-get`、`reopen-log-files`、`command-list` | |
| 規則 | `reload-rules`／`ruleset-reload-rules`（等完成）、`ruleset-reload-nonblocking`、`ruleset-reload-time`、`ruleset-stats`、`ruleset-failed-rules` | |
| 統計 | `iface-list`、`iface-stat`、`dump-counters`、`memcap-list`／`memcap-show`／`memcap-set`、**`get-flow-stats-by-id`** | `memcap-set` 可調：stream、stream-reassembly、flow、applayer-proto-http、defrag、ippair、host（`runmode-unix-socket.c:90`）。`get-flow-stats-by-id` 吃 `flow_id`（即 EVE 裡的 `flow_id`），回 pkts／bytes 兩方向與 age，**唯讀** |
| 注入狀態 | `dataset-add`／`dataset-remove`／`dataset-clear`／`dataset-lookup`／`dataset-dump`（8.0 多 `dataset-add-json`）；`add-hostbit`／`remove-hostbit`／`list-hostbit` | 見 §4 |
| 多租戶 | `register-tenant`、`reload-tenant` 等 | 本專案用不到 |
| pcap 離線 | `pcap-file*` | 只在 `--unix-socket` 的 pcap runmode 下才註冊，NFQ inline 不適用 |

參數鍵名（讀碼）：`dataset-add` 用 `setname`／`settype`／`datavalue`；`add-hostbit` 用 `ipaddress`／`hostbit`／`expire`（秒）；`get-flow-stats-by-id` 用 `flow_id`。

### 不能做什麼
- **不能控制單一 flow。** 指令清單裡沒有任何「對某條 flow 做動作」的指令（沒有 bypass、un-bypass、kill、reset）。這是對 `mechanisms.md` §M3／M4「Suricata 端不能撤銷」的補強：連從外部下指令的路也沒有。[已驗證-讀碼，三個版本的指令清單比對]
- **不能推送事件。** 它是請求–回應，不會主動通知。告警要靠 EVE（§6）。
- **不能餵封包。**

### 在 Pi arm64 + Debian 套件上能不能直接用
**可以。** 兩個 Debian arm64 套件都帶 `/usr/bin/suricatasc`，且依賴 `libjansson4`（unix socket 需要它；`configure.ac:812` 預設 `test`，有 jansson 就編入）。[已驗證-清單／讀碼]
Rust 控制程式要用，不需要任何 crate：`rust/suricatasc/src/unix/client.rs`（檔頭 `SPDX-License-Identifier: MIT`）只有約 100 行，`UnixStream` 加 `serde_json` 就能復刻。[已驗證-讀碼]

---

## 4. Datasets／datarep（以及 hostbits）

### 是什麼
規則關鍵字 `dataset` 與 `datarep`：把一個 sticky buffer 的內容拿去對一個集合做 `isset`／`isnotset`（`dataset` 另可 `set`／`unset`）。集合型別：`string`、`md5`、`sha256`、`ipv4`、`ip`。搭配 `ip.src`／`ip.dst` sticky buffer（7.0.10 已有，`src/detect-ipaddr.c`），就能做 **IP 黑名單／白名單**：

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Inbound bad list"; flow:to_server; ip.src; dataset:isset,badips,type ip,load badips.list; sid:1; rev:1;)
```
（範例原文來自 7.0.10 `doc/userguide/rules/ipaddr.rst`）

### 版本狀態
- 7.0.10：有，且 `dataset-add`／`remove`／`clear`／`lookup`／`dump` 全在（文件 `rules/datasets.rst` 有寫）。
- 8.0.x：新增 JSON 資料集（`format json|ndjson`、`context_key`、可把關聯資料附在 alert 上）、`match subdomain`、`dataset-add-json`；upgrade 註記說明每個 dataset 的 `hashsize` 預設上限為 65536（`datasets.limits` 可調）。
- 7.0 起（6.0.13 起）規則內指定 `save`／`state` 檔名時，絕對路徑與 `..` 預設不允許（`datasets.rules.allow-absolute-filenames`，見 7.0.10 `datasets.rst` Security 段）；`state` 檔放在 `$LOCALSTATEDIR/suricata/data`，Debian 為 `/var/lib/suricata/data`（`configure.ac` 的 `e_datadir = localstatedir + "/lib/suricata/data"`，見 Debian 的 `debian-default-cfg.patch` 上下文；未在實機確認）。
- main：同 8.0。

### 官方文件
https://docs.suricata.io/en/suricata-7.0.10/rules/datasets.html 、https://docs.suricata.io/en/latest/rules/datasets.html

### 能做什麼（對「信任清單／黑名單」）
- **執行期由外部加入／移除**：`dataset-add <set> <type> <data>` 在成功時「the addition becomes active instantly」，**不需要 reload 規則**。IP 型別的資料用字串形式，例如 `192.0.2.1`；字串型別用 base64。[已驗證-文件]
- 「動態集合」（在 yaml 宣告，或只用 `state`／`save` 的集合）在規則重載時**不會**被重載；只用 `load` 的是「靜態」，重載時從磁碟重讀。`state` 檔會在 Suricata 結束時存檔、啟動時載入，所以清單可跨重啟保存。[已驗證-文件]
- **hostbits**（`hostbits:isset,<name>,src` 或 `xbits … track ip_src`）搭配 `add-hostbit` 可以對**某個 IP** 設一個**有到期時間**的旗標。到期由 Suricata 處理，不用我們自己排程。[已驗證-讀碼]

### 不能做什麼
- **粒度是 IP／字串／雜湊，不是 flow。** 沒辦法說「這條 flow 信任」，只能說「這個 IP 在清單內」。
- **集合必須先存在。** `dataset-add` 的說明是「Name of an already defined dataset」（程式碼：`DatasetFind` 找不到就回 `set not found or wrong type`）。所以規則或 yaml 要先宣告好這個集合。hostbit 同理：`add-hostbit` 找不到名稱會回 `hostbit not found`，需要已載入的規則用過這個名字。[已驗證-讀碼]
- **沒有逐元素的 TTL。** 我在 7.0.10、8.0.7、main 的 datasets 文件中找不到 ttl／expire。清單的過期要由控制程式自己 `dataset-remove`。
- **`datarep` 的信譽值不能經 socket 指定**：`dataset-add` 只有 `setname`／`settype`／`datavalue` 三個參數，`DatasetAddSerialized` 沒有 rep 值欄位。信譽值只能來自 `load` 的檔案。[已驗證-讀碼]
- **對我們最關鍵的限制：dataset 只影響 Suricata 內部的判斷，不省 NFQ 往返。** 用 dataset 搭配 `pass` 規則讓某 IP 的流量「不再檢測」，封包仍然會進 queue、仍然要往返 userspace（`mechanisms.md` §M6）。它能當**黑名單**（雲端判 malicious → 加進集合 → `drop` 規則生效）或**告警抑制**，但**不能取代 kernel 的 ct mark 信任**。而且已經被 ct mark 放行的 flow 根本不會進 Suricata，所以只加 dataset 也撤銷不了它，撤銷仍然要改 ct mark。[推測，建立在已驗證的 §M4／M6 上]

### 在 Pi arm64 + Debian 套件上能不能直接用
**可以**（datasets 是 Suricata 內建，不依賴編譯選項）。8.0 的 JSON 資料集也是內建。[已驗證-清單／讀碼]

---

## 5. Lua scripting

### 是什麼
兩種用途：**output**（`lua` output 模組，自己寫 `init/setup/log/deinit` 輸出任意格式）與 **detection**（規則關鍵字 `lua:` 和 `luaxform` transform，腳本 `match()` 回 1 或 0）。

### 版本狀態與 8.0 的變動
| 項目 | 7.0.10 | 8.0.x |
|---|---|---|
| Lua 版本 | 系統的 Lua 5.1 或 LuaJIT，編譯期用 `--enable-lua`／`--enable-luajit`，**預設 `enable_lua="no"`**（`configure.ac:1882-1889`） | **內建（vendored）Lua 5.4**，透過 Rust crate `suricata-lua-sys`（`rust/Cargo.toml.in:89`），不再依賴系統 Lua，所有 8.0 安裝用同一版 |
| Detection 腳本 | 預設停用（upgrade 註記：「Lua rules are now disabled by default (change also introduced in 6.0.13)」） | **預設啟用但在沙盒中**：只開放有限標準函式；沒有 `os`、`io`、`package`、`debug`、`coroutine`；有指令數與記憶體上限；可用 `security.lua` 調整 |
| Output 腳本 | 可用 | 沒有預設的模組搜尋路徑，要在 yaml 設 `path`／`cpath`；範例仍用 `io.open` 寫檔 |

另外 8.0 的全域 Lua 函式改成放進 `require("suricata.xxx")` 的函式庫（`suricata.http`、`suricata.flow`、`suricata.packet`、`suricata.log` 等）。

### 官方文件
https://docs.suricata.io/en/latest/lua/index.html 、https://docs.suricata.io/en/latest/rules/lua-detection.html 、`doc/userguide/output/lua-output.rst`、`doc/userguide/upgrade.rst`。

### 能做什麼／不能做什麼
- 能做：自訂 log 格式；寫比一般規則更複雜的偵測邏輯。
- **不能當外部控制介面。** Lua 在引擎裡跑，是「Suricata 呼叫腳本」，不是「外部程式呼叫 Suricata」。它拿不到 verdict 控制權，也沒有改 flow 狀態的函式。對我們沒有幫助。[推測]

### 在 Pi arm64 + Debian 套件上能不能直接用
- **trixie 7.0.10 arm64：不能（Lua 沒編進去）。** 依據：`debian/rules` 的 `LUAJIT_ARCHS = i386 amd64 powerpc mips mipsel armel armhf`（第 20 行），**不含 arm64**；`CONFIGURE_ARGS` 沒有 `--enable-lua`；`configure.ac` 預設 `enable_lua="no"`；`Packages` 索引中 arm64 套件的 `Depends` 也沒有 `liblua*`／`libluajit*`。[已驗證-讀碼／清單，但沒有 `--build-info` 實測]
- **trixie-backports 8.0.7：應該有**（內建 Lua 5.4，不靠系統套件）。[推測，沒讀 backports 的 `debian/rules`]

---

## 6. EVE JSON 輸出（alert／flow／stats）

### 是什麼
Suricata 的統一事件輸出，每行一個 JSON：`alert`、`flow`、`netflow`、`stats`、`anomaly`、各協定（`dns`、`http`、`tls`…）等。所有事件共用 `flow_id`、`src_ip`、`src_port`、`dest_ip`、`dest_port`、`proto` 等欄位。

### 輸出方式（`filetype`）

| `filetype` | 行為（7.0.10 `util-logopenfile.c`） | 對我們 |
|---|---|---|
| `regular`（檔案） | 每筆事件 `fwrite` 後立刻 `fflush`（第 266–278 行），**無緩衝**；8.0 新增 `buffer-size`（預設 0＝不緩衝）與 `heartbeat.output-flush-interval` | 控制程式用 `tail -F`／inotify 讀。最簡單，但多一層檔案 IO（SD 卡要注意寫入量） |
| `unix_stream`／`unix_dgram` | **Suricata 是 client**：用 `connect()` 連到一個**由我們的程式 listen／bind 的 socket**；連不上時印 "will keep trying" 並定期重連。live 模式下加 `MSG_DONTWAIT`（第 614–618 行）：**對端讀太慢時事件會被丟棄**並累加 `dropped`（第 156–157、179–181 行）。**不支援 `threaded: yes`**（第 561–566 行，會直接 FatalError） | 延遲最低的現成管道；但控制程式必須快速消化，否則靜默丟告警 |
| `redis` | 用 hiredis 送到 Redis（`mode: list\|lpush\|rpush\|channel\|publish`、`async`、`pipelining.batch-size`） | Debian 套件有編 `--enable-hiredis`，arm64 依賴 `libhiredis1.1.0`。多一個 Redis 服務，Pi 上通常不值得 |
| `syslog` | 送 syslog | 不適合 |

### 延遲與事件時機
- **告警是即時的。** `alert` 事件在偵測引擎比對到規則的那個封包處理時就寫出，與封包同一個執行緒（8.0 文件：Write callback 跑在 packet processing thread）。所以「告警到我們收到」的延遲主要是**那一次 IPC 的成本**。我**沒有量測**。[已驗證-讀碼；數字未測]
  - 一個連帶的疑慮：IPS 模式下，封包的 verdict 是在 worker 處理完（含 logging）之後才送回 kernel，所以 EVE 寫出若變慢，會**直接拖慢那個封包的轉送**。用 `regular` 檔案時是同步 `fwrite`＋`fflush`，用 `unix_*` 時是非阻塞 `send`（慢就丟，不拖慢轉送）。這個先後順序是我讀 FlowWorker 與 NFQ verdict 流程的推論，未實測。[推測]
  - NFQ 模式的預設 runmode 是 `autofp`（`runmode-nfq.c` 的 `RunModeIpsNFQGetDefaultMode`），另有 `workers`。
- **`flow` 事件是在 flow 結束時才輸出**，不是即時的。預設 timeout（7.0.10 `suricata.yaml.in`）：TCP `new: 60`、`established: 600`、`closed: 60` 秒；UDP／ICMP `established: 300`。所以 flow record 可能晚數分鐘才出現。[已驗證-讀碼]
- **`stats` 事件**依 `stats.interval`（7.0.10 yaml 預設 8 秒）輸出；`dump-counters` 可隨時用 socket 拉。
- **flow record 的完整性**：`mechanisms.md` §M4／§2.7 已指出，被 ct mark 放行的 flow，Suricata 只看到放行前的封包，所以 EVE `flow` 的計數不完整。給雲端的 flow record 應從 conntrack 產生（`SYNTHESIS.md` §4.2）。EVE `flow` 在這個設計裡的角色只剩「稽核窗內 Suricata 實際看到什麼」。
- `flow_id` 是 Suricata 自己的雜湊值（`FlowGetId`），**不是 conntrack id**。要回到 conntrack 必須用 5-tuple（還要處理 NAT 前後位址）。[推測]

### 官方文件
https://docs.suricata.io/en/suricata-7.0.10/output/eve/eve-json-output.html 、https://docs.suricata.io/en/latest/output/eve/eve-json-output.html 、`doc/userguide/output/eve/eve-json-format.rst`。

### 在 Pi arm64 + Debian 套件上能不能直接用
**可以。** 兩個套件預設就開 `eve-log`；`unix_*` 與 `redis` 都在 Debian 的 configure 參數內。[已驗證-讀碼／清單]

---

## 7. Rust 介面

### 現有 `security_gateway` 在做什麼（只讀）
`/home/sixsquare/wnc_project/security_gateway/`：單一 `src/main.rs`，依賴 `etherparse 0.21.0` 與 `nfq 0.2.5`，edition 2024。程式 `Queue::open()` → `bind(0)` → `set_recv_conntrack(0, true)`，迴圈收 NFQUEUE 封包，印出 L3／L4／L7 摘要與 `ct_id`／`ct_state`，**一律 `Verdict::Accept`**。註解寫明之後要變成「本地判斷 → 判不出來問雲端 → 再決定 Accept/Drop」。**目前完全沒有和 Suricata 互動。**
兩點需注意：
- 它佔用 NFQUEUE 0。若 Suricata 同時走 NFQ，queue 編號要分開。
- `nfq` crate 的 `Message` 有 `get/set_nfmark`（封包 mark），**沒有 conntrack mark 的 setter**（docs.rs 方法清單），所以 ct mark 仍要靠 nft 規則或 ctnetlink。[二手：docs.rs 方法清單；底層是否另有支援未查]

### 官方 crate（OISF 發佈到 crates.io，GPL-2.0-only）
| crate | 版本 | 是什麼 | 對我們 |
|---|---|---|---|
| `suricata` | 8.0.7（2026-09-15）、9.0.0-alpha | Suricata 的 Rust 元件（`staticlib`＋`rlib`），引擎本體的一半 | 不是給外部呼叫的 API；plugin 才會依賴 |
| `suricata-sys` | 8.0.7、9.0.0-alpha | bindgen 產生的 C 介面綁定，輸入只含 plugin 相關標頭 | **寫 Rust plugin 用**；不含 library mode |
| `suricata-ffi` | 只有 9.0.0-alpha（2026-07 首發，72 下載） | `suricata-sys` 之上的 safe wrapper（EVE、flow、thread、applayer、jsonbuilder） | main 才有；與 8.0.x 不相容 |
| `suricata-derive`、`suricata-htp` | 同上 | 內部元件 | 無關 |
| `suricatasc` | 9.0.0-alpha（4,879 下載） | **只有 bin（`main.rs`），沒有 lib** | 當範例看，不是函式庫 |

### 社群 crate
| crate | 狀態 | 評估 |
|---|---|---|
| `suricata_client` 0.1.0-alpha.2 | 2022-01，MIT；crates.io 登記的 repo `jasonish/rust-suricata-extra` 在 2026-10-20 回 404 | 約 85 行的阻塞式 socket 客戶端；沒有維護，**不建議依賴**，自己寫等價的更穩 |
| `suricata-ipc` 0.19.0 | 2021-03，MIT／Apache-2.0；repo 最後 push 2021-03-31；README 要求**特製的 Suricata fork 分支**（`dbcfd/suricata` 的 `4070-packet-reinit-api-2`）加 IPC capture plugin | 概念上就是「Rust 用共享記憶體餵封包給 Suricata plugin、讀 EVE socket 告警」，但綁在舊 fork 上，**不可用** |
| `suritap` 0.1.0-rc1 | 2026-10-15，MPL-2.0，19 下載；plugin 本體在 `jc-lab/suricontroller`（Go 專案，要求 Suricata ≥ 8.0.5） | 做法是 Suricata 8.0 的 **capture plugin**（`--capture-plugin=suritap`），客戶端經 memfd ring 送 TLS 明文並取得 per-request verdict。**非常新、幾乎無使用者**，只能當「capture plugin 可以回 verdict」的存在證明 [二手] |
| `suricatax80-plugin-utils` 0.2.0-alpha.2 | 社群，GPL-2.0-only，143 下載 | 「Minimal Suricata 8.0 plugin ABI bindings」；來源不明，不建議 |
| `evebox`、`suriconf` | 應用程式／設定工具 | 無關 |

**結論**：沒有成熟的、可以「呼叫 Suricata」的 Rust 函式庫。官方的 Rust crate 都是給「寫 plugin 的人」用的；從外部控制 Suricata，Rust 最實際的做法是自己用 `serde_json` 實作 unix socket 協定（約 100 行）、用 `tokio`／標準庫的 `UnixDatagram` 或 `UnixListener` 收 EVE。

---

## 8. 總表：介面 × 我們的需求

圖例：**V** 直接可用且是這個介面的本職；**△** 可以但有限制（見備註）；**X** 做不到或不適用。版本欄寫該能力從哪個版本起、在 Debian 套件上是否現成。

| 介面 | 餵封包進 IDS | 取回告警 | 動態改信任／黑名單 | 執行期控制 | 上傳雲端用的資料 | 版本與 Debian 現況 |
|---|---|---|---|---|---|---|
| **1. Library mode** | **V**（自己的封包迴圈，verdict 在 release callback） | △（in-process 讀 `Packet`／alert 結構，或仍走 EVE） | △（可直接呼叫內部 dataset API，但是內部 API） | △（內部 API 都碰得到，但不穩） | △（flow 結構內有計數） | 8.0+；WIP；**Debian 無**，需自編 |
| **2a. Capture plugin** | **V** | X | X | X | X | 7.0.10 起（無版本檢查）、8.0 起有版本檢查；**Debian 無範例／headers** |
| **2b. EVE filetype plugin** | X | **V**（in-process 拿到 JSON buffer） | X | X | △（可隨 EVE 過濾） | 7.0.10 起；需自編 `.so` |
| **2c. EVE callback／flow callback／app-layer plugin** | X | △（只能追加欄位或觀察 flow） | X | X | △（可累計 per-flow 資料） | **8.0+**；Rust safe wrapper 只有 9.0-alpha |
| **3. Unix socket** | X | X（請求–回應，無推送；只能輪詢 `dump-counters`） | **V**（`dataset-*`、`add-hostbit`） | **V**（reload、memcap、版本等；**不能針對單一 flow**） | △（`dump-counters`、`get-flow-stats-by-id` 唯讀） | 7.0.10 起，三版相同；**Debian 現成**（`suricatasc` 在套件內） |
| **4. Datasets／datarep／hostbits** | X | X（它是規則的比對來源） | **V**（IP／字串，粒度為 host 不是 flow；無 TTL，hostbit 有 `expire`） | X | X | 7.0.10 起；**Debian 現成**；8.0 加 JSON 資料集 |
| **5. Lua** | X | X | X | X | △（output 腳本可自訂輸出） | 7.0.10 **arm64 Debian 沒編**；8.0 內建 Lua 5.4 |
| **6. EVE JSON** | X | **V**（`unix_dgram`／`unix_stream` 延遲最低，live 模式讀太慢會丟） | X | X | △（`flow` 事件，但被 ct mark 放行的 flow 不完整；應改用 conntrack） | 7.0.10 起；**Debian 現成**（redis 也有） |
| **7. Rust crate** | X | X | X | X | X | 官方 crate 只服務 plugin 開發；`suricata-ffi` 僅 9.0-alpha |

---

## 9. 建議的整合架構（全部 [推測]，待跟開發者討論）

三個方案的共同前提：**信任狀態＝kernel 的 ct mark，由我們的控制程式維護**（`SYNTHESIS.md` §4、`mechanisms.md` §7.2）。差別只在「Suricata 和控制程式之間用什麼接」。

### 方案 A：Suricata 當黑盒，控制程式在旁邊（只用 Debian 套件現成介面）

```
 封包 ──▶ nft (forward)
            │ ct mark = trusted ──▶ 直接 accept（不進 queue）
            │ 其餘 ──▶ NFQUEUE ──▶ Suricata（原版套件，IPS 模式）
                                      │ EVE alert/flow/stats（unix_dgram）
                                      ▼
                          控制程式（Rust，延伸 security_gateway）
                           ├─ 讀 EVE：告警 → 改 ct mark（撤銷）、記錄稽核結果
                           ├─ unix socket 回寫 Suricata：dataset-add（雲端判 malicious 的 IP）、
                           │   add-hostbit（帶 expire）、reload-rules、dump-counters
                           └─ ctnetlink / conntrack：改 ct mark、匯出 flow record 給雲端
```
- 用到的介面：§3 unix socket、§4 datasets／hostbits、§6 EVE。**全部 Debian 套件現成**，7.0.10 與 8.0.7 都能用。
- 開發成本：**低到中**。要寫的是 EVE 讀取、socket 客戶端、ct mark 操作，都是標準協定，不需要編 Suricata。
- 版本鎖定風險：**最低。** 依賴的是 EVE JSON 欄位與 socket 指令，這兩者在 7.0.10 → 8.0.7 → main 之間穩定。換版本（7.0.10 到 8.0.7 backports）幾乎不用改程式。
- 效能：Suricata 仍是標準 NFQ 路徑，與 `tests/ids_throughput` 量過的行為一致；額外成本是 EVE 的 IPC 和控制程式的處理。告警到撤銷的反應時間＝Suricata 偵測＋一次 IPC＋一次 ctnetlink，**沒有實測**。
- 是否方便之後自製 engine：**最方便。** 控制程式與 engine 的契約只有「告警事件的 schema」和「寫入黑名單或 hostbit 的指令」，換成自製 engine 只需讓它輸出同樣的事件、接受同樣的寫入。
- 缺點：Suricata 的 flow 表不能被外部重置；稽核窗開始時 TCP 是中途，stream 有洞（`midstream` 相關，見 `mechanisms.md` §7.5）。EVE `unix_dgram` 在讀太慢時靜默丟告警，控制程式必須優先處理並自己監看 `dropped`。

### 方案 B：方案 A ＋ 8.0 的 in-process plugin

在 A 的基礎上，換用 trixie-backports 的 8.0.7，另外自己編一個 8.0.7 的 C（或 Rust，用 `suricata-sys` 8.0.7）plugin：
- **EVE filetype plugin**：把 EVE JSON 直接交給 plugin，再以共享記憶體或內部 queue 轉給控制程式，繞過檔案或 socket 的序列化成本。
- **flow callback**：在 Suricata 內累計「稽核窗內每條 flow 看到的封包／位元組」，EVE 事件時順便附上。
- 開發成本：**中到高。** 要有 8.0.7 的建置環境（官方 release tarball ＋ configure ＋ `make install-library install-headers`），而且每次升到 8.0 的下一個 minor 或 9.0 都要重編。
- 版本鎖定風險：**中到高。** `SC_API_VERSION` 完全相等才載入；plugin 用 Suricata 內部型別；7.0.x 不能用。
- 效能：可能省下 JSON 序列化後再解析的成本，**但這個成本是否值得在 Pi 上優化，沒有量測。** 依專案原則「不要預先最佳化」，建議先量方案 A，確認 EVE 這條路真的是瓶頸才考慮。
- 是否方便自製 engine：中。plugin 綁 Suricata 內部型別，換 engine 時整個 plugin 要丟掉，控制程式那一側則可保留。

### 方案 C：Library mode，自帶 NFQ

控制程式（C／C++ 主程式，或 Rust 加自己對內部標頭 bindgen 的綁定）直接收 NFQUEUE，把封包以 `DLT_RAW` 餵進 libsuricata（8.0.x，自編），用 `ReleasePacket` callback 取得 drop 與否，**在同一個 process 內同時決定 verdict、ct mark 與信任**。
- 開發成本：**最高。** 要處理執行緒與 ThreadVars 建立時機、關閉順序、時間戳、封包池、IPS 模式設定；Rust 沒有現成綁定。
- 版本鎖定風險：**最高。** 官方明講 WIP、target 9.0.0-beta1；8.0.7 → main 已有簽名變動；等於把我們的程式綁在引擎內部。
- Debian 套件：**不能用**，且最終目標平台是 OpenWrt（musl、不同打包）時整套要重做。[推測：`docs/02-architecture.md` 寫目標是 OpenWrt，本次沒查 OpenWrt 的 suricata 套件版本與選項]
- 效能：省掉 Suricata 自己的 NFQ 接收執行緒，但 **kernel 到 userspace 的 netlink 往返仍在**。
- 是否方便自製 engine：**理論上最好**，因為封包迴圈在我們手上，換 engine 只是換被呼叫的那一端；但目前的收益遠小於成本。
- 結論：除非有「方案 A 做不到的事」否則不選。目前看不到這種事。

### 取捨一覽

| | A 黑盒＋旁路 | B A＋plugin | C library mode |
|---|---|---|---|
| 開發成本 | 低–中 | 中–高 | 最高 |
| 能用 Debian 套件 | 7.0.10 與 8.0.7 backports 皆可 | 需 backports 8.0.7 ＋自編 `.so` | 否，整個 Suricata 自編 |
| 版本鎖定風險 | 低 | 中–高（完全相等的 `SC_API_VERSION`） | 最高（WIP，內部 API） |
| 效能（相對 `tests/ids_throughput` 基線） | 與基線一致，加 IPC | 可能略好，未量 | 同 NFQ 往返，未量 |
| 之後換自製 engine | 最容易 | 中 | 理論最好，但現在成本高 |

### 我的建議（[推測]）
**先走方案 A。** 理由：它只依賴 Debian 套件現成且跨版本穩定的三個介面，和 `mechanisms.md` 的結論（信任與撤銷放 kernel＋控制程式）完全一致，也保留了日後替換 engine 的邊界。B 與 C 留到「方案 A 的量測顯示 EVE 路徑確實是瓶頸」或「需要 flow 層級的 in-engine hook」時再討論。

另外一個要提早決定、不屬於介面本身的問題：**Suricata 要不要從 7.0.10 換到 8.0.7（trixie-backports）。** 支持換的理由是 7.0 上游已 EOL、8.0 內建 Lua 5.4、datasets 有 JSON 與 subdomain 比對。反對的理由是 `tests/ids_throughput` 的基線都是 7.0.10，換版要重量；`mechanisms.md` 裡 depth 預設值與 TLS bypass 閘門在 8.0 的差異也要逐項確認。這個決定不影響方案 A 的程式碼，可以後做。

---

## 10. 未能確認清單與最不確定的三件事

### 未能確認
1. **Debian 兩個套件實際的 `suricata --build-info`**：plugin support、unix socket、hiredis、nfqueue、Lua 全是由 `debian/rules`、`configure.ac` 和 `Packages` 依賴推論，沒有實機輸出。
2. **trixie-backports 8.0.7 的 `debian/rules`**：沒讀；Lua 內建、plugin 支援、`libsuricata` 是否被刻意排除都是推測。
3. **Library mode 下 engine 如何進入 IPS 模式**，以及 `ReleasePacket` 裡的 drop 是否等同 NFQ 的 NF_DROP。
4. **NFQ 模式下 `iface-stat` 是否有計數**：`runmode-nfq.c` 呼叫了 `LiveDeviceHasNoStats()`，但它只影響關閉時的日誌，`iface-stat` 實際回什麼沒查。
5. **EVE `unix_dgram`／`unix_stream` 在 Pi 上的實際延遲與丟包率**；`dropped` 計數有沒有出現在 `stats` 事件。
6. **`dataset-add` 在 Pi 上的吞吐與記憶體成本**（大量 IP 時）；8.0 的 `single-hashsize` 預設上限 65536 對大清單的影響。
7. **8.0.x 內 patch 版之間 plugin 的 ABI 相容性**：文件沒承諾，我只看到 `SC_API_VERSION` 只有 major.minor。
8. **`iprep`／reputation 的執行期更新方式**：沒查。
9. **8.0 firewall mode**（experimental，`accept` 動作、default drop）是否能取代部分 nft 規則：本次未評估。
10. **OpenWrt 上 suricata 套件的版本與編譯選項**：`docs/02-architecture.md` 說有，我在 `openwrt/packages` 的 `net/`、`security/`、`admin/`、`utils/` 下查不到 `suricata` 目錄。
11. **`nfq` crate 底層是否支援 `NFQA_CT` 之類的 conntrack 屬性寫入**：只看了 docs.rs 的 `Message` 方法清單。
12. `suritap` 的 plugin 原始碼未讀（只讀了 crate 的 README）；`suricata-ipc` 只讀了 README 與 plugin README。
13. 7.0.10 tag 沒有 `examples/` 的原因（git 樹上確實沒有，是否在發佈 tarball 裡不同未查）。

### 最不確定的三件事
1. **EVE → 控制程式 → ct mark 撤銷這條路的端到端反應時間與丟包行為。** 整個方案 A 的「稽核窗命中就撤銷」都押在這條路上，目前全部來自讀碼推論（非阻塞送出、讀太慢就丟）。建議第一個實驗：在筆電 netns 用 Suricata 7.0.10 設 `filetype: unix_dgram`，讓一個小 Rust listener 量「封包送出到收到告警」的延遲，再加壓看何時開始丟。
2. **7.0.10 → 8.0.7 換版對 Pi 的實際影響。** 效能（pps、RSS）、`mechanisms.md` 提到的 depth 預設值與 TLS bypass 閘門差異、Debian backports 的實際編譯選項，都沒實測。7.0 上游已 EOL，這件事遲早要決定。
3. **Library mode 與 plugin 的長期可行性。** 兩者官方都說還在進行；我只確認了「8.0.x 有、7.0.x 沒有」和「main 已有 API 變動」，**沒有編譯過、沒有跑過**。如果之後要考慮方案 B 或 C，要先做一個最小的 8.0.7 範例（官方 `examples/lib/live` 或 `examples/plugins/c-json-filetype`）在 arm64 上實際編過，才能判斷成本。

---

## 11. 來源索引

**Suricata 文件（均已確認可開，HTTP 200）**
- https://docs.suricata.io/en/latest/devguide/libsuricata/index.html
- https://docs.suricata.io/en/suricata-8.0.7/devguide/libsuricata/index.html
- https://docs.suricata.io/en/suricata-7.0.10/devguide/extending/index.html
- https://docs.suricata.io/en/latest/devguide/extending/output/eve-filetypes.html
- https://docs.suricata.io/en/latest/devguide/extending/output/eve-hooks.html
- https://docs.suricata.io/en/latest/plugins/index.html
- https://docs.suricata.io/en/suricata-7.0.10/unix-socket.html 、 https://docs.suricata.io/en/latest/unix-socket.html
- https://docs.suricata.io/en/suricata-7.0.10/rules/datasets.html 、 https://docs.suricata.io/en/latest/rules/datasets.html
- https://docs.suricata.io/en/suricata-7.0.10/rules/xbits.html
- https://docs.suricata.io/en/suricata-7.0.10/output/eve/eve-json-output.html 、 https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- https://docs.suricata.io/en/latest/lua/index.html 、 https://docs.suricata.io/en/latest/rules/lua-detection.html
- https://docs.suricata.io/en/latest/upgrade.html
- 7.0.10 的 libsuricata devguide 頁：`https://docs.suricata.io/en/suricata-7.0.10/devguide/libsuricata/index.html` 回 404（確認 7.0 沒有這頁）

**Redmine／公告**
- https://redmine.openinfosecfoundation.org/issues/2693 （tracking: libsuricata，In Progress，target 9.0.0-beta1）
- https://redmine.openinfosecfoundation.org/issues/4101 （plugins 追蹤票）
- https://forum.suricata.io/t/suricata-8-0-0-released/5854 （8.0.0 發佈說明，2025-07-08）
- https://suricata.io/?p=8314 （2026-07-09：8.0.6 與 7.0.17 公告，「Suricata 7 has reached EOL」）
- https://suricata.io/?p=1253 （「7.0.x: end of life since July 7th, 2026」）

**Suricata 原始碼**（tag 7.0.10、8.0.7，以及 main@`9451642a`）
- https://github.com/OISF/suricata/blob/suricata-8.0.7/src/runmode-lib.c 、 `src/runmode-lib.h` 、 `src/source-lib.c`
- https://github.com/OISF/suricata/tree/suricata-8.0.7/examples/lib （custom、live、simple、cplusplus）
- https://github.com/OISF/suricata/tree/suricata-8.0.7/examples/plugins （altemplate、c-custom-loggers、c-json-filetype、ci-capture）
- https://github.com/OISF/suricata/blob/suricata-8.0.7/src/util-plugin.c （第 54 行版本檢查）
- https://github.com/OISF/suricata/blob/suricata-7.0.10/src/suricata-plugin.h 、 `src/util-plugin.c`
- https://github.com/OISF/suricata/blob/suricata-8.0.7/src/suricata-plugin.h 、 `src/flow-callbacks.h` 、 `src/output-eve.h`
- https://github.com/OISF/suricata/blob/suricata-7.0.10/src/unix-manager.c 、 `src/runmode-unix-socket.c`
- https://github.com/OISF/suricata/blob/suricata-7.0.10/src/util-logopenfile.c
- https://github.com/OISF/suricata/blob/suricata-8.0.7/rust/suricatasc/src/unix/client.rs
- https://github.com/OISF/suricata/tree/main/examples/plugins/rust 、 `rust/ffi` 、 `rust/sys`
- https://github.com/OISF/suricata/blob/suricata-7.0.10/configure.ac （第 394–413 行 plugin、第 1882–1889 行 Lua）

**Debian**
- https://packages.debian.org/trixie/suricata 、 https://packages.debian.org/trixie/arm64/suricata/filelist 、 https://packages.debian.org/trixie-backports/arm64/suricata/filelist
- `Packages.xz` 索引：trixie-security、trixie main、trixie-backports、sid（arm64）
- https://salsa.debian.org/pkg-suricata-team/pkg-suricata/-/raw/debian/trixie/debian/rules 、 `debian/control` 、 `debian/patches/debian-default-cfg.patch`

**Rust crate（crates.io API 與 crate 原始檔）**
- https://crates.io/crates/suricata 、 `suricata-sys` 、 `suricata-ffi` 、 `suricatasc` 、 `suricata_client` 、 `suricata-ipc` 、 `suritap` 、 `suricatax80-plugin-utils`
- https://github.com/protectwise/suricata-ipc
- https://github.com/jc-lab/suricontroller
- https://docs.rs/nfq/0.2.5/nfq/struct.Message.html
