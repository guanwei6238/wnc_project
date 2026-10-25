# 實驗室網路與 SSH（這台電腦 ↔ Raspberry Pi）

> 最後更新：2026-10-11 晚。標記 ✔ = 已實測；△ = 推測或尚未實測；⏳ = 驗證進行中。
> 這份文件只講「怎麼連、怎麼設定、哪裡有坑」。實驗本身的內容不在這裡。

## 1. 架構

```
 這台電腦 (sixsquare-laptop)                              Raspberry Pi 4 Model B Rev 1.4 (4 GB)
 ┌───────────────────────────────┐                        ┌────────────────────────────────────┐
 │ eno2  04:42:1a:85:7f:e7       │────────── 線 1 ────────│ eth1  9c:69:d3:24:1b:d9 (ASIX USB) │ ✔ 2026-10-24 在 Pi 上用 ip link 確認
 │       10.254.254.1/24  (WAN側)│                        │       10.254.254.2/24  ✔ 已設定    │
 │                               │                        │                                    │
 │ enx9c69d32a1154 (USB 網卡)    │────────── 線 2 ────────│ eth0  e4:5f:01:2d:03:bf (內建)     │ △ 依封包計數推測
 │ 9c:69:d3:2a:11:54             │                        │       仍是舊設定 172.24.8.131      │
 │       10.254.127.1/24  (LAN側)│                        │       預計 10.254.127.2/24 (未做)  │
 └───────────────────────────────┘                        └────────────────────────────────────┘
```

- **2026-10-16 兩張 USB 網卡對調過**（見 `lab-net.sh`）：Pi 的 `eth1` 現在是 `9c:69:d3:24:1b:d9`，筆電的 USB 網卡是 `9c:69:d3:2a:11:54`。
- **Pi 的 `eth1` 已經是靜態 `10.254.254.2/24`**（✔，永久設定，存在 NetworkManager 裡）。`eth0` 還是舊設定（尚未需要，未改）。
- **網卡名稱會因機型而不同**：Pi 3B+ 時 `eth0` 是 USB 網卡；Pi 4 是反過來。**請用 MAC 認網卡，不要用 `eth0`/`eth1`。**

## 2. SSH 登入（複製即用）

**主要用這個（IPv4，✔）：**

```bash
ssh wnc@10.254.254.2
```

**備用：IPv6 link-local（✔；位址最後的 `%eno2` 不能省）：**

```bash
ssh wnc@fe80::1f9d:9dcc:3f01:5e15%eno2
```

- ✔ 免密碼（金鑰），帳號 `wnc`，主機名稱 `wnc-project`。
- ✔ 主機金鑰指紋（ED25519）：`SHA256:o7WbaqCy0EX3IdI/KvT6A5+kEO8ZTnV8NIH9edsysmI`
  （同一張 SD 卡從舊的 Pi 3B+ 換過來，所以和舊 Pi 相同。）

### 傳檔案 ✔

```bash
scp 檔案 wnc@10.254.254.2:~/
scp wnc@10.254.254.2:~/檔案 .
rsync -a 目錄/ wnc@10.254.254.2:~/目錄/
# 若用 link-local，位址要加方括號和引號：
scp 檔案 'wnc@[fe80::1f9d:9dcc:3f01:5e15%eno2]:~/'
```

### 在 Pi 上執行單一指令 ✔

```bash
ssh wnc@10.254.254.2 'vcgencmd get_throttled; vcgencmd measure_temp'
```

### 設一個短別名（寫進 `~/.ssh/config`）✔

```
Host pi4
    HostName 10.254.254.2
    User wnc
```

（若別名要用 link-local：`HostName fe80::1f9d:9dcc:3f01:5e15%%eno2`，**`%` 在 SSH 設定檔裡是特殊字元，必須寫成 `%%`**，
寫成單個 `%` 會出現 `percent_expand: failed`。）設好之後：`ssh pi4`。

### 連不上時，怎麼找 Pi ✔

```bash
ping -c 2 10.254.254.2                 # IPv4 通不通
ping -6 -c 2 -I eno2 ff02::1           # 對線上所有 IPv6 裝置喊話
ip -6 neigh show dev eno2              # 找 MAC 是 9c:69:d3:24:1b:d9 的那一行，就是 Pi 的 eth1
```

## 3. 已知問題與曾經踩過的坑

### 問題 A：Pi 的網路每 8 分鐘中斷約 5 分鐘（✔ 已確認原因；✔ 已修並驗證穩定）

- 原因（✔）：Pi 的連線設定 `Wired connection 2` 套在 `eth1`、設成 DHCP，但這條線上沒有 DHCP 伺服器。
  NetworkManager 連續試 4 次（每次 45 秒，約 3 分鐘，這段 SSH 通），然後冷卻 5 分鐘（`fe80::` 消失，SSH 不通），再重來。
- 修法（✔ 已執行）：改成靜態位址，見第 4 節 4b。
- **這會讓所有量測失去可信度**（量到一半線斷了）。修好後必須長時間探測確認不再中斷，結果見第 7 節。

### 問題 B：Pi 上的 `sudo` 會卡住很久（✔ 已確認原因；已修）

- 原因：Pi 的 `/etc/hosts` 沒有它自己的主機名稱 `wnc-project`（舊名稱 `raspberrypi` 還在），`sudo` 會做 DNS 解析，
  Pi 沒有網際網路，DNS 一直逾時。
- 修法（✔ 已執行）：`/etc/hosts` 現在是 `127.0.1.1  wnc-project raspberrypi`，見第 4 節 4a。
- **曾踩的坑**：把指令直接貼在 Pi 的終端機時，`\"` 會被當成真的雙引號寫進 `/etc/hosts`，
  造成一行 `"127.0.1.1 wnc-project"`（開頭帶引號，不是有效位址）。已清除。引號問題請用「放腳本再執行」的做法（4a）。

### 問題 C：`ssh: ... Network is unreachable`（✔）

- 原因：網卡沒有 IPv6 link-local 位址。NetworkManager 管這張卡時，會把 `addr_gen_mode` 設成 1（不自動產生）。
- 解法：這台電腦已經安裝了開機設定（第 5 節），不會再發生。

### 問題 D：`Host key verification failed`（✔）

- 原因：這台電腦的 `known_hosts` 沒有這個位址。比對指紋與上面相同後，加入信任：

```bash
ssh -o StrictHostKeyChecking=accept-new wnc@10.254.254.2 true
```

### 注意 E：Pi 的 `wnc` 目前是「免密碼 sudo」（✔ 2026-10-11 依使用者決定設定）

- 決定者：使用者。理由：實驗需要自動化設定 CPU governor、限制記憶體、重開機。**已被告知的風險：任何能用 `wnc` 的
  SSH 金鑰連進 Pi 的人或程式，都等於取得 root。**
- 實作：`/etc/sudoers.d/90-wnc-nopasswd`，內容 `wnc ALL=(ALL) NOPASSWD: ALL`（用 `visudo -cf` 驗證語法後才安裝）。
  ✔ 已驗證：先 `sudo -k` 清掉快取，`sudo -n id` 仍成功（約 0.04 秒），整份 sudoers 語法 OK。
- **還原**（在 Pi 上）：`sudo rm /etc/sudoers.d/90-wnc-nopasswd`
- 補充：Pi 另有 `/etc/sudoers.d/010_global-tty`（`timestamp_type=global`），代表即使沒有免密碼，
  輸入一次密碼後約 5 分鐘內，任何連線（包含非互動 SSH）都能用 sudo。
- 約定（主 agent）：只在實驗需要時使用 Pi 的 root（設 governor、限制記憶體、重開機、讀硬體狀態）；
  **重開機與修改 `config.txt` 會先告知使用者**。

## 4. 曾經做過的 Pi 修復（紀錄，也是重做的指令）

**4a. 修 `/etc/hosts`（✔ 已執行）。** 做法是把一個小腳本放到 Pi，再用 `sudo sh` 執行，避免引號出錯：

```bash
# 在這台電腦上：腳本內容見 scratchpad，或用 4a 的描述重寫。
# 在 Pi 上執行：
sudo sh ~/fix_hosts.sh
```

腳本做的事：備份 `/etc/hosts` 到 `/etc/hosts.bak.<時間>`；移除帶引號的壞行；把 `127.0.1.1 raspberrypi` 改成 `127.0.1.1 wnc-project raspberrypi`。
（Pi 的家目錄裡仍有 `~/fix_hosts.sh`，可以重複執行，結果不會再變。）

**4b. 把 `eth1` 改成靜態位址（✔ 已執行；NetworkManager 永久設定）：**

```bash
sudo nmcli con mod 'Wired connection 2' ipv4.method manual ipv4.addresses 10.254.254.2/24 ipv6.method link-local
sudo nmcli con up 'Wired connection 2'
```

執行後 `eth1` 的 `fe80::1f9d:9dcc:3f01:5e15` **沒有變**（✔）。

## 5. 這台電腦的開機設定：`lab-net.sh`（✔ 已安裝並重開機驗證）

做什麼：讓 NetworkManager 不管 `eno2` 和 USB 網卡、讓核心自動產生 `fe80::`、設定 `10.254.254.1/24` 與
`10.254.127.1/24`。只動這兩張網卡，不設預設路由，不碰 Wi-Fi / Docker / `172.24.x`。

```bash
cd ~/wnc_project/scripts
./lab-net.sh status           # 看狀態（不需要 root）
DRY=1 ./lab-net.sh install    # 只印出會做什麼，不真的做
sudo ./lab-net.sh up          # 立刻套用（可重複執行）
sudo ./lab-net.sh down        # 只移除我們加的 IPv4 位址
sudo ./lab-net.sh install     # 安裝成開機自動執行
sudo ./lab-net.sh uninstall   # 完整移除，網卡還給 NetworkManager
```

- 安裝時會把腳本**複製**到 `/usr/local/sbin/wnc-lab-net`。之後改了 `lab-net.sh`，要重跑 `sudo ./lab-net.sh install` 才會生效。
- 網卡的 MAC 與位址集中在檔案最上面的 `NICS` 區，要換網卡只改那裡。
- `netns.sh` 會把 USB 網卡搬進 namespace，之後 `status` 會顯示「找不到這張網卡」，這是預期行為。
  `netns.sh` / `netns-down.sh` 在這個新設定下**尚未實測**（△）。

## 6. Pi 現況（✔ 2026-10-11 實測）

| 項目 | 內容 |
|---|---|
| 機型 | Raspberry Pi 4 Model B Rev 1.4，**4 GB**（可用約 3.8 GB） |
| 系統 | Debian 13.7 (trixie)，kernel 6.18.50+rpt-rpi-v8，aarch64 |
| CPU | 4 核，硬體上限 1800 MHz。**量測時固定在「量測模式」：governor=`performance`、最高時脈鎖 1000 MHz**（見下方「散熱」）。用 `pi_lab_mode.sh up` / `down` 切換，只影響這次開機 |
| 供電 | 官方電源；✔ 供電沒有問題：所有滿載驗收中都**沒有出現欠壓（bit0）** |
| 散熱 | ★ **不足**：未加散熱時，1800 MHz 持續滿載約 30 秒就達 80°C 開始降頻（見下方） |
| 網卡 | `eth0` = 內建 bcmgenet（`e4:5f:01:2d:03:bf`），`eth1` = ASIX USB（`9c:69:d3:24:1b:d9`，cdc_ncm；10/16 對調前是 `9c:69:d3:2a:11:54`） |
| 網際網路 | **沒有**（預設閘道 `172.24.8.254` 不通）；因此不能 `apt install`、不能校時（時鐘停在 10/3） |
| `sudo` | 可用，**免密碼**（注意 E） |
| 已安裝 | Suricata 7.0.10（Debian 套件，**無 Hyperscan**，有 AF_PACKET 與 NFQUEUE）、Snort 3 3.12.2.0-1（舊 My-Compiler CI 打的 deb，trixie 上可執行）、nftables、tcpdump、ethtool、python3 |
| 沒裝 | tcpreplay、iperf3、vectorscan、`bc` |

### ★ 散熱與時脈：Pi 4 必須鎖頻才能做可重現的量測（✔ 2026-10-11 實測）

Pi 4（沒有加散熱片／風扇）持續 4 核心滿載時，溫度很快升到 80°C 以上，CPU 開始降頻，時脈在 600～1700 MHz 之間亂跳，
**量測結果會隨溫度飄移而不可重現**。所以量測一律在「量測模式」下做：

| 最高時脈上限 | 滿載長度 | 最高溫度 | 結果 |
|---|---|---|---|
| 1800 MHz（預設） | 600 s | 85.7°C | **FAIL**：30 秒達 80.8°C，之後降頻，時脈 600～1680 MHz 亂跳 |
| 1500 MHz | 240 s | 84.7°C | FAIL（軟性溫度限制，110 秒起） |
| 1200 MHz | 240 s | 80.3°C | 邊緣：無降頻旗標，但只差 0.3°C，沒有餘裕 |
| **1000 MHz** | 240 s | 75.4°C | PASS |
| **1000 MHz** | **600 s** | **77.4°C** | **PASS**（溫度約 75–77°C 趨於平穩；距離 80°C 只有約 2.6°C 餘裕） |

- 全程**沒有欠壓**，問題純粹是散熱。
- **報告要明講**：Pi 4 的結果是在 **1000 MHz** 下量的（散熱限制），低於它的實際能力。**不能寫成「Pi 4 的吞吐」**，
  也不能直接類比 Pi 3B+（沒有量過兩者的對應關係）。
- 若之後加了散熱片／風扇：`pi_lab_mode.sh up 1800`，再跑 `pi_power_check.sh 600 4 10` 驗收，通過就可以用完整速度重測。
- 餘裕只有約 2.6°C，環境溫度升高就可能降頻。**每次量測前後都要檢查 `get_throttled` 與溫度**，不是 `0x0`（目前位元）就作廢。

```bash
scp ~/wnc_project/scripts/pi_lab_mode.sh wnc@10.254.254.2:~/
ssh wnc@10.254.254.2 'bash ~/pi_lab_mode.sh up 1000'     # 進入量測模式（鎖 1000 MHz）
ssh wnc@10.254.254.2 'bash ~/pi_lab_mode.sh status'      # 看目前狀態
ssh wnc@10.254.254.2 'bash ~/pi_lab_mode.sh down'        # 還原（ondemand、1800 MHz）
# 重新找可持續的最高時脈（約 20–40 分鐘，每個候選含降溫等待）：
ssh wnc@10.254.254.2 'nohup bash ~/pi_freq_cap_search.sh 1500 1200 1000 > ~/freq_cap_search.log 2>&1 < /dev/null &'
```

### 完整驗收：供電與散熱（`pi_power_check.sh`）

在 Pi 上開 4 個滿載程序，每 10 秒取樣 `get_throttled`／時脈／溫度，最後給 PASS 或 FAIL。
判準：全程沒有欠壓／降頻、最高溫 < 80°C、最低時脈 ≥ 上限的 95%。**每次正式量測之前都應該先過這一關。**

```bash
scp ~/wnc_project/scripts/pi_power_check.sh wnc@10.254.254.2:~/
ssh wnc@10.254.254.2 'bash ~/pi_power_check.sh 600 4 10'        # 完整 10 分鐘
ssh wnc@10.254.254.2 'bash ~/pi_power_check.sh 20 4 2'          # 20 秒快速試跑（✔ 已測，PASS）
# 想在背景跑、不佔用 SSH：
ssh wnc@10.254.254.2 'nohup bash ~/pi_power_check.sh 600 4 10 > ~/power_check_600.log 2>&1 < /dev/null &'
```

### 檢查供電與溫度（單次，複製即用）

```bash
ssh wnc@10.254.254.2 'echo "throttled=$(vcgencmd get_throttled | cut -d= -f2)"; vcgencmd measure_temp; echo "ARM $(( $(vcgencmd measure_clock arm | cut -d= -f2) / 1000000 )) MHz"'
```

`throttled=0x0` 才是正常。非 0 時，每一位的意思：bit0 目前欠壓、bit2 目前降頻、bit16 開機後曾欠壓、bit18 開機後曾降頻。
（bit16、bit18 只有重新開機才會清掉。）

## 7. 驗證紀錄與還沒做的事

- ✔ 修復後的連線穩定性（2026-10-11 16:46–17:00）：14 分鐘連續探測 `10.254.254.2:22` 與 link-local `:22`，每 3 秒一次，
  **0 次中斷、0 秒不通**（修復前是約每 8 分鐘中斷 5 分鐘）。
- Pi 側 LAN 口（內建網口 `10.254.127.2`）與 IP 轉送還沒設定（離線量測不需要，之後做 inline 才需要）。
- 線 2（Pi 內建網口 ↔ USB 網卡）只是依封包計數推測，沒有直接驗證。
- 測試時 SSH 管理要走哪條路還沒決定（走測試線會干擾量測；Pi 4 有 Wi-Fi 可以專用於管理）。
- 若要模擬 Pi 3B+ 的 1 GB 記憶體，可在 Pi 的 `/boot/firmware/config.txt` 加 `total_mem=1024`（△ 印象中的韌體選項，未驗證，且需要 root 與重開機）。
- `scp` 用別名（`scp 檔案 pi4:~/`）應該可用，但我只測了 `ssh pi4`。
