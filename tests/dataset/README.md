# Dataset 可用性測試

回答一個問題：**公開資料集（目前是 IoT-23 小樣本）能不能拿來測我們的 security gateway？**

| 關卡 | 指令 | 驗證什麼 | 需要 lab |
|---|---|---|---|
| 1 | `./01_verify.sh` | 檔案雜湊、PCAP 完整、封包數／標籤列數；小案例可重新裁切出相同檔案 | 否 |
| 2 | `./02_align.py [conn.log] [pcap]` | 每條有標籤的 flow 能不能對回 PCAP 的封包；各標籤有沒有 payload | 否 |
| 3 | `./03_replay.sh [次數] [cases/*.env]` | 改寫位址後重播穿過 gw；規則停用／啟用對照，看入口、出口、計數器 | 是（`docker/up.sh`） |

- `data/`：資料集補充包的原始樣本、裁切小案例與兩支檢查腳本（未修改）
- `cases/*.env`：一個檔案 = 一個測試案例（PCAP、位址對應、規則、預期處置）。換 dataset 只要加檔案
- `Dockerfile.tools`：tcpreplay / tcprewrite 的工具 image，用 `--network container:wnc-cli` 借用 cli 的網路
- `out/<時間>/`：第 3 關的抓包證據與 `summary.txt`

**不能證明的事**：C&C 標籤的封包全是無 payload 的 SYN，規則只能用 IP/port 封鎖，
這只證明「gateway 依設定處置」，不代表 gateway 能辨識 C&C。
