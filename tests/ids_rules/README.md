# tests/ids_rules — 產生 `full` rule 檔（ET Open 的 Suricata 版與 Snort 版）

這個資料夾只做一件事：取得 ET Open 2026-10-11 的規則快照，整理成兩個 engine 都能完整載入的 `full` rule 檔，
交給 `tests/ids_throughput/` 量處理速度（`sel`、`gw_corp` 都是從 `full` 再挑出來的，在那邊產生）。

| rule 檔 | 來源 | 條數 | 交給 `ids_throughput` 的檔名 |
|---|---|---|---|
| Suricata 版 `full` | ET Open `suricata-7.0.10` 包，所有啟用的 rule | 52,606（Suricata 全部載入，0 條失敗） | `suricata_full.rules` |
| Snort 版 `full` | ET Open `snort-3.0.0` 包，經 `snort2lua` 轉換後 Snort 3 能載入的 rule | 52,445（啟用 52,491 條的 99.91%） | `snort_full.rules` |

兩個 engine 用的是 ET 各自維護的兩份規則文字（語法不同、rev 也常不同），同一個 sid 不代表規則內容完全一樣。

## 環境

- Docker image `wnc-ids-lab`（`Dockerfile`）：基底 `debian:trixie`，和 Pi 的 Raspberry Pi OS 同一個 Debian 版本；
  Suricata 用 apt（7.0.10）；Debian trixie 沒有 Snort 套件，所以用官方 release tag 編譯 Snort 3.12.2.0 + libdaq 3.0.27。
  建立：`docker build -t wnc-ids-lab - < Dockerfile`（需要網路，約 10 分鐘）。
- 執行階段一律 `--network none`（`lib.sh` 的 `dk()` 已固定），並用 `--user` 避免寫出 root 擁有的檔案。
- 大檔放 repo 外的 `/home/sixsquare/datasets/rulesets/`：
  - `dl/`、`dl_snort/`：下載的規則包與下載時間、sha256
  - `snapshot_2026-10-11/`：Suricata 版快照；`snapshot_snort-3.0.0_2026-10-11/`、`snapshot_snort-2.9.0_2026-10-11/`：Snort 版快照（兩包內容完全相同，流程用 3.0.0）
  - `work/`：合併後的規則（容器內唯讀掛在 `/rules`）；`work/snort_pack/`：Snort 版的合併、轉換、迭代載入結果
  - `runs/`：每次執行的 log（容器內 `/out`）
- 下載來的規則包是不受信任的資料：解壓前檢查 tar 清單沒有絕對路徑或 `..`、解到新的空目錄並設唯讀；Python 一律用 `python3 -I`。

## 最小流程

以下在這個資料夾執行，`R=/home/sixsquare/datasets/rulesets`。快照已經存在時，`00`、`13` 會拒絕覆蓋（實驗要用同一份）。

**Suricata 版**

```bash
./00_fetch_rules.sh snapshot_2026-10-11                                       # 下載、檢查、解壓、設唯讀
python3 -I 01_snapshot_stats.py $R/snapshot_2026-10-11/rules results/rule_stats.tsv   # 啟用 52,606、註解停用 19,494
python3 -I 02_prep_rules.py $R/snapshot_2026-10-11/rules $R/work                # -> work/et_all.rules（52,606 條）+ et_all.map.tsv
# （選用）確認 Suricata 全部載入：log 應有 "52606 rules successfully loaded, 0 rules failed"
source lib.sh; dk -- /scripts/ids.sh suri-T /out/suri_T /rules/et_all.rules; grep 'successfully loaded' $R/runs/suri_T/out.log
```

**Snort 版**

```bash
./13_fetch_snort_rules.sh 2026-10-11                                          # 下載 snort-3.0.0 與 snort-2.9.0 兩包
python3 -I 01_snapshot_stats.py $R/snapshot_snort-3.0.0_2026-10-11/rules results/rule_stats_snort.tsv   # 啟用 52,491
python3 -I 02_prep_rules.py $R/snapshot_snort-3.0.0_2026-10-11/rules $R/work/snort_pack
./15_snort_convert.sh                                                         # snort2lua：轉換成功 52,447、轉不了 44
./16_snort_iter_load.sh                                                       # 迭代載入：第 1 輪移除 2 條（PCRE2 編譯錯誤），第 2 輪通過
python3 -I 18_snort_attribute.py $R/work/snort_pack $R/runs $R/per_rule_status_snort.tsv results/snort_attribution_summary.txt
```

**交給 `ids_throughput`**

```bash
B=/home/sixsquare/datasets/throughput/rules
cp $R/work/et_all.rules                    $B/suricata_full.rules   # sha256 2eb7d7db…
cp $R/work/snort_pack/snort_accepted.rules $B/snort_full.rules      # sha256 32dd7ba9…
(cd $B && sha256sum -c --ignore-missing SHA256SUMS)                  # 和量測時記錄的 sha256 比對
```

## 檔案

| 檔案 | 做什麼 |
|---|---|
| `00_fetch_rules.sh` | 下載 ET Open `suricata-7.0.10` 包（ET 依 Suricata 版本分目錄，7.0.10 是 Debian trixie 的 Suricata 版本），檢查 tar 清單、解壓到新目錄、設唯讀 |
| `01_snapshot_stats.py` | 統計每個 `.rules` 檔有幾條「啟用」與「被 `#` 註解停用」的 rule |
| `02_prep_rules.py` | 把啟用的 rule 合併成一個檔（`et_all.rules`），另存「行號 → sid、category」對照（`et_all.map.tsv`）。engine 的錯誤訊息都帶「檔案:行號」，合併後才能逐條對回 sid |
| `13_fetch_snort_rules.sh` | 下載 ET Open 的 Snort 版包（`snort-3.0.0`、`snort-2.9.0`；"2.9" 只是規則語法世代，跑的仍是 Snort 3），檢查、解壓、設唯讀 |
| `15_snort_convert.sh` | 用 Snort 3 附的 `snort2lua` 把 Snort 版規則轉成 Snort 3 語法。轉不了的整條被 `#` 註解並寫進 `snort2lua_err.txt` |
| `16_snort_iter_load.sh` + `16b_drop_bad_rules.py` | Snort 3 只要有一條 rule 出錯就整個 FATAL，所以 `-T` 載入 → 從 `ERROR: 檔:行號` 找出壞 rule 移除 → 重載，迭代到沒有 ERROR。每輪移除的 sid 與原因記在 `runs/snort_iter/removed.tsv`，最後的檔是 `work/snort_pack/snort_accepted.rules` |
| `18_snort_attribute.py` | Snort 版逐條歸因（有沒有轉換成功、有沒有載入、原因、哪一輪移除）。完整表放 repo 外，摘要寫到 `results/snort_attribution_summary.txt` |
| `ids.sh` | 容器內的統一入口：`suri-T`／`suri-r`／`snort-T`／`snort-r`，包 `/usr/bin/time -v`；預設 matcher 是 Suricata `ac-ks` + `bm`、Snort 3 `ac_bnfa`，並設定 Snort 3 的 `HOME_NET` |
| `lib.sh` | 共用路徑與 `dk()`（`docker run --network none --user …`，掛上 `/scripts`、`/rules`、`/out`） |
| `Dockerfile` | `wnc-ids-lab` image；依 CPU 架構選 Hyperscan（amd64）或 vectorscan（arm64） |
| `rules_manifest.txt` | Suricata 版快照的下載網址、時間、tarball 與每個 `.rules` 檔的 sha256 |
| `results/rule_stats.tsv`、`results/rule_stats_snort.tsv` | `01` 的輸出（Suricata 版、Snort 版） |
| `results/snort_attribution_summary.txt` | `18` 的輸出 |
| `results/versions.txt` | image 內 engine 的版本與編譯資訊（Snort 3 `BUILD_INFO`、`suricata --build-info`、`snort -V`、`search_method` 選項） |

## 載入時要注意的地方

- **Snort 3 的 `HOME_NET`**：預設 `any` 會讓 ET 的 `!$HOME_NET` 報 "!any is not allowed"，這是設定問題不是規則問題。
  `ids.sh`（和 `tests/ids_throughput/measure.sh`）把 `HOME_NET` 設成和 Suricata 預設相同的 RFC1918 三段。
- **Snort 3 的 `total rules loaded` 不能直接當載入數**：它把有錯的 rule 也算進去，而且多算 219 條內建的 file_id rule
  （空規則檔也是 219）。所以載入數要用「沒有 ERROR 的那一輪」再減 219：52,664 − 219 = 52,445。
- **Suricata 的 `signatures processed`（52,611）比 `rules successfully loaded`（52,606）多**：header 用 `<>`（雙向）的 rule，
  Suricata 內部會展開成兩條 signature。
- **`threshold`**：`snort2lua` 把 rule 裡的 `threshold` 改寫成 `.lua` 的 `event_filter`。只用 `-R` 載 rule 時這些不會生效，
  要另外載入（`ids.sh` 的 `EVENT_FILTER_LUA`）。`tests/ids_throughput` 量速度時沒有載入，所以兩個 engine 的 alert 數不能直接比。
- **matcher**：Pi 上 Debian 套件的 Suricata 沒有 Hyperscan，所以 Suricata 固定 `mpm-algo=ac-ks`、`spm-algo=bm`，Snort 3 用 `ac_bnfa`，
  讓 x86 容器和 Pi 用同樣的演算法。

## 和 Pi 的對應

`full` rule 檔是文字檔，Pi 上直接用同一份（sha256 相同）。規則能不能解析、哪幾條被拒絕，只取決於 engine 版本與規則文字，
和 CPU 架構無關；Pi 上裝的也是 Suricata 7.0.10 與 Snort 3.12.2.0。這個資料夾在 x86 的 Docker 裡做，**沒有**量載入時間與 memory；
Pi 上的數字在 `tests/ids_throughput/`。
