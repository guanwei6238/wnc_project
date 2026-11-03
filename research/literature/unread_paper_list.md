# Related Work 閱讀清單：Resource-Constrained Security Gateway Framework

## 1. 研究背景與目前方向

本研究以**低硬體資源的 Edge Gateway**（原型使用 Raspberry Pi，後續可移植至其他 ARM 裝置）為目標，設計、實作並評估一套**可擴充的 Security Gateway Framework**。研究定位是系統架構與實作驗證，而非提出新的 ML 入侵偵測演算法。

目前規劃的主要封包處理流程為：

```text
NIC
 └─ XDP（可選：依網卡與驅動能力決定）
     └─ TCX / TC eBPF（Flow 特徵、規則、Fast Path）
         └─ Netfilter / nftables
             └─ NFQUEUE → Suricata（本地 IDS）
                 └─ 正常轉送

非同步控制流程：
Suricata Events + Flow Features
    → User-space Agent
    → Cloud API（可選）
    → Response / Policy Decision
    → 更新 Kernel 規則與 Flow 狀態
```

框架的設計目標包括：

- **可擴充的 eBPF 模組**：允許依需求載入或停用 XDP、TCX 等 eBPF 程式。
- **本地 IDS 整合**：以 Suricata 為初期主要引擎，保留替換或擴充的可能。
- **可選的 Cloud Integration**：Cloud 可以開啟或完全關閉，關閉後仍能獨立運作。
- **可配置的 Cloud API 與資料轉換**：Request、Response、欄位與對應規則由使用者配置，而非綁定特定雲端模型。
- **低資源部署與可量測性**：評估 Throughput、Latency、CPU、Memory、Packet Drop 與 Cloud Transmission Cost。

## 2. 前面討論後的研究定位

先前閱讀的 Edge Multi-agent IDS（ICPS 2024）著重多個 Edge ML 模型之間的協作。它和本研究同樣涉及 Edge / Cloud，但**研究問題不同**：本研究不是要整合多個 ML 模型做投票，而是建立一個能配置封包處理、本地 IDS 與可選 Cloud 分析的 **Gateway Framework**。

相關文獻已經提出過 eBPF Network Function Framework、Kernel / User-space 分層、Suricata Gateway，以及 Edge–Cloud IDS。因此，論文**不應以「第一次把 eBPF、IDS、Cloud 組合起來」作為主要創新宣稱**。

以碩士論文為目標，比較合適的主線是：

1. **Design**：說明低資源限制、模組邊界、插件介面與可選 Cloud 的設計理由。
2. **Implementation**：完成可運作的 Gateway 原型，展示 eBPF、Suricata 與 Cloud Connector 的整合。
3. **Extensibility Evaluation**：證明不同 eBPF 程式與 Request / Response 設定能替換，且停用 Cloud 不影響本地運作。
4. **Performance Evaluation**：測量框架本身及不同模組組合增加的成本；必要時再評估 Fast Path 的節省效果與風險。

**閱讀這些論文的主要目的**不是再增加功能，而是確認哪些架構已有前例、如何合理切分模組、以及如何設計足以支撐碩士論文的實驗。

## 3. Related Work — 優先閱讀（6 篇）

這六篇最接近「框架架構、低資源設備、模組擴充、實機效能評估」的需求。

| 順序 | 論文 | 年份 | 主要閱讀目的 | 論文連結 |
|---:|---|:---:|---|---|
| 1 | **GALETTE: a Lightweight XDP Dataplane on your Raspberry Pi** | 2023 | 低階 SBC、Fast / Slow Path、實機 Benchmark | [DOI](https://doi.org/10.23919/IFIPNetworking57963.2023.10186412) · [全文資訊](https://eprints.gla.ac.uk/296605/) |
| 2 | **A Framework for eBPF-Based Network Functions in an Era of Microservices**（Polycube） | 2021 | 可擴充 eBPF Framework、控制／資料平面、Framework Overhead | [DOI](https://doi.org/10.1109/TNSM.2021.3055676) · [PDF](https://sebymiano.github.io/publication/2021-polycube/2021-polycube.pdf) |
| 3 | **An eBPF-Based Programmable Network Architecture for OT Digital Resilience Use-Cases** | 2025 | 可程式化 eBPF Pipeline、Network Function Chaining | [DOI](https://doi.org/10.1109/ISCC65549.2025.11325939) · [全文資訊](https://eprints.gla.ac.uk/354500/) |
| 4 | **MiddleNet: A Unified, High-Performance NFV and Middlebox Framework with eBPF and DPDK** | 2023 | Kernel / User-space 分工、不同處理路徑與效能比較 | [DOI](https://doi.org/10.1109/TNSM.2023.3256891) · [預印本](https://arxiv.org/abs/2303.04404) |
| 5 | **PASS: A Flexible Programmable Framework for Building Integrated Security Stack in Public Cloud** | 2025 | Framework 擴充能力的評估方式、開發與維護成本 | [DOI](https://doi.org/10.3390/electronics14132650) · [全文](https://www.mdpi.com/2079-9292/14/13/2650) |
| 6 | **Edge Computing IoT Security (ECIS): Implementation of IPS and Encryption for My I-Pond** | 2025 | Raspberry Pi 上整合 Suricata 的實作與測試 | [DOI](https://doi.org/10.1109/ICOIACT67584.2025.11345049) |

## 4. Related Work — 延伸閱讀（6 篇）

這一組補強動態 eBPF、Edge / Cloud IDS、流量篩選與相關研究全貌；不必一開始全部精讀。

| # | 論文 | 年份 | 主要閱讀目的 | 論文連結 |
|---:|---|:---:|---|---|
| 7 | **BPFabric: Data Plane Programmability for Software Defined Networks** | 2017 | eBPF 程式動態部署、Data Plane 可程式化 | [DOI](https://doi.org/10.1109/ANCS.2017.14) · [全文資訊](https://eprints.gla.ac.uk/138952/) |
| 8 | **Real-Time eBPF/XDP-Based Deep Learning Framework for Anomaly Traffic Detection in Internet of Things Networks** | 2026 | Raspberry Pi 上 eBPF 與 User-space IDS 的整合量測 | [DOI](https://doi.org/10.1109/MIC.2026.3692726) |
| 9 | **HorusEye: A Realtime IoT Malicious Traffic Detection Framework using Programmable Switches** | 2023 | Fast / Slow Path、選擇性分析與 Offloading 成本 | [PDF](https://www.usenix.org/system/files/usenixsecurity23-dong-yutao.pdf) |
| 10 | **An Energy-Efficient Intrusion Detection Offloading Based on DNN for Edge Computing** | 2025 | Cloud Offloading 的成本、延遲與評估設計 | [DOI](https://doi.org/10.1109/JIOT.2025.3544060) · [作者 PDF](https://secplab.ppgia.pucpr.br/files/papers/2025_3.pdf) |
| 11 | **PALANTIR: An NFV-Based Security-as-a-Service Approach for Automating Threat Mitigation** | 2023 | 安全功能協調、Policy Management、分散式系統架構 | [DOI](https://doi.org/10.3390/s23031658) · [全文](https://www.mdpi.com/1424-8220/23/3/1658) |
| 12 | **eBPF-based cybersecurity mechanisms: a systematic literature review** | 2026 | 擴大搜尋範圍、分類 eBPF Security 相關研究 | [DOI](https://doi.org/10.1007/s10207-026-01326-x) · [預印本](https://arxiv.org/abs/2608.27511) |

> 注意：第 12 篇是 Systematic Literature Review，其數據主要來自既有文獻整理；其餘研究包含各自的實驗，但測試平台與量測指標不完全相同，不宜直接跨論文比較數值。

## 5. 閱讀時要整理的資訊

不用逐篇寫長篇摘要。建議每篇只記錄下面這些資訊，方便後續寫 Related Work 比較表：

| 欄位 | 要記錄什麼 |
|---|---|
| Problem | 作者想解決的系統問題 |
| Architecture | Kernel、User Space、IDS、Cloud 的分工方式 |
| Extensibility | 插件／模組如何載入、替換或停用 |
| Hardware | CPU 架構、RAM、網卡與實驗平台 |
| Baselines | 和哪些框架或配置比較 |
| Metrics | Throughput、Latency、CPU、Memory 等實際量測項目 |
| Limitations | 尚未支援或未驗證的情境 |
| Relevance | 哪些設計或實驗方法可以借鑑到本研究 |

### 建議先回答的三個問題

1. **框架類研究怎麼證明自己的價值？** 主要參考 Polycube、PASS。
2. **低階硬體的網路處理效能應該怎麼量？** 主要參考 GALETTE、ECIS。
3. **哪些設計已有人做過，哪些需要在自己的論文中說明取捨？** 主要參考 MiddleNet、BPFabric、PALANTIR 與 eBPF Systematic Review。

## 6. 暫定論文方向

**英文題目（工作名稱）**  
*Design, Implementation, and Evaluation of an Extensible Security Gateway Framework for Resource-Constrained Edge Devices*

**中文題目（工作名稱）**  
*適用於資源受限邊緣裝置之可擴充安全閘道器框架：設計、實作與效能評估*

這個題目聚焦於框架本身，保留 Cloud 作為**可選功能**，也不把研究限制在特定 eBPF Hook、Suricata 規則或 ML 模型。正式題目可隨最終完成的功能與實驗結果調整。
