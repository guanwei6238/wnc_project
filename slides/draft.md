# 報告製作規劃

## 標題
security gateway 實做規劃

## 內容主題
### 1. 實體與模擬環境建立
目前是使用樹莓派(型號: Raspberry Pi 3 Model B+) 搭配 OS(Raspberry Pi OS Lite 64-bit) 來建立實際 gateway。
因為未來實際會使用 OpenWrt 正式建立 gateway，所以我們也用 docker 搭設模擬環境來做輔助測試

note: 這部份可以說明多一點像是架構怎麼樣等等

### 2. packet processer 介紹
介紹 XDP + netfilter 解析分包的架構(目前看起來是主流研究方向)，與 DPDK 的架構（基本上不會使用這個，因為在 openwrt 並且架構是 arm 上）

note: 目前主要是說明有什麼解決方法，所以慨念上可以只有架構圖並說明一下目前社群使用得架構是什麼

### 3. 有什麼 bench 可以做？
主要以列點的方式說明有哪些 benchmark 可以讓我們測試

### 4. 目前有的 rule
是否有 ids 或是 open source 的規則可以拿來直接用

### 5. openwrt 整合
到時候怎麼將研究出來的實驗遷移到實體的 openWrt 上面
