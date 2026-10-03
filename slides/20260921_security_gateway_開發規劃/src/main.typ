#import "../../template.typ": *

#show: slides.with(
  title: "Security Gateway 開發規劃",
  date: "2026-09-21",
)

#title-slide

== 大綱

#v(1.2em)
#align(left)[
  #block(inset: (left: 12%))[
    #set text(size: 1.2em)
    #set par(leading: 1.4em)
    #set align(left)
    + 實體與模擬環境建立
    + Packet Processor 介紹
    + Benchmark
    + 可用的規則與引擎
  ]
]

= 1. 實體與模擬環境建立

== 設備的目標形態

#v(0.3em)
#align(center)[
  #diagram(
    spacing: (4em, 3em),
    node-stroke: none,
    boxnode((1, 0), [Cloud Analysis], color: c-cloud, width: 4.6cm),
    boxnode((0, 1), [LAN Client], color: c-lan, width: 4.2cm),
    boxnode((1, 1), [Security Gateway], color: c-muted, width: 4.6cm),
    boxnode((2, 1), [Internet], color: c-wan, width: 4.2cm),
    edge((0, 1), (1, 1), "-|>", [LAN port], label-size: 0.8em, stroke: 1pt + c-lan),
    edge((1, 1), (2, 1), "-|>", [WAN port], label-size: 0.8em, stroke: 1pt + c-wan),
    edge((1, 1), (1, 0), "-|>", [uncertain], label-side: left, label-pos: 55%, label-size: 0.75em, stroke: (paint: c-cloud, dash: "dashed", thickness: 1pt)),
  )
]

#v(0.5em)
- *兩個網路 port*：內外網分離，安全閘道器在流量的必經路徑上。
- #hl[閘道器判斷不出來：]送雲端分析

== 實體環境

#align(center)[
  #diagram(
    spacing: (2.6em, 2.0em),
    node-stroke: none,

    // 內外網兩端是同一台 laptop 的兩個網路介面，接成一個迴路。
    // 直接畫成「一個 laptop 方塊、裡面兩個介面」，而不是用外框去圈兩個分離的方塊 ——
    // fletcher 的框線位置會被格線欄寬牽動，圈不準。
    node(
      (0, 0),
      [
        #text(size: 0.62em, fill: c-muted)[Same Laptop]
        #v(0.35em)
        #grid(
          columns: (auto, auto), gutter: 2cm,
          block(
            inset: (x: 8pt, y: 5pt), radius: 3pt,
            fill: tint(c-lan, amount: 90%), stroke: 1pt + c-lan,
          )[#text(size: 0.72em)[LAN #text(size: 0.8em)[(netns)]]],
          block(
            inset: (x: 8pt, y: 5pt), radius: 3pt,
            fill: tint(c-wan, amount: 90%), stroke: 1pt + c-wan,
          )[#text(size: 0.72em)[WAN]],
        )
      ],
      stroke: (paint: c-line, dash: "dashed", thickness: 0.8pt),
      inset: 9pt, fill: none, corner-radius: 4pt,
    ),

    boxnode((0, 1), [Raspberry Pi], color: c-muted, width: 3cm),

    edge((0, 0), (0, 1), "-|>", [LAN port], label-pos: 25%, label-sep: 2pt, label-size: 0.64em, bend: -34deg, stroke: 1pt + c-lan),
    edge((0, 1), (0, 0), "-|>", [WAN port], label-pos: 75%, label-sep: 2pt, label-size: 0.64em, bend: -34deg, stroke: 1pt + c-wan),
  )
]

#v(0.15em)
#align(center)[
  #tbl(
    columns: (auto, 2fr, 2fr),
    [], [前期原型], [最終目標],
    [硬體], [Raspberry Pi 3 Model B+], [ARM Based 設備],
    [OS], [Raspberry Pi OS Lite 64-bit], [#hl[OpenWrt]],
  )
]

#v(0.2em)
#text(size: 0.7em)[
  - 閘道器是 *Raspberry Pi 3 Model B+*，內建網口 + 一張 USB 網卡湊出兩個 port
]

== 模擬環境

#v(0.3em)
#align(center)[
  #diagram(
    spacing: (5.5em, 2em),
    node-stroke: none,
    boxnode((0, 0), [cli\ LAN client], color: c-lan, width: 3.6cm),
    boxnode((1, 0), [gw\ gateway container], color: c-muted, width: 3.6cm),
    boxnode((2, 0), [srv\ WAN server], color: c-wan, width: 3.6cm),
    edge((0, 0), (1, 0), "-|>", [lan network], label-size: 0.75em, stroke: 1pt + c-lan),
    edge((1, 0), (2, 0), "-|>", [wan network], label-size: 0.75em, stroke: 1pt + c-wan),
  )
]

#v(1em)
- 用 *Docker* 搭三個容器節點模擬「內網 → 閘道器 → 外網」，#hl[閘道器容器掛在兩個網段上]，對應實機的雙 port
- 用途：在動實機之前，先在模擬環境驗證網路拓撲與 nftables 規則

== 為什麼兩個環境都要

#v(0.4em)
#align(center)[
  #block(width: 88%)[
    #set align(left)
    #set text(size: 0.95em)
    每改一次規則就要搬上樹莓派重測，迭代太慢，所以#hl[邏輯的部分先在 Docker 驗]。

    #v(0.4em)
    但 #hl[Docker 容器共用 host 的 kernel]，有些東西它驗不到。
  ]
]

#v(0.7em)
#align(center)[
  // 區塊置中，但區塊「裡面」的文字要靠左 ——
  // 否則條列換行後的第二行會縮在中間，讀起來像斷句錯誤。
  #block(width: 84%)[
    #set align(left)
    #set text(size: 0.94em)
    - *Docker 能夠驗證*：nftables 規則語意、conntrack、NFQUEUE 的決策流程
    - *樹莓派能夠驗證*：aarch64 指令集、資源受限環境下的行為、實體雙 port 接線與部署流程
    ]
]

= 2. Packet Processor 介紹

== 封包分析的兩種方法

#v(0.4em)
#align(center)[
  #grid(
    columns: (1fr, 1fr),
    gutter: 2.5em,
    align(center)[
      #block(text(size: 0.9em, weight: "bold", fill: c-stage1)[方法 1：留在 kernel 內])
      #diagram(
        spacing: (4.2em, 0.6em),
        node-stroke: none,
        boxnode((0, 0), [NIC], color: c-muted, width: 2.2cm),
        boxnode((1, 0), [kernel:\ XDP + netfilter], color: c-stage2, width: 3.4cm),
        boxnode((2, 0), [user space], color: c-stage3, width: 2.4cm),
        edge((0, 0), (1, 0), "-|>"),
        edge((1, 0), (2, 0), "-|>", [if needed], label-side: left, label-size: 0.62em),
      )
    ],
    align(center)[
      #block(text(size: 0.9em, weight: "bold", fill: c-bad)[方法 2：kernel bypass])
      #diagram(
        spacing: (4.2em, 0.6em),
        node-stroke: none,
        boxnode((0, 0), [NIC], color: c-muted, width: 2.2cm),
        boxnode((1, 0), [PMD driver], color: c-bad, width: 2.4cm),
        boxnode((2, 0), [user space\ app], color: c-muted, width: 3cm),
        edge((0, 0), (1, 0), "-|>"),
        edge((1, 0), (2, 0), "-|>", [✗ bypass], label-side: left, label-size: 0.62em),
      )
    ],
  )
]

#v(0.5em)
#text(size: 0.8em)[
  #tbl(
    columns: (auto, 2fr, 2fr),
    [], [方法 1：留在 kernel 內], [方法 2：kernel bypass],
    [代表技術], [*XDP + netfilter / nftables*], [*DPDK*],
    [封包走向], [走 kernel 的網路路徑], [#hl(color: c-bad)[繞過 kernel]，直接進 user space],
    [網卡歸屬], [仍屬於作業系統], [#hl(color: c-bad)[整張交給 user space 程式]],
  )
]


== 方法 1：留在 kernel 內（XDP + netfilter）

#align(center)[
  #diagram(
    spacing: (1.1em, 1em),
    node-stroke: none,
    boxnode((0, 0), [NIC], color: c-muted, width: 2cm),
    boxnode((1, 0), [XDP], color: c-stage1, width: 2.3cm),
    boxnode((2, 0), [Network Stack], color: c-muted, width: 4.1cm),
    boxnode((3, 0), [netfilter / nftables], color: c-stage2, width: 3.8cm),
    boxnode((4, 0), [Routing], color: c-muted, width: 3.1cm),
    boxnode((3, 1), [NFQUEUE\ user space decision], color: c-stage3, width: 5.2cm),
    edge((0, 0), (1, 0), "-|>"),
    edge((1, 0), (2, 0), "-|>"),
    edge((2, 0), (3, 0), "-|>"),
    edge((3, 0), (4, 0), "-|>"),
    edge((3, 0), (3, 1), "-|>"),
  )
]

#text(size: 0.73em)[
  #set table(inset: (x: 6pt, y: 3pt))
  #tbl(
    columns: (auto, 2.4fr, 2.4fr),
    [], [XDP], [netfilter / nftables],
    [位置], [stack 前], [stack 內],
    [適合做], [無狀態即可判定], [需要連線狀態才能判的],
    [內建 conntrack], [#no], [#yes],
    [能處理 IP 分片], [#no], [#yes],
    [能交給 user space], [#no], [#yes 透過 NFQUEUE],
  )
]

#text(size: 0.7em)[
  #hl[現成可參考的實作]：`xdp-filter` —— 比對 IP／port／MAC，*刻意不做複雜比對*以換取極高的丟包速率。\
  #hl[可用的函式庫]：`libbpf`／`aya`（XDP）、`libnftnl`／`rustables`（nftables）、`libnetfilter_queue`／`nfq`（NFQUEUE）。
]

== 方法 2：kernel bypass（DPDK）

#v(0.3em)
#align(center)[
  #diagram(
    spacing: (5.6em, 1.4em),
    node-stroke: none,
    boxnode((0, 0), [NIC], color: c-muted, width: 2.6cm),
    boxnode((1, 0), [PMD driver], color: c-bad, width: 3.6cm),
    boxnode((2, 0), [user space app\ #text(size: 0.7em)[(own polling loop)]], color: c-muted, width: 4.6cm),
    edge((0, 0), (1, 0), "-|>"),
    edge((1, 0), (2, 0), "-|>", [✗ bypasses\ kernel stack], label-size: 0.58em, label-side: left, label-pos: 50%),
  )
]

#v(0.6em)
#align(center)[
  #tbl(
    columns: (auto, 3fr, 4fr),
    [], [得到], [失去],
    [DPDK], [極高的封包處理效能], [#hl(color: c-bad)[conntrack、nftables、路由表全部不能用]],
  )
]

#v(0.3em)
#text(size: 0.74em)[#hl[現成可參考的實作]：`rte_acl`： 分類函式庫，支援優先序與多重比對，搭配官方的 `l3fwd` 範例。]

== 目前選擇：方法 1

#v(0.6em)
#text(size: 0.88em)[
+ *OpenWrt 上的主流做法就是這套*：官方 feed 裡的 `snort3`、`kmod-nft-queue`、`libnetfilter-queue` 都是使用這個方法。

+ *用 DPDK 會讓 OpenWrt 的 offload 全部失效*：OpenWrt 的 software flow offload 與 hardware flow offload（MediaTek PPE 等）都是由 kernel 的 netfilter flowtable 驅動的。網卡一旦交給 DPDK，#hl(color: c-bad)[這些加速路徑就不存在]，等於退回純軟體轉發。

]

= 3. Benchmark

== 可以量的指標

#v(0.8em)
#align(center)[
  #block(width: 86%)[
    #set align(left)
    #grid(
      columns: (1fr, 1fr),
      gutter: 3em,
      align: top,
      [
        - Throughput
        - Latency
        - Packet loss rate
        - CPU utilization
        - Concurrent connections
        - CPS / TPS
      ],
      [
        - NDR / PDR
        - Frame size sweep
        - pps / bps limits
        - Latency percentile (p50 / p99)
        - TTFB / TTLB
        - TLS handshake rate
      ],
    )
  ]
]

= 4. 可用的規則與引擎

== 規則來源與開源引擎

#v(0.8em)
#grid(
  columns: (1.6fr, 1fr),
  gutter: 3em,
  align: top,
  [
    #text(weight: "bold", size: 1.05em, fill: c-stage2)[規則]
    #v(0.6em)
    #tbl(
      columns: (auto, auto),
      [來源], [授權],
      [*ET Open*], [#hl(color: c-good)[BSD + GPLv2]],
      [*Snort 3 Community*], [#hl(color: c-good)[GPLv2]],
      [Snort Registered], [免費，需註冊],
      [Snort Subscriber], [付費],
    )
  ],
  [
    #text(weight: "bold", size: 1.05em, fill: c-stage3)[開源引擎]
    #v(0.6em)
    - *Suricata*
    - *Snort 3*
    - *Zeek*
  ],
)

#focus-slide[Q & A]
