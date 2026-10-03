// ============================================================
//  簡報共用模板
//
//  外觀與元件由 slydekit 提供（主題、box library、版面工具）。
//  這個檔案只負責兩件事：
//    1. 把 slydekit 設定成這個專案要的樣子（中文字型、繁中標點、16:9）
//    2. 補上 slydekit 不會有的「專案語意」—— 封包處理三階段的配色與標籤
//
//  每份報告的 src/*.typ 用 #import "../../template.typ": * 匯入。
//  slydekit 自己的元件（warning-box、adaptive-columns、focus-slide…）
//  會一併被 re-export，可以直接使用。
// ============================================================

#import "@preview/slydekit:0.4.1": *
#import "@preview/fletcher:0.5.8" as fletcher: diagram, node, edge
#import "@preview/cetz:0.4.2"

// ------------------------------------------------------------
//  字型
// ------------------------------------------------------------
#let font-sans = "Noto Sans CJK TC"
#let font-mono = "Noto Sans Mono CJK TC"

// ------------------------------------------------------------
//  配色：封包處理管線的三個階段
//  這是本專案的語意色，全份報告共用，不要在個別頁面另外指定顏色
// ------------------------------------------------------------
#let c-stage1 = rgb("#2f7d4f") //  ① XDP                綠
#let c-stage2 = rgb("#c77b16") //  ② netfilter          黃／橘
#let c-stage3 = rgb("#9b3a6e") //  ③ NFQUEUE/user space 紅／紫

#let c-cloud = rgb("#3a6ea5") //  雲端
#let c-lan = rgb("#4a6572") //  內網 LAN
#let c-wan = rgb("#7a5c3e") //  外網 WAN
#let c-muted = rgb("#6b7280") //  次要文字
#let c-line = rgb("#9ca3af") //  框線
#let c-good = rgb("#2f7d4f")
#let c-warn = rgb("#c77b16")
#let c-bad = rgb("#b3261e")

// 淡色底（用於方塊填色）
#let tint(c, amount: 88%) = c.lighten(amount)

// ------------------------------------------------------------
//  主設定
//  用法：#show: slides.with(title: "...", subtitle: "...", date: "...")
//        接著 #title-slide
// ------------------------------------------------------------
#let slides(
  title: "",
  subtitle: none,
  short-title: none,
  author: none,
  date: none,
  body,
) = {
  show: slydekit.with(
    title: title,
    subtitle: subtitle,
    short-title: short-title,
    author: author,
    date: date,
    theme: metropolis,
    lang: "zh",
    aspect-ratio: "16-9",
    // minislide 會把每個章節標題都印在頁首。中文標題偏長，
    // 五個節擠在一起會換行、和內容搶注意力，所以用 topbar：
    // 頁首只顯示目前這一頁的所在位置。
    navigation-style: "topbar",
    fonts: (body: font-sans, raw: font-mono, math: font-sans),
  )

  // slydekit 的 lang: "zh" 預設走簡體標點（逗號置中），
  // 補 region 才會得到繁中的標點與斷行規則。
  set text(region: "tw")

  // 等寬字型在同一 size 下的視覺大小比 CJK sans 大不少，
  // 不收一點的話 inline code（`nft`、`.ipk`）會把行高撐開。
  show raw: set text(size: 0.82em)

  // 投影片常有多欄／卡片這種窄版面，左右對齊會把中文字距拉開
  // （「規 則 語 意」），可讀性反而變差。一律不對齊。
  set par(justify: false)

  body
}

// ------------------------------------------------------------
//  提示框
//  實際是 slydekit 的 custom-box，這裡只是把種類收斂成四種，
//  讓全份報告的用法一致。也可以直接用 slydekit 原本的
//  warning-box / info-box / tip-box / important-box。
// ------------------------------------------------------------
#let callout(body, kind: "warn", title: none) = {
  let (c, icon) = if kind == "bad" {
    (c-bad, "stop")
  } else if kind == "good" {
    (c-good, "tip")
  } else if kind == "info" {
    (c-cloud, "info")
  } else {
    (c-warn, "alert")
  }
  custom-box(title: title, icon: icon, color: c, body)
}

// ------------------------------------------------------------
//  排版小工具
// ------------------------------------------------------------

// 重點字
#let hl(body, color: c-stage3) = text(fill: color, weight: "bold", body)

// 置中強調的結語
#let punch(body) = align(center)[
  #block(
    inset: (x: 14pt, y: 10pt),
    radius: 4pt,
    fill: tint(c-stage3, amount: 93%),
    text(size: 1.05em, weight: "bold", body),
  )
]

// 判斷標記
#let yes = text(fill: c-good, weight: "bold")[✓]
#let no = text(fill: c-bad, weight: "bold")[✗]
#let partly = text(fill: c-warn, weight: "bold")[△]

// 階段標籤：#stage(1)[XDP] → 帶圈號與專屬配色的標籤
#let stage(n, body) = {
  let c = (c-stage1, c-stage2, c-stage3).at(n - 1)
  box(
    inset: (x: 6pt, y: 3pt),
    radius: 3pt,
    fill: tint(c, amount: 88%),
    text(fill: c, weight: "bold", size: 0.9em)[#(("①", "②", "③").at(n - 1)) #body],
  )
}

// slydekit 已經幫 table 上好樣式，tbl 只是保留一個統一入口
#let tbl(columns: auto, align: left, ..cells) = table(
  columns: columns,
  align: align,
  ..cells,
)

// ------------------------------------------------------------
//  架構圖節點（搭配 fletcher 的 diagram() 使用）
// ------------------------------------------------------------

// 彩色方塊節點
#let boxnode(pos, body, color: c-muted, width: auto, ..args) = node(
  pos,
  align(center, text(size: 0.8em, body)),
  fill: tint(color, amount: 90%),
  stroke: 1pt + color,
  corner-radius: 3pt,
  inset: 8pt,
  width: width,
  ..args,
)

// 虛線外框，用來框住一組節點（例如 kernel space / user space）
#let groupnode(pos, body, color: c-line, ..args) = node(
  pos,
  body,
  stroke: (paint: color, dash: "dashed", thickness: 1pt),
  corner-radius: 4pt,
  inset: 10pt,
  fill: none,
  ..args,
)

// kernel / user space 分界線的標籤樣式
#let boundary(body) = text(size: 0.72em, fill: c-muted, style: "italic", body)
