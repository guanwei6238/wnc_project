#!/usr/bin/env bash
# 編譯報告。
#
# 標題只在 src/main.typ 的 `title:` 出現一次，輸出的 PDF 檔名由它決定 ——
# 所以改標題只要改那一行，不用再手動改檔名。
#
# 用法：
#   ./build.sh                  在報告資料夾裡直接跑
#   ./build.sh <報告資料夾>       從別處指定
#   ./build.sh -p               順便逐頁輸出 PNG（方便檢查排版）
#   ./build.sh --clean          編譯後直接刪掉檔名不符的舊 PDF（不再詢問）
#
# 檔名裡的空格會換成底線：「Security Gateway 開發規劃」→ Security_Gateway_開發規劃.pdf
#
# 為什麼需要 --root：
#   src/main.typ 會 import "../../template.typ"，那個路徑在報告資料夾之外。
#   typst 預設不准跨出輸入檔所在的目錄，所以要把 root 指到 slides/。
set -euo pipefail

SLIDES_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PNG=0
CLEAN=0
TARGET=""
for arg in "$@"; do
  case "$arg" in
    -p | --png) PNG=1 ;;
    --clean) CLEAN=1 ;;
    -*) echo "未知選項：$arg" >&2; exit 1 ;;
    *) TARGET="$arg" ;;
  esac
done

DIR="$(cd "${TARGET:-$PWD}" && pwd)"
SRC="$DIR/src/main.typ"

[[ -f "$SRC" ]] || { echo "找不到 $SRC" >&2; exit 1; }

# 從 main.typ 抓標題（第一個 title: "..."）
TITLE="$(sed -n 's/^[[:space:]]*title:[[:space:]]*"\(.*\)",[[:space:]]*$/\1/p' "$SRC" | head -1)"
[[ -n "$TITLE" ]] || { echo "在 $SRC 裡找不到 title:" >&2; exit 1; }

# 檔名用底線，避免路徑帶空格
NAME="${TITLE// /_}"
PDF="$DIR/$NAME.pdf"

echo "標題：$TITLE"
typst compile --root "$SLIDES_ROOT" "$SRC" "$PDF"

PAGES="$(pdfinfo "$PDF" 2>/dev/null | awk '/^Pages:/{print $2}')"
echo "輸出：$NAME.pdf${PAGES:+（$PAGES 頁）}"

if [[ $PNG -eq 1 ]]; then
  OUT="/tmp/$(basename "$DIR")"
  rm -rf "$OUT"; mkdir -p "$OUT"
  typst compile --root "$SLIDES_ROOT" --format png --ppi 110 "$SRC" "$OUT/p{0p}.png"
  echo "逐頁 PNG：$OUT/"
fi

# 改過標題之後，舊檔名的 PDF 會留在資料夾裡。
# CLAUDE.md 規定「只會有一個 [標題].pdf」，所以提醒一下。
mapfile -t STALE < <(find "$DIR" -maxdepth 1 -name '*.pdf' ! -name "$NAME.pdf" -printf '%f\n')
if [[ ${#STALE[@]} -gt 0 ]]; then
  echo
  if [[ $CLEAN -eq 1 ]]; then
    echo "刪除檔名不符的舊 PDF："
    for f in "${STALE[@]}"; do rm -v "$DIR/$f"; done
  else
    echo "⚠️  檔名不符的舊 PDF："
    printf '    %s\n' "${STALE[@]}"
    echo "    （要刪的話加 --clean）"
  fi
fi
