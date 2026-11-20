#!/bin/bash
# Download and freeze a snapshot of the "Snort" ET Open rules (for Snort 3; Suricata uses the Suricata version from 00_fetch_rules.sh).
# Why a separate one: the Suricata rules use Suricata-only keywords such as dns.query/tls.sni…, which Snort 3 cannot use. ET also ships packages in Snort syntax:
#   open/snort-3.0.0/  and  open/snort-2.9.0/   ("2.9" is the rule syntax generation; the engine we run is still Snort 3.12.2.0,
#   snort2lua is just the rule converter bundled with Snort 3). Both are downloaded (the two are identical in the 2026-10-11 snapshot); the rest of the pipeline uses snort-3.0.0.
# Safety: downloads are untrusted data -> check for absolute paths or '..' before extracting, extract each into a new empty directory and make it read-only.
# Once a snapshot exists, never re-download over it. Usage: 13_fetch_snort_rules.sh [date tag, default today]
set -e
RULESETS=/home/sixsquare/datasets/rulesets
TAG=${1:-$(date +%F)}
DL=$RULESETS/dl_snort
mkdir -p "$DL"; cd "$RULESETS"
for ver in 3.0.0 2.9.0; do
  name=snort-$ver
  SNAP=snapshot_${name}_$TAG
  [ -e "$SNAP" ] && { echo "$SNAP 已存在，不覆蓋"; exit 1; }
  curl -sS -D "$DL/$name.hdr.txt" -o "$DL/$name.tar.gz" "https://rules.emergingthreats.net/open/$name/emerging.rules.tar.gz"
  date -u +%FT%TZ > "$DL/$name.download_date.txt"
  sha256sum "$DL/$name.tar.gz" | tee "$DL/$name.sha256"
  tar tzf "$DL/$name.tar.gz" > "$DL/$name.tar_list.txt"
  if grep -qE '^/|(^|/)\.\.(/|$)' "$DL/$name.tar_list.txt"; then echo "$name tar 清單含絕對路徑或 ..，中止"; exit 1; fi
  mkdir "$SNAP" && tar xzf "$DL/$name.tar.gz" -C "$SNAP" --no-same-owner
  chmod -R a-w "$SNAP"
  echo "ok -> $RULESETS/$SNAP"
done
