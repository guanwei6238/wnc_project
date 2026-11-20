#!/bin/bash
# Download and freeze an ET Open rules snapshot. Usage: 00_fetch_rules.sh [snapshot dir name, default snapshot_<today>]
# The URL uses suricata-7.0.10: ET organizes directories by Suricata version, and this is the version of Debian trixie's suricata package.
# Safety: the rule package is untrusted data -> check for absolute paths or '..' before extracting, and extract into a new empty directory.
# Note: once a snapshot exists, never re-download over it (experiments must use the same one). The snapshot frozen this time is listed in rules_manifest.txt.
set -e
RULESETS=/home/sixsquare/datasets/rulesets
SNAP=${1:-snapshot_$(date +%F)}
URL=https://rules.emergingthreats.net/open/suricata-7.0.10/emerging.rules.tar.gz
mkdir -p "$RULESETS/dl"; cd "$RULESETS"
[ -e "$SNAP" ] && { echo "$SNAP 已存在，不覆蓋"; exit 1; }
curl -sS -o dl/emerging.rules.tar.gz "$URL"; date -u +%FT%TZ > dl/download_date.txt
sha256sum dl/emerging.rules.tar.gz
tar tzf dl/emerging.rules.tar.gz > dl/tar_list.txt
if grep -qE '^/|(^|/)\.\.(/|$)' dl/tar_list.txt; then echo "tar 清單含絕對路徑或 ..，中止"; exit 1; fi
mkdir "$SNAP" && tar xzf dl/emerging.rules.tar.gz -C "$SNAP" --no-same-owner
chmod -R a-w "$SNAP"     # read-only, so the frozen snapshot is not modified by accident
echo "ok -> $RULESETS/$SNAP/rules"
