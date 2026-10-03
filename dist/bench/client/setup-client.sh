#!/usr/bin/env bash
# Install the measurement tools on the CLIENT host (Debian/Ubuntu). Idempotent.
#   sudo bench/client/setup-client.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "setup-client.sh: must run as root" >&2; exit 1; }
PKGS=(iperf3 sockperf nghttp2-client curl openssl iproute2 ethtool python3)
missing=()
for p in "${PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
if [ "${#missing[@]}" -gt 0 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends "${missing[@]}"
else
  echo "setup-client.sh: all packages already installed"
fi
for t in iperf3 sockperf h2load curl openssl; do
  command -v "$t" >/dev/null 2>&1 && echo "ok: $t -> $(command -v "$t")" || echo "MISSING: $t (sockperf is optional: latency falls back to ping)" >&2
done
cat <<'EOF'

Next:
  1. Give the test NIC an address, e.g.   sudo ip addr add 10.10.0.2/24 dev eth1; sudo ip link set eth1 up
  2. Disable offloads on it:               sudo ethtool -K eth1 gro off lro off gso off tso off
  3. Check the path to the server through the Pi:   ping -c3 10.10.0.3
  4. Make this repo's bench/ directory available at the path used by CLIENT_CMD (default: ~/bench on the client).
EOF
