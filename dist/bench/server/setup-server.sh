#!/usr/bin/env bash
# Set up the SERVER host (Debian/Ubuntu): nginx on :80 and :443, iperf3 -s, sockperf server (:11111). Idempotent.
#   sudo bench/server/setup-server.sh             install + configure (+ systemd units if systemd is running)
#   sudo bench/server/setup-server.sh --start     (re)start nginx, iperf3 -s and sockperf servers as background daemons
#   sudo bench/server/setup-server.sh --stop      stop the daemons started by --start
#   --no-install  skip apt (packages already present)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "setup-server.sh: must run as root" >&2; exit 1; }
DO_INSTALL=1 ACTION=setup
for a in "$@"; do
  case "$a" in
    --start) ACTION=start ;; --stop) ACTION=stop ;; --no-install) DO_INSTALL=0 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done
WEB=/var/www/bench
PIDDIR=/run/bench-server
SOCKPERF_PORT=${SOCKPERF_PORT:-11111}

install_pkgs() {
  local missing=() p
  for p in nginx iperf3 sockperf openssl iproute2 ethtool; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  if [ "${#missing[@]}" -gt 0 ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends "${missing[@]}"
  fi
}

make_objects() {
  mkdir -p "$WEB"
  local spec name size
  for spec in 1k:1024 100k:102400 1m:1048576; do
    name=${spec%%:*}; size=${spec##*:}
    [ "$(stat -c %s "$WEB/$name" 2>/dev/null || echo 0)" = "$size" ] || head -c "$size" /dev/urandom > "$WEB/$name"
  done
  [ -f "$WEB/index.html" ] || echo "bench server" > "$WEB/index.html"
  chmod -R a+rX "$WEB"
}

make_cert() {
  mkdir -p /etc/nginx/bench-tls
  if [ ! -s /etc/nginx/bench-tls/bench.crt ] || [ ! -s /etc/nginx/bench-tls/bench.key ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=bench.local" \
      -keyout /etc/nginx/bench-tls/bench.key -out /etc/nginx/bench-tls/bench.crt 2>/dev/null
    chmod 600 /etc/nginx/bench-tls/bench.key
  fi
}

configure_nginx() {
  rm -f /etc/nginx/sites-enabled/default
  mkdir -p /etc/nginx/conf.d
  cat > /etc/nginx/conf.d/bench.conf <<EOF
# managed by bench/server/setup-server.sh
server {
    listen 80 default_server backlog=4096 reuseport;
    listen 443 ssl default_server backlog=4096 reuseport;   # no http2: HTTP/1.1 only
    server_name _;
    root $WEB;
    ssl_certificate     /etc/nginx/bench-tls/bench.crt;
    ssl_certificate_key /etc/nginx/bench-tls/bench.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    ssl_session_cache off;
    sendfile on;
    tcp_nopush on;
    gzip off;
    access_log off;
    keepalive_timeout 65;
    keepalive_requests 1000000;
    location / { try_files \$uri =404; }
}
EOF
  # Debian's nginx.conf already includes conf.d/*.conf; make sure of it and use all cores
  grep -q 'conf.d/\*.conf' /etc/nginx/nginx.conf || sed -i '/^http {/a\    include /etc/nginx/conf.d/*.conf;' /etc/nginx/nginx.conf
  nginx -t
}

write_units() {
  [ -d /run/systemd/system ] || return 1
  cat > /etc/systemd/system/bench-iperf3.service <<EOF
[Unit]
Description=bench iperf3 server
After=network-online.target
[Service]
ExecStart=/usr/bin/iperf3 -s
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  local p
  for p in udp tcp; do
    cat > /etc/systemd/system/bench-sockperf-$p.service <<EOF
[Unit]
Description=bench sockperf server ($p)
After=network-online.target
[Service]
ExecStart=/usr/bin/sockperf server $([ $p = tcp ] && echo --tcp) -i 0.0.0.0 -p $SOCKPERF_PORT
Restart=always
[Install]
WantedBy=multi-user.target
EOF
  done
  systemctl daemon-reload
  systemctl enable --now nginx bench-iperf3 bench-sockperf-udp bench-sockperf-tcp >/dev/null 2>&1 || true
  systemctl restart nginx
  return 0
}

stop_daemons() {
  local f
  for f in "$PIDDIR"/*.pid; do
    [ -e "$f" ] || continue
    kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"
  done
  nginx -s stop 2>/dev/null || true
}

start_daemons() {
  stop_daemons
  sleep 0.5
  mkdir -p "$PIDDIR"
  nginx                                   # daemonises itself
  iperf3 -s -D -P "$PIDDIR/iperf3.pid" >/dev/null 2>&1 || { iperf3 -s >/dev/null 2>&1 & echo $! > "$PIDDIR/iperf3.pid"; }
  sockperf server -i 0.0.0.0 -p "$SOCKPERF_PORT" >/dev/null 2>&1 & echo $! > "$PIDDIR/sockperf-udp.pid"
  sockperf server --tcp -i 0.0.0.0 -p "$SOCKPERF_PORT" >/dev/null 2>&1 & echo $! > "$PIDDIR/sockperf-tcp.pid"
  sleep 1
  echo "started: nginx :80/:443, iperf3 -s :5201, sockperf server udp+tcp :$SOCKPERF_PORT (pids in $PIDDIR)"
}

case "$ACTION" in
  stop)  stop_daemons; exit 0 ;;
  start) start_daemons; exit 0 ;;
esac
[ "$DO_INSTALL" = 1 ] && install_pkgs
make_objects; make_cert; configure_nginx
if write_units; then
  echo "systemd units enabled: nginx bench-iperf3 bench-sockperf-udp bench-sockperf-tcp"
else
  echo "no systemd: run  sudo $0 --start  (or by hand: nginx; iperf3 -s -D; sockperf server -p $SOCKPERF_PORT & sockperf server --tcp -p $SOCKPERF_PORT &)"
fi
cat <<EOF
objects: $(ls "$WEB" | tr '\n' ' ')(in $WEB);  self-signed cert: /etc/nginx/bench-tls/bench.crt
Next: ip addr add 10.10.0.3/24 dev <test NIC>; ethtool -K <test NIC> gro off lro off gso off tso off
EOF
