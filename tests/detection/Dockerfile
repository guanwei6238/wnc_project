# Suricata 8.0.7: same Debian package as on the Pi (trixie-backports), just the amd64 build
FROM debian:trixie
RUN echo 'deb http://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/backports.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends -t trixie-backports suricata=1:8.0.7-1~bpo13+1 \
 && rm -rf /var/lib/apt/lists/*
