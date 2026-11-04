# Suricata 8.0.7：和 Pi 上同一個 Debian 套件（trixie-backports），只是 amd64 版
FROM debian:trixie
RUN echo 'deb http://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/backports.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends -t trixie-backports suricata=1:8.0.7-1~bpo13+1 \
 && rm -rf /var/lib/apt/lists/*
