# 基底刻意選 Debian 13 (trixie)，因為最新的 Raspberry Pi OS 也是 trixie，
# 套件版本會跟實機對得上，規則與腳本可以直接搬過去。
FROM debian:trixie-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 \
      nftables \
      iptables \
      conntrack \
      iputils-ping \
      tcpdump \
      iperf3 \
      netsniff-ng \
      netcat-openbsd \
      ethtool \
      curl \
      python3 \
      procps \
      less \
      vim-tiny \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# 只有 gw 需要 Suricata。版本跟架構決定的一樣，用 trixie-backports 的 8.0.7。
FROM base AS gw

RUN echo 'deb http://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/backports.list \
 && apt-get update && apt-get install -y --no-install-recommends -t trixie-backports suricata \
 && rm -rf /var/lib/apt/lists/*
