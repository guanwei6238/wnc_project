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

# 只有 gw 需要 Suricata。版本跟 Pi 一樣用 trixie-backports 的 8.0.7；
# backports 11/03 換成 8.0.8，所以取 snapshot.debian.org 上 11/02 的 backports。
FROM base AS gw

RUN echo 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261102T000000Z trixie-backports main' > /etc/apt/sources.list.d/backports.list \
 && apt-get update && apt-get install -y --no-install-recommends -t trixie-backports suricata=1:8.0.7-1~bpo13+1 \
 && rm -rf /var/lib/apt/lists/*

# bpftool：看 wnc-gw 掛在每個 port 上的 eBPF 程式和 map
RUN apt-get update && apt-get install -y --no-install-recommends bpftool \
 && rm -rf /var/lib/apt/lists/*

# rep 重播 dataset 的 pcap
FROM base AS rep

RUN apt-get update && apt-get install -y --no-install-recommends tcpreplay \
 && rm -rf /var/lib/apt/lists/*
