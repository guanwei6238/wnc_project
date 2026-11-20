# Debian 13 (trixie) is chosen on purpose because the latest Raspberry Pi OS is also trixie,
# so package versions match the real hardware and rules and scripts carry over as-is.
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

# Only gw needs Suricata. Same version as the Pi: 8.0.7 from trixie-backports;
# backports moved to 8.0.8 on 11/03, so use the 11/02 backports from snapshot.debian.org.
FROM base AS gw

RUN echo 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261102T000000Z trixie-backports main' > /etc/apt/sources.list.d/backports.list \
 && apt-get update && apt-get install -y --no-install-recommends -t trixie-backports suricata=1:8.0.7-1~bpo13+1 \
 && rm -rf /var/lib/apt/lists/*

# bpftool: inspect the eBPF programs and maps wnc-gw attaches to each port
RUN apt-get update && apt-get install -y --no-install-recommends bpftool \
 && rm -rf /var/lib/apt/lists/*

# rep replays dataset pcaps
FROM base AS rep

RUN apt-get update && apt-get install -y --no-install-recommends tcpreplay \
 && rm -rf /var/lib/apt/lists/*
