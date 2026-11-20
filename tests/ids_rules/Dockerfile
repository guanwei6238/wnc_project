# One image with both Suricata (apt) and Snort 3 (built from source), to compare them in the same environment.
# Based on debian:trixie: the same distro as the Pi (Raspberry Pi OS Lite, Debian trixie),
# so package versions and glibc match the Pi; only the CPU architecture differs (x86_64 vs aarch64).
#
# Why build Snort 3 ourselves: Debian trixie has no snort / snort3 package
# (checked with apt-cache policy), so build it from the official GitHub release tag.
# This Dockerfile also builds as-is on aarch64 (rerun the same file on the Pi).

# ---------- stage 1: build Snort 3 ----------
FROM debian:trixie AS snort-build
ARG LIBDAQ_TAG=v3.0.27
ARG SNORT_TAG=3.12.2.0
# Hyperscan is x86 (amd64) only; aarch64 needs vectorscan (same API, and the two Conflict with each other on Debian,
# so they cannot both be installed). So pick the package by arch. Suricata's apt dependencies pull in the matching runtime library.
RUN apt-get update && HS=$([ "$(dpkg --print-architecture)" = amd64 ] && echo libhyperscan-dev || echo libvectorscan-dev) \
 && apt-get install -y --no-install-recommends $HS \
      ca-certificates git build-essential cmake pkg-config \
      autoconf automake libtool flex bison libfl-dev \
      libpcap-dev libpcre2-dev libdumbnet-dev libhwloc-dev libluajit-5.1-dev \
      libssl-dev zlib1g-dev libunwind-dev liblzma-dev uuid-dev \
    && rm -rf /var/lib/apt/lists/*

# libdaq: Snort 3's packet acquisition layer (pcap / nfq), a required dependency of Snort 3
RUN git clone --depth 1 --branch ${LIBDAQ_TAG} https://github.com/snort3/libdaq.git /src/libdaq \
 && cd /src/libdaq && ./bootstrap && ./configure --prefix=/opt/snort \
 && make -j"$(nproc)" && make install

# Snort 3 itself. vectorscan provides hs.h so Snort's hyperscan search_method works
# (on both x86 and aarch64; the original Hyperscan is x86 only).
RUN git clone --depth 1 --branch ${SNORT_TAG} https://github.com/snort3/snort3.git /src/snort3 \
 && cd /src/snort3 \
 && PKG_CONFIG_PATH=/opt/snort/lib/pkgconfig \
    ./configure_cmake.sh --prefix=/opt/snort --build-type=Release \
 && cd build && make -j"$(nproc)" && make install \
 && { echo "snort3_tag=${SNORT_TAG}"; echo "snort3_commit=$(git -C /src/snort3 rev-parse HEAD)"; \
      echo "libdaq_tag=${LIBDAQ_TAG}"; echo "libdaq_commit=$(git -C /src/libdaq rev-parse HEAD)"; \
      echo "arch=$(dpkg --print-architecture)"; \
      grep -E 'CMAKE_BUILD_TYPE|HAVE_HYPERSCAN|HAVE_LZMA|HAVE_UUID|ENABLE_' CMakeCache.txt | head -30; } > /opt/snort/BUILD_INFO.txt

# ---------- stage 2: runtime ----------
FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends \
      suricata time procps python3 python3-scapy tcpdump \
      libpcap0.8t64 libpcre2-8-0 libdumbnet1 libhwloc15 libluajit-5.1-2 libssl3t64 \
      zlib1g libunwind8 liblzma5 libuuid1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=snort-build /opt/snort /opt/snort
ENV PATH=/opt/snort/bin:$PATH LD_LIBRARY_PATH=/opt/snort/lib
