# 一個 image 同時放 Suricata(apt) 與 Snort 3(原始碼編譯)，方便在同一環境比較。
# 基底用 debian:trixie：跟 Pi (Raspberry Pi OS Lite, Debian trixie) 同一個發行版，
# 這樣套件版本、glibc 與 Pi 一致；差別只在 CPU 架構(x86_64 vs aarch64)。
#
# 為什麼要自己編譯 Snort 3：Debian trixie 沒有 snort / snort3 套件
# (apt-cache policy 查過)，所以用官方 GitHub release tag 編譯。
# 這份 Dockerfile 在 aarch64 上也能直接 build（Pi 上重跑同一份）。

# ---------- stage 1: 編譯 Snort 3 ----------
FROM debian:trixie AS snort-build
ARG LIBDAQ_TAG=v3.0.27
ARG SNORT_TAG=3.12.2.0
# Hyperscan 只有 x86(amd64)；aarch64 要用 vectorscan（兩者 API 相同，且 Debian 上互相 Conflicts，
# 不能同時裝）。所以依架構挑套件。Suricata 的 apt 依賴會自己帶進對應的 runtime 函式庫。
RUN apt-get update && HS=$([ "$(dpkg --print-architecture)" = amd64 ] && echo libhyperscan-dev || echo libvectorscan-dev) \
 && apt-get install -y --no-install-recommends $HS \
      ca-certificates git build-essential cmake pkg-config \
      autoconf automake libtool flex bison libfl-dev \
      libpcap-dev libpcre2-dev libdumbnet-dev libhwloc-dev libluajit-5.1-dev \
      libssl-dev zlib1g-dev libunwind-dev liblzma-dev uuid-dev \
    && rm -rf /var/lib/apt/lists/*

# libdaq: Snort 3 讀封包(pcap / nfq)的抽象層，Snort 3 必要依賴
RUN git clone --depth 1 --branch ${LIBDAQ_TAG} https://github.com/snort3/libdaq.git /src/libdaq \
 && cd /src/libdaq && ./bootstrap && ./configure --prefix=/opt/snort \
 && make -j"$(nproc)" && make install

# Snort 3 本體。vectorscan 提供 hs.h，讓 Snort 的 hyperscan search_method 可用
# (x86 與 aarch64 皆可；原版 Hyperscan 只有 x86)。
RUN git clone --depth 1 --branch ${SNORT_TAG} https://github.com/snort3/snort3.git /src/snort3 \
 && cd /src/snort3 \
 && PKG_CONFIG_PATH=/opt/snort/lib/pkgconfig \
    ./configure_cmake.sh --prefix=/opt/snort --build-type=Release \
 && cd build && make -j"$(nproc)" && make install \
 && { echo "snort3_tag=${SNORT_TAG}"; echo "snort3_commit=$(git -C /src/snort3 rev-parse HEAD)"; \
      echo "libdaq_tag=${LIBDAQ_TAG}"; echo "libdaq_commit=$(git -C /src/libdaq rev-parse HEAD)"; \
      echo "arch=$(dpkg --print-architecture)"; \
      grep -E 'CMAKE_BUILD_TYPE|HAVE_HYPERSCAN|HAVE_LZMA|HAVE_UUID|ENABLE_' CMakeCache.txt | head -30; } > /opt/snort/BUILD_INFO.txt

# ---------- stage 2: 執行環境 ----------
FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends \
      suricata time procps python3 python3-scapy tcpdump \
      libpcap0.8t64 libpcre2-8-0 libdumbnet1 libhwloc15 libluajit-5.1-2 libssl3t64 \
      zlib1g libunwind8 liblzma5 libuuid1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=snort-build /opt/snort /opt/snort
ENV PATH=/opt/snort/bin:$PATH LD_LIBRARY_PATH=/opt/snort/lib
