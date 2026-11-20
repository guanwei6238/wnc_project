#!/bin/bash
# doctor_docker.sh — [[features]] 的載入前檢查（routed testbed 的 wnc-gw 容器）
#   編 prog/（一支程式：BTF 的 hash FLOWS、BTF 的 per-CPU hash PFLOWS、BTF 的 ringbuf EVENTS、舊式 #[map] 的 LEGACY），
#   五個 [[features]]：flows、pflows（tc-ingress）、legacy、events、swapped（packets／bytes 對調，xdp）
#   預期：flows／pflows／swapped 各一個 G008（key 的 pad 沒列）、legacy G007、swapped G006、events 沒有問題
# 用法: bash doctor_docker.sh   （先 docker/up.sh，並編好 security_gateway 的 x86_64-unknown-linux-musl debug 版）
set -e
D=$(cd "$(dirname "$0")" && pwd); GW="docker exec wnc-gw"
(cd "$D/prog" && env -u RUSTC -u RUSTC_WRAPPER CARGO_ENCODED_RUSTFLAGS=$'-Cdebuginfo=2\x1f-Clink-arg=--btf' \
  rustup run nightly-2026-11-13 cargo build --quiet --release --target bpfel-unknown-none -Z build-std=core)
$GW sh -c 'rm -rf /tmp/feat; mkdir -p /tmp/feat'
docker cp "$D/prog/target/bpfel-unknown-none/release/feature-prog" wnc-gw:/tmp/feat/prog.o > /dev/null
for f in "$D"/*.json; do docker cp "$f" wnc-gw:/tmp/feat/ > /dev/null; done
$GW sh -c 'cp /etc/wnc-gw/setting.toml /tmp/feat/setting.toml
for n in flows:flows_tc:tc-egress pflows:flows_tc:tc-ingress legacy:flows_tc:tc-egress events:flows_tc:tc-egress swapped:flows_xdp:xdp; do
  name=${n%%:*}; rest=${n#*:}; entry=${rest%%:*}; hook=${rest#*:}
  printf "\n[[features]]\nname = \"%s\"\nprogram = \"/tmp/feat/prog.o\"\nentry = \"%s\"\ndefinition = \"/tmp/feat/%s.json\"\nhook = \"%s\"\n" \
    $name $entry $name $hook >> /tmp/feat/setting.toml
done
chmod 644 /tmp/feat/*; chown root:root /tmp/feat/*
/opt/sg/wnc-gw -c /tmp/feat/setting.toml doctor' | sed -n '/^feature /,/^$/p;/G0[0-9][0-9]/p' || true
