#!/bin/bash
# doctor_docker.sh — pre-load checks for [[features]] (wnc-gw container in the routed testbed)
#   builds prog/ (one program: BTF hash FLOWS, BTF per-CPU hash PFLOWS, BTF ringbuf EVENTS, legacy #[map] LEGACY),
#   five [[features]]: flows, pflows (tc-ingress), legacy, events, swapped (packets/bytes swapped, xdp)
#   expected: one G008 each for flows/pflows/swapped (key pad not listed), legacy G007, swapped G006, events clean
# Usage: bash doctor_docker.sh   (run docker/up.sh first and build the x86_64-unknown-linux-musl debug build of security_gateway)
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
