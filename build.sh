#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-x86_64-unknown-linux-musl}"
BINARY="target/${TARGET}/release/nanoproxy"
HOME_DIR="${HOME:-/root}"

echo "[build] target=${TARGET}"

echo "[build] building nanoproxy..."
RUSTFLAGS="\
  -C link-arg=-Wl,--gc-sections \
  -C link-arg=-Wl,--strip-all \
  -Z location-detail=none \
  -Z unstable-options \
  -C panic=immediate-abort \
  --remap-path-prefix=${HOME_DIR}/.cargo= \
  --remap-path-prefix=${HOME_DIR}/.rustup= \
  --remap-path-prefix=$(pwd)= \
" \
cargo +nightly build \
    --release \
    --target "${TARGET}" \
    -Z build-std=std,panic_abort

echo "[build] packing with UPX..."
upx --best --lzma "${BINARY}"

SIZE=$(stat -c%s "${BINARY}")
echo "[build] final size: $(numfmt --to=iec ${SIZE})"
