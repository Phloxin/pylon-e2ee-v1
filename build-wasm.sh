#!/usr/bin/env bash
# Builds the E2EE module for the client's worker: build-wasm.sh OUT_DIR
# Runs itself inside this repo's dev shell when wasm-bindgen is not on PATH.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?usage: build-wasm.sh OUT_DIR}"

if ! command -v wasm-bindgen >/dev/null; then
  if [[ -n "${PYLON_E2EE_IN_DEV_SHELL:-}" ]]; then
    echo "wasm-bindgen is missing from the pylon-e2ee dev shell" >&2
    exit 1
  fi
  export PYLON_E2EE_IN_DEV_SHELL=1
  # path: so the flake works before its files are tracked in git.
  exec nix develop "path:$repo" --command "$0" "$out"
fi

mkdir -p "$out"
cargo build \
  --manifest-path "$repo/Cargo.toml" \
  --target-dir "$repo/target" \
  --features wasm \
  --target wasm32-unknown-unknown \
  --release

wasm-bindgen \
  --target web \
  --out-dir "$out" \
  --out-name pylon_e2ee \
  "$repo/target/wasm32-unknown-unknown/release/pylon_e2ee.wasm"

echo "pylon-e2ee wasm written to $out"
