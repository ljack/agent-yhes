#!/bin/sh
# Public validation code only; no enrollment or key operations.
set -eu
signer_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
signer_repo=$(CDPATH= cd -- "$signer_root/../.." && pwd)
cargo build --manifest-path "$signer_repo/secure/Cargo.toml" --package yhes-wire-ffi \
    --release --locked --target-dir "$signer_root/.build/rust"
