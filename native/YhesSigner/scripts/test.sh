#!/bin/sh
# Pure tests only. No native app launch, Keychain or Touch ID.
set -eu
signer_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
signer_repo=$(CDPATH= cd -- "$signer_root/../.." && pwd)
"$signer_root/scripts/prepare-validator.sh"
cargo test --manifest-path "$signer_repo/secure/Cargo.toml" --package yhes-wire-ffi \
    --locked --target-dir "$signer_root/.build/rust"
swift test --package-path "$signer_root"
