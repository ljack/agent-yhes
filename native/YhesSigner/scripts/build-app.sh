#!/bin/sh
# Default preview is inert. --signed requires dedicated Xcode profiles and builds
# the pinned engine before signing nested helper and app. Neither mode launches.
set -eu
signer_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "${1:---preview}" in
  --signed) exec python3 "$signer_root/scripts/package-signed.py" ;;
  --preview) ;;
  *) printf '%s\n' 'Usage: build-app.sh [--preview|--signed]' >&2; exit 64 ;;
esac
"$signer_root/scripts/prepare-validator.sh"
swift build --package-path "$signer_root" -c release
signer_bin=$(swift build --package-path "$signer_root" -c release --show-bin-path)
signer_app="$signer_root/build/Preview/YhesSigner.app"
mkdir -p "$signer_app/Contents/MacOS"
cp "$signer_bin/YhesSigner" "$signer_app/Contents/MacOS/YhesSigner"
cp "$signer_root/Bundle/Info.plist" "$signer_app/Contents/Info.plist"
plutil -lint "$signer_app/Contents/Info.plist"
printf '%s\n' "$signer_app" 'Inert preview only: no listener, Keychain or signing identity.'
