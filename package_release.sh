#!/usr/bin/env bash
# Package a Sentinel release: debug APK (if built) + source zip + SHA256SUMS.
# Usage: ./package_release.sh [version]   e.g. ./package_release.sh 1.3.7
# With no argument the version is read from android-app/app/build.gradle.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
cd "$root"

if [[ $# -ge 1 ]]; then
  ver="$1"
else
  ver="$(sed -n "s/.*versionName '\([^']*\)'.*/\1/p" android-app/app/build.gradle | head -1)"
fi
[[ -n "$ver" ]] || { echo "ERROR: could not determine version (pass one: $0 1.3.7)" >&2; exit 1; }

apk="android-app/app/build/outputs/apk/debug/app-debug.apk"
if [[ ! -f "$apk" ]]; then
  echo "ERROR: APK not found at $apk" >&2
  echo "Build it first:  (cd android-app && ./gradlew assembleDebug)" >&2
  exit 1
fi

rm -rf "app/v$ver"
mkdir -p "app/v$ver"
cp "$apk" "app/v$ver/Sentinel-v$ver-debug.apk"
(cd android-app && zip -qr "../app/v$ver/Sentinel-app-source-v$ver.zip" . -x 'app/build/*' '.gradle/*')
(cd "app/v$ver" && sha256sum Sentinel-* > SHA256SUMS.txt)
echo "Packaged v$ver:"
ls -la "app/v$ver"
