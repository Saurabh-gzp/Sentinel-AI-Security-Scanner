#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
cd "$root"
rm -rf app/v1.3.6
mkdir -p app/v1.3.6
if [[ -f android-app/app/build/outputs/apk/debug/app-debug.apk ]]; then
  cp android-app/app/build/outputs/apk/debug/app-debug.apk app/v1.3.6/Sentinel-v1.3.6-debug.apk
fi
(cd android-app && zip -qr ../app/v1.3.6/Sentinel-app-source-v1.3.6.zip . -x 'app/build/*' '.gradle/*')
(cd app/v1.3.6 && sha256sum Sentinel-*) > app/v1.3.6/SHA256SUMS.txt
