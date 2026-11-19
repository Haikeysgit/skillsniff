#!/usr/bin/env bash
# Fill the version and SHA-256 placeholders in packaging/ from a release's
# sha256.sum file. Usage: scripts/fill-packaging.sh <version> <sha256.sum>
set -euo pipefail
ver="${1:?version, for example 0.1.0}"
sums="${2:?path to sha256.sum}"
x64=$(grep 'x86_64-pc-windows-msvc.zip' "$sums" | cut -d' ' -f1)
[ -n "$x64" ] || { echo "missing Windows zip hashes in $sums" >&2; exit 1; }
for f in packaging/scoop/skillsniff.json packaging/winget/*.yaml; do
  sed -i \
    -e "s/REPLACE_WITH_SHA256_OF_x86_64_ZIP/$x64/" \
    -e "s#download/v[0-9][^/]*/#download/v$ver/#g" \
    -e "s/^\(PackageVersion:\) .*/\1 $ver/" \
    -e "s/^\(    \"version\":\) .*/\1 \"$ver\",/" "$f"
done
echo "filled packaging/ for $ver"
