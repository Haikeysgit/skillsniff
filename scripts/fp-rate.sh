#!/usr/bin/env bash
# Scans every skill in tests/benign/corpus.yaml with the release binary.
# Exits 1 when any skill is a false BLOCK, or when more than 10% of the
# skills are CAUTION. Each flagged skill is listed with its rule ids.
#
#   scripts/fp-rate.sh [corpus.yaml]
#
# Needs the network. Set GITHUB_TOKEN, or log in with `gh`, to avoid rate limits.
set -u

root=$(cd "$(dirname "$0")/.." && pwd)
corpus=${1:-$root/tests/benign/corpus.yaml}
bin=${SKILLSNIFF_BIN:-$root/target/release/skillsniff}
limit=${CAUTION_LIMIT_PERCENT:-10}

if [ ! -x "$bin" ] && [ ! -x "$bin.exe" ]; then
  echo "release binary not found: build it with 'cargo build --release'" >&2
  exit 3
fi
if [ -z "${GITHUB_TOKEN:-}" ] && command -v gh >/dev/null 2>&1; then
  GITHUB_TOKEN=$(gh auth token 2>/dev/null || true)
fi
export GITHUB_TOKEN

total=0
flagged=0
blocks=0
cautions=0
errors=0
while IFS= read -r line; do
  repo=$(printf '%s' "$line" | sed -n 's/.*repo: *\([^,} ]*\).*/\1/p')
  path=$(printf '%s' "$line" | sed -n 's/.*path: *\([^,} ]*\).*/\1/p')
  sha=$(printf '%s' "$line" | sed -n 's/.*commit: *\([0-9a-f]\{40\}\).*/\1/p')
  [ -n "$repo" ] && [ -n "$sha" ] || continue
  total=$((total + 1))
  target="$repo/$path@$sha"
  out=$("$bin" scan "$target" --json --quiet 2>/dev/null)
  code=$?
  case $code in
    0) ;;
    1 | 2)
      flagged=$((flagged + 1))
      if [ "$code" -eq 2 ]; then blocks=$((blocks + 1)); else cautions=$((cautions + 1)); fi
      verdict=$(printf '%s' "$out" | sed -n 's/^  "verdict": "\([A-Z]*\)".*/\1/p' | head -n1)
      rules=$(printf '%s' "$out" | sed -n 's/^      "rule": "\([^"]*\)".*/\1/p' | sort -u | paste -sd, -)
      echo "flagged: $verdict $target"
      echo "         $rules"
      ;;
    *)
      errors=$((errors + 1))
      echo "error (exit $code): $target" >&2
      ;;
  esac
done < <(grep 'commit:' "$corpus")

if [ "$total" -eq 0 ]; then
  echo "no entries found in $corpus" >&2
  exit 3
fi
pct=$(awk -v n="$flagged" -v m="$total" 'BEGIN { printf "%.1f", 100 * n / m }')
cpct=$(awk -v n="$cautions" -v m="$total" 'BEGIN { printf "%.1f", 100 * n / m }')
echo "false positives: $flagged/$total (${pct}%)"
echo "false BLOCK: $blocks/$total"
echo "benign CAUTION: $cautions/$total (${cpct}%, limit ${limit}%)"
if [ "$errors" -gt 0 ]; then
  echo "scans that failed: $errors" >&2
  exit 3
fi
[ "$blocks" -eq 0 ] || exit 1
awk -v p="$cpct" -v l="$limit" 'BEGIN { exit (p > l) ? 1 : 0 }'
