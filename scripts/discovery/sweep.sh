#!/usr/bin/env bash
# Sweep a list of npm targets through UoPFuzz in the hardened container, one at a
# time, reusing the canonical ./run-sandboxed.sh runner (cap-drop=ALL, seccomp,
# no-new-privileges, non-root, read-only rootfs, pid/memory caps).
#
# Advisory classification (OSV.dev + GitHub Advisory DB) is left ON so each
# reproduced gadget is labelled known-cve / previously-discovered / undocumented.
# Pair with triage.mjs, which surfaces only the reproduced *undocumented* findings
# as candidates for RESPONSIBLE DISCLOSURE (this tool finds; a human discloses).
#
# Usage:
#   scripts/discovery/sweep.sh <targets-file> [max-iterations] [timeout-secs]
#   scripts/discovery/sweep.sh targets-today.txt 30 15
#
# A targets file has one `pkg@version` (or `pkg@latest`) per line; # comments and
# blank lines are ignored.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

LIST="${1:?usage: sweep.sh <targets-file> [max-iterations] [timeout-secs]}"
ITERS="${2:-30}"
TIMEOUT="${3:-15}"
OUT_ROOT="results/hunt"

mkdir -p "$OUT_ROOT"
echo "[sweep] targets=$LIST  max-iterations=$ITERS  timeout=${TIMEOUT}s  ->  $OUT_ROOT/"

while IFS= read -r line; do
  t="${line%%#*}"; t="$(echo "$t" | xargs)"   # strip comment + surrounding whitespace
  [ -z "$t" ] && continue
  safe="$(echo "$t" | tr '/@.' '___')"
  mkdir -p "$OUT_ROOT/$safe"
  echo "=== $t ==="
  # `< /dev/null` is REQUIRED: without it the container inherits this loop's stdin
  # and consumes the rest of the targets file, so only the first target runs.
  ./run-sandboxed.sh --target "$t" -o "$OUT_ROOT/$safe" --max-iterations "$ITERS" -t "$TIMEOUT" \
    < /dev/null > "$OUT_ROOT/$safe/run.log" 2>&1
  rc=$?
  proven="$(grep -c 'PROVEN' "$OUT_ROOT/$safe/run.log" 2>/dev/null || echo 0)"
  echo "  exit=$rc  proven_lines=$proven"
done < "$LIST"

echo "[sweep] done. Triage with:  node scripts/discovery/triage.mjs $OUT_ROOT"
