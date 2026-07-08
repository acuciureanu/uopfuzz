#!/usr/bin/env bash
# run-sandboxed.sh
# Run uopfuzz inside the security-hardened container.
#
# Usage:
#   ./run-sandboxed.sh versions --library handlebars.js --last 5
#   ./run-sandboxed.sh mass --top 20
#   ./run-sandboxed.sh --target lodash@4.17.20

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECCOMP="$SCRIPT_DIR/.devcontainer/seccomp.json"
IMAGE="uopfuzz-sandbox"

# Ensure the image exists
if ! docker image inspect "$IMAGE" &>/dev/null; then
  echo "[uopfuzz] Building sandbox image..."
  docker build -t "$IMAGE" "$SCRIPT_DIR/.devcontainer/"
fi

# Named volumes persist across runs (node_modules, results)
docker volume create uopfuzz-node-modules &>/dev/null || true
docker volume create uopfuzz-results      &>/dev/null || true

echo "[uopfuzz] Starting sandboxed run: node src/cli.js $*"
echo "[uopfuzz] Security: cap-drop=ALL, seccomp, no-new-privileges, memory=3g, pids=512"
echo ""

docker run --rm -it \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --security-opt="seccomp=$SECCOMP" \
  --memory=3g \
  --memory-swap=3g \
  --cpus=2 \
  --pids-limit=512 \
  -e UOPFUZZ_CONTAINER=1 \
  -v "$SCRIPT_DIR":/workspace:ro \
  -v uopfuzz-node-modules:/workspace/node_modules \
  -v uopfuzz-results:/workspace/results \
  "$IMAGE" \
  src/cli.js "$@"
