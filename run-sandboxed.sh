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

# Preflight: Docker must be installed and reachable. A raw "permission denied on
# docker.sock" or "cannot connect to the Docker daemon" mid-build is opaque;
# translate it into an actionable message and stop before building.
if ! command -v docker &>/dev/null; then
  echo "[uopfuzz] Docker is not installed or not on PATH." >&2
  echo "          Install Docker (or enable Docker Desktop's WSL integration) and retry." >&2
  exit 1
fi
if ! docker info &>/dev/null; then
  echo "[uopfuzz] Cannot talk to the Docker daemon." >&2
  echo "          Common fixes:" >&2
  echo "            - Permission denied on /var/run/docker.sock (Linux/WSL native Docker):" >&2
  echo "                sudo usermod -aG docker \$USER && newgrp docker   # then reopen the terminal" >&2
  echo "            - Docker Desktop: make sure it is running, and enable WSL integration for this distro." >&2
  echo "            - Native install with the daemon stopped:  sudo service docker start" >&2
  echo "          Verify with:  docker run --rm hello-world" >&2
  echo "          (Avoid 'sudo ./run-sandboxed.sh' — the container runs as an unprivileged user and can't write root-owned results.)" >&2
  exit 1
fi

# Ensure the image exists
if ! docker image inspect "$IMAGE" &>/dev/null; then
  echo "[uopfuzz] Building sandbox image..."
  docker build -t "$IMAGE" "$SCRIPT_DIR/.devcontainer/"
fi

# node_modules is a named volume so the install cache persists across runs.
docker volume create uopfuzz-node-modules &>/dev/null || true

# The workspace is mounted read-only, so the fuzzer's own dependencies live in
# the writable node_modules volume — which starts empty. Populate it once (and
# after package.json changes) or the very first run dies with
# "Cannot find package 'commander'". The base node image's entrypoint turns a
# leading-dash arg into `node <arg>`, so `-e "…"` runs a probe; a fresh volume is
# root-owned, so the install chowns it before running npm as the node user.
if ! docker run --rm \
      -v uopfuzz-node-modules:/workspace/node_modules \
      "$IMAGE" -e "process.exit(require('fs').existsSync('/workspace/node_modules/commander') ? 0 : 1)" &>/dev/null; then
  echo "[uopfuzz] Installing fuzzer dependencies into the node_modules volume (first run)..."
  docker run --rm \
    -v "$SCRIPT_DIR":/workspace:ro \
    -v uopfuzz-node-modules:/workspace/node_modules \
    --user root \
    --entrypoint sh \
    "$IMAGE" \
    -c "chown -R node:node /workspace/node_modules && su node -c 'cd /workspace && npm install --cache /home/node/.npm --no-package-lock'"
  echo "[uopfuzz] Dependencies ready."
  echo ""
fi

# Results are bind-mounted to a host directory so findings are readable on the
# host after a scan (the workspace itself is mounted read-only). Override with
# UOPFUZZ_RESULTS_DIR=/some/path to send them elsewhere.
RESULTS_DIR="${UOPFUZZ_RESULTS_DIR:-$SCRIPT_DIR/results}"
mkdir -p "$RESULTS_DIR"

echo "[uopfuzz] Starting sandboxed run: node src/cli.js $*"
echo "[uopfuzz] Security: cap-drop=ALL, seccomp, no-new-privileges, memory=3g, pids=512"
echo "[uopfuzz] Results  -> $RESULTS_DIR  (readable on the host)"
echo ""

# Allocate a TTY only when attached to one. A batch loop (scripts/discovery) or
# CI has no TTY, and `-it` there fails with "the input device is not a TTY".
TTY_FLAGS=()
[ -t 0 ] && [ -t 1 ] && TTY_FLAGS=(-it)

docker run --rm "${TTY_FLAGS[@]}" \
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
  -v "$RESULTS_DIR":/workspace/results \
  "$IMAGE" \
  src/cli.js "$@"
