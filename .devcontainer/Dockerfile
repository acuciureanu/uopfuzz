# UoPFuzz Sandbox Container
#
# Security-hardened container for fuzzing untrusted npm packages.
#
# Isolation layers:
# 1. Non-root user (node:node, UID 1000)
# 2. Read-only root filesystem (--read-only in runArgs)
# 3. No network access (--network=none in runArgs)
# 4. Dropped capabilities (--cap-drop=ALL)
# 5. Memory/CPU/PID limits
# 6. noexec on /tmp (no writing then executing binaries)

FROM node:20-slim

# Install only what's absolutely needed
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      git \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a writable workspace owned by the non-root user
RUN mkdir -p /workspace /home/node/.npm && \
    chown -R node:node /workspace /home/node

# Set npm config to avoid writing outside allowed paths
RUN npm config set cache /home/node/.npm --global && \
    npm config set update-notifier false --global

USER node
WORKDIR /workspace

# Default to running the fuzzer
CMD ["node", "src/cli.js"]
