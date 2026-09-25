#!/usr/bin/env bash
#
# Builds the gcp-mcp container image with Docker, or with Apple container when Docker is not
# installed. IMAGE overrides the image name (default: gcp-mcp:latest). ARCH selects the
# architectures: amd64, arm64 or amd64,arm64 (default: the host's).

set -euo pipefail

cd "$(dirname "$0")/.."
image="${IMAGE:-gcp-mcp:latest}"
version="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"

if command -v docker >/dev/null 2>&1; then
    platform=()
    if [[ -n "${ARCH:-}" ]]; then
        platform=(--platform "linux/${ARCH//,/,linux/}")
    fi
    docker build "${platform[@]}" --build-arg "VERSION=${version}" -t "${image}" .
elif command -v container >/dev/null 2>&1; then
    arch=()
    for name in ${ARCH//,/ }; do
        arch+=(--arch "${name}")
    done
    # Starts the Apple container services when they are stopped.
    container system status >/dev/null 2>&1 || container system start
    container build "${arch[@]}" --build-arg "VERSION=${version}" -t "${image}" .
else
    echo "Error: neither docker nor Apple container is installed" >&2
    exit 1
fi
