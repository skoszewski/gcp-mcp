#!/usr/bin/env bash
#
# Builds the gcp-mcp binary into bin/. GOOS and GOARCH select another target platform.

set -euo pipefail

cd "$(dirname "$0")/.."
version="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"

CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${version}" -o bin/gcp-mcp ./cmd/gcp-mcp
echo "bin/gcp-mcp ${version}"
