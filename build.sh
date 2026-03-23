#!/usr/bin/env bash
set -euo pipefail

# Build packetforge locally with version info injected,
# using the same ldflags scheme as CI.
#
# Usage:
#   build.sh [version]
# Example:
#   build.sh v0.1.0
#   build.sh          # auto-detect from git (fallback: dev)

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

LDFLAGS="-s -w \
  -X github.com/yanjiulab/packetforge/internal/version.Version=${VERSION} \
  -X github.com/yanjiulab/packetforge/internal/version.Commit=${COMMIT} \
  -X github.com/yanjiulab/packetforge/internal/version.Date=${DATE} \
  -X github.com/yanjiulab/packetforge/internal/version.BuiltBy=local"

echo "Building packetforge locally with:"
echo "  VERSION=${VERSION}"
echo "  COMMIT=${COMMIT}"
echo "  DATE=${DATE}"
echo "  GOOS=${GOOS:-$(go env GOOS)}"
echo "  GOARCH=${GOARCH:-$(go env GOARCH)}"

export CGO_ENABLED="${CGO_ENABLED:-0}"

go build -trimpath -ldflags "${LDFLAGS}" -o pf ./cmd/pf

echo "Done."
echo "  ./pf version"

