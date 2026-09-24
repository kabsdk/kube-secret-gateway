#!/usr/bin/env bash
# Cross-compile kube-secret-gateway-agent for supported host platforms and write
# SHA256SUMS next to the binaries.
#
# Usage: scripts/build-release.sh [VERSION]
#
# VERSION defaults to `git describe --tags --always --dirty`. The binaries are
# static (CGO_ENABLED=0) and reproducible for a given version and toolchain
# (-trimpath, no build ID paths).
#
# Environment:
#   OUT         output directory (default: dist)
#   PLATFORMS   space-separated os/arch list
#   SKIP_TESTS=1  skip go vet and go test
set -euo pipefail

cd "$(dirname "$0")/.."

out=${OUT:-dist}
platforms=${PLATFORMS:-"linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 freebsd/amd64"}

repo_dir=$(pwd -P)
out_dir=$(realpath -m -- "$out")
case "$out_dir" in
  "$repo_dir"/*) ;;
  *)
    echo "error: OUT must be a directory inside $repo_dir" >&2
    exit 2
    ;;
esac

version=${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
if [[ $version == *-dirty ]]; then
  echo "warning: uncommitted changes; the build is tagged $version" >&2
fi

if [[ ${SKIP_TESTS:-} != 1 ]]; then
  echo "==> go vet ./... && go test ./..."
  go vet ./...
  go test ./...
fi

rm -rf -- "$out_dir"
mkdir -p "$out_dir"

for platform in $platforms; do
  os=${platform%%/*}
  arch=${platform##*/}
  name="kube-secret-gateway-agent-$version-$os-$arch"
  echo "==> $name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags="-s -w -X main.version=${version}" \
      -o "$out_dir/$name" ./cmd/kube-secret-gateway-agent
done

echo "==> SHA256SUMS"
(cd "$out_dir" && sha256sum kube-secret-gateway-agent-* > SHA256SUMS && cat SHA256SUMS)
echo "==> done: $out_dir"
