#!/usr/bin/env bash
# Build the kube-secret-gateway image and push it to the registry.
#
# Usage: scripts/push-image.sh [TAG]
#
# TAG defaults to `git describe --tags --always --dirty`, for example v0.1.0,
# v0.1.0-3-gabc1234, or abc1234-dirty when there are uncommitted changes.
#
# The registry credentials are asked for on every run and never stored: login
# and push use a temporary Docker configuration that is deleted on exit, so
# nothing is written to ~/.docker/config.json or a credential store.
#
# Environment:
#   IMAGE              repository (default: registry.aslot.dk/kube-secret-gateway)
#   PLATFORM           target platform (default: linux/amd64)
#   REGISTRY_USERNAME  default for the username prompt
#   SKIP_TESTS=1       skip go vet and go test
set -euo pipefail

image=${IMAGE:-registry.aslot.dk/kube-secret-gateway}
registry=${image%%/*}
platform=${PLATFORM:-linux/amd64}

cd "$(dirname "$0")/.."

tag=${1:-$(git describe --tags --always --dirty)}
if [[ ! $tag =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  echo "error: invalid image tag: $tag" >&2
  exit 1
fi
if [[ $tag == *-dirty ]]; then
  echo "warning: uncommitted changes; the image is tagged $tag" >&2
fi

if [[ ${SKIP_TESTS:-} != 1 ]]; then
  echo "==> go vet ./... && go test ./..."
  go vet ./...
  go test ./...
fi

echo "==> building $image:$tag ($platform)"
docker build --pull --platform "$platform" --build-arg VERSION="$tag" --tag "$image:$tag" .

# Credentials are asked for only once the slow part has succeeded.
read -r -p "Username for $registry${REGISTRY_USERNAME:+ [$REGISTRY_USERNAME]}: " username
username=${username:-${REGISTRY_USERNAME:-}}
read -r -s -p "Password for $username@$registry: " password
echo
if [[ -z $username || -z $password ]]; then
  echo "error: username and password are required" >&2
  exit 1
fi

docker_config=$(mktemp -d)
trap 'rm -rf "$docker_config"' EXIT
trap 'exit 130' INT TERM
# Talk to the same daemon as the current Docker context, which lives in the
# regular configuration that the temporary one replaces.
docker_host=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
docker_ephemeral() {
  DOCKER_CONFIG=$docker_config DOCKER_HOST=$docker_host docker "$@"
}

echo "==> logging in to $registry"
echo "    (a warning about unencrypted storage refers to the temporary config, which is deleted on exit)"
# printf is a shell builtin, so the password never appears in the process list.
printf '%s' "$password" | docker_ephemeral login "$registry" --username "$username" --password-stdin
unset password

echo "==> pushing $image:$tag"
docker_ephemeral push "$image:$tag"

digest=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image:$tag" | grep -m1 "^$image@" || true)
echo "==> done: $image:$tag"
if [[ -n $digest ]]; then
  echo "    pin deployments to: $digest"
fi
