# Releasing Kube Secret Gateway

Kube Secret Gateway and its agent share one version. A release publishes the
gateway as a container image and the agent as static host binaries, all built
from the same Git tag.

## Version policy

Releases use [Semantic Versioning](https://semver.org/) with a `v`-prefixed Git
tag, for example `v0.1.0`.

- Increment `PATCH` for backward-compatible fixes.
- Increment `MINOR` for backward-compatible features. Before `v1.0.0`, use a
  minor release for any necessary breaking change and document the migration.
- Increment `MAJOR` for breaking changes after `v1.0.0`.
- Use tags such as `v0.2.0-rc.1` for prereleases.

A published version is immutable. Never move or reuse its Git tag and never
overwrite its container tag. Publish a new patch version instead. The
`latest` container tag is the only moving release tag and is updated only by
stable releases.

## One-time repository setup

Before the first public release:

1. Enable GitHub Actions and allow workflows to create packages and releases.
2. After the first GHCR package is created, make
   `ghcr.io/kabsdk/kube-secret-gateway` public and connect it to this
   repository if GitHub has not done so automatically.
3. Enable immutable releases in the repository settings.
4. Protect `main` and require the `CI / Test and build` check before merging.

The workflows use the repository's `GITHUB_TOKEN`; no registry password or
release token is required.

## Create a release

Release only a commit already merged to `main` with a passing CI run. Start
from an up-to-date, clean checkout:

```sh
git switch main
git pull --ff-only
git status --short
```

Choose the next version, review the changes since the previous release, then
create and push an annotated tag:

```sh
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The release workflow validates the tag, reruns all checks, and publishes:

- `ghcr.io/kabsdk/kube-secret-gateway:v0.1.0` for Linux AMD64 and ARM64;
- `ghcr.io/kabsdk/kube-secret-gateway:latest` for a stable release;
- `kube-secret-gateway-agent-v0.1.0-linux-amd64`;
- `kube-secret-gateway-agent-v0.1.0-linux-arm64`; and
- `SHA256SUMS` alongside automatically generated release notes.

Prereleases publish their exact image tag and GitHub release assets but do not
update `latest`.

## After publishing

Check the release page and inspect the multi-platform image:

```sh
gh release view v0.1.0
docker buildx imagetools inspect ghcr.io/kabsdk/kube-secret-gateway:v0.1.0
```

Deployments should pin an exact version or image digest. The Ansible role
should likewise require an explicit agent version and verify the downloaded
binary against `SHA256SUMS`; it must not install an implicit latest version.
