# Releasing Kube Secret Gateway

ksg and ksg-agent share one version. A release publishes ksg as a container
image and ksg-agent as static host binaries, all built from the same Git tag.

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

## Create a release

Prepare the changelog on the PR branch before merging the release to `main`:

1. Confirm that `[Unreleased]` contains every change since the previous
   release.
2. Add a new empty `[Unreleased]` section and move the existing entries under
   `[vX.Y.Z] - YYYY-MM-DD`.
3. Change the `[Unreleased]` comparison link to start at `vX.Y.Z` and add a
   comparison link from the previous version to `vX.Y.Z`.
4. Commit the changelog as part of the PR, let CI pass, and merge the PR.

Tag promptly after merging so no unrelated commits land between the release
commit and its tag. Release only a commit already merged to `main`. From an
up-to-date, clean checkout:

```sh
git switch main
git pull --ff-only
git status --short
```

Verify that `HEAD` is the intended release commit, then create and push an
annotated tag:

```sh
# Example release; replace this with the version being published.
version=v0.2.0
git tag -a "$version" -m "$version"
git push origin "$version"
```

The release workflow validates the tag, reruns all checks, and publishes:

- `ghcr.io/kabsdk/kube-secret-gateway:vX.Y.Z` for Linux AMD64 and ARM64;
- `ghcr.io/kabsdk/kube-secret-gateway:latest` for a stable release;
- `kube-secret-gateway-agent-vX.Y.Z-linux-amd64`;
- `kube-secret-gateway-agent-vX.Y.Z-linux-arm64`; and
- `SHA256SUMS` alongside automatically generated release notes.

Prereleases publish their exact image tag and GitHub release assets but do not
update `latest`.

## After publishing

Check the release page and inspect the multi-platform image:

```sh
# Example release; replace this with the version that was published.
version=v0.2.0
gh release view "$version"
docker buildx imagetools inspect "ghcr.io/kabsdk/kube-secret-gateway:$version"
```

Deployments should pin an exact version or image digest. The Ansible role
should likewise require an explicit agent version and verify the downloaded
binary against `SHA256SUMS`; it must not install an implicit latest version.
