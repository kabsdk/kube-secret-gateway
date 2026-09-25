# Changelog

## [Unreleased]

## [v0.2.0] - 2026-09-25

### Breaking

- Replaced `/secrets/{exposure}/{key}` and `/bundles/{exposure}` with
  `GET|HEAD /exposures/{name}`. No compatibility routes remain.
- Gateway configuration now uses `exposures` with required explicit `keys`.
  Removed `secrets`, `includeKeys`, `excludeKeys`, and authentication
  `type` fields.
- Agent configuration now has one `exposures` list containing authentication,
  polling, `targets`, and the change command. Removed the credential registry,
  `bundles`, `files`, `credentialsFile`, and `passwordEnv`.
- Renamed `-bundle` to `-exposure`. Agent metric labels now use `exposure`,
  and `bundle_healthy` is now `exposure_healthy`.

### Changed

- Fetching an exposure returns every configured key as one atomic JSON
  snapshot. Clients cannot request a subset.
- ksg-agent fetches the complete exposure and writes only configured targets.
  Exposure names now identify polling, logs, metrics, and state files.
- Password-file contents are now used exactly as stored, without removing a
  trailing line ending.
- Updated all guides, references, tests, manifests, and examples for the new
  exposure/target model.
- Fixed a flaky metrics test and duplicate CI runs after pull-request merges.

## [v0.1.0] - 2026-09-24

Initial release of ksg and ksg-agent, including authenticated Secret delivery,
atomic host-file synchronization, Kubernetes watches and RBAC, TLS, Prometheus
metrics, systemd examples, CI, and versioned release artifacts.

[Unreleased]: https://github.com/kabsdk/kube-secret-gateway/compare/v0.2.0...HEAD
[v0.2.0]: https://github.com/kabsdk/kube-secret-gateway/compare/v0.1.0...v0.2.0
[v0.1.0]: https://github.com/kabsdk/kube-secret-gateway/releases/tag/v0.1.0
