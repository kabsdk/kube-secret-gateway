# Kube Secret Gateway

Kube Secret Gateway (ksg) serves selected Kubernetes Secrets to servers outside your
cluster through a controlled, authenticated HTTP(S) API with a minimal
blast radius. Using kube-secret-gateway-agent (ksg-agent), those Secrets are predictably synchronized to
local files.

# Purpose

If you are anything like me, you probably have a tight grip on certificate management in
Kubernetes. You know: cert-manager, Prometheus metrics, Grafana alerts and whatnot.
You are probably the type to know exactly when something is wrong and that's what I like about you!

Then, you suddenly need to configure something on a server outside the cluster - you know,
some half-forgotten server running a god-knows-how-old docker-compose stack. You need
to serve some webpage from it, so of course it needs a TLS certificate. At this
point, you only really have four options:

- Install another ACME client directly on your half-forgotten server, copy over
  the Cloudflare credentials, and hope and pray its renewal job keeps working.
- Implement an **entire** secret manager such as OpenBao for the single purpose
  of fetching a certificate once a week from your cluster.
- Copy the secret manually once in a while when it's renewed.
- Open up kube-api access, configure RBAC and hope that you haven't misconfigured it.

ksg closes that gap: keep ACME and its monitoring in one
place (where you already have it, in Kubernetes), then distribute each renewed certificate only where and when it is needed.

```text
cert-manager -> Kubernetes Secret -> ksg -> ksg-agent -> local files -> service reload
```

The blast radius is intentionally small. Clients never receive Kubernetes
API credentials, and ksg exposes only the Secrets and keys you configure.
Each exposure has a network allow-list and Basic Auth, while Kubernetes RBAC
limits what ksg itself can read from the cluster. There is no exposure-listing API, and
Secret values stay in memory.

Both ksg and ksg-agent expose Prometheus metrics, so monitoring does not
end at the cluster boundary.

## Components

| Component                                        | Runs                  | Purpose                                                                           |
| ------------------------------------------------ | --------------------- | --------------------------------------------------------------------------------- |
| [**kube-secret-gateway**](gateway/README.md)     | In Kubernetes         | Exposes configured Secrets through the HTTP API.                                  |
| [**kube-secret-gateway-agent**](agent/README.md) | On a destination host | Synchronizes Secrets to files and optionally reloads the service that uses them.  |

ksg can also be used directly without ksg-agent.

## Get started

- Follow the [ksg guide](gateway/README.md) to configure and deploy the
  API.
- Follow the [ksg-agent guide](agent/README.md) to synchronize files on an
  external host.
- See the [ksg reference](gateway/REFERENCE.md) for the complete API,
  configuration, TLS, proxy, metrics, and security details.

Releases publish the ksg container image at
`ghcr.io/kabsdk/kube-secret-gateway` and attach ksg-agent binaries and checksums to
[GitHub Releases](https://github.com/kabsdk/kube-secret-gateway/releases).
See [CHANGELOG.md](CHANGELOG.md) for release history and breaking changes.

ksg distributes Secrets; it does not create, modify, or revoke
them.

## Development

ksg and ksg-agent are separate Go modules joined by the root `go.work`.

```sh
make check
make test-race
make build
```

The tests require no Kubernetes cluster. Built binaries are written to
`dist/`. See [RELEASING.md](RELEASING.md) for the release process.

Licensed under the [Apache License 2.0](LICENSE).
