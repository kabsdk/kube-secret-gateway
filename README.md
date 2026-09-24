# Kube Secret Gateway

Kube Secret Gateway exposes selected Kubernetes Secret data through an
authenticated HTTP API. It is designed for software outside a cluster that
needs a secret without receiving Kubernetes credentials or direct access to
the Kubernetes API.

A client can fetch one value from a Secret or fetch several values together as
a consistent bundle. The API can be used directly with any HTTP client. When
values need to remain synchronized with files on a host, the optional agent
polls the bundle endpoint and can reload the consuming service after a change.

| Component                                        | Runs                  | Purpose                                                                                          |
| ------------------------------------------------ | --------------------- | ------------------------------------------------------------------------------------------------ |
| [**kube-secret-gateway**](gateway/README.md)     | In Kubernetes         | Watches explicitly configured Secrets and exposes them through the HTTP API.                     |
| [**kube-secret-gateway-agent**](agent/README.md) | On a destination host | Polls the gateway, writes changed values to files, and optionally reloads the consuming service. |

```text
Kubernetes Secrets -> gateway HTTP API -> direct clients
                              |
                              +-> agent -> local files -> service reload
```

The gateway exposes only explicitly selected Secrets and keys. Kubernetes RBAC
still controls what the gateway itself may read. The gateway stores values
only in memory and never writes them to disk.

## Repository layout

```text
gateway/   Gateway server, container image, Kubernetes examples and API docs
agent/     Host agent, systemd examples and synchronization docs
```

The components are separate Go modules joined by the root `go.work`. They have
independent dependencies and release artifacts, while the gateway's end-to-end
tests build and exercise the real agent.

## Documentation

- Start with the [gateway guide](gateway/README.md) to configure the API,
  deploy it in Kubernetes, and fetch individual values or bundles.
- Use the [agent guide](agent/README.md) when a host needs continuous file
  synchronization or a command such as `systemctl reload nginx` after an
  update.
- Consult the [gateway reference](gateway/REFERENCE.md) for the complete HTTP
  contract, proxy behavior, TLS, metrics, and security details.

The gateway is a distribution service, not a general secret manager. It does
not create or modify Secrets, and a value already delivered to a client cannot
be remotely revoked.

## Development

Run checks for both components from the repository root:

```sh
make check
make test-race
```

The test suites use fake Kubernetes and HTTP servers; no cluster is required.
Build the two binaries with:

```sh
make build
```

The binaries are written to `dist/`.

Build the gateway container from its module directory:

```sh
docker build -t kube-secret-gateway:dev gateway
```
