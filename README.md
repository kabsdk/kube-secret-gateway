# Kube Secret Gateway

Kube Secret Gateway (ksg) delivers Kubernetes Secrets to servers outside the cluster
and keeps them up to date. You configure *exposures*: each one names a Secret, the
keys to share from it, and who may fetch them. ksg serves exactly those keys over an
authenticated HTTP(S) API.

On the receiving server, kube-secret-gateway-agent (ksg-agent) fetches the exposure,
writes each value to a local file and, whenever the values change, reloads or
restarts the service that uses them.

# Purpose

If you are anything like me, you have secrets in Kubernetes well under control. An
operator generates your database credentials, rotates them on a schedule, and every
workload in the cluster picks up the new Secret automatically. The one exception is
the reporting server outside the cluster running docker compose, where Gary has deployed
the rotated password manually twice a month.

That server runs the nightly reporting job that finance swears is business-critical.
The automation that rotates the Postgres credentials stops at the cluster boundary;
like most in-cluster automation, it was never designed to reach beyond it. Extending
it to servers outside the cluster would mean giving something in the cluster SSH
access to the server, or worse, setting up an FTP drop. So after every rotation, Gary
copies the new password out of the Secret, pastes it into the server's `.env` file
and restarts the stack. It works, as long as Gary remembers, isn't on holiday and gets every character
right.

To take Gary out of the loop, you only really have three options:

- Turn off rotation for that user, so there is nothing left to deploy.
- Implement an **entire** secret manager such as OpenBao for the single purpose
  of handing one password to one server.
- Open up kube-api access, configure RBAC, hope that you haven't misconfigured it,
  and have the server fetch the Secret itself with a shell script that handles every
  error case. And when that script fails, it fails silently: your alerting stack won't
  notice it.

ksg is the fourth option: keep the credentials where they are created and rotated
(where you already have them, in Kubernetes), and let ksg-agent install each new
version on the hosts that need it. Every rotation reaches the server the same way,
within one polling interval, without anyone involved. The Postgres username and
password come straight from the Kubernetes Secret as one snapshot, and the service
is only restarted once both are in place.

```text
database operator -> Kubernetes Secret -> ksg -> ksg-agent -> local files -> service restart
```

Unlike opening up kube-api access, no ksg configuration can give clients access to
the Kubernetes API. ksg answers a single endpoint, `GET|HEAD /exposures/{name}`, from
memory; it never forwards requests to Kubernetes and never hands out its own
credentials. The worst a configuration mistake can do is expose the wrong Secret,
and Kubernetes RBAC limits which Secrets ksg can read in the first place.

Each exposure has a network allow-list and Basic Auth, there is no API for listing
exposures, and Secret values stay in memory.

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
