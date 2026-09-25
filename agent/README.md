# kube-secret-gateway-agent

ksg-agent is the host-side component of the Kube Secret Gateway stack. It
fetches exposures from ksg, installs selected values as local files, and can
reload a service or run an arbitrary command after those files change.

```text
Kubernetes Secret -> Exposure -> Local targets
```

Each request fetches the complete exposure as one atomic snapshot. The
configured targets decide which returned keys are written locally; extra keys
are ignored. Target selection is not an authorization boundary because
ksg-agent already received every key in the exposure - it is simply a way to discard unwanted keys from an exposure.

Create another server exposure when a client needs different keys,
credentials, permissions, polling behavior, or reload behavior. Multiple
exposures may reference the same Kubernetes Secret.

## What ksg-agent does

For each configured exposure, ksg-agent:

1. Polls `GET /exposures/{name}` using the exposure's Basic Auth credentials.
2. Sends the last completed ETag so unchanged polling returns `304 Not Modified` without transferring values.
3. Validates that every target key exists before changing any files.
4. Writes and flushes temporary files, then atomically replaces each target.
5. Updates the exposure stamp and optionally runs `onChangeCommand`.
6. Records the new ETag only after the entire synchronization succeeds.

## Install

Download the binary for a published version, verify it against the release
checksums, and install it. For example, on Linux AMD64:

```sh
# Example release; replace this with the version you want to install.
version=v0.2.0
asset="kube-secret-gateway-agent-${version}-linux-amd64"
base="https://github.com/kabsdk/kube-secret-gateway/releases/download/${version}"

curl --fail --location --remote-name "${base}/${asset}"
curl --fail --location --remote-name "${base}/SHA256SUMS"
grep " ${asset}$" SHA256SUMS | sha256sum --check
sudo install -m 0755 "$asset" /usr/local/bin/kube-secret-gateway-agent
```

ARM64 hosts use the corresponding `linux-arm64` asset.

Install the example configuration and systemd service:

```sh
sudo install -d -m 0700 /etc/kube-secret-gateway-agent
sudo install -m 0600 examples/config.yaml \
  /etc/kube-secret-gateway-agent/config.yaml
sudo install -m 0644 examples/kube-secret-gateway-agent.service \
  /etc/systemd/system/kube-secret-gateway-agent.service
```

Edit the configuration, create its password files, and validate it locally:

```sh
sudo /usr/local/bin/kube-secret-gateway-agent -check
sudo systemctl daemon-reload
sudo systemctl enable --now kube-secret-gateway-agent
```

`-check` reads configuration and credentials but does not contact ksg.

## Configuration

The default configuration file is
`/etc/kube-secret-gateway-agent/config.yaml`. Unknown fields and invalid
combinations are rejected at startup.

```yaml
gateway:
  url: https://gateway.example.com
  caFile: /etc/kube-secret-gateway-agent/gateway-ca.crt
  timeout: 30s

metrics:
  listenAddress: 0.0.0.0:9091

exposures:
  - name: my-cert
    auth:
      username: fetcher
      passwordFile: /etc/kube-secret-gateway-agent/my-cert.password
    interval: 24h
    targets:
      - key: tls.crt
        path: /etc/ssl/nginx/tls.crt
        mode: "0644"
      - key: tls.key
        path: /etc/ssl/nginx/tls.key
    onChangeCommand: [systemctl, reload, nginx]
```

Configuration is read at startup. Restart ksg-agent after changing it.
Password files are read before every request and can be rotated without a
restart.

### ksg connection

| Field     | Required | Meaning                                                               |
| --------- | -------- | --------------------------------------------------------------------- |
| `url`     | yes      | Base URL of ksg's delivery listener. A path prefix is allowed.        |
| `caFile`  | no       | PEM CA used instead of the system trust store.                        |
| `timeout` | no       | Request timeout from `1s` to `10m`; default `30s`.                    |

Use HTTPS whenever the connection leaves an already encrypted, trusted
network. When `caFile` is set, it replaces rather than extends the system
trust store.

### Metrics listener

| Field           | Required | Meaning                                                              |
| --------------- | -------- | -------------------------------------------------------------------- |
| `listenAddress` | no       | Prometheus listener used in continuous mode; default `0.0.0.0:9091`. |

The default accepts connections on every IPv4 interface. Restrict port 9091
with the host firewall, or bind to `127.0.0.1:9091` when scraping through a
local collector. One-shot runs do not open the listener.

### Exposures

| Field             | Required | Meaning                                                                 |
| ----------------- | -------- | ----------------------------------------------------------------------- |
| `name`            | yes      | Exact server exposure name and stable local identity.                   |
| `auth.username`   | yes      | Non-empty Basic Auth username.                                          |
| `auth.passwordFile` | yes    | Absolute path to a file containing only the password.                   |
| `interval`        | no       | Poll interval from `10s` to `168h`; default `5m`.                      |
| `targets`         | yes      | One or more keys and their local destinations.                          |
| `onChangeCommand` | no       | Command and arguments run after all targets change.                     |

Exposure names use Kubernetes DNS-subdomain syntax and must be unique. The
name is used in request paths, logs, metrics, one-shot selection, and the state filenames
`{exposure}.etag` and `{exposure}.stamp`.

The password file is read immediately before each request. Credentials are
never placed in URLs, command-line arguments, logs, metrics, or the
environment.

### Targets

| Field  | Required | Meaning                                             |
| ------ | -------- | --------------------------------------------------- |
| `key`  | yes      | Key from the fetched exposure.                      |
| `path` | yes      | Absolute destination filename.                      |
| `mode` | no       | File mode written as an octal string; default `0600`. |

An exposure must have at least one target. Target keys must be unique within
the exposure, and destination paths must be unique across the complete
configuration. Paths are lexically normalized before this uniqueness check.

`onChangeCommand` is executed directly without a shell. If it fails, the
files remain installed and the exposure is retried at its next interval. The
timeout is controlled by `-command-timeout` and defaults to two minutes.

## Running

Without `-once`, ksg-agent polls each exposure on its own interval. A failure
in one exposure does not stop the others.

Use `-once` when systemd or cron owns the schedule. Exposure intervals are
ignored in one-shot mode. Use `-exposure` to select one or more configured
exposures:

```sh
kube-secret-gateway-agent -once -exposure my-cert,app-token
```

The example `kube-secret-gateway-agent-once.service` and `.timer` files show
the systemd setup.

### Reloading services

The simplest option is to configure the reload directly:

```yaml
onChangeCommand: [systemctl, reload, nginx]
```

To keep service control separate from ksg-agent, omit `onChangeCommand` and
use a systemd path unit to watch the exposure stamp. Examples are provided in
`examples/nginx-reload.path` and `examples/nginx-reload.service`.

Watch the stamp rather than an individual target. The stamp changes only after
every configured target has been replaced.

## Prometheus metrics

In continuous mode, ksg-agent serves Prometheus metrics at `/metrics` on the
configured listener.

| Metric                                                             | Meaning                                                                |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| `kube_secret_gateway_agent_exposure_healthy`                       | Whether the latest synchronization attempt succeeded.                  |
| `kube_secret_gateway_agent_sync_attempts_total`                    | Synchronization attempts.                                              |
| `kube_secret_gateway_agent_sync_errors_total`                      | Failed synchronization attempts.                                       |
| `kube_secret_gateway_agent_changes_total`                          | Successful synchronizations that installed changed targets.            |
| `kube_secret_gateway_agent_last_attempt_timestamp_seconds`         | Time of the latest attempt.                                             |
| `kube_secret_gateway_agent_last_successful_sync_timestamp_seconds` | Time of the latest successful synchronization, including `304`.         |
| `kube_secret_gateway_agent_last_change_timestamp_seconds`          | Time targets were last installed successfully.                          |
| `kube_secret_gateway_agent_sync_duration_seconds`                  | Histogram of synchronization duration.                                 |
| `kube_secret_gateway_agent_build_info`                             | Running ksg-agent version.                                             |

Every synchronization metric uses the configured `exposure` name as its only
identity label. Secret values, credentials, destination paths, and command
output are never exposed.

## Update and failure behavior

ksg-agent validates the complete response before touching any targets. It
writes each value to a temporary file beside its destination, flushes it, and
renames it over the destination. Each replacement is atomic, but the targets
as a group are not a filesystem transaction.

If a crash occurs between renames, the ETag has not yet been committed. The
next run fetches the complete exposure and repairs every target. Reload
commands and stamp watchers run only after all replacements finish.

Fetch and validation errors leave installed files untouched. A reload failure
leaves new files installed but does not commit the ETag, so the next interval
reinstalls the targets and retries the reload. A missing upstream Secret does
not delete files already installed on the host.

## Troubleshooting

ksg-agent logs to standard error, which the provided service sends to the
systemd journal:

```sh
journalctl -u kube-secret-gateway-agent
```

| Status | What to check                                                                                                  |
| ------ | -------------------------------------------------------------------------------------------------------------- |
| `401`  | The exposure username or password is incorrect.                                                                |
| `404`  | The exposure name is wrong or the host is outside its `allowedCidrs`.                                         |
| `503`  | A source or authentication Secret is missing or incomplete; check ksg logs and metrics.                       |

`-check` confirms that password files can be read locally; it cannot confirm
that ksg accepts the credentials.

## Command reference

| Flag               | Default                                      | Meaning                                                                |
| ------------------ | -------------------------------------------- | ---------------------------------------------------------------------- |
| `-config`          | `/etc/kube-secret-gateway-agent/config.yaml` | Configuration file.                                                    |
| `-state-dir`       | `/var/lib/kube-secret-gateway-agent`         | Per-exposure ETag and stamp files.                                     |
| `-once`            | off                                          | Synchronize selected exposures once and exit.                          |
| `-exposure`        | all                                          | Comma-separated exposure names to synchronize.                         |
| `-command-timeout` | `2m`                                         | Maximum runtime for `onChangeCommand`.                                 |
| `-check`           | off                                          | Validate configuration and credentials without contacting ksg.        |
| `-log-level`       | `info`                                       | `debug`, `info`, `warn`, or `error`.                                 |
| `-log-format`      | `text`                                       | `text` or `json`.                                                       |
| `-version`         |                                              | Print the version.                                                     |

Exit status is `0` for success, `1` when a one-shot synchronization fails,
and `2` for invalid arguments, configuration, or credentials.

## Limitations

- One exposure comes from one Kubernetes Secret.
- ksg-agent sets file modes but not owner or group.
- Configuration changes require a restart.
- Metrics are available only in continuous mode. Monitor one-shot services
  through their exit status and systemd timer state.
- ksg distributes values; it cannot revoke copies already delivered.

## Development

From the `agent/` directory:

```sh
go test ./...
go test -race ./...
go vet ./...
go build -o kube-secret-gateway-agent ./cmd/kube-secret-gateway-agent
```

Tests use an in-memory ksg and require no Kubernetes or external network
access. Maintainers can use `scripts/build-release.sh` to create
cross-platform binaries and a `SHA256SUMS` file.
