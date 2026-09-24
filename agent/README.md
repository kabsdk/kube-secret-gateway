# kube-secret-gateway-agent

`kube-secret-gateway-agent` is a small host-side service that continuously
synchronizes Secret bundles from kube-secret-gateway to local files and can
run a command when those files change.

Suppose cert-manager continuously renews a certificate in Kubernetes, while
the nginx server that uses it runs on another machine. Without Kube Secret
Gateway and its agent, you would need to give that machine Kubernetes access,
copy every renewed certificate manually, or build and operate your own polling
script. That script would also need to detect changes, keep the certificate
and private key together, install files safely, survive failures, and reload
nginx at the right time.

`kube-secret-gateway-agent` provides that host-side synchronization. It polls
the gateway, installs changed values as local files, and optionally runs a
command such as `systemctl reload nginx`. The host needs gateway credentials,
but no Kubernetes credentials or Kubernetes client.

See the [project overview](../README.md) for the full architecture and the
[gateway guide](../gateway/README.md) for individual-value and bundle API
usage.

## What the agent does

```text
Kubernetes Secret -> gateway -> HTTPS -> agent -> local files -> service reload
```

For each configured bundle, the agent:

1. Polls the gateway on its own interval using per-exposure credentials.
2. Uses an ETag so an unchanged bundle returns `304 Not Modified` without
   downloading or rewriting anything.
3. Downloads related values together from one Kubernetes Secret version. A
   renewed certificate is therefore never fetched separately from its key.
4. Validates the complete response before touching destination files, then
   writes and renames each file atomically.
5. Updates the bundle stamp, optionally runs `onChangeCommand`, and records the
   completed ETag only after the whole sync succeeds.
6. Keeps installed files on errors and retries failed fetches or reloads at the
   next interval.

It also detects missing files or incorrect file modes and reinstalls the
bundle even when the upstream version has not changed. Each bundle can use a
different polling interval, destination paths, modes, and reload command.

## Install the agent

The agent is a static binary intended to run on the destination host under
systemd. Running it on the host lets it write directly to the required paths
and run commands such as `systemctl reload nginx`.

From the `agent/` directory, build and install it:

```sh
CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X main.version=$(git describe --tags --always)" \
  -o kube-secret-gateway-agent ./cmd/kube-secret-gateway-agent
sudo install -m 0755 kube-secret-gateway-agent /usr/local/bin/
```

Create the configuration directory and install the example files:

```sh
sudo install -d -m 0700 /etc/kube-secret-gateway-agent
sudo install -m 0600 examples/config.yaml \
  /etc/kube-secret-gateway-agent/config.yaml
sudo install -m 0644 examples/kube-secret-gateway-agent.service \
  /etc/systemd/system/kube-secret-gateway-agent.service
```

Edit the configuration and add its credential files, then check everything
that can be validated locally:

```sh
sudo /usr/local/bin/kube-secret-gateway-agent -check
```

The check reads the configuration and credentials but does not contact the
gateway. Once it succeeds, start the agent:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now kube-secret-gateway-agent
```

`scripts/build-release.sh` can be used to create cross-platform release
binaries and a `SHA256SUMS` file.

## Configuration

The default configuration file is
`/etc/kube-secret-gateway-agent/config.yaml`. Unknown fields and invalid
combinations are rejected at startup.

```yaml
gateway:
  url: https://gateway.example.com
  caFile: /etc/kube-secret-gateway-agent/gateway-ca.crt
  timeout: 30s

exposures:
  - name: my-cert
    username: fetcher
    passwordFile: /etc/kube-secret-gateway-agent/my-cert.password

bundles:
  - name: nginx-tls
    exposure: my-cert
    interval: 24h
    onChangeCommand: [systemctl, reload, nginx]
    files:
      tls.crt: {path: /etc/ssl/nginx/tls.crt, mode: "0644"}
      tls.key: /etc/ssl/nginx/tls.key
```

The configuration is read at startup. Restart the agent after changing it.
Credential files are read before every request and can be rotated without a
restart.

### Gateway connection

| Field     | Required | Meaning                                                               |
| --------- | -------- | --------------------------------------------------------------------- |
| `url`     | yes      | Base URL of the gateway's Secrets listener. A path prefix is allowed. |
| `caFile`  | no       | PEM CA used instead of the system trust store.                        |
| `timeout` | no       | Request timeout from `1s` to `10m`; default `30s`.                    |

Use HTTPS whenever the connection leaves an already encrypted, trusted
network. When `caFile` is set, it replaces rather than extends the system trust
store for this connection.

### Exposure credentials

Each entry under `exposures` supplies credentials for an exposure configured
on the gateway. Exactly one credential source must be used:

| Field             | Meaning                                                            |
| ----------------- | ------------------------------------------------------------------ |
| `name`            | Exposure name configured on the gateway.                           |
| `username`        | Basic Auth username used with `passwordFile` or `passwordEnv`.     |
| `passwordFile`    | Absolute path to a file containing only the password.              |
| `credentialsFile` | Absolute path to a file containing one `username:password` line.   |
| `passwordEnv`     | Environment variable containing the password. A file is preferred. |

A trailing newline in a credential file is ignored. Password environment
variables are removed from the environment inherited by `onChangeCommand`.

### Bundles

| Field             | Required | Meaning                                                              |
| ----------------- | -------- | -------------------------------------------------------------------- |
| `name`            | yes      | Unique name used in logs and state-file names.                       |
| `exposure`        | yes      | Exposure to fetch. One bundle maps to one Kubernetes Secret.         |
| `interval`        | no       | Poll interval from `10s` to `168h`; default `5m`.                    |
| `files`           | yes      | Map of Secret keys to absolute destination paths and optional modes. |
| `onChangeCommand` | no       | Command and arguments to run after the files change.                 |

The default file mode is `0600`. A file can use the short form or specify its
mode explicitly:

```yaml
files:
  tls.key: /etc/ssl/nginx/tls.key
  tls.crt: {path: /etc/ssl/nginx/tls.crt, mode: "0644"}
```

No two bundles may write the same destination path.

`onChangeCommand` is executed directly, without a shell. If it fails, the
bundle is retried at its next interval. The timeout is controlled by
`-command-timeout` and defaults to two minutes.

## Running the agent

Without `-once`, the agent runs continuously and polls each bundle on its own
interval. A failure in one bundle is logged and retried without stopping the
others.

Use `-once` when systemd or cron should own the schedule. The example
`kube-secret-gateway-agent-once.service` and `.timer` files show this setup.
Bundle intervals are ignored in one-shot mode. `-bundle` can restrict a run to
one or more named bundles.

### Reloading services

The simplest option is to configure the reload directly:

```yaml
onChangeCommand: [systemctl, reload, nginx]
```

To keep service control separate from the agent, omit `onChangeCommand` and
use a systemd path unit to watch the bundle's stamp file. Examples are provided
in `examples/nginx-reload.path` and `examples/nginx-reload.service`.

Watch the stamp rather than an individual destination file. The stamp changes
only after every configured destination file has been replaced.

## Update and failure behavior

When a bundle changes, the agent first checks that the response contains every
configured key. It then writes each value to a temporary file beside its
destination, flushes the file, and renames it over the destination. After all
renames have completed, it updates the stamp and runs the change command. The
new ETag is recorded only after the entire sync succeeds.

Each destination file is replaced atomically and is never left half-written.
The files as a group are not a filesystem transaction: a crash between
renames can leave files from different versions. Because the ETag is recorded
last, the next run detects the incomplete sync and installs the complete
bundle again. Reload commands and stamp watchers run only after all renames
have completed.

Fetch and validation errors leave the installed files untouched. A reload
failure leaves the new files installed but does not commit the ETag, so the
agent installs the bundle and tries the reload again at the next interval. A
missing or deleted upstream Secret does not delete files already installed on
the host. Kube Secret Gateway distributes Secret values; it cannot revoke
copies that have already been delivered.

The state directory is `/var/lib/kube-secret-gateway-agent` by default and
contains two files per bundle:

- `{bundle}.etag` records the last completed sync.
- `{bundle}.stamp` changes after all destination files have been replaced.

## Troubleshooting

The agent logs to standard error, which the provided service sends to the
systemd journal:

```sh
journalctl -u kube-secret-gateway-agent
```

Common gateway responses are:

| Status | What to check                                                                                                             |
| ------ | ------------------------------------------------------------------------------------------------------------------------- |
| `401`  | The exposure username or password is incorrect.                                                                           |
| `404`  | The exposure name is wrong, the host is outside its `allowedCidrs`, or the gateway does not provide the bundle endpoint.  |
| `503`  | The source or authentication Secret is missing or does not contain the expected keys. Check the gateway logs and metrics. |

`-check` confirms that credentials can be read locally; it cannot confirm that
the gateway will accept them.

## Command reference

| Flag               | Default                                      | Meaning                                                                |
| ------------------ | -------------------------------------------- | ---------------------------------------------------------------------- |
| `-config`          | `/etc/kube-secret-gateway-agent/config.yaml` | Configuration file.                                                    |
| `-state-dir`       | `/var/lib/kube-secret-gateway-agent`         | ETag and stamp files.                                                  |
| `-once`            | off                                          | Synchronize selected bundles once and exit.                            |
| `-bundle`          | all                                          | Comma-separated bundle names to synchronize.                           |
| `-check`           | off                                          | Validate configuration and credentials without contacting the gateway. |
| `-command-timeout` | `2m`                                         | Maximum runtime for `onChangeCommand`.                                 |
| `-log-level`       | `info`                                       | `debug`, `info`, `warn`, or `error`.                                   |
| `-log-format`      | `text`                                       | `text` or `json`.                                                      |
| `-version`         |                                              | Print the version.                                                     |

Exit status is `0` for success, `1` when a one-shot sync fails, and `2` for
invalid arguments, configuration, or credentials.

## Limitations

- A bundle contains keys from one Kubernetes Secret. There is no consistent
  snapshot across multiple Secrets.
- The agent sets file modes but not owner or group.
- Configuration changes require a restart.
- The agent has no metrics listener. Use its logs, exit status, stamp files,
  and the gateway's metrics for monitoring.

## Development

From the `agent/` directory:

```sh
go test ./...
go test -race ./...
go vet ./...
```

Tests use an in-memory gateway and do not require Kubernetes or network
access. The agent and gateway test suites both pin the bundle wire format.
