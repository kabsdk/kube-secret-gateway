# ksg reference

This document defines ksg's complete API and operational behavior.
Start with the [ksg guide](README.md) for the shorter introduction and
deployment example.

## HTTP API

ksg has two listeners:

| Listener   | Default | Endpoints                         |
| ---------- | ------- | --------------------------------- |
| Delivery   | `:8080` | `/exposures/{name}`               |
| Operations | `:8081` | `/healthz`, `/readyz`, `/metrics` |

Only the delivery listener should be externally routed. The exposure endpoint
accepts `GET` and `HEAD`; `HEAD` returns the same status and headers without a
body. Query strings and request bodies are rejected.

Paths must match exactly. Extra or missing segments, trailing slashes, `.` or
`..`, and any percent-encoding return `404`; ksg never redirects.
There is no listing endpoint. Clients must already know the exposure name.

### Exposure snapshot

`GET /exposures/{name}` returns every configured key from one read of one
Kubernetes Secret version:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
X-Content-Type-Options: nosniff
ETag: "hmac-sha256:…"

{"ca.crt":"Q0E=","tls.crt":"LS0t…","tls.key":"LS0t…"}
```

The body is a JSON object whose values use padded standard base64. Keys are
sorted and no insignificant whitespace is added, making the body canonical.
An exposure always contains at least one configured key. If any configured key
is missing, the request returns `503`; snapshots are never partial.

Clients cannot select a subset through the path, query parameters, headers, or
a request body. Configure another exposure when a client needs different keys,
credentials, permissions, polling, or reload behavior. Different exposures may
reference the same Kubernetes Secret.

### ETags and polling

Every successful response has an opaque ETag covering the complete exposure
snapshot. It changes when any configured value changes. Recreating a Secret
also changes the tag because its UID changes. Tags are identical across ksg
replicas.

Send the last installed tag in `If-None-Match`. A match returns `304 Not
Modified` with no body. Weak tags compare normally and `*` always matches.
Conditional requests are served from memory and do not reach Kubernetes.

Tags are HMAC-SHA256 values keyed by the Secret UID, rather than plain hashes,
so an observer who sees response headers cannot test guesses for short secret
values. `Cache-Control: no-store` tells intermediaries not to retain bodies.

### Authentication and status behavior

Each exposure uses HTTP Basic Auth. ksg evaluates requests in this
order:

| Step | Condition                                | Status | Logged reason               |
| ---- | ---------------------------------------- | ------ | --------------------------- |
| 1    | Method is not `GET` or `HEAD`            | `405`  | `method_not_allowed`        |
| 2    | Path is malformed                        | `404`  | `no_route`                  |
| 3    | Exposure is unknown                      | `404`  | `unknown_exposure`          |
| 4    | Client address is outside `allowedCidrs` | `404`  | `client_not_allowed`        |
| 4    | Client address cannot be resolved        | `404`  | `client_address_unresolved` |
| 5    | Authentication Secret is missing         | `503`  | `auth_secret_unavailable`   |
| 5    | Authentication Secret is malformed       | `503`  | `auth_secret_malformed`     |
| 6    | Credentials are missing or wrong         | `401`  | `unauthorized`              |
| 7    | Source Secret is missing                 | `503`  | `source_secret_unavailable` |
| 8    | A configured key is missing              | `503`  | `configured_key_missing`    |
| 9    | `If-None-Match` matches                  | `304`  | `not_modified`              |
| 9    | Response is returned                     | `200`  | `served`                    |

Error bodies contain only generic HTTP status text. Reasons appear in logs and
`kube_secret_gateway_http_requests_total`, never in the response. A `401`
includes `WWW-Authenticate`; a `405` includes `Allow: GET, HEAD`. Unexpected
internal failures return `500`.

The ordering prevents discovery:

- Outside the allow-list, existing and unknown exposures look identical.
- Without valid credentials, no source or configured-key state is revealed.
- Operational `503` responses are visible only after the network and
  authentication checks pass.

### Client correctness

A client that installs files should:

1. Fetch the complete exposure through `/exposures/{name}`.
2. Reuse an ETag only while the local files it represents still exist and
   have the expected modes.
3. Validate every required key before writing anything.
4. Stage every file beside its destination, flush it, and then rename it into
   place. Each rename is atomic; a group of files is not a filesystem
   transaction.
5. Store the new ETag last, after files and any reload command succeed, so a
   crash or reload failure causes the complete exposure to be installed again.
6. Keep credentials out of URLs and command-line arguments.
7. Keep installed files on errors; `401`, `404`, and `503` are not revocation
   instructions.

The [agent](../agent/README.md) implements these rules.

## Configuration

ksg reads `/etc/kube-secret-gateway/config.yaml`, or the path supplied
with `-config`. Configuration is validated completely before startup, unknown
fields are rejected, and changes require a restart.

### Top-level settings

| Field                          | Default  | Meaning                                                        |
| ------------------------------ | -------- | -------------------------------------------------------------- |
| `server.listenAddress`         | `:8080`  | Delivery listener.                                            |
| `server.trustedProxies`        | none     | CIDRs allowed to supply `X-Forwarded-For`.                     |
| `server.tls.certFile`          | none     | PEM serving certificate and intermediates.                     |
| `server.tls.keyFile`           | none     | PEM serving private key.                                       |
| `metrics.listenAddress`        | `:8081`  | Operations listener; must use a different port.                |
| `metrics.auth`                 | none     | Optional Basic Auth Secret for `/metrics`; probes remain open. |
| `metrics.tls`                  | none     | TLS certificate and key for the operations listener.           |
| `kubernetes.defaultNamespace`  | none     | Namespace used by references that omit one.                    |
| `kubernetes.reconcileInterval` | `5m`     | Full-read safety net; allowed range `10s` to `24h`.            |
| `exposures`                    | required | One or more exposures.                                         |

See [`examples/config.yaml`](examples/config.yaml) for a complete document.

Optional metrics authentication uses the same Basic Auth Secret format:

```yaml
metrics:
  auth:
    secretRef:
      name: prometheus-reader
      namespace: monitoring
```

The namespace may be omitted when `kubernetes.defaultNamespace` is set.

### Exposures

Each `exposures` entry has these fields:

| Field                 | Required  | Meaning                                                               |
| --------------------- | --------- | --------------------------------------------------------------------- |
| `name`                | yes       | URL name; must be unique.                                             |
| `secretRef.name`      | yes       | Source Kubernetes Secret.                                             |
| `secretRef.namespace` | sometimes | Defaults to `kubernetes.defaultNamespace`.                            |
| `allowedCidrs`        | yes       | Client networks; an empty list is rejected, not treated as allow-all. |
| `auth.secretRef`      | yes       | Secret containing the exposure credentials.                           |
| `keys`                | yes       | Explicit keys returned by the exposure; at least one is required.     |

There is no implicit all-keys mode. Every key that may leave the cluster must
be named explicitly. Exposure names follow Kubernetes name syntax: lowercase
letters, digits, `-`, and `.`.

A reference without an explicit namespace uses `defaultNamespace`. If neither
is set, validation fails. ksg never assumes its own namespace and
namespaces never appear in URLs.

CIDRs must include a prefix and use their network address. For example,
`10.10.30.40/32` and `10.10.30.0/24` are valid, while `10.10.30.40/24` is
rejected. Duplicate names, CIDRs, and keys are also rejected. Durations require
units such as `90s`, `5m`, or `1h`.

### Source and authentication Secrets

A source Secret may have any Kubernetes Secret type and any keys. Values are
served exactly as they appear in `data`; values supplied through `stringData`
are stored there by Kubernetes as well.

An authentication Secret must contain non-empty `username` and `password`
keys; other keys are ignored. Credentials are checked from watched state on
every request and can be rotated without restarting ksg. Comparison uses
constant-time SHA-256 digests.

A missing or malformed exposure credential Secret makes only that exposure
return `503`. In contrast, `metrics.auth` must be valid at startup; otherwise
the process exits. If it becomes invalid later, `/metrics` returns `503` while
secret serving continues.

A source Secret may also be used as its authentication Secret, but its
credential keys are exposed if they are explicitly included in `keys`.
Separate Secrets are safer and clearer.

## Kubernetes synchronization

Every distinct source or authentication Secret is managed once, even when
several exposures reference it. ksg performs an exact-name list, then
watches using `metadata.name=<name>`. Watches reconnect with jittered
exponential backoff and relist before resuming, so changes made while
disconnected are recovered.

Periodic direct GETs repair any missed event. A missing Secret is normal
runtime state: ksg continues watching and serves it once created. If
the Kubernetes API becomes unavailable, the last known state remains in
memory and is served; freshness and connection metrics show the outage.
Secret values are never written to disk or logged.

## Client addresses, proxies, and NAT

For a direct connection, the TCP peer address is the client and any
`X-Forwarded-For` header is ignored. When the peer is inside
`server.trustedProxies`, the header is read from right to left; the first
address outside the trusted ranges is the client. Invalid trusted portions of
the chain cause the request to be refused. IPv4, IPv6, and IPv4-mapped IPv6
addresses are supported.

For an HTTP ingress such as Traefik:

- Route only `/exposures/` on the HTTP router.
- Put only the ingress pod ranges in `trustedProxies`.
- Use a NetworkPolicy so other pods cannot reach port 8080 and forge a
  forwarded address.
- Preserve the original address on the way into the ingress, commonly with
  `externalTrafficPolicy: Local`. Configure any upstream load balancer and
  Traefik to trust each other explicitly.

TLS passthrough and source NAT hide the original client address. A TCP proxy
could preserve it with the PROXY protocol, but ksg does not implement
that protocol. Use HTTP routing with `X-Forwarded-For` and optional TLS
re-encryption instead. A `client_not_allowed` reason in logs or metrics usually
means the original address was lost.

## TLS

Both listeners can serve TLS independently. `certFile` contains the leaf
certificate followed by intermediates; `keyFile` contains its private key.
TLS 1.2 or newer is required.

Certificates are checked once a minute. A valid renewed pair is adopted
without restart; an invalid replacement is logged and the previous pair stays
active. Missing or invalid files at startup prevent the listener from
starting.

If an ingress terminates client TLS and forwards plain HTTP, Basic Auth and
Secret values cross the cluster network unencrypted. That is suitable only on
an encrypted trusted pod network. Otherwise enable `server.tls` and configure
the ingress to use HTTPS to the Service and trust the issuing CA. With
Traefik, use a `ServersTransport`, set its `serverName` to the Service DNS name,
and reference the CA through `rootCAs` (`rootCAsSecrets` on older releases).
ksg has no `caFile` because client certificates are not supported.

A cert-manager certificate for the Service can be mounted at
`/etc/kube-secret-gateway/tls`. Secret volumes are maintained by the kubelet,
and ksg reloads the mounted pair automatically.

## Health and metrics

- `/healthz` returns `200` while the process is alive.
- `/readyz` returns `200` after initial synchronization has been attempted for
  every referenced Secret and until shutdown starts. A missing Secret does not
  make the whole pod unready.
- `/metrics` exposes Prometheus and Go runtime metrics. Optional
  `metrics.auth` protects only this endpoint, not probes.

Metrics reveal configured exposure, namespace, and Secret names. Keep the
operations listener internal and protect it with NetworkPolicy,
`metrics.auth`, or both. Unknown request names use `exposure="_unknown"`, so
requests cannot create unbounded series.

| Metric                                                       | Labels                            | Meaning                          |
| ------------------------------------------------------------ | --------------------------------- | -------------------------------- |
| `kube_secret_gateway_source_secret_present`                  | `exposure`, `namespace`, `secret` | Source exists.                   |
| `kube_secret_gateway_auth_secret_present`                    | `exposure`, `namespace`, `secret` | Auth Secret exists.              |
| `kube_secret_gateway_auth_secret_valid`                      | `exposure`, `namespace`, `secret` | Auth Secret is usable.           |
| `kube_secret_gateway_expected_key_present`                   | `exposure`, `key`                 | Required key exists.             |
| `kube_secret_gateway_exposure_healthy`                       | `exposure`                        | Exposure can serve.              |
| `kube_secret_gateway_watch_connected`                        | `namespace`, `secret`             | Watch is connected.              |
| `kube_secret_gateway_last_successful_sync_timestamp_seconds` | `namespace`, `secret`             | Last full read; zero if never.   |
| `kube_secret_gateway_watch_errors_total`                     | `namespace`, `secret`             | Watch failures and bad events.   |
| `kube_secret_gateway_sync_errors_total`                      | `namespace`, `secret`             | List or reconciliation failures. |
| `kube_secret_gateway_http_requests_total`                    | `exposure`, `status`, `reason`    | HTTP outcomes.                   |

Useful starting alerts are:

```promql
kube_secret_gateway_exposure_healthy == 0
time() - kube_secret_gateway_last_successful_sync_timestamp_seconds > 600
max_over_time(kube_secret_gateway_watch_connected[10m]) == 0
sum by (exposure) (
  increase(kube_secret_gateway_http_requests_total{reason=~"served|not_modified"}[2d])
) == 0
```

The last query detects that no client has successfully polled an exposure; a
`304` counts as success. Choose a window longer than the clients' longest
polling interval. It cannot distinguish several hosts sharing one exposure.

## Kubernetes permissions

ksg needs `get`, `list`, and `watch` on every source, exposure-auth,
and metrics-auth Secret. List and watch requests always use an exact-name field
selector, allowing namespace Roles to restrict access with `resourceNames`.
ksg never lists every Secret in a namespace.

Create one Role per referenced namespace and bind it to ksg's ServiceAccount.
[`examples/kubernetes.yaml`](examples/kubernetes.yaml) shows
the complete Role and RoleBinding. A denied Secret increases
`sync_errors_total` and makes only affected exposures return `503`.

## Runtime

The supplied image is based on `distroless/static`, has no shell, runs as UID
65532, and contains no configuration. It exposes ports 8080 and 8081 and uses
the pod's mounted ServiceAccount credentials.

| Flag          | Default                                | Meaning                                                                                               |
| ------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `-config`     | `/etc/kube-secret-gateway/config.yaml` | Configuration file.                                                                                   |
| `-kubeconfig` | in-cluster                             | Kubeconfig for running outside Kubernetes; `$KUBECONFIG` and the standard user file are also checked. |
| `-log-level`  | `info`                                 | `debug`, `info`, `warn`, or `error`.                                                                  |
| `-log-format` | `json`                                 | `json` or `text`.                                                                                     |

Logs are structured. Requests include the exposure, a missing configured key
when relevant, resolved client address, status, reason, and duration, but never
credentials or values.

At startup ksg validates configuration, loads TLS certificates,
starts Secret synchronization, and validates `metrics.auth` before serving.
On `SIGTERM` or `SIGINT`, readiness is disabled, in-flight requests get up to
20 seconds to finish, watchers stop, and the process exits. A short Kubernetes
`preStop` delay can cover endpoint-removal propagation.

## Security properties

- Values, passwords, authorization headers, and query strings are never
  logged. Kubernetes error bodies are sanitized.
- Unknown exposures never reach the cache or Kubernetes API.
- Raw path validation prevents encoded path tricks; no filesystem path is
  derived from a request.
- Allow-list and authentication ordering prevents exposure probing.
- ETags do not expose plain hashes of secret values.
- HTTP servers enforce read, write, header, and idle timeouts and a 32 KiB
  header limit.

## Limitations

- Only Basic Auth is supported; client certificates are not.
- ksg does not support the PROXY protocol.
- TLS passthrough and address-rewriting L4 proxies cannot preserve meaningful
  `allowedCidrs` without a supported address-forwarding mechanism.
- There is no exposure listing endpoint.
- An exposure covers one Kubernetes Secret; different Secrets have no shared
  version and cannot form one atomic exposure.
- Configuration reload is not supported; restart after changes.
- During a Kubernetes API outage, last-known values continue to be served.
