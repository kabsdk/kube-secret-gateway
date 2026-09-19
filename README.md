# kube-secret-gateway

kube-secret-gateway serves the values of explicitly configured Kubernetes
Secrets over authenticated HTTP. A typical use is handing a cert-manager
certificate to a machine outside the cluster: the machine polls
`GET /secrets/my-cert/tls.crt` and receives the raw bytes.

It is deliberately small. It is **not** a secret manager: it stores nothing,
creates nothing and serves only what its configuration names. Kubernetes RBAC
remains the final authority over which Secrets it can read.

- Every key of a configured Secret becomes an endpoint, optionally narrowed
  with `includeKeys` or `excludeKeys`.
- Each exposure has its own client network allow-list and its own Basic Auth
  credentials, which live in a Kubernetes Secret.
- Secrets are watched, so changes, deletions and re-creations take effect
  immediately, and their state is visible in Prometheus metrics before any
  client asks for them.
- There is no listing endpoint: a client has to know the exposure name. One
  request can fetch every key of an exposure as a consistent set.

## Contents

- [kube-secret-gateway](#kube-secret-gateway)
  - [Contents](#contents)
  - [How it works](#how-it-works)
  - [HTTP interface](#http-interface)
    - [Fetching a value](#fetching-a-value)
    - [Fetching a bundle](#fetching-a-bundle)
    - [Polling for changes](#polling-for-changes)
    - [Status codes](#status-codes)
  - [Configuration](#configuration)
    - [Exposures](#exposures)
    - [Namespaces](#namespaces)
    - [Validation details](#validation-details)
  - [Authentication Secrets](#authentication-secrets)
  - [Client addresses, proxies and NAT](#client-addresses-proxies-and-nat)
    - [How the address is determined](#how-the-address-is-determined)
    - [Behind Traefik](#behind-traefik)
    - [TLS passthrough and NAT don't work with `allowedCidrs`](#tls-passthrough-and-nat-dont-work-with-allowedcidrs)
  - [TLS](#tls)
    - [Enabling TLS on the gateway](#enabling-tls-on-the-gateway)
    - [Making Traefik re-encrypt](#making-traefik-re-encrypt)
  - [Metrics and health](#metrics-and-health)
    - [Metrics](#metrics)
  - [Kubernetes permissions](#kubernetes-permissions)
  - [Running](#running)
    - [Container image](#container-image)
    - [Flags](#flags)
    - [Startup and shutdown](#startup-and-shutdown)
  - [Security properties](#security-properties)
  - [Limitations](#limitations)
  - [Development](#development)

## How it works

```text
config.yaml ──> exposures ──> unique Secret references (source + auth)
                                        │
                     one watcher per Secret: list, then watch by exact name,
                     periodic GET to correct drift, relist after any failure
                                        │
                                in-memory state
                              ┌─────────┴─────────┐
                    HTTP :8080 (Secrets)    HTTP :8081 (probes, metrics)
```

- Each distinct Secret is watched exactly once, however many exposures refer
  to it, whether as source or as authentication Secret.
- Requests are answered from memory. A request never causes a Kubernetes API
  call, and an unknown exposure name never reaches the cache at all.
- A Secret that does not exist is a normal state, not an error: the gateway
  keeps watching, and serves it as soon as cert-manager (or anyone) creates it.
- Watches reconnect automatically with jittered exponential backoff. After
  losing a watch, the gateway lists the Secret again before watching, so a
  change made while disconnected is never missed. Every `reconcileInterval`
  it additionally fetches each Secret directly and repairs the cache if a
  watch ever missed an event.
- If the API server becomes unreachable, the last known state keeps being
  served; the metrics show that it is no longer being confirmed.
- Secret values are held only in memory. They are never written to disk and
  never logged.

## HTTP interface

The gateway listens on two ports.

| Listener | Default | Paths                                                        |
| -------- | ------- | ------------------------------------------------------------ |
| Secrets  | `:8080` | `GET /secrets/{exposure}/{key}`, `GET /bundles/{exposure}`   |
| Metrics  | `:8081` | `GET /healthz`, `GET /readyz`, `GET /metrics`                 |

Route only the Secrets listener through your ingress. The metrics listener is
for the kubelet and Prometheus.

### Fetching a value

```sh
curl -fsS --user "fetcher:$PASSWORD" \
  https://gateway.example.com/secrets/my-cert/tls.crt -o tls.crt
```

A successful response carries the value's bytes unchanged. There is no
content detection and no special handling of PEM, keys or binary data.

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Cache-Control: no-store
X-Content-Type-Options: nosniff
ETag: "hmac-sha256:…"
```

`HEAD` works like `GET` without the body, and query strings are ignored.

### Fetching a bundle

`GET /bundles/{exposure}` returns every key the exposure serves, from one read
of one incarnation of the Secret, under a single `ETag`.

```sh
curl -fsS --user "fetcher:$PASSWORD" \
  https://gateway.example.com/bundles/my-cert
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
X-Content-Type-Options: nosniff
ETag: "hmac-sha256:…"

{"ca.crt":"Q0E=","tls.crt":"LS0tLS1CRUdJTi…","tls.key":"LS0tLS1CRUdJTi…"}
```

Values are base64 so that arbitrary bytes survive JSON. Keys are sorted, so
the body is byte-for-byte identical for a given Secret version and exposure.

Use this route whenever several keys belong together, such as a certificate
and its private key. One request cannot straddle an update, so the set is
always internally consistent, and the single `ETag` changes when *any* key in
it changes. Fetching the keys one at a time gives neither guarantee: a
renewal can land between two requests, leaving a new certificate next to an
old key.

`includeKeys` and `excludeKeys` decide what a bundle contains, exactly as
they decide which single keys exist. A bundle is never partial: if
`includeKeys` names a key the Secret does not have, the whole request is
`503`, and nothing is served.

`HEAD` works like `GET` without the body, and query strings are ignored. There
is still no way to list exposures, and a bundle reveals nothing that probing
single keys with valid credentials would not.

### Polling for changes

Clients that poll should use the `ETag`:

1. Store the `ETag` of what you installed.
2. On the next poll, send it back as `If-None-Match`.
3. `304 Not Modified` (no body) means nothing changed: don't rewrite any file
   and don't reload anything. `200` means it changed.

The tag changes exactly when the bytes it describes change; recreating a
Secret also changes it once.

Poll `/bundles/{exposure}` rather than individual keys. One conditional
request then answers, for the whole set at once, whether anything a client
installs has changed, and a `200` carries a consistent set.

[kube-secret-gateway-client](../kube-secret-gateway-client) is a small
static binary that does this, with several bundles on independent intervals,
atomic installs and a command to run after a change.

Without it, this is the whole job in standard-library Python. Run it from a
systemd timer or cron:

```python
#!/usr/bin/env python3
"""Mirror one kube-secret-gateway exposure into local files.

Downloads nothing when the bundle is unchanged, replaces files atomically,
never installs a set of values that straddles an update of the Secret, and
runs a command when something changed.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

BUNDLE_URL = "https://gateway.example.com/bundles/my-cert"
FILES = {  # Secret key -> local file
    "tls.crt": "/etc/ssl/my-cert/tls.crt",
    "tls.key": "/etc/ssl/my-cert/tls.key",
}
CREDENTIALS = "/etc/secret-fetcher/credentials"  # "username:password", mode 0600
STATE = "/var/lib/secret-fetcher/my-cert.etag"
ON_CHANGE = ["systemctl", "reload", "nginx"]  # or None


def install(path, data):
    """Replace path atomically. The new file is readable by its owner only."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def main():
    with open(CREDENTIALS, "rb") as f:
        auth = "Basic " + base64.b64encode(f.read().rstrip(b"\n")).decode()
    headers = {"Authorization": auth}

    # Only send the stored ETag if every file it describes is still in place.
    if all(os.path.exists(path) for path in FILES.values()):
        try:
            with open(STATE) as f:
                headers["If-None-Match"] = f.read().strip()
        except FileNotFoundError:
            pass

    request = urllib.request.Request(BUNDLE_URL, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            bundle, etag = json.load(response), response.headers["ETag"]
    except urllib.error.HTTPError as err:
        if err.code == 304:
            return
        raise

    missing = sorted(key for key in FILES if key not in bundle)
    if missing:
        sys.exit(f"the exposure does not serve {', '.join(missing)}")

    # One response is one version of the Secret, so these values belong
    # together. The ETag is stored last: a crash before that leaves a stale
    # tag, and the next run simply fetches and installs again.
    for key, path in FILES.items():
        install(path, base64.b64decode(bundle[key]))
    install(STATE, etag.encode())

    if ON_CHANGE:
        subprocess.run(ON_CHANGE, check=True)


if __name__ == "__main__":
    main()
```

Store the credentials as `username:password` in the credentials file, not on
a command line, where other users could see them in the process list.

The path must be exactly `/secrets/{exposure}/{key}` or
`/bundles/{exposure}`. Extra segments, `.`/`..`, percent-encoding of any kind
and trailing slashes are rejected with `404`. The router works on the raw path
and never redirects.

### Status codes

Checks run in this order, the same for both routes. The order is deliberate:
it decides what a caller can learn about the configuration.

| Step | Condition                                                            | Status | `reason`                    |
| ---- | -------------------------------------------------------------------- | ------ | --------------------------- |
| 1    | Method other than `GET`/`HEAD`                                       | 405    | `method_not_allowed`        |
| 2    | Malformed path                                                       | 404    | `no_route`                  |
| 3    | Exposure not configured                                              | 404    | `unknown_exposure`          |
| 4    | Client address outside the exposure's `allowedCidrs`                 | 404    | `client_not_allowed`        |
| 4    | Client address cannot be determined (broken `X-Forwarded-For` chain) | 404    | `client_address_unresolved` |
| 5    | Authentication Secret missing                                        | 503    | `auth_secret_unavailable`   |
| 5    | Authentication Secret lacks `username` or `password`                 | 503    | `auth_secret_malformed`     |
| 6    | Credentials missing or wrong                                         | 401    | `unauthorized`              |
| 7    | Source Secret missing                                                | 503    | `source_secret_unavailable` |
| 8    | Key listed in `includeKeys` but missing from the Secret              | 503    | `expected_key_missing`      |
| 8    | Any other key the exposure does not serve                            | 404    | `key_not_found`             |
| 9    | Body unchanged since the client's `If-None-Match`                    | 304    | `not_modified`              |
| 9    | Value or bundle served                                               | 200    | `served`                    |

Steps 1 to 7 are identical on both routes, so a bundle request reveals
nothing about the configuration that a single-key request does not. They
differ only at step 8: a bundle names no key, so it never answers
`key_not_found`, and a bundle whose exposure serves no keys at all is `200`
with an empty object. `expected_key_missing` applies unchanged — a bundle is
either whole or `503`.

`includeKeys` and `excludeKeys` define which keys an exposure has. A key
filtered out by them is simply a key the exposure does not have: it answers
exactly like a key that never existed in the Secret, in every state, and it is
absent from the bundle.

What this means for callers:

- **From outside an exposure's allow-list**, an existing exposure answers
  exactly like a name that does not exist: same status, headers and body.
  Exposure names cannot be probed from the outside.
- **On the allow-list but without valid credentials**, every key and every
  bundle answers `401`, whether the key is served, excluded or missing. Which
  keys exist is only visible after authenticating.
- **503 means the gateway is configured correctly but a Secret is not in the
  expected state.** A 404 never hides an operational problem, and a 503 never
  reveals anything to an unauthenticated caller outside the allow-list.

Response bodies are only the generic status text. The `reason` appears in
the request log and as a label on `kube_secret_gateway_http_requests_total`. If a
legitimate client gets unexpected 404s, look there first: `client_not_allowed`
usually means its address does not arrive intact (see
[Client addresses, proxies and NAT](#client-addresses-proxies-and-nat)).

## Configuration

The configuration is read from `/etc/kube-secret-gateway/config.yaml`, or from the
path given with `-config`. It is validated completely before anything
starts, and every problem is reported at once. Unknown fields are errors, so
a typo such as `excludekeys` cannot silently expose a key. Changes require a
restart.

```yaml
server:
  listenAddress: ":8080"            # default
  trustedProxies:                   # peers whose X-Forwarded-For is trusted
    - 10.42.0.0/16
  tls:                              # optional; see "TLS"
    certFile: /etc/kube-secret-gateway/tls/tls.crt
    keyFile: /etc/kube-secret-gateway/tls/tls.key

metrics:
  listenAddress: ":8081"            # default; must not share the Secrets port
  auth:                             # optional; protects /metrics only
    type: basicAuth
    secretRef:
      namespace: monitoring
      name: gateway-scrape-credentials
  tls:                              # optional, same fields as server.tls
    certFile: ...
    keyFile: ...

kubernetes:
  defaultNamespace: certificates    # used when a secretRef omits namespace
  reconcileInterval: 5m             # default; between 10s and 24h

secrets:
  # Served as /secrets/my-cert/{key}: every key except tls.key.
  - secretRef:
      name: my-cert                 # namespace: kubernetes.defaultNamespace
    allowedCidrs:
      - 10.10.30.40/32
      - 10.10.30.41/32
    auth:
      type: basicAuth
      secretRef:
        namespace: certificate-auth
        name: my-cert-fetcher-credentials
    excludeKeys:
      - tls.key

  # Served as /secrets/matrix-prod/tls.crt and .../tls.key only.
  - name: matrix-prod
    secretRef:
      namespace: matrix-prod
      name: matrix-cert
    allowedCidrs:
      - 10.10.40.20/32
    auth:
      type: basicAuth
      secretRef:
        namespace: certificate-auth
        name: matrix-fetcher-credentials
    includeKeys:
      - tls.crt
      - tls.key
```

### Exposures

| Field                 | Required | Meaning                                                                                                                                   |
| --------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `name`                | no       | URL name of the exposure. Defaults to `secretRef.name`. Must be unique and a valid Kubernetes name (lowercase letters, digits, `-`, `.`). |
| `secretRef.name`      | yes      | The Secret to serve; see [What the Secrets contain](#what-the-secrets-contain).                                                           |
| `secretRef.namespace` | no       | Defaults to `kubernetes.defaultNamespace`.                                                                                                |
| `allowedCidrs`        | yes      | Client networks allowed to use the exposure. An empty list is an error, never "allow all".                                                |
| `auth.type`           | yes      | Only `basicAuth`.                                                                                                                         |
| `auth.secretRef`      | yes      | The Secret holding the credentials; same namespace rules as `secretRef`.                                                                  |
| `includeKeys`         | no       | Serve only these keys, and treat each as required (missing means 503).                                                                    |
| `excludeKeys`         | no       | Serve every key except these; they behave exactly like keys that do not exist.                                                            |

`includeKeys` and `excludeKeys` are mutually exclusive. With neither, every
key of the Secret is served, including keys added later. Listed keys don't
need to exist at startup: a Secret that cert-manager hasn't issued yet is
fine.

### What the Secrets contain

**The source Secret (`secretRef`) needs no particular keys.** It can be any
Secret, of any type: a cert-manager `kubernetes.io/tls` Secret, an `Opaque`
Secret you created yourself, and so on. Every key in its `data` is served as
`/secrets/{exposure}/{key}`, within the limits of `includeKeys` or
`excludeKeys`, and each value is returned exactly as stored. Values written
through `stringData` end up in `data` too.

A cert-manager certificate Secret, for example, contains:

| Key       | Content                                                   |
| --------- | --------------------------------------------------------- |
| `tls.crt` | The certificate, followed by any intermediate certificates |
| `tls.key` | The private key                                           |
| `ca.crt`  | The issuing CA's certificate (depends on the issuer)      |

**Authentication Secrets (`auth.secretRef`, `metrics.auth.secretRef`)
must contain `username` and `password`.** Other keys are ignored. See
[Authentication Secrets](#authentication-secrets).

One Secret can be both an exposure's source and its authentication Secret.
In that case its `username` and `password` are served like any other key,
unless you narrow the exposure with `includeKeys` or `excludeKeys`.

### Namespaces

The gateway never assumes that Secrets live in its own namespace, and never
uses its own namespace implicitly. A `secretRef` without a namespace uses
`kubernetes.defaultNamespace`. If that is not set either, the configuration
is rejected. The same applies to authentication Secrets. Namespaces never
appear in URLs.

### Validation details

- CIDRs must be written with their network address. `10.10.30.40/24` is
  rejected, because it is almost certainly a typo that would grant a whole
  /24. Write `10.10.30.0/24` or `10.10.30.40/32`. Bare addresses are also
  rejected: use `/32` or `/128`.
- Duplicate CIDRs, duplicate keys and duplicate exposure names (after
  defaulting) are errors.
- `reconcileInterval` needs a unit (`90s`, `5m`, `1h`).

## Authentication Secrets

A `basicAuth` Secret needs non-empty `username` and `password` keys:

```sh
kubectl -n certificate-auth create secret generic my-cert-fetcher-credentials \
  --from-literal=username=fetcher \
  --from-literal=password="$(openssl rand -base64 32)"
```

Values are compared byte for byte. `--from-file` includes a trailing newline
if the file ends with one, and the client then has to send it too.

- Credentials are read from the watched Secret on every request, so updating
  the Secret rotates them immediately, without a restart. Old credentials stop
  working as soon as the change is observed.
- If an exposure's authentication Secret is missing or malformed, that
  exposure answers `503` until it is fixed. Other exposures are unaffected.
- Comparison is constant-time, on SHA-256 digests, and a `401` never reveals
  whether the username or the password was wrong.

The Secret for `metrics.auth` is different. It is part of the gateway's own
setup, not something that may appear later, so **it must exist and be valid
when the gateway starts**. Otherwise the process exits, and a rollout with a
wrong reference stalls while the previous pods keep serving. After startup it
is watched for rotation like any other Secret. If it is later deleted or
broken, `/metrics` answers `503` (Prometheus sees the target as down), but
Secret serving is not interrupted.

## Client addresses, proxies and NAT

`allowedCidrs` is only as good as the client address the gateway sees. That
address has to survive every hop between the client and the pod.

### How the address is determined

- **Peer not in `trustedProxies`:** the TCP peer address is the client, and
  `X-Forwarded-For` is ignored entirely, so a direct client cannot claim
  another address.
- **Peer in `trustedProxies`:** `X-Forwarded-For` is read from right to left,
  and the first address that is not itself a trusted proxy is the client.
  Entries further left were supplied by that client and are ignored, so
  spoofing through a trusted proxy doesn't work either.
- **Broken chain:** if an entry that a trusted proxy is responsible for is not
  a valid IP address, the request is refused.
- **IPv4 and IPv6** are both supported; IPv4-mapped IPv6 addresses match IPv4
  networks.

### Behind Traefik

- **Route HTTP, not TCP.** Traefik must terminate TLS (optionally
  re-encrypting to the gateway, see [TLS](#tls)) so that it can add
  `X-Forwarded-For`.
- **Trust Traefik's pod network.** Put the address range of the Traefik pods,
  usually the cluster's pod CIDR, into `server.trustedProxies`.
- **Restrict who can reach port 8080.** If `trustedProxies` covers the whole
  pod CIDR, *any* pod could connect directly and send a forged
  `X-Forwarded-For`. Use a NetworkPolicy that admits traffic to the Secrets
  port only from the Traefik pods.
- **Keep the client address on the way into Traefik.** By default,
  kube-proxy replaces the client address with a node address before traffic
  reaches Traefik's pods. Set `externalTrafficPolicy: Local` on Traefik's
  LoadBalancer or NodePort Service. If an external load balancer sits in
  front of Traefik, have it send the PROXY protocol or `X-Forwarded-For`, and
  configure Traefik's entrypoint to trust it (`proxyProtocol.trustedIPs` or
  `forwardedHeaders.trustedIPs`).

### TLS passthrough and NAT don't work with `allowedCidrs`

With TLS passthrough (`IngressRouteTCP` with `passthrough: true`), Traefik
forwards encrypted bytes it cannot read, so it cannot add `X-Forwarded-For`.
The gateway then sees every request coming from a Traefik pod, and
`allowedCidrs` can only allow all of them or none. The same happens with any
hop that rewrites source addresses (SNAT, masquerading, most L4 load
balancers) without passing the original address on: once it is gone, nothing
downstream can recover it.

The PROXY protocol would carry the address through a TCP proxy, but the
gateway does not support it. Use HTTP routing with re-encryption instead,
which gives TLS on every hop and keeps `X-Forwarded-For`.

## TLS

Traefik usually terminates the client's TLS connection and forwards the
request to the gateway over plain HTTP. On that hop, the Basic Auth header
and the Secret values themselves travel unencrypted across the cluster
network, possibly between nodes. That is acceptable only if the pod network
encrypts traffic (for example WireGuard in Cilium or Calico, or a service
mesh). Otherwise, enable `server.tls` and let Traefik re-encrypt. The gateway
logs a warning at startup when it serves Secrets over plain HTTP.

### Enabling TLS on the gateway

- `certFile` holds the certificate followed by any intermediates, exactly
  like a cert-manager `tls.crt`. `keyFile` holds the private key.
- Only TLS 1.2 and newer are accepted.
- The files are checked once a minute and a renewed pair is picked up
  without a restart. If a new pair does not load (for example, a key that
  doesn't match), the previous certificate stays in use and a warning is
  logged.
- Missing or invalid files at startup stop the gateway before it listens.

A cert-manager `Certificate` for the Service name, mounted into the pod:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: kube-secret-gateway-tls
  namespace: kube-secret-gateway
spec:
  secretName: kube-secret-gateway-tls
  dnsNames:
    - kube-secret-gateway.kube-secret-gateway.svc
  issuerRef:
    kind: Issuer
    name: internal-ca          # a CA issuer; its ca.crt ends up in the Secret
```

Mount the Secret at `/etc/kube-secret-gateway/tls/` and point `server.tls` at
`tls.crt` and `tls.key`. Reading its own certificate from a mounted volume
does not conflict with "Secret values are never written to disk": the
kubelet keeps Secret volumes in memory, and this is the gateway's own
certificate, not a served value.

### Making Traefik re-encrypt

Traefik has to use HTTPS to the backend and trust the CA that issued the
gateway's certificate. The CA goes into Traefik's configuration, not the
gateway's. The gateway has no `caFile` option, because on a server a CA file
would only verify client certificates, which are not supported.

```yaml
apiVersion: traefik.io/v1alpha1
kind: ServersTransport
metadata:
  name: kube-secret-gateway
  namespace: kube-secret-gateway
spec:
  serverName: kube-secret-gateway.kube-secret-gateway.svc
  rootCAs:
    - secret: kube-secret-gateway-tls   # uses its ca.crt key
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: kube-secret-gateway
  namespace: kube-secret-gateway
spec:
  entryPoints: [websecure]
  routes:
    - match: Host(`gateway.example.com`) && PathPrefix(`/secrets/`)
      kind: Rule
      services:
        - name: kube-secret-gateway
          port: 8080
          scheme: https
          serversTransport: kube-secret-gateway
  tls:
    secretName: gateway-example-com-tls
```

Older Traefik versions use the now-deprecated `rootCAsSecrets:
[kube-secret-gateway-tls]` instead of `rootCAs`.

## Metrics and health

The metrics listener (default `:8081`) serves:

- **`/healthz`**: `200` while the process is alive.
- **`/readyz`**: `200` once the initial synchronization has been *attempted*
  for every Secret, and until shutdown begins. A missing Secret does not make
  the pod unready; that is per-exposure state, shown in the metrics and as
  `503` on that exposure.
- **`/metrics`**: Prometheus metrics. Optionally protected by `metrics.auth`;
  the probes never require credentials.

The metrics name every exposure, namespace and Secret. They contain no
values, but anyone who can read them learns exactly the names that the
Secrets listener hides from probing. Keep the metrics port unreachable from
outside the cluster, and restrict it with a NetworkPolicy, `metrics.auth`,
or both.

### Metrics

| Metric                                                  | Labels                          | Meaning                                                             |
| ------------------------------------------------------- | ------------------------------- | ------------------------------------------------------------------- |
| `kube_secret_gateway_source_secret_present`                  | `export`, `namespace`, `secret` | Source Secret exists (1) or not (0)                                 |
| `kube_secret_gateway_auth_secret_present`                    | `export`, `namespace`, `secret` | Authentication Secret exists                                        |
| `kube_secret_gateway_auth_secret_valid`                      | `export`, `namespace`, `secret` | Authentication Secret exists and holds usable credentials           |
| `kube_secret_gateway_expected_key_present`                   | `export`, `key`                 | A key from `includeKeys` is present                                 |
| `kube_secret_gateway_export_healthy`                         | `export`                        | All of the above hold, so the exposure can serve                    |
| `kube_secret_gateway_watch_connected`                        | `namespace`, `secret`           | A watch is currently established                                    |
| `kube_secret_gateway_last_successful_sync_timestamp_seconds` | `namespace`, `secret`           | Last successful full read (list or reconciliation); 0 if never      |
| `kube_secret_gateway_watch_errors_total`                     | `namespace`, `secret`           | Failed watches, error events, unexpected events                     |
| `kube_secret_gateway_sync_errors_total`                      | `namespace`, `secret`           | Failed list or reconciliation requests                              |
| `kube_secret_gateway_http_requests_total`                    | `export`, `status`, `reason`    | Requests to the Secrets listener; see [Status codes](#status-codes) |

Standard Go runtime and process metrics are included too.

All label values come from the configuration or from fixed sets. Requests
for names that are not configured are counted under `export="_unknown"`, so
no request can create a new series.

Starting points for alerts:

```promql
# An exposure cannot serve (Secret missing, credentials broken, included key missing)
kube_secret_gateway_export_healthy == 0

# State has not been confirmed for twice the default reconcile interval
time() - kube_secret_gateway_last_successful_sync_timestamp_seconds > 600

# No watch for a while (the API is unreachable, or RBAC is missing watch)
max_over_time(kube_secret_gateway_watch_connected[10m]) == 0
```

## Kubernetes permissions

The gateway needs `get`, `list` and `watch` on exactly the Secrets it
references, including the authentication Secrets and the `metrics.auth`
Secret. Every list and watch request carries the field selector
`metadata.name=<name>` within an explicit namespace, which is what allows
RBAC rules limited by `resourceNames`. The gateway never lists or watches
Secrets without that restriction.

One Role per namespace, bound to the gateway's ServiceAccount:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kube-secret-gateway
  namespace: certificates
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["my-cert"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kube-secret-gateway
  namespace: certificates
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: kube-secret-gateway
subjects:
  - kind: ServiceAccount
    name: kube-secret-gateway
    namespace: kube-secret-gateway
```

A Secret the gateway may not read shows up as `sync_errors_total` increasing
and `503` on the affected exposures. The rest of the gateway keeps working.

## Running

### Container image

```sh
docker build --build-arg VERSION=1.0.0 -t kube-secret-gateway:1.0.0 .
```

The image is based on `distroless/static` (no shell) and runs as UID 65532.
It exposes ports 8080 and 8081 and contains no configuration. It uses the
pod's ServiceAccount token to talk to the API server.

To run the tests, build the image and push it to `registry.aslot.dk` in one
step:

```sh
scripts/push-image.sh           # tag from `git describe`, e.g. v0.1.0 or e4f0e1b
scripts/push-image.sh 0.1.0     # explicit tag
```

The script runs `go vet` and the tests, builds for `linux/amd64` with
`--pull`, then asks for the registry username and password. The credentials
are used through a temporary Docker configuration that is deleted afterwards,
so they are never stored. It prints the image digest at the end; pin
deployments to it. Uncommitted changes are marked by a `-dirty` suffix on the
tag. Set `IMAGE`, `PLATFORM`, `REGISTRY_USERNAME` or `SKIP_TESTS=1` to
override the defaults.

### Flags

| Flag          | Default                           | Meaning                                                                                                                           |
| ------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `-config`     | `/etc/kube-secret-gateway/config.yaml` | Configuration file                                                                                                                |
| `-kubeconfig` | (in-cluster)                      | Kubeconfig for running outside a cluster; `$KUBECONFIG` and `~/.kube/config` also work. The kubeconfig's namespace is never used. |
| `-log-level`  | `info`                            | `debug`, `info`, `warn` or `error`                                                                                                |
| `-log-format` | `json`                            | `json` or `text`                                                                                                                  |

Logs are structured (`log/slog`). Each request is logged with export, key,
client address, status, reason and duration.

### Startup and shutdown

At startup the gateway validates the configuration, loads TLS certificates,
starts the watchers and checks the `metrics.auth` Secret, and only then
serves. On `SIGTERM` or `SIGINT` it reports not-ready, lets in-flight
requests finish (up to 20 seconds), stops the watchers and exits. Kubernetes
removes a terminating pod from load balancing asynchronously, so a short
`preStop` sleep (a few seconds) avoids requests arriving after shutdown has
begun.

## Security properties

- Secret values, passwords, `Authorization` headers and query strings are
  never logged. Kubernetes errors are sanitized before logging, in case one
  embeds an API response body.
- Only configured exposure names are looked up; other names never reach the
  cache or the API.
- Paths are validated on their raw form; no encoding trick can escape the
  `/secrets/{exposure}/{key}` shape. No filesystem is involved.
- Unauthenticated callers cannot probe exposure names (from outside the
  allow-list) or key names (anywhere). See [Status codes](#status-codes).
  The metrics do list exposure names, so protect the metrics port (see
  [Metrics and health](#metrics-and-health)).
- The ETag is an HMAC-SHA256 of the bytes served — one value, or the canonical
  bundle body — keyed with the Secret's UID. A plain hash would let anyone who
  sees response headers but not bodies (a `curl -v` in a CI log, for example)
  test guesses for short values such as passwords. The UID is identical on every replica, so polling still works,
  and unknown to anyone who cannot read the Secret.
- HTTP servers use read, write, header and idle timeouts and a 32 KiB header
  limit.

## Limitations

- **Not supported:** the PROXY protocol, TLS passthrough (with
  `allowedCidrs`), client certificates, and authentication methods other than
  Basic Auth.
- **No Secret listing:** a client has to know the exposure name. Within an
  exposure, `/bundles/{exposure}` returns every key it serves.
- **Bundles cover one Secret:** keys from two different Secrets have no shared
  version, so nothing can serve them as one consistent set.
- **Static configuration:** changes require a restart.
- **During an API outage** the last known state is served; see the sync
  metrics.

## Development

```sh
go test ./...
go test -race ./...
go vet ./...
```

The tests need no cluster. The resource manager is tested against an
in-memory fake of the exact-name Secret API. The end-to-end test runs the
real binary wiring against a fake Kubernetes API server, through client-go,
with and without TLS.

```text
cmd/kube-secret-gateway/   entry point, wiring, shutdown
internal/config/           YAML loading and validation
internal/exposure/         source-independent exposure model
internal/resources/        watchers, reconciliation, in-memory state
internal/kubernetes/       exact-name client-go access (+ kubetest fake)
internal/auth/             Basic Auth against Secret data
internal/clientip/         client address and X-Forwarded-For handling
internal/server/           HTTP listeners, routing, TLS reloading
internal/metrics/          Prometheus metrics
```
