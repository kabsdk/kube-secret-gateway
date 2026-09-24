# kube-secret-gateway

`kube-secret-gateway` runs in Kubernetes and exposes explicitly selected
Kubernetes Secret data through an authenticated HTTP API. It lets software
outside the cluster obtain a secret without receiving Kubernetes credentials
or direct access to the Kubernetes API.

The gateway supports two ways to read an exposure:

- Fetch one value with `GET /secrets/{exposure}/{key}`.
- Fetch all exposed values from one Secret version with
  `GET /bundles/{exposure}`.

Any HTTP client can use either endpoint. The optional
[kube-secret-gateway-agent](../agent/README.md) uses bundles to keep files on a
host synchronized and to reload services after an update.

The gateway is deliberately not a secret manager. It does not create, modify,
or persist Kubernetes Secrets. It serves only the exposures named in its
configuration, subject to Kubernetes RBAC, a client-network allow-list, and
per-exposure Basic Auth credentials.

## How it works

At startup, the gateway reads its configuration and begins watching the source
and authentication Secrets used by each exposure. Requests are served from
memory; an HTTP request never triggers a Kubernetes API request.

```text
Kubernetes Secrets
        |
        | watch
        v
kube-secret-gateway ----> one value: /secrets/{exposure}/{key}
        |
        +----------------> full set: /bundles/{exposure}
```

Secret changes are observed immediately through Kubernetes watches. A periodic
reconciliation catches missed events, and the last known state remains
available during a temporary Kubernetes API outage.

## Configuration

The gateway reads `/etc/kube-secret-gateway/config.yaml` by default. An
exposure maps a public name to one Kubernetes Secret and defines who may read
it:

```yaml
server:
  listenAddress: ":8080"

metrics:
  listenAddress: ":8081"

kubernetes:
  defaultNamespace: kube-secret-gateway
  reconcileInterval: 5m

secrets:
  - name: my-cert
    secretRef:
      name: my-cert
    allowedCidrs:
      - 192.0.2.10/32
    auth:
      type: basicAuth
      secretRef:
        name: my-cert-fetcher
    includeKeys:
      - tls.crt
      - tls.key
```

In this example:

- `my-cert` is both the exposure name and the source Kubernetes Secret.
- Only `tls.crt` and `tls.key` are exposed.
- The client must arrive from the configured network.
- The `my-cert-fetcher` Secret supplies the Basic Auth `username` and
  `password` values.

See [`examples/config.yaml`](examples/config.yaml) for the maintained example.
The [configuration reference](REFERENCE.md#configuration) documents every
field, namespace resolution, validation rule, and authentication Secret
format.

## HTTP API

### Fetching one value

Use the single-value endpoint when the caller needs only one key:

```sh
curl --fail --user fetcher \
  --output tls.crt \
  https://gateway.example.com/secrets/my-cert/tls.crt
```

`curl` prompts for the password. The response body contains the exact bytes
stored under `tls.crt`.

### Fetching a bundle

Use the bundle endpoint when values must come from the same version of a
Secret, such as a TLS certificate and private key:

```sh
curl --fail --user fetcher \
  https://gateway.example.com/bundles/my-cert
```

The response is a JSON object whose keys are Secret keys and whose values are
base64-encoded bytes:

```json
{"tls.crt":"...","tls.key":"..."}
```

Both endpoints return an `ETag`. A polling client can send it in
`If-None-Match`; the gateway returns `304 Not Modified` without a body when the
value has not changed. The agent handles this automatically.

Common responses are:

| Status | Meaning                                                                  |
| ------ | ------------------------------------------------------------------------ |
| `200`  | The requested value or bundle was returned.                              |
| `304`  | The value still matches `If-None-Match`.                                 |
| `401`  | Basic Auth credentials were missing or incorrect.                        |
| `404`  | The route, exposure, key, or allowed client network did not match.       |
| `503`  | A required source or authentication Secret is unavailable or incomplete. |

The [HTTP API reference](REFERENCE.md#http-api) defines the wire format,
validation order, status behavior, and safe client rules.

## Deploying

[`examples/kubernetes.yaml`](examples/kubernetes.yaml) is a self-contained
Kubernetes example with:

- a gateway Deployment and ClusterIP Service;
- a ServiceAccount with exact-name Secret RBAC;
- readiness and liveness probes;
- an inline ConfigMap containing the gateway configuration.

Before applying it, choose a published image version and replace the example
client CIDR in the manifest. Production deployments should pin the image by
digest.

```sh
kubectl apply -f gateway/examples/kubernetes.yaml
```

The example expects a source Secret named `my-cert` and an authentication
Secret named `my-cert-fetcher` in the `kube-secret-gateway` namespace. The
authentication Secret must contain non-empty `username` and `password` keys.

Route only port 8080 through an ingress or load balancer. Port 8081 contains
health and Prometheus endpoints and should remain internal.

## TLS and client addresses

HTTP remains a good fit for this API: it provides authentication headers,
conditional requests through ETags, familiar proxy support, and simple client
implementations. Use HTTPS whenever traffic leaves an already encrypted,
trusted network.

TLS can terminate at the gateway or at a trusted HTTP reverse proxy. When a
proxy is used, configure `server.trustedProxies` so the gateway accepts
`X-Forwarded-For` only from that proxy. The PROXY protocol is not supported;
it is not part of the secret-delivery protocol and is unnecessary when an HTTP
proxy preserves the client address correctly.

See [client addresses and proxies](REFERENCE.md#client-addresses-proxies-and-nat)
and [TLS](REFERENCE.md#tls) for the complete deployment guidance.

## Operations

The separate metrics listener provides:

- `/healthz` for liveness;
- `/readyz` for readiness;
- `/metrics` for Prometheus.

Metrics report exposure health, source and authentication Secret state,
watch connectivity, reconciliation freshness, and HTTP outcomes. See the
[operations reference](REFERENCE.md#health-and-metrics) for metric names and
suggested alerts.

## Development

From the repository root:

```sh
go test ./gateway/...
go test -race ./gateway/...
go vet ./gateway/...

docker build --build-arg VERSION=dev \
  -t kube-secret-gateway:dev gateway
```

The tests use a fake Kubernetes API and require no cluster. The end-to-end
suite builds the real agent and runs it against the gateway to keep both Go
modules aligned on the HTTP contract.

For complete configuration, API, proxy, TLS, metrics, security, and failure
semantics, see the [gateway reference](REFERENCE.md).
