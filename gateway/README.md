# kube-secret-gateway

ksg is the server-side component of the Kube Secret Gateway stack. It runs in
Kubernetes and serves the Secrets you choose to expose.

Each exposure is a named, authenticated projection of explicitly selected
keys from one Kubernetes Secret. It is fetched as one atomic JSON snapshot:

```text
GET|HEAD /exposures/{name}
```

Clients cannot request individual keys or filter the response. If two clients
should receive different keys or credentials, configure two exposures. The
optional [ksg-agent](../agent/README.md) can fetch an exposure and install only
the keys configured as local targets.

ksg is deliberately not a secret manager. It does not create, modify, or
persist Kubernetes Secrets.

## How it works

At startup, ksg reads its configuration and watches every source and
authentication Secret. Requests are served from memory; an HTTP request never
causes a Kubernetes API request.

```text
Kubernetes Secret --watch--> ksg --> /exposures/{name}
```

Secret changes arrive through Kubernetes watches. Periodic reconciliation
catches missed events, and the last known state remains available during a
temporary Kubernetes API outage.

## Configuration

ksg reads `/etc/kube-secret-gateway/config.yaml` by default:

```yaml
server:
  listenAddress: ":8080"

metrics:
  listenAddress: ":8081"

kubernetes:
  defaultNamespace: kube-secret-gateway
  reconcileInterval: 5m

exposures:
  - name: my-cert
    secretRef:
      name: my-cert
    keys:
      - tls.crt
      - tls.key
    allowedCidrs:
      - 192.0.2.10/32
    auth:
      secretRef:
        name: my-cert-fetcher
```

In this example:

- `my-cert` is the public exposure name.
- `tls.crt` and `tls.key` are the only values returned.
- The client must arrive from the configured network.
- The `my-cert-fetcher` Secret supplies non-empty `username` and
  `password` values for Basic Auth.

Every exposure must list at least one key. If a configured key is absent, the
entire exposure is unavailable; ksg never returns a partial snapshot.

See [`examples/config.yaml`](examples/config.yaml) for the maintained example.
The [configuration reference](REFERENCE.md#configuration) documents every
field and validation rule.

## Fetching an exposure

```sh
curl --fail --user fetcher \
  https://gateway.example.com/exposures/my-cert
```

`curl` prompts for the password. The response is a JSON object whose keys are
Secret keys and whose values are padded standard base64:

```json
{"tls.crt":"...","tls.key":"..."}
```

Object keys are sorted and the response contains no insignificant whitespace.
`HEAD` returns the same status and headers as `GET`, without a body.

Responses include an `ETag` for the complete exposure. A polling client can
send it in `If-None-Match`; ksg returns `304 Not Modified` without a body
when none of the exposed values has changed. ksg-agent handles this
automatically.

Common responses are:

| Status | Meaning                                                               |
| ------ | --------------------------------------------------------------------- |
| `200`  | The complete exposure snapshot was returned.                          |
| `304`  | The exposure still matches `If-None-Match`.                           |
| `401`  | Basic Auth credentials were missing or incorrect.                     |
| `404`  | The route, exposure, or allowed client network did not match.         |
| `503`  | A source or authentication Secret is unavailable or incomplete.       |

The [HTTP API reference](REFERENCE.md#http-api) defines the exact wire format,
validation order, and status behavior.

## Deploying

[`examples/kubernetes.yaml`](examples/kubernetes.yaml) is a self-contained
Kubernetes example with:

- a ksg Deployment and ClusterIP Service;
- a ServiceAccount with exact-name Secret RBAC;
- readiness and liveness probes;
- an inline ConfigMap containing the ksg configuration.

Choose a published image version and replace the example client CIDR before
applying it. Production deployments should pin the image by digest.

```sh
kubectl apply -f gateway/examples/kubernetes.yaml
```

The example expects a source Secret named `my-cert` and an authentication
Secret named `my-cert-fetcher` in the `kube-secret-gateway` namespace.

Route only port 8080 through an ingress or load balancer. Port 8081 contains
health and Prometheus endpoints and should remain internal.

## TLS and client addresses

Use HTTPS whenever traffic leaves an already encrypted, trusted network. TLS
can terminate at ksg or at a trusted HTTP reverse proxy. When using a proxy,
configure `server.trustedProxies` so ksg accepts `X-Forwarded-For` only from
that proxy.

See [client addresses and proxies](REFERENCE.md#client-addresses-proxies-and-nat)
and [TLS](REFERENCE.md#tls) for complete deployment guidance.

## Operations

The separate metrics listener provides:

- `/healthz` for liveness;
- `/readyz` for readiness;
- `/metrics` for Prometheus.

Metrics report exposure health, configured-key presence, source and
authentication Secret state, watch connectivity, reconciliation freshness,
and HTTP outcomes. Neither metrics nor logs contain Secret values or
credentials.

## Development

From the repository root:

```sh
go test ./gateway/...
go test -race ./gateway/...
go vet ./gateway/...

docker build --build-arg VERSION=dev \
  -t kube-secret-gateway:dev gateway
```

The tests use a fake Kubernetes API and require no cluster. For complete
configuration, API, proxy, TLS, metrics, security, and failure semantics, see
the [ksg reference](REFERENCE.md).
