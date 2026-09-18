# syntax=docker/dockerfile:1

ARG GO_VERSION=1.27

# Build on the native platform and cross-compile, so multi-arch builds do not
# run the Go toolchain under emulation.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

# Only sources are copied: no configuration or credentials enter the image.
COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/kube-secret-gateway ./cmd/kube-secret-gateway

# distroless/static: no shell or package manager, CA certificates included,
# runs as the unprivileged "nonroot" user (65532). In a pod, the API server CA
# and token come from the mounted service account.
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/kube-secret-gateway /kube-secret-gateway
USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/kube-secret-gateway"]
