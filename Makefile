.PHONY: build test test-race vet check

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -X main.version=$(VERSION)' \
		-o dist/kube-secret-gateway ./gateway/cmd/kube-secret-gateway
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -X main.version=$(VERSION)' \
		-o dist/kube-secret-gateway-agent ./agent/cmd/kube-secret-gateway-agent

test:
	go test ./gateway/... ./agent/...

test-race:
	go test -race ./gateway/... ./agent/...

vet:
	go vet ./gateway/... ./agent/...

check: vet test
