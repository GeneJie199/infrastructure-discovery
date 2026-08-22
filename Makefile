.PHONY: test build verify

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/GeneJie199/infrastructure-discovery/pkg/infrascout.Version=$(VERSION)

test:
	go test -timeout 60s ./...

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/infrascout ./cmd/infrascout

verify:
	go vet ./...
	go test -timeout 60s ./...
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/infrascout ./cmd/infrascout
