.PHONY: test build verify

test:
	go test -timeout 60s ./...

build:
	go build -trimpath -o bin/infrascout ./cmd/infrascout

verify:
	go vet ./...
	go test -timeout 60s ./...
	go build -trimpath -o bin/infrascout ./cmd/infrascout
