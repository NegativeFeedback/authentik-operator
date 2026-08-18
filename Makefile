.PHONY: build test vet fmt run

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/authentik-operator ./cmd/authentik-operator

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

run:
	go run ./cmd/authentik-operator
