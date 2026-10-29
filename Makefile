GO ?= go
VERSION ?= dev

.PHONY: build test check demo clean
build:
	$(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/gateway ./cmd/gateway
	$(GO) build -trimpath -o bin/mock-resource ./cmd/mock-resource
test:
	$(GO) test -race ./...
check:
	$(GO) vet ./...
	$(GO) mod verify
demo: build
	./bin/gateway init-demo
clean:
	rm -rf bin
