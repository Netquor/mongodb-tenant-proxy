BINARY   := mongodb-tenant-proxy
PKG      := ./cmd/mongodb-tenant-proxy
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
IMAGE    ?= ghcr.io/netquor/$(BINARY)

.PHONY: build test test-race vet lint docker docker-push helm-lint helm-template install clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

test-race:
	go test ./... -race

vet:
	go vet ./...

lint: vet
	@test -z "$$(gofmt -l .)" || (gofmt -l .; echo "gofmt needed"; exit 1)

docker:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t $(IMAGE):$(VERSION) .

docker-push: docker
	docker push $(IMAGE):$(VERSION)

helm-lint:
	helm lint deploy/helm/$(BINARY)

helm-template:
	helm template $(BINARY) deploy/helm/$(BINARY)

# Installs the binary, unit and a sample config (run as root).
install: build
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)
	install -m 0644 deploy/systemd/$(BINARY).service /etc/systemd/system/$(BINARY).service
	install -d -m 0750 /etc/$(BINARY) /var/lib/$(BINARY) /var/log/$(BINARY)

clean:
	rm -rf bin
