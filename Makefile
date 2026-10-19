BINARY   := mongodb-tenant-proxy
PKG      := ./cmd/mongodb-tenant-proxy
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
IMAGE    ?= ghcr.io/netquor/$(BINARY)

.PHONY: build test test-race stress stress-long vet lint security security-tools docker docker-push helm-lint helm-template install clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

test-race:
	go test ./... -race

# Concurrency stress suite (internal/*/stress_test.go, test/stress_*_test.go).
# Short mode is part of plain `go test ./...`; this repeats it under -race
# across GOMAXPROCS settings. stress-long is the soak variant (MTP_STRESS=long).
stress:
	go test ./internal/... ./test -race -run 'Stress|TestManagerClose' -count=$(or $(COUNT),3) -cpu 1,4,8

stress-long:
	MTP_STRESS=long go test ./internal/... ./test -race -run 'Stress|TestManagerClose' -count=$(or $(COUNT),1) -cpu 4 -timeout 60m

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

# ---- security scanners -------------------------------------------------------
# Tool versions match .github/workflows/security.yml. `make security-tools`
# installs the Go ones; gitleaks and trivy are optional locally (skipped with a
# notice when absent) and always run in CI.
GOBIN_DIR := $(shell go env GOPATH)/bin

security-tools:
	go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
	go install github.com/securego/gosec/v2/cmd/gosec@v2.29.0
	go install honnef.co/go/tools/cmd/staticcheck@v0.8.2
	go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
	go install github.com/zricethezav/gitleaks/v8@v8.30.1

security: export PATH := $(PATH):$(GOBIN_DIR)
security: vet
	govulncheck ./...
	CGO_ENABLED=0 go build -trimpath -o bin/$(BINARY) $(PKG) && govulncheck -mode=binary bin/$(BINARY)
	gosec -severity medium -quiet ./...
	staticcheck ./...
	actionlint
	@if command -v gitleaks >/dev/null; then gitleaks git --config .gitleaks.toml --redact . ; else echo "gitleaks not installed: skipped (runs in CI)"; fi
	@if command -v trivy >/dev/null; then trivy fs --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 . && trivy config --config trivy.yaml --severity HIGH,CRITICAL --exit-code 1 . ; else echo "trivy not installed: skipped (runs in CI)"; fi
