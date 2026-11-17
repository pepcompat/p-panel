# pPanel Agent build
VERSION   ?= $(shell cat VERSION 2>/dev/null || echo 0.1.0)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILDDATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG       := github.com/ppanel/ppanel/apps/agent/internal/version
LDFLAGS   := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).BuildDate=$(BUILDDATE)
GOFLAGS   := -trimpath
BIN       := bin
TARGETS   := linux/amd64 linux/arm64 darwin/arm64 darwin/amd64

.PHONY: all build native cross checksums test vet clean

all: build

## build: native binary (bin/ppanel-agent) + cross builds + bin/SHA256SUMS
build: native cross checksums

native:
	@mkdir -p $(BIN)
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN)/ppanel-agent ./cmd/ppanel-agent

cross:
	@mkdir -p $(BIN)
	@set -e; for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "build $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o $(BIN)/ppanel-agent-$$os-$$arch ./cmd/ppanel-agent; \
	done

checksums:
	@cd $(BIN) && { if command -v sha256sum >/dev/null; then sha256sum ppanel-agent-*; else shasum -a 256 ppanel-agent-*; fi; } > SHA256SUMS
	@cat $(BIN)/SHA256SUMS

vet:
	go vet ./...
	GOOS=linux GOARCH=amd64 go vet ./...

test:
	go test ./... -race -cover

clean:
	rm -f $(BIN)/ppanel-agent $(BIN)/ppanel-agent-* $(BIN)/SHA256SUMS
