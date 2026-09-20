GOCACHE_DIR := $(CURDIR)/.cache/go-build
BIN_DIR := $(CURDIR)/bin
TOOLS_BIN := $(CURDIR)/.tools/bin
GOLANGCI_LINT_VERSION := v2.10.1
GOLANGCI_LINT := $(TOOLS_BIN)/$(GOLANGCI_LINT_VERSION)/golangci-lint

.DEFAULT_GOAL := build
.PHONY: build run fmt fmt-check vet test race lint-install lint skills-check verify check clean

build:
	mkdir -p "$(BIN_DIR)"
	GOCACHE="$(GOCACHE_DIR)" go build -trimpath -o "$(BIN_DIR)/cloudattrib" ./cmd/cloudattrib

run:
	GOCACHE="$(GOCACHE_DIR)" go run ./cmd/cloudattrib

fmt:
	gofmt -w cmd internal

fmt-check:
	sh scripts/verify-go.sh

vet:
	GOCACHE="$(GOCACHE_DIR)" go vet ./...

test:
	GOCACHE="$(GOCACHE_DIR)" go test ./...

race:
	GOCACHE="$(GOCACHE_DIR)" go test -race ./...

lint-install: $(GOLANGCI_LINT)

$(GOLANGCI_LINT):
	mkdir -p "$(dir $(GOLANGCI_LINT))"
	GOBIN="$(dir $(GOLANGCI_LINT))" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) config verify --config .golangci.yml
	$(GOLANGCI_LINT) run ./...

skills-check:
	python3 -B scripts/verify-skills.py

verify: fmt-check vet test lint skills-check

check: verify race build

clean:
	rm -rf -- "$(BIN_DIR)"
