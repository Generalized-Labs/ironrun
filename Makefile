# ironrun — reproducible build, test, and installer-check targets.
#
# Reproducible build contract (see docs/INSTALL.md):
#   * -trimpath strips local filesystem paths from the binary;
#   * -s -w strips symbol tables and DWARF debug info;
#   * CGO_ENABLED=0 removes toolchain/libc variance;
#   * Version/Commit come from git (deterministic for a given commit);
#   * Date is the *commit* date, never wall-clock time;
#   * go.sum pins every module dependency.
#
# Verify: `make verify-reproducible` builds the same tree twice and requires
# byte-identical output.

GO          ?= go
BUILDINFO    = github.com/generalized-labs/ironrun/internal/buildinfo
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse HEAD 2>/dev/null || echo none)
DATE        ?= $(shell git log -1 --format=%cI 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS      = -s -w \
               -X $(BUILDINFO).Version=$(VERSION) \
               -X $(BUILDINFO).Commit=$(COMMIT) \
               -X $(BUILDINFO).Date=$(DATE)
REPRO_DIR    = /tmp/ironrun-reproducible-check

.PHONY: build
build: ## Build the ironrun binary (reproducible flags + VCS stamping).
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/ironrun ./cmd/ironrun

.PHONY: verify-reproducible
verify-reproducible: ## Build twice from this tree; fail unless hashes are identical.
	rm -rf $(REPRO_DIR) && mkdir -p $(REPRO_DIR)/a $(REPRO_DIR)/b
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(REPRO_DIR)/a/ironrun ./cmd/ironrun
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(REPRO_DIR)/b/ironrun ./cmd/ironrun
	@sha256sum $(REPRO_DIR)/a/ironrun $(REPRO_DIR)/b/ironrun
	@if [ "$$(sha256sum $(REPRO_DIR)/a/ironrun | cut -d' ' -f1)" = \
	      "$$(sha256sum $(REPRO_DIR)/b/ironrun | cut -d' ' -f1)" ]; then \
		echo "REPRODUCIBLE: two builds from this tree are byte-identical"; \
	else \
		echo "NOT REPRODUCIBLE: hashes differ" >&2; exit 1; \
	fi
	rm -rf $(REPRO_DIR)

.PHONY: version-info
version-info: ## Show the VCS stamping that would go into the next build.
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Date:    $(DATE)"

.PHONY: test
test: ## Run the full Go test suite.
	$(GO) test ./...

.PHONY: test-race
test-race: ## Run the full Go test suite with the race detector.
	$(GO) test -race ./...

.PHONY: vet
vet: ## go vet across the module.
	$(GO) vet ./...

.PHONY: fmt
fmt: ## gofmt all Go sources.
	gofmt -l -w .

.PHONY: check-installer
check-installer: ## Syntax-check install.sh with sh, dash, and bash; shellcheck if present.
	sh -n install.sh
	dash -n install.sh
	bash -n install.sh
	if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -s sh install.sh; \
	else \
		echo "(shellcheck not installed; skipped)"; \
	fi
	./install.sh --help >/dev/null

.PHONY: check-npm
check-npm: ## Run the npm launcher unit tests.
	node --test npm/test/*.test.js

.PHONY: help
help: ## List targets.
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-22s %s\n", $$1, $$2}'
