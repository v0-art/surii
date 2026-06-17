GO ?= /home/vol/.local/go/bin/go
GOFMT ?= /home/vol/.local/go/bin/gofmt
ZIG ?= /home/vol/.local/zig/current/zig

.PHONY: fmt-check test vet build build-bin race mod-verify shell-syntax fake-e2e traffic-lab live-traffic-lab package release-snapshot ci ci-full

fmt-check:
	@out="$$( $(GOFMT) -l . )"; \
	if [ -n "$$out" ]; then \
		echo "$$out"; \
		exit 1; \
	fi
	@echo "fmt-check: ok"

test:
	@$(GO) test ./...

vet:
	@$(GO) vet ./...

build:
	@$(GO) build ./cmd/surituner

build-bin:
	@$(GO) build -o surituner ./cmd/surituner

mod-verify:
	@$(GO) mod verify

shell-syntax:
	@bash -n scripts/*.sh

fake-e2e:
	@tmp_bin="$$(mktemp)"; \
	trap 'rm -f "$$tmp_bin"' EXIT; \
	$(GO) build -o "$$tmp_bin" ./cmd/surituner; \
	SURITUNER_BIN="$$tmp_bin" ./scripts/e2e_fake_cli.sh

traffic-lab:
	@./scripts/traffic_pcap_lab.sh

live-traffic-lab:
	@./scripts/traffic_live_loopback_lab.sh

package:
	@./scripts/package_release.sh

release-snapshot:
	@./scripts/package_release.sh --version snapshot

race:
	@if [ -x "$(ZIG)" ]; then \
		echo "race: using zig toolchain at $(ZIG)"; \
		CC="$(ZIG) cc" CXX="$(ZIG) c++" CGO_ENABLED=1 $(GO) test -race ./...; \
	elif command -v gcc >/dev/null 2>&1; then \
		echo "race: using system gcc"; \
		CGO_ENABLED=1 $(GO) test -race ./...; \
	else \
		echo "race: no C compiler found (need gcc/clang or zig)"; \
		exit 1; \
	fi

ci: fmt-check test vet build mod-verify shell-syntax fake-e2e

ci-full: ci race package
