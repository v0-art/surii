GO ?= /home/vol/.local/go/bin/go
GOFMT ?= /home/vol/.local/go/bin/gofmt
ZIG ?= /home/vol/.local/zig/current/zig

.PHONY: fmt-check test vet build race ci ci-full

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

ci: fmt-check test vet build

ci-full: ci race
