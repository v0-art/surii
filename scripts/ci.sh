#!/usr/bin/env bash
set -euo pipefail

GO_BIN="${GO_BIN:-/home/vol/.local/go/bin/go}"
GOFMT_BIN="${GOFMT_BIN:-/home/vol/.local/go/bin/gofmt}"
ZIG_BIN="${ZIG_BIN:-/home/vol/.local/zig/current/zig}"

echo "[ci] fmt-check"
FMT_OUT="$("$GOFMT_BIN" -l .)"
if [[ -n "$FMT_OUT" ]]; then
  echo "$FMT_OUT"
  echo "[ci] fmt-check failed"
  exit 1
fi

echo "[ci] go test"
"$GO_BIN" test ./...

echo "[ci] go vet"
"$GO_BIN" vet ./...

echo "[ci] go build"
"$GO_BIN" build ./cmd/surituner

echo "[ci] go test -race"
if [[ -x "$ZIG_BIN" ]]; then
  CC="$ZIG_BIN cc" CXX="$ZIG_BIN c++" CGO_ENABLED=1 "$GO_BIN" test -race ./...
elif command -v gcc >/dev/null 2>&1; then
  CGO_ENABLED=1 "$GO_BIN" test -race ./...
else
  echo "[ci] skip race: no C compiler found (need gcc/clang or zig)"
  exit 1
fi

echo "[ci] all checks passed"
