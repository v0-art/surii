#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/package_release.sh [--version <version>] [--out-dir <dir>]

Builds release tarballs under dist/ by default.

Targets:
  linux/amd64
  linux/arm64
EOF
}

VERSION=""
OUT_DIR="dist"
TARGETS=("linux/amd64" "linux/arm64")

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    exit 1
  }
}

resolve_go() {
  if [[ -n "${GO_BIN:-}" ]]; then
    printf '%s\n' "${GO_BIN}"
    return
  fi
  if command -v go >/dev/null 2>&1; then
    command -v go
    return
  fi
  if [[ -x /home/vol/.local/go/bin/go ]]; then
    printf '%s\n' /home/vol/.local/go/bin/go
    return
  fi
  echo "go binary not found; set GO_BIN" >&2
  exit 1
}

need_cmd tar
need_cmd sha256sum

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

GO_BIN="$(resolve_go)"

LOCK_DIR="${OUT_DIR}.lock"
if ! mkdir "${LOCK_DIR}" 2>/dev/null; then
  echo "package output is locked: ${LOCK_DIR}" >&2
  echo "another package build may be running; remove the lock only after confirming it is stale" >&2
  exit 1
fi
trap 'rm -rf "${LOCK_DIR}"' EXIT

if [[ -z "${VERSION}" ]]; then
  VERSION="$(git describe --tags --dirty --always 2>/dev/null || date -u +%Y%m%dT%H%M%SZ)"
fi

SAFE_VERSION="${VERSION//\//-}"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}"

echo "[package] version=${SAFE_VERSION}"
echo "[package] go=$("${GO_BIN}" version)"

for target in "${TARGETS[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  package_name="surituner_${SAFE_VERSION}_${os}_${arch}"
  work_dir="$(mktemp -d)"
  package_dir="${work_dir}/${package_name}"

  mkdir -p "${package_dir}/docs" "${package_dir}/scripts"

  echo "[package] building ${target}"
  GOOS="${os}" GOARCH="${arch}" CGO_ENABLED=0 "${GO_BIN}" build -trimpath -o "${package_dir}/surituner" ./cmd/surituner

  cp README.md "${package_dir}/"
  cp docs/*.md "${package_dir}/docs/"
  cp scripts/check_dpdk_prereqs.sh "${package_dir}/scripts/"
  cp scripts/e2e_fake_cli.sh "${package_dir}/scripts/"
  cp scripts/e2e_real_smoke.sh "${package_dir}/scripts/"
  cp scripts/install_suricata.sh "${package_dir}/scripts/"
  cp scripts/production_acceptance.sh "${package_dir}/scripts/"
  cp scripts/traffic_live_loopback_lab.sh "${package_dir}/scripts/"
  cp scripts/traffic_pcap_lab.sh "${package_dir}/scripts/"
  chmod +x "${package_dir}/surituner" "${package_dir}/scripts/"*.sh

  tar -C "${work_dir}" -czf "${OUT_DIR}/${package_name}.tar.gz" "${package_name}"
  rm -rf "${work_dir}"
done

(
  cd "${OUT_DIR}"
  sha256sum ./*.tar.gz > sha256sums.txt
)

echo "[package] wrote ${OUT_DIR}"
