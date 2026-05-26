#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/check_dpdk_prereqs.sh --iface <name> [--install-tools]

Behavior:
  - Optionally installs the distro DPDK tools package.
  - Disables dpdk.service autostart after package install to avoid boot-time
    hugepage/runtime side effects during SuriTuner lab checks.
  - Loads vfio-pci when available.
  - Prints dpdk-devbind.py status and SuriTuner DPDK plan blockers.
  - Does not bind or unbind any NIC.
EOF
}

IFACE=""
INSTALL_TOOLS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)
      IFACE="${2:-}"
      shift 2
      ;;
    --install-tools)
      INSTALL_TOOLS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must be run as root."
  exit 1
fi

if [[ -z "${IFACE}" ]]; then
  echo "--iface is required"
  usage
  exit 1
fi

if [[ ! -d "/sys/class/net/${IFACE}" ]]; then
  echo "interface does not exist: ${IFACE}"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SURITUNER_BIN="${REPO_ROOT}/surituner"

if [[ "${INSTALL_TOOLS}" -eq 1 ]]; then
  echo "[dpdk] installing distro DPDK tools"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y dpdk
  if command -v systemctl >/dev/null 2>&1; then
    echo "[dpdk] disabling dpdk.service autostart for lab safety"
    systemctl disable dpdk.service >/dev/null 2>&1 || true
  fi
fi

PCI_ADDR="$(basename "$(readlink "/sys/class/net/${IFACE}/device")")"
DRIVER_LINK="$(readlink "/sys/class/net/${IFACE}/device/driver" 2>/dev/null || true)"
DRIVER_NAME="$(basename "${DRIVER_LINK:-unknown}")"
IOMMU_GROUP=""
if [[ -L "/sys/class/net/${IFACE}/device/iommu_group" ]]; then
  IOMMU_GROUP="$(basename "$(readlink "/sys/class/net/${IFACE}/device/iommu_group")")"
fi

echo "[dpdk] iface=${IFACE}"
echo "[dpdk] pci=${PCI_ADDR}"
echo "[dpdk] kernel_driver=${DRIVER_NAME}"
echo "[dpdk] iommu_group=${IOMMU_GROUP:-missing}"

if modprobe -n -v vfio-pci >/dev/null 2>&1; then
  echo "[dpdk] loading vfio-pci"
  modprobe vfio-pci || true
else
  echo "[dpdk] vfio-pci module is not available"
fi

if command -v dpdk-devbind.py >/dev/null 2>&1; then
  echo "[dpdk] dpdk-devbind.py status"
  dpdk-devbind.py --status
else
  echo "[dpdk] dpdk-devbind.py is not installed"
fi

if [[ -x "${SURITUNER_BIN}" ]]; then
  echo "[dpdk] SuriTuner DPDK full plan blockers"
  "${SURITUNER_BIN}" plan --profile dpdk --iface "${IFACE}" --scope full --json \
    | jq '{blocked, hard_blocked, blocking_reasons}'
else
  echo "[dpdk] SuriTuner binary not found or not executable: ${SURITUNER_BIN}"
fi
