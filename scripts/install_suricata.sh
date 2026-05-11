#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must be run as root (use: sudo ./scripts/install_suricata.sh)"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "[install] apt update"
apt-get update -y

echo "[install] installing Suricata stack"
apt-get install -y \
  suricata \
  suricata-update \
  ethtool \
  iproute2 \
  jq

echo "[install] versions"
suricata --build-info | head -n 40 || true
suricata-update --version || true

echo "[install] downloading/updating ruleset"
suricata-update

echo "[install] validating base config"
suricata -T -c /etc/suricata/suricata.yaml

echo "[install] completed"
echo "Next step:"
echo "  sudo ./scripts/e2e_real_smoke.sh --iface <capture_iface>"
