#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/e2e_fake_cli.sh

Runs a non-root fake-host CLI scenario using stubbed host tools in PATH.
This validates JSON command paths and hard-block behavior without touching
real Suricata, systemd, NIC, firewall, HugePages, or sysctl state.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[fake-e2e] required command not found: $1" >&2
    exit 1
  }
}

need_cmd jq

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SURITUNER_BIN="${SURITUNER_BIN:-${REPO_ROOT}/surituner}"

if [[ ! -x "${SURITUNER_BIN}" ]]; then
  echo "[fake-e2e] surituner binary not found or not executable: ${SURITUNER_BIN}" >&2
  echo "[fake-e2e] build it first: make build" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

BIN_DIR="${TMP_DIR}/bin"
RULES_DIR="${TMP_DIR}/rules"
CONFIG_PATH="${TMP_DIR}/suricata.yaml"
LOG_PATH="${TMP_DIR}/commands.log"
mkdir -p "${BIN_DIR}" "${RULES_DIR}"

write_fake_tool() {
  local path="$1"
  cat >"${path}" <<'EOF'
#!/bin/sh
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$SURITUNER_FAKE_E2E_LOG"
case "$name" in
  suricata)
    if [ "$1" = "--build-info" ]; then
      cat <<'EOT'
This is Suricata version 8.0.3 RELEASE
Suricata Configuration:
  AF_XDP support: yes
  DPDK support: no
  NFQueue support: yes
  HWLOC support: yes
EOT
    fi
    exit 0
    ;;
  lscpu)
    printf '# CPU,NODE\n0,0\n1,0\n'
    exit 0
    ;;
  ethtool)
    case "$1" in
      -k)
        printf 'Features for %s:\ngeneric-receive-offload: on\nlarge-receive-offload: on\n' "$2"
        ;;
      -l)
        cat <<'EOT'
Channel parameters for lo:
Pre-set maximums:
Combined: 1
Current hardware settings:
Combined: 1
EOT
        ;;
      -g)
        cat <<'EOT'
Ring parameters for lo:
Pre-set maximums:
RX: 4096
TX: 4096
Current hardware settings:
RX: 512
TX: 512
EOT
        ;;
      -x)
        printf 'RSS hash function: toeplitz\n'
        ;;
      -S)
        printf 'NIC statistics:\nrx_dropped: 0\nrx_missed_errors: 0\n'
        ;;
    esac
    exit 0
    ;;
  ip)
    if [ "$1" = "route" ] && [ "$2" = "show" ]; then
      printf 'default via 192.0.2.1 dev ens33 proto dhcp\n'
      exit 0
    fi
    if [ "$1" = "route" ] && [ "$2" = "get" ]; then
      printf '%s dev ens33 src 192.0.2.10\n' "$3"
      exit 0
    fi
    if [ "$1" = "-details" ]; then
      printf '1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue\n'
      exit 0
    fi
    if [ "$1" = "-o" ]; then
      printf '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n'
      exit 0
    fi
    exit 0
    ;;
  sysctl)
    if [ "$1" = "-n" ]; then
      printf '1\n'
    fi
    exit 0
    ;;
  systemctl)
    if [ "$1" = "--version" ]; then
      printf 'systemd 255\n'
      exit 0
    fi
    if [ "$1" = "is-active" ]; then
      printf 'active\n'
      exit 0
    fi
    exit 0
    ;;
  uname)
    printf '6.8.12-test\n'
    exit 0
    ;;
  ss|nft)
    exit 0
    ;;
esac
exit 0
EOF
  chmod +x "${path}"
}

for tool in suricata lscpu ethtool ip sysctl systemctl uname ss nft; do
  write_fake_tool "${BIN_DIR}/${tool}"
done

cat >"${CONFIG_PATH}" <<EOF
default-rule-path: ${RULES_DIR}
rule-files:
  - suricata.rules
runmode: autofp
af-packet:
  - interface: lo
EOF
printf 'alert tcp any any -> any any (msg:"fake"; sid:1;)\n' > "${RULES_DIR}/suricata.rules"

export PATH="${BIN_DIR}:${PATH}"
export SURITUNER_FAKE_E2E_LOG="${LOG_PATH}"

ARTIFACT_DIR="${TMP_DIR}/artifacts"
mkdir -p "${ARTIFACT_DIR}"

echo "[fake-e2e] detect"
"${SURITUNER_BIN}" detect --iface lo --config-path "${CONFIG_PATH}" --json \
  | tee "${ARTIFACT_DIR}/detect.json" >/dev/null
jq -e '.snapshot.iface=="lo" and .snapshot.build.supports_af_xdp==true and .snapshot.safety.is_management_iface==false' "${ARTIFACT_DIR}/detect.json" >/dev/null

echo "[fake-e2e] pcap full plan"
"${SURITUNER_BIN}" plan --profile pcap --iface lo --config-path "${CONFIG_PATH}" --scope full --json \
  | tee "${ARTIFACT_DIR}/plan-pcap-full.json" >/dev/null
jq -e '.profile=="pcap" and .scope=="full" and .hard_blocked==false and ([.actions[].id] | index("systemd-profile"))' "${ARTIFACT_DIR}/plan-pcap-full.json" >/dev/null

echo "[fake-e2e] dpdk hard block"
"${SURITUNER_BIN}" plan --profile dpdk --iface lo --config-path "${CONFIG_PATH}" --scope full --force --json \
  | tee "${ARTIFACT_DIR}/plan-dpdk-full.json" >/dev/null
jq -e '.profile=="dpdk" and .scope=="full" and .hard_blocked==true and (.blocking_reasons|length>=1)' "${ARTIFACT_DIR}/plan-dpdk-full.json" >/dev/null

echo "[fake-e2e] af-xdp interface-signal hard block"
"${SURITUNER_BIN}" plan --profile af-xdp --iface lo --config-path "${CONFIG_PATH}" --scope full --force --json \
  | tee "${ARTIFACT_DIR}/plan-af-xdp-full.json" >/dev/null
jq -e '.profile=="af-xdp" and .scope=="full" and .hard_blocked==true and (.blocking_reasons | join("\n") | test("interface XDP support signal"))' "${ARTIFACT_DIR}/plan-af-xdp-full.json" >/dev/null

echo "[fake-e2e] report"
"${SURITUNER_BIN}" report --iface lo --config-path "${CONFIG_PATH}" --json \
  | tee "${ARTIFACT_DIR}/report.json" >/dev/null
jq -e '.snapshot.iface=="lo" and .recommendations and .monitoring_recommendations' "${ARTIFACT_DIR}/report.json" >/dev/null

echo "[fake-e2e] PASS"
