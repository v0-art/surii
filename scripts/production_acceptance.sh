#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/production_acceptance.sh --profile <profile> --iface <name> [options]

Profiles:
  af-packet | pcap | nfq | dpdk | af-xdp

Default behavior:
  - Non-destructive production preflight only.
  - Writes artifacts under /tmp/surituner-production-acceptance-<timestamp>.
  - Refuses management/default-route interfaces unless --allow-management is explicit.
  - Refuses full live apply unless --apply-full is explicit.

Options:
  --config-path <path>                 Suricata config path.
  --artifact-dir <path>                Artifact directory.
  --apply-full                         Run full apply after preflight.
  --rollback-after                     Roll back after apply (default when --apply-full is used).
  --keep-applied                       Do not roll back after apply.
  --force                              Pass --force to SuriTuner apply/plan.
  --allow-management                   Allow management-interface plan/apply.
  --traffic-ready                      Operator attests mirror/tap/generator traffic is present.
  --monitor-duration <seconds>         Wait and collect a post-apply report. Default: 120.
  --zero-copy-verified                 Operator attests AF_XDP hardware zero-copy was verified.
  --allow-af-xdp-zero-copy-unverified  Allow AF_XDP full acceptance without zero-copy attestation.
  --allow-no-carrier                   Allow iface carrier != 1 during preflight.
  --help                               Show this help.

Production gates:
  DPDK requires a non-management NIC, an IOMMU group, vfio-pci readiness, and
  a non-hard-blocked SuriTuner full plan. VFIO no-IOMMU is rejected.

  AF_XDP requires kernel support, an interface-specific XDP signal, and either
  --zero-copy-verified or --allow-af-xdp-zero-copy-unverified.
EOF
}

PROFILE=""
IFACE=""
CONFIG_PATH=""
ARTIFACT_DIR=""
APPLY_FULL=0
ROLLBACK_AFTER=1
FORCE=0
ALLOW_MANAGEMENT=0
TRAFFIC_READY=0
MONITOR_DURATION=120
ZERO_COPY_VERIFIED=0
ALLOW_AFXDP_ZERO_COPY_UNVERIFIED=0
ALLOW_NO_CARRIER=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --iface)
      IFACE="${2:-}"
      shift 2
      ;;
    --config-path)
      CONFIG_PATH="${2:-}"
      shift 2
      ;;
    --artifact-dir)
      ARTIFACT_DIR="${2:-}"
      shift 2
      ;;
    --apply-full)
      APPLY_FULL=1
      shift
      ;;
    --rollback-after)
      ROLLBACK_AFTER=1
      shift
      ;;
    --keep-applied)
      ROLLBACK_AFTER=0
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --allow-management)
      ALLOW_MANAGEMENT=1
      shift
      ;;
    --traffic-ready)
      TRAFFIC_READY=1
      shift
      ;;
    --monitor-duration)
      MONITOR_DURATION="${2:-}"
      shift 2
      ;;
    --zero-copy-verified)
      ZERO_COPY_VERIFIED=1
      shift
      ;;
    --allow-af-xdp-zero-copy-unverified)
      ALLOW_AFXDP_ZERO_COPY_UNVERIFIED=1
      shift
      ;;
    --allow-no-carrier)
      ALLOW_NO_CARRIER=1
      shift
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

die() {
  echo "[acceptance] ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

if [[ "${EUID}" -ne 0 ]]; then
  die "this script must be run as root"
fi

case "${PROFILE}" in
  af-packet|pcap|nfq|dpdk|af-xdp) ;;
  "")
    die "--profile is required"
    ;;
  *)
    die "unsupported profile: ${PROFILE}"
    ;;
esac

if [[ -z "${IFACE}" ]]; then
  die "--iface is required"
fi

if ! [[ "${MONITOR_DURATION}" =~ ^[0-9]+$ ]]; then
  die "--monitor-duration must be an integer number of seconds"
fi

need_cmd jq
need_cmd ip
need_cmd systemctl

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SURITUNER_BIN="${REPO_ROOT}/surituner"

if [[ ! -x "${SURITUNER_BIN}" ]]; then
  die "surituner binary not found or not executable: ${SURITUNER_BIN}"
fi

if [[ ! -d "/sys/class/net/${IFACE}" ]]; then
  die "interface does not exist in Linux sysfs before apply: ${IFACE}"
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "${ARTIFACT_DIR}" ]]; then
  ARTIFACT_DIR="/tmp/surituner-production-acceptance-${TS}"
fi
mkdir -p "${ARTIFACT_DIR}"

CFG_ARGS=()
if [[ -n "${CONFIG_PATH}" ]]; then
  CFG_ARGS+=(--config-path "${CONFIG_PATH}")
fi
PLAN_ARGS=(--profile "${PROFILE}" --iface "${IFACE}" "${CFG_ARGS[@]}" --scope full --json)
APPLY_ARGS=(--profile "${PROFILE}" --iface "${IFACE}" "${CFG_ARGS[@]}" --full --yes)
if [[ "${FORCE}" -eq 1 ]]; then
  PLAN_ARGS+=(--force)
  APPLY_ARGS+=(--force)
fi

echo "[acceptance] artifacts: ${ARTIFACT_DIR}"
echo "[acceptance] profile=${PROFILE} iface=${IFACE}"

echo "[acceptance] default route"
ip route show default | tee "${ARTIFACT_DIR}/default-route.txt"

echo "[acceptance] detect"
"${SURITUNER_BIN}" detect --iface "${IFACE}" "${CFG_ARGS[@]}" --json | tee "${ARTIFACT_DIR}/detect.json" >/dev/null
jq -e '.snapshot.iface and .snapshot.safety and .snapshot.nic' "${ARTIFACT_DIR}/detect.json" >/dev/null

IS_MANAGEMENT="$(jq -r '.snapshot.safety.is_management_iface' "${ARTIFACT_DIR}/detect.json")"
if [[ "${IS_MANAGEMENT}" == "true" && "${ALLOW_MANAGEMENT}" -ne 1 ]]; then
  die "${IFACE} is detected as management-risk; pass --allow-management only for an intentional maintenance-window test"
fi

CARRIER_PATH="/sys/class/net/${IFACE}/carrier"
if [[ -r "${CARRIER_PATH}" ]]; then
  CARRIER="$(cat "${CARRIER_PATH}" 2>/dev/null || echo unknown)"
  echo "[acceptance] carrier=${CARRIER}" | tee "${ARTIFACT_DIR}/carrier.txt"
  if [[ "${CARRIER}" != "1" && "${ALLOW_NO_CARRIER}" -ne 1 ]]; then
    die "${IFACE} carrier is not up; attach link/mirror/generator traffic or pass --allow-no-carrier for lab-only preflight"
  fi
fi

echo "[acceptance] full plan"
"${SURITUNER_BIN}" plan "${PLAN_ARGS[@]}" | tee "${ARTIFACT_DIR}/plan-full.json" >/dev/null
jq -e '.scope=="full" and .profile=="'"${PROFILE}"'"' "${ARTIFACT_DIR}/plan-full.json" >/dev/null

if jq -e '.hard_blocked == true' "${ARTIFACT_DIR}/plan-full.json" >/dev/null; then
  jq '{blocked, hard_blocked, blocking_reasons}' "${ARTIFACT_DIR}/plan-full.json"
  die "full plan has non-overridable hard blockers"
fi

if jq -e '.blocked == true' "${ARTIFACT_DIR}/plan-full.json" >/dev/null && [[ "${FORCE}" -ne 1 ]]; then
  jq '{blocked, hard_blocked, blocking_reasons}' "${ARTIFACT_DIR}/plan-full.json"
  die "full plan is blocked by guardrails; use --force only after confirming the target is safe"
fi

case "${PROFILE}" in
  dpdk)
    need_cmd dpdk-devbind.py
    PCI_ADDR="$(basename "$(readlink "/sys/class/net/${IFACE}/device")")"
    echo "[acceptance] dpdk pci=${PCI_ADDR}" | tee "${ARTIFACT_DIR}/dpdk-pci.txt"
    if [[ ! -L "/sys/class/net/${IFACE}/device/iommu_group" ]]; then
      die "DPDK production acceptance requires /sys/class/net/${IFACE}/device/iommu_group"
    fi
    IOMMU_GROUP="$(basename "$(readlink "/sys/class/net/${IFACE}/device/iommu_group")")"
    echo "[acceptance] iommu_group=${IOMMU_GROUP}" | tee "${ARTIFACT_DIR}/dpdk-iommu-group.txt"
    if [[ -r /sys/module/vfio/parameters/enable_unsafe_noiommu_mode ]]; then
      NOIOMMU="$(cat /sys/module/vfio/parameters/enable_unsafe_noiommu_mode)"
      echo "[acceptance] vfio_noiommu=${NOIOMMU}" | tee "${ARTIFACT_DIR}/dpdk-vfio-noiommu.txt"
      case "${NOIOMMU}" in
        Y|y|1)
          die "VFIO unsafe no-IOMMU mode is enabled; this is lab-only and rejected for production acceptance"
          ;;
      esac
    fi
    dpdk-devbind.py --status | tee "${ARTIFACT_DIR}/dpdk-devbind-status.txt"
    if ! jq -e '.snapshot.nic.dpdk_can_bind_vfio == true or .snapshot.nic.dpdk_current_driver == "vfio-pci"' "${ARTIFACT_DIR}/plan-full.json" >/dev/null; then
      die "DPDK plan does not prove vfio-pci bind readiness"
    fi
    if ! jq -e '.snapshot.nic.dpdk_bind_ready == true' "${ARTIFACT_DIR}/plan-full.json" >/dev/null; then
      die "DPDK plan does not prove bind/unbind readiness"
    fi
    ;;
  af-xdp)
    if ! jq -e '.snapshot.nic.xdp_kernel_supported == true' "${ARTIFACT_DIR}/plan-full.json" >/dev/null; then
      die "AF_XDP kernel support is not detected"
    fi
    if ! jq -e '.snapshot.nic.xdp_interface_signal_detected == true' "${ARTIFACT_DIR}/plan-full.json" >/dev/null; then
      die "AF_XDP interface-specific XDP signal is not detected"
    fi
    if [[ "${ZERO_COPY_VERIFIED}" -ne 1 && "${ALLOW_AFXDP_ZERO_COPY_UNVERIFIED}" -ne 1 ]]; then
      die "AF_XDP zero-copy must be verified on hardware or explicitly accepted with --allow-af-xdp-zero-copy-unverified"
    fi
    ;;
esac

if [[ "${APPLY_FULL}" -ne 1 ]]; then
  echo "[acceptance] preflight-only PASS"
  echo "[acceptance] run with --apply-full --traffic-ready during a maintenance window to execute live full apply/rollback"
  exit 0
fi

if [[ "${TRAFFIC_READY}" -ne 1 ]]; then
  die "--apply-full requires --traffic-ready to confirm mirror/tap/generator traffic is available"
fi

echo "[acceptance] service status before apply"
systemctl is-active suricata.service | tee "${ARTIFACT_DIR}/suricata-active-before.txt"

echo "[acceptance] apply full"
set +e
"${SURITUNER_BIN}" apply "${APPLY_ARGS[@]}" | tee "${ARTIFACT_DIR}/apply-full.txt"
APPLY_STATUS="${PIPESTATUS[0]}"
set -e
if [[ "${APPLY_STATUS}" -ne 0 ]]; then
  echo "[acceptance] apply failed; inspect ${ARTIFACT_DIR}/apply-full.txt" >&2
  exit "${APPLY_STATUS}"
fi

STATE_PATH="$(awk '/^State file:/ { print $3 }' "${ARTIFACT_DIR}/apply-full.txt")"
if [[ -z "${STATE_PATH}" || ! -f "${STATE_PATH}" ]]; then
  die "apply did not report a readable state file"
fi
echo "${STATE_PATH}" > "${ARTIFACT_DIR}/state-path.txt"
jq -e '.status=="applied"' "${STATE_PATH}" >/dev/null

echo "[acceptance] service status after apply"
systemctl is-active suricata.service | tee "${ARTIFACT_DIR}/suricata-active-after-apply.txt"

if [[ "${MONITOR_DURATION}" -gt 0 ]]; then
  echo "[acceptance] monitoring for ${MONITOR_DURATION}s"
  sleep "${MONITOR_DURATION}"
  "${SURITUNER_BIN}" report --iface "${IFACE}" "${CFG_ARGS[@]}" --json | tee "${ARTIFACT_DIR}/report-after-apply.json" >/dev/null || true
fi

if [[ "${ROLLBACK_AFTER}" -eq 1 ]]; then
  echo "[acceptance] rollback"
  "${SURITUNER_BIN}" rollback --state "${STATE_PATH}" --yes | tee "${ARTIFACT_DIR}/rollback.txt"
  jq -e '.status=="rolled_back" and ([.rollback[] | select(.status=="failed")] | length)==0' "${STATE_PATH}" >/dev/null
  systemctl is-active suricata.service | tee "${ARTIFACT_DIR}/suricata-active-after-rollback.txt"
fi

echo "[acceptance] PASS"
echo "Artifacts: ${ARTIFACT_DIR}"

