#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sudo ./scripts/e2e_real_smoke.sh --iface <name> [--config-path <path>] [--run-os-tuning] [--run-full]

Behavior:
  - Always runs detect/plan/report JSON checks.
  - Always runs apply+rollback with --config-only (safe default).
  - Optional:
      --run-os-tuning  additionally runs apply --os-tuning (higher risk)
      --run-full       additionally runs apply --full (highest risk; may be blocked by guardrails)
EOF
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script must be run as root."
  exit 1
fi

IFACE=""
CONFIG_PATH=""
RUN_OS_TUNING=0
RUN_FULL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)
      IFACE="${2:-}"
      shift 2
      ;;
    --config-path)
      CONFIG_PATH="${2:-}"
      shift 2
      ;;
    --run-os-tuning)
      RUN_OS_TUNING=1
      shift
      ;;
    --run-full)
      RUN_FULL=1
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

if [[ -z "${IFACE}" ]]; then
  echo "--iface is required"
  usage
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SURITUNER_BIN="${REPO_ROOT}/surituner"

if [[ ! -x "${SURITUNER_BIN}" ]]; then
  echo "surituner binary not found or not executable: ${SURITUNER_BIN}"
  echo "Build it first: /home/vol/.local/go/bin/go build -o surituner ./cmd/surituner"
  exit 1
fi

if ! command -v suricata >/dev/null 2>&1; then
  echo "suricata is not installed. Run: sudo ./scripts/install_suricata.sh"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for JSON validation"
  exit 1
fi

if [[ ! -s /var/lib/suricata/rules/suricata.rules && ! -s /etc/suricata/rules/suricata.rules ]]; then
  echo "[e2e] no suricata.rules found, running suricata-update"
  suricata-update
fi

if [[ ! -d "/sys/class/net/${IFACE}" ]]; then
  echo "interface does not exist: ${IFACE}"
  exit 1
fi

BASE_CONFIG="${CONFIG_PATH:-/etc/suricata/suricata.yaml}"

current_af_packet_iface() {
  awk '
    /^af-packet:[[:space:]]*$/ { in_af = 1; next }
    in_af && /^[^[:space:]#][^:]*:[[:space:]]*$/ { exit }
    in_af && /^[[:space:]]*-[[:space:]]+interface:[[:space:]]*/ { print $3; exit }
  ' "$1"
}

ensure_base_af_packet_iface() {
  local cfg="$1"
  local iface="$2"
  local current
  current="$(current_af_packet_iface "${cfg}")"
  if [[ "${current}" == "${iface}" ]]; then
    return
  fi
  echo "[e2e] base af-packet interface is '${current:-unknown}', setting it to '${iface}' for real service startup"
  local backup="${cfg}.surituner-e2e.$(date -u +%Y%m%dT%H%M%SZ).bak"
  local tmp="${cfg}.surituner-e2e.tmp"
  cp -p "${cfg}" "${backup}"
  awk -v iface="${iface}" '
    /^af-packet:[[:space:]]*$/ { in_af = 1 }
    in_af && replaced == 0 && /^[^[:space:]#][^:]*:[[:space:]]*$/ && $0 !~ /^af-packet:/ { in_af = 0 }
    in_af && replaced == 0 && /^[[:space:]]*-[[:space:]]+interface:[[:space:]]*/ {
      sub(/interface:[[:space:]]*[^[:space:]#]+/, "interface: " iface)
      replaced = 1
    }
    { print }
  ' "${backup}" > "${tmp}"
  install -o "$(stat -c '%u' "${cfg}")" -g "$(stat -c '%g' "${cfg}")" -m "$(stat -c '%a' "${cfg}")" "${tmp}" "${cfg}"
  rm -f "${tmp}"
  echo "[e2e] backup of original config: ${backup}"
}

ensure_service_start_timeout() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return
  fi
  echo "[e2e] ensuring suricata.service has enough startup time for large rulesets"
  mkdir -p /etc/systemd/system/suricata.service.d
  tee /etc/systemd/system/suricata.service.d/surituner-e2e-timeout.conf >/dev/null <<'EOF'
[Service]
TimeoutStartSec=5min
EOF
  systemctl daemon-reload
  systemctl reset-failed suricata.service || true
}

ensure_base_af_packet_iface "${BASE_CONFIG}" "${IFACE}"
ensure_service_start_timeout

echo "[e2e] validating base Suricata config"
suricata -T -c "${BASE_CONFIG}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_DIR="$(mktemp -d "/tmp/surituner-e2e-${TS}.XXXXXX")"

CFG_ARGS=()
if [[ -n "${CONFIG_PATH}" ]]; then
  CFG_ARGS+=(--config-path "${CONFIG_PATH}")
fi

echo "[e2e] artifacts: ${ARTIFACT_DIR}"

echo "[e2e] detect"
"${SURITUNER_BIN}" detect --iface "${IFACE}" "${CFG_ARGS[@]}" --json | tee "${ARTIFACT_DIR}/detect.json" >/dev/null
jq -e '.snapshot.iface and .snapshot.build and .snapshot.nic and .snapshot.ruleset and .snapshot.safety' "${ARTIFACT_DIR}/detect.json" >/dev/null

echo "[e2e] plan (config-only)"
"${SURITUNER_BIN}" plan --profile af-packet --iface "${IFACE}" "${CFG_ARGS[@]}" --scope config-only --json | tee "${ARTIFACT_DIR}/plan-config-only.json" >/dev/null
jq -e '.scope=="config-only" and (.actions|length>=1)' "${ARTIFACT_DIR}/plan-config-only.json" >/dev/null

echo "[e2e] apply (config-only)"
"${SURITUNER_BIN}" apply --profile af-packet --iface "${IFACE}" "${CFG_ARGS[@]}" --config-only --yes | tee "${ARTIFACT_DIR}/apply-config-only.txt" >/dev/null
CONFIG_STATE="$(awk '/^State file:/ { print $3 }' "${ARTIFACT_DIR}/apply-config-only.txt")"
if [[ -z "${CONFIG_STATE}" || ! -f "${CONFIG_STATE}" ]]; then
  echo "[e2e] apply did not produce a readable state file"
  exit 1
fi
jq -e '.status=="applied" and .yaml_backup.backup_path and (.applied|length)==1 and .applied[0].action_id=="yaml-tuning"' "${CONFIG_STATE}" >/dev/null

echo "[e2e] report"
"${SURITUNER_BIN}" report --iface "${IFACE}" "${CFG_ARGS[@]}" --json | tee "${ARTIFACT_DIR}/report.json" >/dev/null
jq -e '.snapshot and .recommendations and .monitoring_recommendations' "${ARTIFACT_DIR}/report.json" >/dev/null

echo "[e2e] rollback latest"
"${SURITUNER_BIN}" rollback --state latest --yes | tee "${ARTIFACT_DIR}/rollback.txt" >/dev/null
ROLLBACK_STATE="$(awk '/^State:/ { print $2 }' "${ARTIFACT_DIR}/rollback.txt")"
if [[ -z "${ROLLBACK_STATE}" || ! -f "${ROLLBACK_STATE}" ]]; then
  echo "[e2e] rollback did not report a readable state file"
  exit 1
fi
jq -e '.status=="rolled_back" and (.rollback|length)>=1 and ([.rollback[] | select(.status=="failed")] | length)==0' "${ROLLBACK_STATE}" >/dev/null

echo "[e2e] guardrail (full plan on management interface)"
"${SURITUNER_BIN}" plan --profile af-packet --iface "${IFACE}" "${CFG_ARGS[@]}" --scope full --json | tee "${ARTIFACT_DIR}/plan-full-guardrail.json" >/dev/null
if jq -e '.snapshot.safety.is_management_iface == true' "${ARTIFACT_DIR}/plan-full-guardrail.json" >/dev/null; then
  jq -e '.blocked == true and ([.actions[] | select(.blocked_by_guardrail==true)] | length) >= 1' "${ARTIFACT_DIR}/plan-full-guardrail.json" >/dev/null
  if "${SURITUNER_BIN}" apply --profile af-packet --iface "${IFACE}" "${CFG_ARGS[@]}" --full --yes >"${ARTIFACT_DIR}/apply-full-guardrail.stdout" 2>"${ARTIFACT_DIR}/apply-full-guardrail.stderr"; then
    echo "[e2e] expected --full apply to be blocked on management interface"
    exit 1
  fi
  grep -qi "blocked by guardrails" "${ARTIFACT_DIR}/apply-full-guardrail.stderr"
else
  echo "[e2e] interface is not detected as management; skipping guardrail-block assertion"
fi

if [[ "${RUN_OS_TUNING}" -eq 1 ]]; then
  echo "[e2e] plan (os-tuning)"
  "${SURITUNER_BIN}" plan --profile af-packet --iface "${IFACE}" "${CFG_ARGS[@]}" --scope os-tuning --json | tee "${ARTIFACT_DIR}/plan-os-tuning.json" >/dev/null
  jq -e '.scope=="os-tuning"' "${ARTIFACT_DIR}/plan-os-tuning.json" >/dev/null

  if jq -e '.blocked == true' "${ARTIFACT_DIR}/plan-os-tuning.json" >/dev/null; then
    echo "[e2e] os-tuning is blocked by guardrails; verifying apply refuses it"
    if "${SURITUNER_BIN}" apply --profile af-packet --iface "${IFACE}" "${CFG_ARGS[@]}" --os-tuning --yes >"${ARTIFACT_DIR}/apply-os-tuning.stdout" 2>"${ARTIFACT_DIR}/apply-os-tuning.stderr"; then
      echo "[e2e] expected os-tuning apply to be blocked"
      exit 1
    fi
    grep -qi "blocked by guardrails" "${ARTIFACT_DIR}/apply-os-tuning.stderr"
  else
    echo "[e2e] apply (os-tuning)"
    "${SURITUNER_BIN}" apply --profile af-packet --iface "${IFACE}" "${CFG_ARGS[@]}" --os-tuning --yes | tee "${ARTIFACT_DIR}/apply-os-tuning.txt" >/dev/null

    echo "[e2e] rollback latest (after os-tuning)"
    "${SURITUNER_BIN}" rollback --state latest --yes | tee "${ARTIFACT_DIR}/rollback-os-tuning.txt" >/dev/null
  fi
fi

if [[ "${RUN_FULL}" -eq 1 ]]; then
  echo "[e2e] plan (full)"
  "${SURITUNER_BIN}" plan --profile af-packet --iface "${IFACE}" "${CFG_ARGS[@]}" --scope full --json | tee "${ARTIFACT_DIR}/plan-full.json" >/dev/null
  jq -e '.scope=="full"' "${ARTIFACT_DIR}/plan-full.json" >/dev/null

  if jq -e '.blocked == true' "${ARTIFACT_DIR}/plan-full.json" >/dev/null; then
    echo "[e2e] full apply is blocked by guardrails; verifying apply refuses it"
    if "${SURITUNER_BIN}" apply --profile af-packet --iface "${IFACE}" "${CFG_ARGS[@]}" --full --yes >"${ARTIFACT_DIR}/apply-full.stdout" 2>"${ARTIFACT_DIR}/apply-full.stderr"; then
      echo "[e2e] expected full apply to be blocked"
      exit 1
    fi
    grep -qi "blocked by guardrails" "${ARTIFACT_DIR}/apply-full.stderr"
  else
    echo "[e2e] apply (full)"
    "${SURITUNER_BIN}" apply --profile af-packet --iface "${IFACE}" "${CFG_ARGS[@]}" --full --yes | tee "${ARTIFACT_DIR}/apply-full.txt" >/dev/null

    echo "[e2e] rollback latest (after full)"
    "${SURITUNER_BIN}" rollback --state latest --yes | tee "${ARTIFACT_DIR}/rollback-full.txt" >/dev/null
  fi
fi

echo "[e2e] done"
echo "Artifacts: ${ARTIFACT_DIR}"
