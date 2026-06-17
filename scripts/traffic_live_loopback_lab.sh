#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/traffic_live_loopback_lab.sh [--port <port>] [--artifact-dir <dir>] [--cleanup]

Sends a real TCP payload over 127.0.0.1:<port>, captures it with tcpdump,
then verifies a Suricata alert from the captured pcap.

Requires tcpdump privileges. If not running as root, the script uses
`sudo -n tcpdump`.

This validates live loopback traffic generation/capture and Suricata offline
alerting. It does not validate physical NIC drops, DPDK IOMMU binding, or
AF_XDP hardware zero-copy.
EOF
}

PORT="18080"
ARTIFACT_DIR=""
CLEANUP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    --artifact-dir)
      ARTIFACT_DIR="${2:-}"
      shift 2
      ;;
    --cleanup)
      CLEANUP=1
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

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[live-traffic-lab] required command not found: $1" >&2
    exit 1
  }
}

need_cmd python3
need_cmd suricata
need_cmd tcpdump

if ! [[ "${PORT}" =~ ^[0-9]+$ ]] || [[ "${PORT}" -lt 1 || "${PORT}" -gt 65535 ]]; then
  echo "[live-traffic-lab] --port must be 1..65535" >&2
  exit 1
fi

if [[ -z "${ARTIFACT_DIR}" ]]; then
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  ARTIFACT_DIR="$(mktemp -d "/tmp/surituner-live-loopback-lab-${TS}.XXXXXX")"
else
  mkdir -p "${ARTIFACT_DIR}"
fi

PCAP_PATH="${ARTIFACT_DIR}/live-loopback.pcap"
RULE_PATH="${ARTIFACT_DIR}/live-loopback.rules"
LOG_DIR="${ARTIFACT_DIR}/log"
TCPDUMP_STDERR="${ARTIFACT_DIR}/tcpdump.stderr"
mkdir -p "${LOG_DIR}"

cat >"${RULE_PATH}" <<'EOF'
alert tcp any any -> any any (msg:"SuriTuner live loopback lab"; content:"SURI_TUNER_LIVE_LOOPBACK_LAB"; sid:9000002; rev:1;)
EOF

TCPDUMP=(tcpdump -i lo -nn -s 0 -c 6 -w "${PCAP_PATH}" "tcp port ${PORT}")
if [[ "${EUID}" -ne 0 ]]; then
  TCPDUMP=(sudo -n "${TCPDUMP[@]}")
fi

echo "[live-traffic-lab] artifacts: ${ARTIFACT_DIR}"
echo "[live-traffic-lab] capturing lo tcp port ${PORT}"
set +e
timeout 10 "${TCPDUMP[@]}" 2>"${TCPDUMP_STDERR}" &
tcpdump_pid=$!
set -e

sleep 1

python3 - "${PORT}" <<'PY'
import socket
import sys
import threading
import time

port = int(sys.argv[1])
marker = b"SURI_TUNER_LIVE_LOOPBACK_LAB"
received = []

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(1)
        conn, _ = s.accept()
        with conn:
            received.append(conn.recv(4096))

t = threading.Thread(target=server)
t.start()
time.sleep(0.2)
with socket.create_connection(("127.0.0.1", port), timeout=3) as c:
    c.sendall(b"GET / HTTP/1.1\r\nHost: loopback.lab\r\n\r\n" + marker + b"\r\n")
t.join(timeout=3)
if not received or marker not in received[0]:
    raise SystemExit("loopback server did not receive marker")
PY

if ! wait "${tcpdump_pid}"; then
  echo "[live-traffic-lab] tcpdump failed" >&2
  sed -n '1,120p' "${TCPDUMP_STDERR}" >&2 || true
  exit 1
fi

if [[ ! -s "${PCAP_PATH}" ]]; then
  echo "[live-traffic-lab] capture pcap is empty" >&2
  sed -n '1,120p' "${TCPDUMP_STDERR}" >&2 || true
  exit 1
fi

echo "[live-traffic-lab] running Suricata offline on captured pcap"
suricata -r "${PCAP_PATH}" -S "${RULE_PATH}" -l "${LOG_DIR}" -k none >"${ARTIFACT_DIR}/suricata.stdout" 2>"${ARTIFACT_DIR}/suricata.stderr"

if ! grep -q 'SuriTuner live loopback lab' "${LOG_DIR}/fast.log"; then
  echo "[live-traffic-lab] expected alert not found in fast.log" >&2
  echo "[live-traffic-lab] see ${ARTIFACT_DIR}" >&2
  exit 1
fi

echo "[live-traffic-lab] PASS"

if [[ "${CLEANUP}" -eq 1 ]]; then
  rm -rf "${ARTIFACT_DIR}"
fi
