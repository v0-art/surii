#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/traffic_pcap_lab.sh [--artifact-dir <dir>] [--cleanup]

Generates a deterministic TCP/HTTP pcap, runs Suricata offline against a local
test rule, and verifies that the packet is decoded and alerted.

This is a non-root traffic lab. It validates Suricata packet/rule processing,
not live NIC capture, DPDK bind safety, AF_XDP zero-copy, or hardware drop
counters.
EOF
}

ARTIFACT_DIR=""
CLEANUP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
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
    echo "[traffic-lab] required command not found: $1" >&2
    exit 1
  }
}

need_cmd python3
need_cmd suricata

if [[ -z "${ARTIFACT_DIR}" ]]; then
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  ARTIFACT_DIR="$(mktemp -d "/tmp/surituner-traffic-pcap-lab-${TS}.XXXXXX")"
else
  mkdir -p "${ARTIFACT_DIR}"
fi
mkdir -p "${ARTIFACT_DIR}/log"

PCAP_PATH="${ARTIFACT_DIR}/traffic-lab.pcap"
RULE_PATH="${ARTIFACT_DIR}/traffic-lab.rules"
LOG_DIR="${ARTIFACT_DIR}/log"

python3 - "${PCAP_PATH}" <<'PY'
import struct
import sys
import time

path = sys.argv[1]
payload = b"GET /SURI_TUNER_TRAFFIC_LAB HTTP/1.1\r\nHost: lab.local\r\n\r\n"

eth_dst = b"\x02\x00\x00\x00\x00\x02"
eth_src = b"\x02\x00\x00\x00\x00\x01"
eth_type = b"\x08\x00"

version_ihl = 0x45
tos = 0
total_len = 20 + 20 + len(payload)
ident = 1
flags_frag = 0x4000
ttl = 64
proto = 6
ip_checksum = 0
src = bytes([10, 0, 0, 1])
dst = bytes([10, 0, 0, 2])
ip = struct.pack("!BBHHHBBH4s4s", version_ihl, tos, total_len, ident, flags_frag, ttl, proto, ip_checksum, src, dst)

sport = 12345
dport = 8080
seq = 1
ack = 0
data_offset = 5 << 4
flags = 0x18
window = 65535
tcp_checksum = 0
urg = 0
tcp = struct.pack("!HHLLBBHHH", sport, dport, seq, ack, data_offset, flags, window, tcp_checksum, urg)

packet = eth_dst + eth_src + eth_type + ip + tcp + payload

with open(path, "wb") as f:
    f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    f.write(struct.pack("<IIII", int(time.time()), 0, len(packet), len(packet)))
    f.write(packet)
PY

cat >"${RULE_PATH}" <<'EOF'
alert tcp any any -> any 8080 (msg:"SuriTuner traffic lab"; content:"SURI_TUNER_TRAFFIC_LAB"; sid:9000001; rev:1;)
EOF

echo "[traffic-lab] artifacts: ${ARTIFACT_DIR}"
echo "[traffic-lab] running Suricata offline"
suricata -r "${PCAP_PATH}" -S "${RULE_PATH}" -l "${LOG_DIR}" -k none >"${ARTIFACT_DIR}/suricata.stdout" 2>"${ARTIFACT_DIR}/suricata.stderr"

if ! grep -q 'SuriTuner traffic lab' "${LOG_DIR}/fast.log"; then
  echo "[traffic-lab] expected alert not found in fast.log" >&2
  echo "[traffic-lab] see ${ARTIFACT_DIR}" >&2
  exit 1
fi

if ! grep -q '"event_type":"alert"' "${LOG_DIR}/eve.json"; then
  echo "[traffic-lab] expected alert event not found in eve.json" >&2
  echo "[traffic-lab] see ${ARTIFACT_DIR}" >&2
  exit 1
fi

echo "[traffic-lab] PASS"

if [[ "${CLEANUP}" -eq 1 ]]; then
  rm -rf "${ARTIFACT_DIR}"
fi
