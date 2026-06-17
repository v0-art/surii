# Target Acceptance Scenario

This scenario is for the final maintenance window on the real Suricata host.

## Preconditions

- You are on the target host with root access.
- The selected interface is a dedicated capture interface, not the default route or SSH management interface.
- Traffic is available through a mirror, tap, or generator.
- Rollback ownership is clear: who can restore networking, driver binding, and service state if the host becomes unhealthy.
- The release artifact was unpacked and `./surituner` is executable.

## Phase 1: Identify The Interface

```bash
ip route show default
echo "$SSH_CONNECTION"
ip -br link
./surituner detect --iface <capture_iface> --json | tee detect.json | jq '.snapshot.safety,.snapshot.nic'
```

Stop if `.snapshot.safety.is_management_iface` is `true` unless the maintenance plan explicitly allows `--force`.

## Phase 2: Read-Only Plans

```bash
./surituner plan --profile af-packet --iface <capture_iface> --scope full --json | tee plan-af-packet-full.json | jq '{blocked,hard_blocked,blocking_reasons}'
./surituner plan --profile pcap --iface <capture_iface> --scope full --json | tee plan-pcap-full.json | jq '{blocked,hard_blocked,blocking_reasons}'
./surituner plan --profile nfq --iface <capture_iface> --scope full --json | tee plan-nfq-full.json | jq '{blocked,hard_blocked,blocking_reasons}'
./surituner plan --profile dpdk --iface <capture_iface> --scope full --json | tee plan-dpdk-full.json | jq '{blocked,hard_blocked,blocking_reasons}'
./surituner plan --profile af-xdp --iface <capture_iface> --scope full --json | tee plan-af-xdp-full.json | jq '{blocked,hard_blocked,blocking_reasons}'
```

Pass criteria:

- The intended profile is not hard-blocked.
- Any management guardrail bypass is documented before using `--force`.
- DPDK full has an IOMMU group and bind readiness.
- AF_XDP full has interface-specific XDP signal and external zero-copy proof.

## Phase 3: Production Acceptance Preflight

```bash
sudo ./scripts/production_acceptance.sh --profile <profile> --iface <capture_iface>
```

If you need a quick non-root packet/rule sanity check before touching live interfaces:

```bash
./scripts/traffic_pcap_lab.sh
```

This confirms Suricata can decode and alert on a generated pcap. It does not validate live capture or NIC counters.

If tcpdump privileges are available and you want a local live-port sanity check:

```bash
./scripts/traffic_live_loopback_lab.sh
```

This sends real TCP traffic over loopback and validates Suricata alerting from the captured pcap.

For DPDK:

```bash
sudo ./scripts/check_dpdk_prereqs.sh --iface <capture_iface>
sudo ./scripts/production_acceptance.sh --profile dpdk --iface <capture_iface>
```

For AF_XDP:

```bash
sudo ./scripts/production_acceptance.sh --profile af-xdp --iface <capture_iface> --zero-copy-verified
```

Stop on any hard blocker. Do not convert VFIO no-IOMMU lab success into production approval.

## Phase 4: Live Apply And Rollback Proof

Default pattern:

```bash
sudo ./scripts/production_acceptance.sh --profile <profile> --iface <capture_iface> --apply-full --traffic-ready
```

AF_XDP zero-copy:

```bash
sudo ./scripts/production_acceptance.sh --profile af-xdp --iface <capture_iface> --zero-copy-verified --apply-full --traffic-ready
```

If the interface is intentionally management-risk and approved for disruption:

```bash
sudo ./scripts/production_acceptance.sh --profile <profile> --iface <capture_iface> --force --allow-management --apply-full --traffic-ready
```

Pass criteria:

- Apply reaches state `applied`.
- Rollback reaches state `rolled_back`.
- No rollback record has `status=="failed"`.
- `suricata.service` is active after rollback.
- The NIC is restored to the expected driver and link state.

## Phase 5: Post-Apply Observation

If the final operation keeps the profile applied, run:

```bash
systemctl is-active suricata.service
sudo suricata -T -c /etc/suricata/suricata.yaml
./surituner report --iface <capture_iface> --json | tee report-after-apply.json | jq .
```

Watch at least one traffic interval:

- `capture.kernel_drops`
- `rx_dropped`
- `rx_missed_errors`
- `tcp.reassembly_gap`
- worker CPU balance
- Suricata service restarts or watchdog events

## Evidence To Keep

- The release tarball and `sha256sums.txt`.
- `detect.json`.
- Full plan JSON for the chosen profile.
- Production acceptance artifact directory.
- State files under `/var/lib/surituner/state`.
- Any manual zero-copy or DPDK driver evidence.
