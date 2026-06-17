# Operator Runbook

This runbook is for safe SuriTuner operation on a host running Suricata.

## Before You Start

Confirm the target interface is not the management interface unless you intend to use `--force`:

```bash
ip route show default
echo "$SSH_CONNECTION"
./surituner detect --iface <iface> --json | jq '.snapshot.safety'
```

Rules:

- Do not bind or bring down the default route interface during remote work.
- Do not run DPDK full apply on a management interface.
- Do not use VFIO no-IOMMU as production acceptance.
- Keep a shell open with root privileges during real apply/rollback windows.

## Safe Read-Only Checks

```bash
./surituner detect --iface <iface> --json | jq empty
./surituner plan --profile af-packet --iface <iface> --scope config-only --json | jq empty
./surituner report --iface <iface> --json | jq empty
```

For each profile:

```bash
./surituner plan --profile af-packet --iface <iface> --scope full --json | jq .
./surituner plan --profile pcap --iface <iface> --scope full --json | jq .
./surituner plan --profile nfq --iface <iface> --scope full --json | jq .
./surituner plan --profile dpdk --iface <iface> --scope full --json | jq .
./surituner plan --profile af-xdp --iface <iface> --scope full --json | jq .
```

## Config-Only Apply

This is the default apply mode.

```bash
sudo ./surituner apply --profile af-packet --iface <iface> --config-only --yes
sudo ./surituner rollback --state latest --yes
```

Expected:

- Apply creates a state file.
- `suricata -T` validation runs before live write.
- Service restarts and remains active.
- Rollback restores YAML and service state.

## OS Tuning Apply

Use only when NIC pre-state is available and interface disruption is acceptable.

```bash
./surituner plan --profile af-packet --iface <iface> --scope os-tuning --json | jq .
sudo ./surituner apply --profile af-packet --iface <iface> --os-tuning --yes
sudo ./surituner rollback --state latest --yes
```

Expected:

- No YAML validation.
- No Suricata restart.
- Rollback restores ethtool, sysctl, IRQ, promisc, and HugePages state as applicable.

## Full Apply

Full mode changes YAML, OS/NIC state, profile-specific state, systemd profile, and service state.

```bash
./surituner plan --profile <profile> --iface <iface> --scope full --json | jq .
sudo ./surituner apply --profile <profile> --iface <iface> --full --yes
sudo ./surituner rollback --state latest --yes
```

Use `--force` only after confirming the interface is safe to disrupt:

```bash
sudo ./surituner apply --profile <profile> --iface <iface> --full --force --yes
```

`--force` does not bypass hard blockers.

## DPDK Production Procedure

Prerequisites:

- Dedicated non-management NIC.
- IOMMU group present.
- `vfio-pci` available.
- Known rollback driver.

Check:

```bash
sudo ./scripts/check_dpdk_prereqs.sh --iface <iface>
sudo ./scripts/production_acceptance.sh --profile dpdk --iface <iface>
dpdk-devbind.py --status
ls -l /sys/class/net/<iface>/device/iommu_group
```

Apply:

```bash
./surituner plan --profile dpdk --iface <iface> --scope full --json | jq .
sudo ./surituner apply --profile dpdk --iface <iface> --full --yes
sudo ./surituner rollback --state latest --yes
```

Do not convert no-IOMMU lab success into production approval.

## AF_XDP Production Procedure

Prerequisites:

- Kernel supports AF_XDP.
- Interface-specific XDP signal exists.
- NIC/driver zero-copy capability is verified outside generic kernel-version checks.

Check:

```bash
./surituner detect --iface <iface> --json | jq '.snapshot.nic'
sudo ./scripts/production_acceptance.sh --profile af-xdp --iface <iface> --zero-copy-verified
./surituner plan --profile af-xdp --iface <iface> --scope full --json | jq .
```

Apply:

```bash
sudo ./surituner apply --profile af-xdp --iface <iface> --full --yes
sudo ./surituner rollback --state latest --yes
```

## Failed Apply

If apply fails:

1. Read the reported state path.
2. Check whether auto-rollback ran.
3. Inspect rollback records.

```bash
sudo jq '{status,error,applied,rollback}' /var/lib/surituner/state/<state>.json
systemctl is-active suricata.service
sudo suricata -T -c /etc/suricata/suricata.yaml
```

If state is `rollback_partial_after_failure`, do not retry full apply until the failed rollback record is understood and manually repaired.

## Final Health Checks

```bash
systemctl is-active suricata.service
sudo suricata -T -c /etc/suricata/suricata.yaml
./surituner report --iface <iface> --json | jq .
```

Watch after apply:

- `capture.kernel_drops`
- `rx_dropped`
- `rx_missed_errors`
- `tcp.reassembly_gap`
- Suricata worker CPU balance

## One-Command Target Acceptance

Use this on the target host during the final maintenance window:

```bash
sudo ./scripts/production_acceptance.sh --profile <profile> --iface <iface>
sudo ./scripts/production_acceptance.sh --profile <profile> --iface <iface> --apply-full --traffic-ready
```

For AF_XDP zero-copy acceptance:

```bash
sudo ./scripts/production_acceptance.sh --profile af-xdp --iface <iface> --zero-copy-verified --apply-full --traffic-ready
```

For the full step-by-step maintenance-window procedure, use [Target Acceptance Scenario](TARGET_ACCEPTANCE_SCENARIO.md).

Before cutting or shipping a build, use [Pre-Release Checklist](PRE_RELEASE_CHECKLIST.md).
