# Production Readiness

This document separates what is complete in this repository from what still requires external hardware.

## Ready Now

- CLI commands: `detect`, `plan`, `apply`, `rollback`, `report`.
- Safe apply scopes:
  - default apply is `--config-only`;
  - `--os-tuning`;
  - `--full`.
- `plan` is dry-run and does not write config, state, sysctl, NIC, firewall, HugePages, IRQ, or systemd state.
- `apply` rejects non-root before collector, planner, state, config writes, or live changes.
- State is written before live changes.
- Rollback uses reverse order of applied live actions.
- Shell command execution in Go uses argv arrays via `exec.CommandContext`.
- Management guardrail treats an interface as management-risk when it matches either SSH interface or default route interface.
- Config-only on management interface remains allowed.
- `--force` bypasses guardrail blockers only; hard blockers remain non-overridable.
- Supported profiles: `af-packet`, `dpdk`, `af-xdp`, `nfq`, `pcap`.
- YAML tuning:
  - AF_PACKET/DPDK use `workers`;
  - NFQ/PCAP use `autofp`;
  - PCAP writes a `pcap` interface section;
  - Suricata-valid exception policies are used: `drop-flow`, `pass-flow`, `ignore`.
- DPDK preflight remains strict for production full apply: Suricata DPDK support, PCI address, `dpdk-devbind.py`, vfio-pci bind readiness, rollback driver, and IOMMU group.
- AF_XDP preflight is split into kernel support, interface XDP signal, legacy compatibility flag, and zero-copy proof field.
- Warning actions remain in plans/state but are not counted as applied live actions.

## Verified In This VM

- Unit tests, race tests, vet, gofmt, build, module verify, and shell syntax checks passed.
- PCAP config-only/full plans and real config-only apply+rollback on `ens37` passed.
- AF_PACKET full on management interface `ens33` is blocked by guardrails.
- DPDK full on `ens37` remains hard-blocked by missing IOMMU group.
- Non-root offline traffic lab with generated TCP/HTTP pcap and Suricata alert can be run with `./scripts/traffic_pcap_lab.sh`.
- Live loopback traffic capture with tcpdump privileges can be run with `./scripts/traffic_live_loopback_lab.sh`.
- Unsafe DPDK no-IOMMU lab on non-management `ens37`:
  - `ens37` was temporarily bound to `vfio-pci`;
  - `dpdk-testpmd --iova-mode=pa` opened Port 0 using `net_e1000_em`;
  - `dpdk-pdump` attached and wrote a header-only pcap because the interface had `NO-CARRIER`;
  - cleanup restored `ens37` to `e1000`, cleared HugePages, and left default route on `ens33`.

The no-IOMMU lab is useful evidence that DPDK can operate in this VM, but it is not production acceptance because VFIO no-IOMMU removes DMA isolation.

## Not Possible To Close In This VM

### DPDK Production Full Apply

Why it cannot be closed here:

- `ens37` has no `/sys/class/net/ens37/device/iommu_group`.
- SuriTuner intentionally hard-blocks DPDK full mode without an IOMMU group.
- Using VFIO no-IOMMU would weaken the safety model and must not be treated as production readiness.

Needed:

- Dedicated non-management PCI NIC.
- IOMMU enabled in BIOS/UEFI and kernel.
- `/sys/class/net/<iface>/device/iommu_group` present.
- `dpdk-devbind.py --status` shows the NIC with a known kernel driver and `unused=vfio-pci`, or already bound to `vfio-pci` with an explicit operational rollback plan.
- Maintenance window where driver rebinding and Suricata restart are acceptable.

Acceptance:

```bash
sudo ./scripts/check_dpdk_prereqs.sh --iface <capture_iface>
sudo ./scripts/production_acceptance.sh --profile dpdk --iface <capture_iface>
./surituner plan --profile dpdk --iface <capture_iface> --scope full --json | jq .
sudo ./surituner apply --profile dpdk --iface <capture_iface> --full --yes
sudo ./surituner rollback --state latest --yes
dpdk-devbind.py --status
systemctl is-active suricata.service
```

Pass criteria:

- Full plan is not hard-blocked.
- Apply reaches `applied`.
- Rollback reaches `rolled_back`.
- NIC is restored to the expected driver.
- Suricata service is active.
- Rollback records have no failures.

### AF_XDP Hardware Zero-Copy

Why it cannot be closed here:

- This VM does not prove hardware zero-copy support.
- Kernel support alone is not enough.
- Interface-specific XDP signal and driver/NIC zero-copy capability must be validated on suitable hardware.

Needed:

- NIC and driver known to support AF_XDP.
- Kernel with AF_XDP support.
- Interface-specific XDP signal.
- Maintenance window where XDP can affect normal interface networking.

Acceptance:

```bash
./surituner detect --iface <capture_iface> --json | jq '.snapshot.nic'
sudo ./scripts/production_acceptance.sh --profile af-xdp --iface <capture_iface> --zero-copy-verified
./surituner plan --profile af-xdp --iface <capture_iface> --scope full --json | jq .
sudo ./surituner apply --profile af-xdp --iface <capture_iface> --full --yes
sudo ./surituner rollback --state latest --yes
```

Pass criteria:

- Full plan is not hard-blocked.
- AF_XDP critical warning appears in the plan.
- Apply reaches `applied`.
- Rollback reaches `rolled_back`.
- Hardware zero-copy is verified by appropriate driver/tooling or traffic evidence.

## Release Gate

Before calling a build production-ready for a target environment:

```bash
make ci-full
./scripts/e2e_fake_cli.sh
./scripts/traffic_pcap_lab.sh
./scripts/package_release.sh --version snapshot
```

Optional when installed:

```bash
golangci-lint run ./...
```

Use [Pre-Release Checklist](PRE_RELEASE_CHECKLIST.md) for the full local, GitHub, and target-host gate.

For the final target-host gate, use:

```bash
sudo ./scripts/production_acceptance.sh --profile <profile> --iface <capture_iface>
sudo ./scripts/production_acceptance.sh --profile <profile> --iface <capture_iface> --apply-full --traffic-ready
```

Use [Target Acceptance Scenario](TARGET_ACCEPTANCE_SCENARIO.md) for the full maintenance-window procedure.
