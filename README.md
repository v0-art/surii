# SuriTuner

SuriTuner is a local Safe Decision Engine for hardware-aware Suricata 7.x/8.x tuning.

It inspects the host, builds a dry-run plan, applies only validated changes, stores rollback state, and can restore Suricata/OS/NIC settings best-effort from that state.

## Status

Current implementation status against the approved v1 requirements: production-candidate at code/test level.

What is covered locally:

- CLI commands: `detect`, `plan`, `apply`, `rollback`, `report`.
- `apply` scopes: default `--config-only`, explicit `--os-tuning`, explicit `--full`.
- Detect/preflight for Suricata build-info, DPDK, AF_XDP, NFQ, hwloc, CPU/NUMA, NIC driver, PCI address, RSS queues, NIC NUMA node, ruleset inventory, default route, SSH management interface best-effort.
- Planner actions with summary, reason, risk level, apply command, rollback command.
- Risk levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- Management-interface guardrails for OS/NIC/firewall/capture-driver actions unless `--force`.
- YAML tuning for runmode, hwloc autopin, CPU affinity fallback, memcaps, max-pending-packets, exception policies, and `run-as` hardening.
- OS/NIC tuning actions for GRO/LRO, ring buffers, RSS combined queues, IRQ affinity, sysctl buffers, promiscuous mode.
- Capture profile logic for AF_PACKET, DPDK, AF_XDP, NFQ, and PCAP.
- Transactional apply: root check, state file before live changes, YAML backup, temporary YAML, `suricata -T`, live write after validation, systemd restart/status check, auto-rollback.
- State and rollback model under `/var/lib/surituner/state`.
- Human and JSON report output.
- Unit/integration-style tests for planner, YAML tuner, state, executor, rollback, JSON, root checks, and management-interface safety.

What has also been verified on this host:

- Safe real-host smoke on Suricata 8.0.3, `ens33`, AF_PACKET, `config-only apply + rollback`: PASS.
- Additional real-host `config-only apply + rollback` checks for AF_XDP, NFQ, and DPDK: PASS.
- Real AF_PACKET `--full --force apply + rollback` on `ens33`: PASS, including OS/NIC tuning, IRQ affinity, systemd drop-in, service restart, YAML restore, and OS/NIC rollback.
- Real NFQ `--full --force` failure transaction on `ens33`: PASS. Apply failed at the missing `nft inet filter forward` chain and auto-rollback restored YAML, OS/NIC settings, and service state without rollback errors.
- A non-management lab veth pair `suri0`/`suri1` was created inside the VM for isolated interface tests. Default route remained on `ens33`; `suri0` is not detected as the management interface.
- AF_PACKET full apply on `suri0` was refused before live changes because veth has no parseable ring-buffer pre-state and no IRQ affinity pre-state. The resulting state had zero applied actions, which confirms pre-state safety on unsupported virtual interfaces.
- A second VM NIC `ens37` was found and verified as non-management/host-only: default route and SSH management remain on `ens33`.
- DPDK tooling was installed for lab checks (`dpdk-devbind.py` present), `vfio-pci` was loaded, and `dpdk.service` autostart was disabled to avoid boot-time DPDK runtime side effects.
- DPDK `config-only apply + rollback` and `os-tuning apply + rollback` on `ens37`: PASS.
- DPDK `full` on `ens37` correctly hard-blocks before live bind because the VM does not expose an IOMMU group for PCI `0000:02:05.0`.
- The smoke created state, validated tuned YAML with `suricata -T`, restarted and checked `suricata.service`, rolled back YAML, validated restored YAML, restarted and checked service again.
- Full apply on `ens33` was blocked by management-interface guardrails as expected.
- Real dry-run matrix for `af-packet`, `dpdk`, `af-xdp`, and `nfq` across `config-only`, `os-tuning`, and `full` was checked against scope separation, hard blockers, and management-interface guardrails.

What still must be verified on an IOMMU-capable dedicated capture NIC:

- DPDK full bind/unbind with `/sys/class/net/<iface>/device/iommu_group` present and `dpdk-devbind.py --status` showing `unused=vfio-pci`.
- Hardware-specific AF_XDP zero-copy support, RSS symmetry, and NUMA hugepage restore on production-like hardware.

## Build

The repository uses Go. In this workspace the normal `go` binary is not in `PATH`; the Makefile points at the local toolchain:

```bash
/home/vol/.local/go/bin/go version
/home/vol/.local/go/bin/go build -o surituner ./cmd/surituner
```

If Go is already in `PATH`, this also works:

```bash
go build -o surituner ./cmd/surituner
```

## User Guide

### Basic Commands

```bash
./surituner detect --iface eth0
./surituner plan --profile af-packet --iface eth0 --scope config-only
sudo ./surituner apply --profile af-packet --iface eth0 --config-only --yes
sudo ./surituner rollback --state latest --yes
./surituner report --iface eth0
```

JSON output is available for `detect`, `plan`, and `report`:

```bash
./surituner detect --iface eth0 --json
./surituner plan --profile af-packet --iface eth0 --scope full --json
./surituner report --iface eth0 --json
```

### Profiles

Supported capture profiles:

- `af-packet`
- `dpdk`
- `af-xdp`
- `nfq`
- `pcap`

Examples:

```bash
./surituner plan --profile af-packet --iface eth0 --scope full
./surituner plan --profile dpdk --iface ens5f0 --scope full
./surituner plan --profile af-xdp --iface ens5f0 --scope full
./surituner plan --profile nfq --iface eth0 --scope full --ips-mode strict
./surituner plan --profile pcap --iface eth0 --scope full
```

### Apply Scopes

`apply` is safe-by-default:

```bash
sudo ./surituner apply --profile af-packet --iface eth0 --yes
```

That is the same as:

```bash
sudo ./surituner apply --profile af-packet --iface eth0 --config-only --yes
```

Scopes are mutually exclusive:

- `--config-only`: tune `suricata.yaml`, validate with `suricata -T`, then restart/check `suricata.service`.
- `--os-tuning`: apply OS/NIC tuning only. It does not validate YAML and does not restart Suricata.
- `--full`: apply YAML tuning, OS/NIC tuning, profile-specific actions, and systemd capture profile drop-in.

Examples:

```bash
sudo ./surituner apply --profile af-packet --iface eth0 --config-only --yes
sudo ./surituner apply --profile af-packet --iface eth0 --os-tuning --yes
sudo ./surituner apply --profile af-packet --iface eth0 --full --yes
```

### IPS Modes

Supported IPS modes use Suricata-valid exception-policy names while preserving the v1 intent:

- `strict`: fail-close behavior. YAML uses `exception-policy: drop-flow`; NFQ uses `fail-open: false`.
- `availability`: fail-open behavior. YAML uses `exception-policy: pass-flow`; NFQ uses `fail-open: true`.
- `ids`: non-IPS behavior. YAML uses `exception-policy: ignore`; NFQ `fail-open` is removed.

Defaults:

- NFQ defaults to `strict`.
- Other profiles, including PCAP, default to `ids`.

### Detect

`detect` collects a read-only host snapshot:

- Suricata version and build capabilities from `suricata --build-info`.
- DPDK, AF_XDP, NFQ, and hwloc/autopin support.
- CPU and NUMA topology.
- NIC driver, PCI address, queues, RSS channel data, RSS symmetry signal, NUMA node, offload flags, promisc state.
- DPDK preflight: `dpdk-devbind.py`, PCI status line, current driver, vfio-pci availability, rollback driver, IOMMU group.
- AF_XDP preflight: interface presence, kernel >= 4.18, interface-specific XDP signal from `ip -details`, and an explicit note that hardware zero-copy is not proven by the generic probe.
- Ruleset inventory: `suricata-update`, total/enabled rules, PCRE-heavy rules, rule sources, rules file size, update timestamp.
- Safety guardrails: default route interface and SSH management interface best-effort via `SSH_CONNECTION`, `ss`, and routing table.

Example:

```bash
./surituner detect --iface eth0 --json
```

### Plan

`plan` is a dry-run. It does not write Suricata config, state files, sysctls, NIC settings, firewall rules, systemd files, hugepages, or IRQ affinity.

Each action contains:

- summary
- reason
- risk level
- apply command
- rollback command
- guardrail status

Example:

```bash
./surituner plan --profile af-packet --iface eth0 --scope full
```

Use `--force` only when you intentionally bypass management-interface guardrails:

```bash
./surituner plan --profile af-packet --iface eth0 --scope full --force
sudo ./surituner apply --profile af-packet --iface eth0 --full --force --yes
```

Capability hard-blocks are not bypassed by `--force`.

### Apply

`apply` requires root. It refuses to start without root before planning or writing state.

Before live changes, it:

1. Captures rollback pre-state.
2. Creates the state file under `/var/lib/surituner/state`.
3. Validates that required rollback pre-state exists for OS/NIC actions.
4. Builds tuned YAML in memory.
5. Writes a temporary YAML.
6. Runs `suricata -T -c <temp-yaml>`.
7. Creates and persists YAML backup metadata.
8. Applies live changes only after validation.

For config/full applies that change YAML, it restarts and checks `suricata.service`.

If a live action fails, SuriTuner attempts auto-rollback of already applied actions in reverse order.

### Rollback

Rollback requires root.

```bash
sudo ./surituner rollback --state latest --yes
sudo ./surituner rollback --state /var/lib/surituner/state/20260525T120000.000000000Z.json --yes
```

Rollback restores, best-effort:

- `suricata.yaml` from backup with SHA256 verification.
- ethtool offload flags from captured `ethtool -k`.
- ring buffers from captured `ethtool -g`.
- RSS combined queues from captured `ethtool -l`.
- sysctl values.
- IRQ affinity.
- promiscuous mode.
- HugePages and per-NUMA HugePages.
- NFQ firewall rules inserted by SuriTuner.
- DPDK bind rollback when a validated previous driver is known.
- SuriTuner systemd drop-in state.
- Suricata service state after YAML restore when the previous state was known.

State files are trust-checked before rollback:

- state selector must be `latest` or an absolute path inside the configured state dir;
- file must be a direct `.json` state file;
- symlinks are rejected;
- group/world-readable state files are rejected.

### Report

`report` prints a current host report and, when available, latest planned/applied action IDs from state.

It includes:

- hardware and Suricata summary;
- capabilities;
- unsupported options;
- bottlenecks;
- runtime acceptance signals from `stats.log` and `ethtool -S`;
- monitoring recommendations.

```bash
./surituner report --iface eth0
./surituner report --iface eth0 --json
```

## Safety Model

### Management Interface Protection

SuriTuner detects the management interface best-effort from:

- default route;
- `SSH_CONNECTION`;
- `ss -tnp`;
- `ip route get <remote-ip>`.

An interface is treated as management-risk when it matches either the SSH management interface or the default route interface. On the management interface, risky OS/NIC/firewall/capture-driver actions are blocked unless `--force` is explicitly provided.

Config-only YAML changes remain allowed.

### Command Execution

SuriTuner uses `exec.CommandContext` with argv arrays, not shell strings.

When running as root, command lookup is restricted to trusted system directories:

- `/usr/sbin`
- `/usr/bin`
- `/sbin`
- `/bin`
- `/usr/local/sbin`
- `/usr/local/bin`

Interface names and paths are validated before use.

### State Files

Default state path:

```text
/var/lib/surituner/state/<timestamp>.json
```

Permissions:

- state directory: `0700`
- state files: `0600`
- YAML backup files: `0600`

State includes:

- backup YAML path and SHA256;
- host fingerprint;
- metadata, profile, scope, IPS mode, interface, config path;
- full detection snapshot;
- pre-state for ethtool, sysctl, IRQ affinity, irqbalance, promisc, HugePages, systemd service status;
- plan actions with apply/rollback commands;
- applied command records;
- rollback command records;
- final status/error.

## Capture Profile Details

### AF_PACKET

- YAML runmode: `workers`.
- Uses `cluster_qm` only when symmetric RSS is explicitly detected.
- Falls back to `cluster_flow` when RSS is unknown or not proven symmetric.

### DPDK

- Requires Suricata DPDK build support.
- Requires NIC PCI address.
- Requires `dpdk-devbind.py --status` preflight.
- Requires vfio-pci bind readiness and rollback driver knowledge unless already bound.
- Requires detectable IOMMU group.
- Uses NUMA-local HugePages action in full mode.

For a real DPDK full apply, the capture NIC must be separate from management traffic and the host/VM must expose an IOMMU group:

```bash
sudo ./scripts/check_dpdk_prereqs.sh --iface <capture_iface> --install-tools
ls -l /sys/class/net/<capture_iface>/device/iommu_group
sudo dpdk-devbind.py --status
```

The expected ready shape is:

- `dpdk-devbind.py` is present.
- `vfio-pci` appears in the device `unused=` list.
- `iommu_group` exists for the PCI device.
- SuriTuner `plan --profile dpdk --scope full` is not hard-blocked.

In this VM, `ens37` is safe as a non-management test NIC, but DPDK full remains correctly hard-blocked because `0000:02:05.0` has no IOMMU group.

### AF_XDP

- Requires Suricata AF_XDP build support.
- Config-only requires Suricata AF_XDP build support and kernel support.
- Full mode requires kernel support plus an interface-specific XDP signal; kernel version alone is not treated as full AF_XDP readiness.
- Emits an explicit CRITICAL warning that AF_XDP may reduce or remove standard network use of the interface.
- Uses HugePages for unaligned chunks in full mode.
- Reports that hardware zero-copy support is not verified unless proven by hardware/tooling outside the generic preflight.

### NFQ

- Requires Suricata NFQ build support.
- Requires detected `nftables` or `iptables` backend for full NFQ queue rules.
- YAML runmode: `autofp`.
- Adds an NFQUEUE rule for queue `0`.
- `nftables` rules are tagged with a SuriTuner comment and verified after insert.

### PCAP

- Does not require DPDK, AF_XDP, or NFQ Suricata build capabilities.
- YAML runmode: `autofp`.
- YAML configures a `pcap` interface entry for the target interface.
- Config-only applies YAML only.
- Full mode includes YAML, normal OS/NIC tuning, and a systemd profile using Suricata live PCAP capture with `-i <iface>`.

## Developer Guide

### Project Layout

```text
cmd/surituner/main.go              CLI entrypoint
internal/surituner/cli.go          command parsing and top-level command behavior
internal/surituner/collector.go    detect/preflight collection
internal/surituner/planner.go      plan generation, risks, scopes, guardrails
internal/surituner/yaml_tuner.go   YAML tuning and backups
internal/surituner/executor.go     apply transaction, command execution, auto-rollback helpers
internal/surituner/rollback.go     manual rollback orchestration
internal/surituner/state.go        state path, save/load, trust checks
internal/surituner/reporter.go     human/JSON output and recommendations
internal/surituner/runner.go       command runner and trusted executable lookup
internal/surituner/validation.go   CLI input validation
scripts/ci.sh                      local CI checks
scripts/e2e_real_smoke.sh          real-host smoke test
scripts/install_suricata.sh        Debian/Ubuntu Suricata setup helper
scripts/check_dpdk_prereqs.sh      safe DPDK tooling/preflight helper, no bind/unbind
```

### Local Checks

In this workspace use the local Go toolchain and writable caches:

```bash
GOCACHE=/tmp/go-build-cache /home/vol/.local/go/bin/go test ./...
GOCACHE=/tmp/go-build-cache /home/vol/.local/go/bin/go vet ./...
/home/vol/.local/go/bin/gofmt -l .
GOCACHE=/tmp/go-build-cache /home/vol/.local/go/bin/go build ./cmd/surituner
ZIG_LOCAL_CACHE_DIR=/tmp/zig-cache \
ZIG_GLOBAL_CACHE_DIR=/tmp/zig-global-cache \
GOCACHE=/tmp/go-build-cache \
CC="/home/vol/.local/zig/current/zig cc" \
CXX="/home/vol/.local/zig/current/zig c++" \
CGO_ENABLED=1 \
/home/vol/.local/go/bin/go test -race ./...
```

If `make` is available:

```bash
make ci
make race
```

`golangci-lint` is optional. Run it only when installed:

```bash
golangci-lint run ./...
```

### Current Local Verification

Last local verification in this workspace:

- 2026-05-26 v1 completion checks:
  - `/home/vol/.local/go/bin/go test ./...`: PASS.
  - `CGO_ENABLED=1 CC="/home/vol/.local/zig/current/zig cc" CXX="/home/vol/.local/zig/current/zig c++" /home/vol/.local/go/bin/go test -race ./...`: PASS. Plain `go test -race` without cgo/toolchain env fails in this VM because `gcc` is not installed.
  - `/home/vol/.local/go/bin/go vet ./...`: PASS.
  - `/home/vol/.local/go/bin/gofmt -l .`: PASS, empty output.
  - `/home/vol/.local/go/bin/go build -o surituner ./cmd/surituner`: PASS.
  - `/home/vol/.local/go/bin/go mod verify`: PASS.
  - `bash -n scripts/*.sh`: PASS.
  - `golangci-lint`: not run because the binary is not installed.
- PCAP JSON checks on `ens37`: config-only and full plans parse with `jq empty`; config-only has only `yaml-tuning`; full includes YAML, OS/NIC actions, and `systemd-profile` with `-i ens37`.
- Management guardrail check: `af-packet --iface ens33 --scope full` is blocked on management interface, including OS/NIC actions and `systemd-profile`.
- DPDK `ens37` full remains hard-blocked by missing IOMMU group/readiness in this VM.
- `detect --iface ens37 --json` and `report --iface ens37 --json` parse with `jq empty`.
- Non-root `apply --profile pcap --iface ens37 --config-only --yes` refuses before planning with `this command requires root privileges`.
- Real safe PCAP config-only apply and rollback on `ens37`: `/var/lib/surituner/state/20260526T151125.997723793Z.json`, final status `rolled_back`, all rollback records `ok`; `suricata.service` remained `active` and `suricata -T -c /etc/suricata/suricata.yaml` passes after rollback.
- AF_XDP `ens37` full is now hard-blocked because this VM shows kernel support but no interface-specific XDP signal; hardware zero-copy remains hardware-verification only.
- `go version`: not available in `PATH`.
- `/home/vol/.local/go/bin/go version`: `go1.26.3 linux/amd64`.
- `make`: not installed in this VM; final continuation checks were run with direct Go commands.
- `go test ./...`: PASS with `GOCACHE=/tmp/go-build-cache`.
- `go test -race ./...`: PASS with Zig and caches under `/tmp`.
- `go vet ./...`: PASS.
- `gofmt -l .`: PASS, empty output.
- `go build ./cmd/surituner`: PASS.
- `plan --json | jq empty`: PASS.
- `report --json | jq empty`: PASS.
- non-root `apply`: exits with `this command requires root privileges`.
- `sudo ./scripts/e2e_real_smoke.sh --iface ens33`: PASS for safe config-only apply, rollback, JSON checks, and management-interface guardrail assertion. Latest artifact: `/tmp/surituner-e2e-20260525T150922Z`.
- Latest smoke state: `/var/lib/surituner/state/20260525T150923.729172185Z.json`, status `rolled_back`, all rollback records `ok`.
- Additional profile config-only states:
  - AF_XDP: `/var/lib/surituner/state/20260525T152426.729641239Z.json`, status `rolled_back`, all rollback records `ok`.
  - NFQ: `/var/lib/surituner/state/20260525T152528.172012317Z.json`, status `rolled_back`, all rollback records `ok`.
  - DPDK: `/var/lib/surituner/state/20260525T152634.377556496Z.json`, status `rolled_back`, all rollback records `ok`.
- Latest DPDK `ens37` config-only state after DPDK tooling install: `/var/lib/surituner/state/20260526T142343.518558532Z.json`, status `rolled_back`, 1 applied action, 4 rollback records, all rollback records `ok`.
- Latest DPDK `ens37` os-tuning state: `/var/lib/surituner/state/20260526T142503.887135814Z.json`, status `rolled_back`, 6 applied actions, 6 rollback records, all rollback records `ok`; ring, sysctl, and promiscuous mode were restored.
- `sudo ./scripts/check_dpdk_prereqs.sh --iface ens37`: PASS; reports `dpdk-devbind.py` present, `unused=vfio-pci`, rollback driver `e1000`, and expected hard-block due to missing IOMMU group.
- DPDK `ens37` full apply with `--force`: correctly refused before live changes with non-overridable DPDK blockers; NIC stayed bound to `e1000`, ring/sysctl/promisc stayed restored, and `suricata.service` stayed `active`.
- AF_PACKET full state: `/var/lib/surituner/state/20260525T154301.499029222Z.json`, status `rolled_back`, 8 applied actions, 11 rollback records, all rollback records `ok`.
- NFQ full failure state: `/var/lib/surituner/state/20260525T154527.193498144Z.json`, status `rolled_back_after_failure`, failed at missing `nft inet filter forward` chain, 10 rollback records, all rollback records `ok`.
- Lab veth pre-state safety state: `/var/lib/surituner/state/20260525T160310.461230908Z.json`, status `failed`, zero applied actions, failure before live changes due to missing `ethtool -g` and IRQ pre-state on `suri0`.
- Real plan matrix on `ens33`: config-only plans are unblocked where build/interface preflight allows them; OS/full plans are blocked by management-interface guardrails; DPDK full additionally preserves non-bypassable DPDK preflight blockers.
- Root negative apply checks: AF_PACKET full without `--force` is blocked before live changes; DPDK full with `--force` still refuses hard capability blockers; rollback with an outside state path is rejected.
- Root state trust checks: world-readable state files and symlink state files are rejected before rollback.
- `go test -count=1 ./...`: PASS.
- `go test -cover ./...`: PASS, `internal/surituner` coverage 66.7%.
- `go mod verify`: PASS.
- `bash -n scripts/*.sh`: PASS.
- `govulncheck` via `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`: PASS, no vulnerabilities found.
- `suricata.service` after smoke: `active`.
- `surituner-profile.conf` systemd drop-in after full rollback: absent; only the e2e timeout drop-in remains.
- Post-rollback `ens33` checks after full apply/failure tests: ring RX/TX restored to `256`, promiscuous mode off, sysctl buffer values restored, and `suricata -T -c /etc/suricata/suricata.yaml` passes.
- `golangci-lint`: not run because the binary is not installed.

### Lab Veth Interface

For non-management interface tests inside a VM, a temporary veth pair can be created:

```bash
sudo ip link add suri0 type veth peer name suri1
sudo ip addr add 10.250.0.1/30 dev suri0
sudo ip addr add 10.250.0.2/30 dev suri1
sudo ip link set suri0 up
sudo ip link set suri1 up
```

This is useful for guardrail and pre-state tests, but it is not a replacement for a second PCI NIC:

- DPDK bind requires a PCI-backed interface, `dpdk-devbind.py`, vfio-pci/IOMMU readiness, and rollback driver knowledge.
- Full OS/NIC tuning requires hardware features such as ring buffers and IRQ affinity; veth does not provide them.
- AF_XDP can be explored on virtual interfaces only as a limited generic-XDP lab case, not as production zero-copy validation.

Remove the lab pair with:

```bash
sudo ip link del suri0
```

### Test Coverage

Tests currently cover:

- CLI scope resolution and root checks.
- Default config-only apply separation from OS/NIC tuning.
- PCAP profile parsing, help text, config-only/full planning, YAML `pcap` section tuning, systemd `-i <iface>` startup, and config-only apply separation from OS/NIC tuning.
- OS-tuning separation from YAML validation/restart.
- Rollback `--state latest --yes`.
- Planner guardrails and `--force`.
- Management-risk detection for SSH interface or default route interface.
- Capability blockers for DPDK, AF_XDP, NFQ.
- AF_XDP split kernel/interface preflight and full-mode hard-blocking when interface XDP signal is absent.
- Scope-aware capability guards for config-only, os-tuning, and full plans.
- Preservation of hard-block reasons when management-interface guardrails are also present.
- NFQ iptables/nftables behavior.
- YAML tuning for runmode, affinity, AF_PACKET cluster choice, DPDK interface, AF_XDP unaligned memory, exception policies.
- State save/load/latest, permissions, and path confinement.
- Executor transaction ordering, YAML validation before write, backup before live write, pre-state validation before OS/NIC commands.
- Reverse-order rollback.
- Warning actions remaining in plans/state while not being counted as applied live actions.
- Refusal to execute unsupported rollback commands from state.
- JSON output validity and nil-slice normalization.
- Trusted root command lookup.
- Unsafe interface/path rejection.

### Adding a New Tuning Action

When adding a new action:

1. Add the `PlanAction` in `planner.go`.
2. Give it a stable `ID`, `Kind`, `RiskLevel`, reason, apply command, rollback command, and metadata.
3. Add capability blockers in `applyCapabilityGuards` if the action depends on host support.
4. Add management-interface blocking in `isManagementGuardedAction` if it can disrupt network access.
5. Capture required rollback pre-state in `capturePreState`.
6. Enforce required pre-state in `validatePreStateForActions`.
7. Implement apply handling in `Executor.Apply`.
8. Implement typed rollback handling in `rollbackApplied`.
9. Do not rely on arbitrary `RollbackExec` from state for new privileged behavior.
10. Add negative tests for missing pre-state, rollback failure, root behavior, and guardrails.

### Real Host Acceptance

Before production use, run on a disposable or maintenance-window host:

```bash
sudo ./scripts/install_suricata.sh
GOCACHE=/tmp/go-build-cache /home/vol/.local/go/bin/go build -o surituner ./cmd/surituner
sudo ./scripts/e2e_real_smoke.sh --iface <capture_iface>
```

Optional higher-risk checks:

```bash
sudo ./scripts/e2e_real_smoke.sh --iface <capture_iface> --run-os-tuning
sudo ./scripts/e2e_real_smoke.sh --iface <capture_iface> --run-full
```

Run DPDK and AF_XDP full-mode tests only on hosts where interface disruption, driver rebinding, HugePages changes, and service restarts are acceptable.
