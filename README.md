# SuriTuner (Go v1)

`surituner` is a local Safe Decision Engine for hardware-aware Suricata tuning.

## Commands

- `detect` - collect hardware and Suricata capabilities snapshot.
- `plan` - dry-run action plan with risk levels and rollback commands.
- `apply` - transactional apply with state file and auto-rollback on failures.
- `rollback` - restore previous state by state file.
- `report` - current state report with recommendations.
  - Includes unsupported options, bottlenecks, runtime acceptance signals, and monitoring recommendations in JSON/human output.

## Build

```bash
go build -o surituner ./cmd/surituner
```

## Quality Gates

```bash
make test
make vet
make build
make race
make ci
# if make is unavailable:
./scripts/ci.sh
```

## Quick examples

```bash
surituner detect --iface eth0
surituner plan --profile af-packet --iface eth0 --ips-mode ids
surituner apply --profile nfq --iface eth0 --ips-mode strict --full --yes
surituner rollback --state latest --yes
surituner report --iface eth0 --json
```

## Notes

- `apply` and `rollback` require root privileges.
- State files are stored under `/var/lib/surituner/state` by default.
- `apply` validates tuned configuration via `suricata -T` on a temporary file before writing the live config.
- `--config-only` only changes `suricata.yaml`; `--full` also installs a managed `suricata.service` drop-in so systemd starts the selected capture backend (`--af-packet`, `--af-xdp`, `--dpdk`, or NFQ `-q 0`).
- `report` reads the latest Suricata `stats.log` block and selected `ethtool -S` counters when available.
- State and backup files are created with restricted permissions (`0700` directories, `0600` files).
- Management interface guardrails block high-risk operations unless `--force` is explicitly set.
- On a detected management interface, OS/NIC/firewall/capture-driver actions are blocked unless `--force`; `config-only` YAML changes remain allowed.
- Capability blockers (missing DPDK/AF_XDP/NFQ support in `suricata --build-info`) are hard blocks and are not bypassed by `--force`.
- NFQ routing supports both `nft` and `iptables` backends (auto-detected).
- NFQ `nft` apply verifies that the managed rule can be found by comment after insertion; if verification fails it attempts cleanup before returning an error.
- OS/NIC tuning is refused before live changes if required rollback pre-state cannot be captured.
- Rollback restores NIC offload flags (`GRO/LRO`) from captured pre-state instead of fixed defaults.
- Root command execution and root-time utility discovery use trusted system directories instead of caller-controlled relative paths.
- Rollback validates restored YAML and restores the previous Suricata service state when it was known before apply.
- IPS strict mode uses Suricata's `exception-policy: auto` fail-close master switch (`drop-flow` with `drop-packet` fallback in IPS) plus NFQ `fail-open=false`; availability mode uses fail-open/pass semantics.
- DPDK apply is hard-blocked unless `dpdk-devbind.py --status` preflight confirms bind/rollback readiness (PCI entry, `vfio-pci` availability, rollback driver, and detectable IOMMU group).
- Rollback restores per-NUMA hugepages (`/sys/devices/system/node/node*/.../nr_hugepages`) from pre-state snapshots.
- AF_XDP preflight checks Suricata build support, interface presence, `ip -details` XDP signals, and kernel release support (`>= 4.18`). Kernel-only inference is reported as a warning because driver-specific zero-copy support is not proven.

## Testing Without Suricata Installed

- Unit and integration-style tests use mocked command runners and simulated command failures.
- `config-only` behavior is tested with forced `suricata -T` failure handling.
- `os-tuning` behavior is tested to ensure Suricata validation/restart is not invoked.

## Real Host Testing (With Suricata Installed)

```bash
# install dependencies + Suricata (root)
sudo ./scripts/install_suricata.sh

# smoke e2e (safe path: config-only + rollback + guardrail assertion)
sudo ./scripts/e2e_real_smoke.sh --iface <capture_iface>

# optional higher-risk paths:
sudo ./scripts/e2e_real_smoke.sh --iface <capture_iface> --run-os-tuning
sudo ./scripts/e2e_real_smoke.sh --iface <capture_iface> --run-full
```

Notes:
- On fresh installs, `suricata.rules` may be missing until `suricata-update` runs.
- The provided scripts now auto-handle this and validate base `suricata -T` before SuriTuner apply.
- The real smoke script verifies the generated state JSON, confirms rollback changes state to `rolled_back`, and asserts that dangerous `--full` apply is blocked on a detected management interface.
- For package defaults that still reference `eth0`, the smoke script adjusts the active `af-packet` interface to the requested `--iface` and keeps a timestamped backup next to the config.
- Large rulesets can take longer than the package's default systemd startup timeout, so the smoke script installs a test drop-in with `TimeoutStartSec=5min`.
