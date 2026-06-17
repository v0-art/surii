# Pre-Release Checklist

Use this checklist before tagging or shipping a SuriTuner build.

## Local Code Gate

Run from the repository root:

```bash
make ci-full
./scripts/e2e_fake_cli.sh
make release-snapshot
```

If Suricata is installed locally, also run:

```bash
./scripts/traffic_pcap_lab.sh
```

If tcpdump privileges are available, also run:

```bash
./scripts/traffic_live_loopback_lab.sh
```

Equivalent explicit commands:

```bash
/home/vol/.local/go/bin/gofmt -l .
/home/vol/.local/go/bin/go test ./...
CGO_ENABLED=1 CC="/home/vol/.local/zig/current/zig cc" CXX="/home/vol/.local/zig/current/zig c++" /home/vol/.local/go/bin/go test -race ./...
/home/vol/.local/go/bin/go vet ./...
/home/vol/.local/go/bin/go build -o surituner ./cmd/surituner
/home/vol/.local/go/bin/go mod verify
bash -n scripts/*.sh
./scripts/e2e_fake_cli.sh
./scripts/package_release.sh --version snapshot
```

Add this command when Suricata is installed:

```bash
./scripts/traffic_pcap_lab.sh
```

Pass criteria:

- Working tree is clean except intentional release artifacts under `dist/`.
- Unit tests, race tests, vet, module verify, shell syntax, fake CLI e2e, optional traffic labs, and package build pass.
- `dist/sha256sums.txt` exists and covers every release tarball.

## Readiness Matrix

| Area | VM/code gate | Real hardware gate | Release status |
| --- | --- | --- | --- |
| CLI parsing and validation | `go test ./...` | None | Can be closed locally |
| Planner scopes and guardrails | Unit tests and fake CLI e2e | Optional dry-run on target | Can be closed locally |
| Config-only apply/rollback | Unit tests and real VM smoke | Target host smoke recommended | Mostly local, target confirmation recommended |
| OS/NIC tuning rollback | Unit tests and guarded VM smoke | Capture NIC maintenance window | Needs target confirmation |
| DPDK config-only | Unit tests and VM config-only smoke | Target Suricata build check | Mostly local |
| DPDK production full apply | Hard-block tests in VM | Dedicated IOMMU NIC, vfio-pci, rollback driver | Cannot be closed in this VM |
| AF_XDP config-only | Unit tests and VM plan/apply checks | Target Suricata build check | Mostly local |
| AF_XDP zero-copy full apply | Hard-block tests in VM | NIC/driver zero-copy proof and traffic | Cannot be closed in this VM |
| Offline traffic decode/rules | `scripts/traffic_pcap_lab.sh` | Optional replay on target | Can be closed locally when Suricata is installed |
| Live loopback traffic capture | `scripts/traffic_live_loopback_lab.sh` | Optional live capture on target interface | Can be closed locally for loopback only |
| Runtime drops and counters | JSON/report parser checks | Mirror/tap/generator traffic after apply | Cannot be closed in this VM |
| Release artifacts | `scripts/package_release.sh` | Install/use artifact on target | Can be built locally, should be smoke-tested on target |

## GitHub Gate

After pushing a branch or tag:

```bash
git status --short --branch
git log --oneline --decorate -3
git push origin main
```

Then confirm the `ci` workflow is green in GitHub Actions.

For release tags:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

The `release` workflow builds `linux/amd64` and `linux/arm64` tarballs and attaches them to the tag release.

## Hardware Acceptance Gate

Do not mark DPDK full or AF_XDP zero-copy as production accepted until the target-host scenario passes:

```bash
sudo ./scripts/production_acceptance.sh --profile <profile> --iface <capture_iface>
sudo ./scripts/production_acceptance.sh --profile <profile> --iface <capture_iface> --apply-full --traffic-ready
```

For AF_XDP zero-copy:

```bash
sudo ./scripts/production_acceptance.sh --profile af-xdp --iface <capture_iface> --zero-copy-verified --apply-full --traffic-ready
```

Keep the artifact directory from `/tmp/surituner-production-acceptance-*` with the release notes.
