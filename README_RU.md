# SuriTuner

[English version](README.md)

SuriTuner - локальный Safe Decision Engine для аппаратно-зависимой настройки Suricata 7.x/8.x.

Он инспектирует хост, строит dry-run план, применяет только проверенные изменения, сохраняет состояние для rollback и умеет best-effort восстанавливать настройки Suricata, ОС и сетевой карты из этого состояния.

## Статус

Текущее состояние реализации относительно утвержденных требований v1: production-candidate на уровне кода и тестов.

Что закрыто локально:

- CLI-команды: `detect`, `plan`, `apply`, `rollback`, `report`.
- Режимы `apply`: дефолтный `--config-only`, явный `--os-tuning`, явный `--full`.
- Detect/preflight для Suricata build-info, DPDK, AF_XDP, NFQ, hwloc, CPU/NUMA, драйвера NIC, PCI-адреса, RSS-очередей, NUMA-ноды NIC, инвентаризации ruleset, default route и best-effort определения SSH management interface.
- Действия planner с summary, reason, risk level, apply command и rollback command.
- Уровни риска: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- Guardrails для management-интерфейса: OS/NIC/firewall/capture-driver действия блокируются, если не указан `--force`.
- YAML tuning для runmode, hwloc autopin, fallback CPU affinity, memcaps, max-pending-packets, exception policies и `run-as` hardening.
- OS/NIC tuning действия для GRO/LRO, ring buffers, RSS combined queues, IRQ affinity, sysctl buffers и promiscuous mode.
- Логика capture-профилей AF_PACKET, DPDK, AF_XDP, NFQ и PCAP.
- Транзакционный apply: root-check, state file до live-изменений, YAML backup, временный YAML, `suricata -T`, live-write только после validation, systemd restart/status check, auto-rollback.
- Модель state и rollback в `/var/lib/surituner/state`.
- Human и JSON report output.
- Unit/integration-style тесты для planner, YAML tuner, state, executor, rollback, JSON, root checks и безопасности management-интерфейса.

Что дополнительно проверено на этом хосте:

- Safe real-host smoke на Suricata 8.0.3, `ens33`, AF_PACKET, `config-only apply + rollback`: PASS.
- Дополнительные real-host `config-only apply + rollback` проверки для AF_XDP, NFQ и DPDK: PASS.
- Real AF_PACKET `--full --force apply + rollback` на `ens33`: PASS, включая OS/NIC tuning, IRQ affinity, systemd drop-in, service restart, YAML restore и OS/NIC rollback.
- Real NFQ `--full --force` failure transaction на `ens33`: PASS. Apply упал на отсутствующей chain `nft inet filter forward`, auto-rollback восстановил YAML, OS/NIC settings и service state без rollback errors.
- Внутри VM создавалась non-management lab veth-пара `suri0`/`suri1` для изолированных interface tests. Default route оставался на `ens33`; `suri0` не определяется как management interface.
- AF_PACKET full apply на `suri0` был отклонен до live-изменений, потому что veth не дает parseable ring-buffer pre-state и IRQ affinity pre-state. Итоговый state имел zero applied actions, что подтверждает pre-state safety на неподдерживаемых virtual interfaces.
- Вторая VM NIC `ens37` найдена и проверена как non-management/host-only: default route и SSH management остаются на `ens33`.
- DPDK tooling установлен для lab checks (`dpdk-devbind.py` присутствует), `vfio-pci` загружен, а autostart `dpdk.service` отключен, чтобы избежать boot-time DPDK runtime side effects.
- DPDK `config-only apply + rollback` и `os-tuning apply + rollback` на `ens37`: PASS.
- DPDK `full` на `ens37` корректно hard-blocked до live bind, потому что VM не exposes IOMMU group для PCI `0000:02:05.0`.
- Smoke создал state, проверил tuned YAML через `suricata -T`, перезапустил и проверил `suricata.service`, откатил YAML, проверил restored YAML, снова перезапустил и проверил service.
- Full apply на `ens33` был заблокирован management-interface guardrails, как и ожидалось.
- Real dry-run matrix для `af-packet`, `dpdk`, `af-xdp` и `nfq` по `config-only`, `os-tuning` и `full` проверена на разделение scopes, hard blockers и management-interface guardrails.
- Non-root fake-host e2e проверяет JSON detect/plan/report paths и hard-block behavior без root и без live system changes.
- Offline traffic lab генерирует TCP/HTTP pcap и проверяет Suricata alert без root.
- Live loopback traffic lab отправляет реальный TCP payload через `127.0.0.1:<port>`, снимает его через `tcpdump`, затем проверяет Suricata alert по captured pcap.
- `production_acceptance.sh --apply-full` в lab-mode на non-management `ens37` прошел apply/rollback: AF_PACKET full apply, service active, rollback без failed records.
- `e2e_real_smoke.sh --iface ens33` прошел safe config-only apply/rollback, JSON checks и assertion, что full plan на management interface блокируется.

Что все еще должно быть проверено на dedicated capture NIC с IOMMU:

- DPDK full bind/unbind при наличии `/sys/class/net/<iface>/device/iommu_group` и `dpdk-devbind.py --status`, где видно `unused=vfio-pci`.
- Hardware-specific AF_XDP zero-copy support, RSS symmetry и NUMA hugepage restore на production-like железе.
- Runtime drop counters под реальным mirror/tap/generator traffic на целевом интерфейсе.

## Какое железо нужно для финального закрытия

Минимально нужен отдельный тестовый или staging-сервер, где допустимы driver rebinding, изменение NIC state, HugePages и restart Suricata.

Для DPDK production full acceptance:

- Dedicated PCIe NIC, не management interface и не default route.
- Включенный IOMMU в BIOS/UEFI: Intel VT-d или AMD-Vi.
- Linux kernel boot с IOMMU: обычно `intel_iommu=on iommu=pt` для Intel или `amd_iommu=on iommu=pt` для AMD.
- В sysfs должен существовать путь `/sys/class/net/<iface>/device/iommu_group`.
- NIC/driver должен поддерживать безопасный bind to `vfio-pci`.
- `dpdk-devbind.py --status` должен показывать PCI device и rollback driver.
- Желательно NIC класса Intel X520/X540/X550/82599, Intel i350/i210 для простого lab, Intel E810 или Mellanox/NVIDIA ConnectX для более серьезного стенда. Главное - не бренд сам по себе, а наличие IOMMU group, driver rollback и DPDK-compatible PMD.

Для AF_XDP zero-copy acceptance:

- NIC и driver с известной поддержкой AF_XDP zero-copy.
- Практичные варианты: Intel i40e/ice/ixgbe, Mellanox mlx5, либо другой NIC/driver, где zero-copy подтверждается документацией и tooling.
- Kernel с AF_XDP support.
- Interface-specific XDP signal должен быть виден на target interface.
- Нужен способ подтвердить zero-copy: driver/tooling evidence, Suricata/AF_XDP runtime evidence или проверенный vendor/kernel method.

Для проверки runtime counters под трафиком:

- Источник трафика: SPAN/mirror port, TAP, packet generator или второй сервер с `tcpreplay`/`iperf3`/реальным трафиком.
- Линк на capture NIC должен быть up.
- Нужен maintenance window, чтобы сравнить до/после: `capture.kernel_drops`, `rx_dropped`, `rx_missed_errors`, `tcp.reassembly_gap`, CPU balance workers.

## Build

Репозиторий использует Go. В этом workspace обычный `go` не находится в `PATH`; Makefile указывает на локальный toolchain:

```bash
/home/vol/.local/go/bin/go version
/home/vol/.local/go/bin/go build -o surituner ./cmd/surituner
```

Если Go уже есть в `PATH`, работает и так:

```bash
go build -o surituner ./cmd/surituner
```

## User Guide

### Базовые команды

```bash
./surituner detect --iface eth0
./surituner plan --profile af-packet --iface eth0 --scope config-only
sudo ./surituner apply --profile af-packet --iface eth0 --config-only --yes
sudo ./surituner rollback --state latest --yes
./surituner report --iface eth0
```

JSON output доступен для `detect`, `plan` и `report`:

```bash
./surituner detect --iface eth0 --json
./surituner plan --profile af-packet --iface eth0 --scope full --json
./surituner report --iface eth0 --json
```

### Profiles

Поддерживаемые capture profiles:

- `af-packet`
- `dpdk`
- `af-xdp`
- `nfq`
- `pcap`

Примеры:

```bash
./surituner plan --profile af-packet --iface eth0 --scope full
./surituner plan --profile dpdk --iface ens5f0 --scope full
./surituner plan --profile af-xdp --iface ens5f0 --scope full
./surituner plan --profile nfq --iface eth0 --scope full --ips-mode strict
./surituner plan --profile pcap --iface eth0 --scope full
```

### Apply Scopes

`apply` безопасен по умолчанию:

```bash
sudo ./surituner apply --profile af-packet --iface eth0 --yes
```

Это то же самое, что:

```bash
sudo ./surituner apply --profile af-packet --iface eth0 --config-only --yes
```

Scopes взаимоисключающие:

- `--config-only`: настроить `suricata.yaml`, проверить через `suricata -T`, затем restart/check `suricata.service`.
- `--os-tuning`: применить только OS/NIC tuning. YAML не валидируется, Suricata не перезапускается.
- `--full`: применить YAML tuning, OS/NIC tuning, profile-specific actions и systemd capture profile drop-in.

Примеры:

```bash
sudo ./surituner apply --profile af-packet --iface eth0 --config-only --yes
sudo ./surituner apply --profile af-packet --iface eth0 --os-tuning --yes
sudo ./surituner apply --profile af-packet --iface eth0 --full --yes
```

### IPS Modes

Поддерживаемые IPS modes используют валидные для Suricata имена exception-policy и сохраняют intent v1:

- `strict`: fail-close behavior. YAML использует `exception-policy: drop-flow`; NFQ использует `fail-open: false`.
- `availability`: fail-open behavior. YAML использует `exception-policy: pass-flow`; NFQ использует `fail-open: true`.
- `ids`: non-IPS behavior. YAML использует `exception-policy: ignore`; NFQ `fail-open` удаляется.

Defaults:

- NFQ по умолчанию использует `strict`.
- Остальные profiles, включая PCAP, по умолчанию используют `ids`.

### Detect

`detect` собирает read-only snapshot хоста:

- Версия Suricata и build capabilities из `suricata --build-info`.
- Поддержка DPDK, AF_XDP, NFQ и hwloc/autopin.
- CPU и NUMA topology.
- NIC driver, PCI address, queues, RSS channel data, RSS symmetry signal, NUMA node, offload flags, promisc state.
- DPDK preflight: `dpdk-devbind.py`, PCI status line, current driver, vfio-pci availability, rollback driver, IOMMU group.
- AF_XDP preflight: наличие interface, kernel >= 4.18, interface-specific XDP signal из `ip -details`, и явное указание, что hardware zero-copy не доказывается generic probe.
- Ruleset inventory: `suricata-update`, total/enabled rules, PCRE-heavy rules, rule sources, rules file size, update timestamp.
- Safety guardrails: default route interface и SSH management interface best-effort через `SSH_CONNECTION`, `ss` и routing table.

Пример:

```bash
./surituner detect --iface eth0 --json
```

### Plan

`plan` - dry-run. Он не пишет Suricata config, state files, sysctls, NIC settings, firewall rules, systemd files, hugepages или IRQ affinity.

Каждое действие содержит:

- summary;
- reason;
- risk level;
- apply command;
- rollback command;
- guardrail status.

Пример:

```bash
./surituner plan --profile af-packet --iface eth0 --scope full
```

Используйте `--force` только когда вы намеренно bypass management-interface guardrails:

```bash
./surituner plan --profile af-packet --iface eth0 --scope full --force
sudo ./surituner apply --profile af-packet --iface eth0 --full --force --yes
```

Capability hard-blocks не bypassed через `--force`.

### Apply

`apply` требует root. Без root он отказывается стартовать до planning или записи state.

До live changes он:

1. Captures rollback pre-state.
2. Создает state file в `/var/lib/surituner/state`.
3. Валидирует, что required rollback pre-state существует для OS/NIC actions.
4. Собирает tuned YAML в памяти.
5. Пишет временный YAML.
6. Запускает `suricata -T -c <temp-yaml>`.
7. Создает и сохраняет YAML backup metadata.
8. Применяет live changes только после validation.

Для config/full apply, которые меняют YAML, он перезапускает и проверяет `suricata.service`.

Если live action падает, SuriTuner пытается auto-rollback уже примененных actions в reverse order.

### Rollback

Rollback требует root.

```bash
sudo ./surituner rollback --state latest --yes
sudo ./surituner rollback --state /var/lib/surituner/state/20260525T120000.000000000Z.json --yes
```

Rollback best-effort восстанавливает:

- `suricata.yaml` из backup с SHA256 verification.
- ethtool offload flags из captured `ethtool -k`.
- ring buffers из captured `ethtool -g`.
- RSS combined queues из captured `ethtool -l`.
- sysctl values.
- IRQ affinity.
- promiscuous mode.
- HugePages и per-NUMA HugePages.
- NFQ firewall rules, вставленные SuriTuner.
- DPDK bind rollback, когда известен validated previous driver.
- SuriTuner systemd drop-in state.
- Suricata service state после YAML restore, когда previous state был known.

State files проходят trust-check перед rollback:

- state selector должен быть `latest` или absolute path внутри configured state dir;
- файл должен быть direct `.json` state file;
- symlinks rejected;
- group/world-readable state files rejected.

### Report

`report` печатает текущий host report и, когда доступно, latest planned/applied action IDs из state.

Он включает:

- hardware и Suricata summary;
- capabilities;
- unsupported options;
- bottlenecks;
- runtime acceptance signals из `stats.log` и `ethtool -S`;
- monitoring recommendations.

```bash
./surituner report --iface eth0
./surituner report --iface eth0 --json
```

## Safety Model

### Management Interface Protection

SuriTuner best-effort определяет management interface из:

- default route;
- `SSH_CONNECTION`;
- `ss -tnp`;
- `ip route get <remote-ip>`.

Интерфейс считается management-risk, когда он совпадает с SSH management interface или default route interface. На management interface рискованные OS/NIC/firewall/capture-driver actions блокируются, если явно не указан `--force`.

Config-only YAML changes остаются разрешенными.

### Command Execution

SuriTuner использует `exec.CommandContext` с argv arrays, а не shell strings.

При запуске от root command lookup ограничен trusted system directories:

- `/usr/sbin`
- `/usr/bin`
- `/sbin`
- `/bin`
- `/usr/local/sbin`
- `/usr/local/bin`

Interface names и paths валидируются перед использованием.

### State Files

Default state path:

```text
/var/lib/surituner/state/<timestamp>.json
```

Permissions:

- state directory: `0700`
- state files: `0600`
- YAML backup files: `0600`

State включает:

- backup YAML path и SHA256;
- host fingerprint;
- metadata, profile, scope, IPS mode, interface, config path;
- полный detection snapshot;
- pre-state для ethtool, sysctl, IRQ affinity, irqbalance, promisc, HugePages, systemd service status;
- plan actions с apply/rollback commands;
- applied command records;
- rollback command records;
- final status/error.

## Capture Profile Details

### AF_PACKET

- YAML runmode: `workers`.
- Использует `cluster_qm` только когда symmetric RSS явно detected.
- Falls back to `cluster_flow`, когда RSS неизвестен или не доказан symmetric.

### DPDK

- Требует Suricata DPDK build support.
- Требует NIC PCI address.
- Требует `dpdk-devbind.py --status` preflight.
- Требует vfio-pci bind readiness и rollback driver knowledge, если NIC еще не bound.
- Требует detectable IOMMU group.
- В full mode использует NUMA-local HugePages action.

Для реального DPDK full apply capture NIC должна быть отделена от management traffic, а host/VM должен expose IOMMU group:

```bash
sudo ./scripts/check_dpdk_prereqs.sh --iface <capture_iface> --install-tools
ls -l /sys/class/net/<capture_iface>/device/iommu_group
sudo dpdk-devbind.py --status
```

Ожидаемое ready-состояние:

- `dpdk-devbind.py` присутствует.
- `vfio-pci` есть в device `unused=` list.
- `iommu_group` существует для PCI device.
- SuriTuner `plan --profile dpdk --scope full` не hard-blocked.

В этой VM `ens37` безопасен как non-management test NIC, но DPDK full корректно hard-blocked, потому что `0000:02:05.0` не имеет IOMMU group.

Небезопасная no-IOMMU DPDK lab может доказать, что DPDK сам по себе может bind и open VM NIC, но это не satisfies production full-apply safety requirement. SuriTuner намеренно сохраняет full DPDK hard-blocked без IOMMU group, потому что VFIO no-IOMMU убирает DMA isolation и неприемлем для normal safe apply path.

### AF_XDP

- Требует Suricata AF_XDP build support.
- Config-only требует Suricata AF_XDP build support и kernel support.
- Full mode требует kernel support плюс interface-specific XDP signal; kernel version alone не считается full AF_XDP readiness.
- Выдает явное CRITICAL warning, что AF_XDP может reduce or remove standard network use of the interface.
- Использует HugePages для unaligned chunks в full mode.
- Сообщает, что hardware zero-copy support не verified, пока он не доказан hardware/tooling вне generic preflight.

### NFQ

- Требует Suricata NFQ build support.
- Требует detected `nftables` или `iptables` backend для full NFQ queue rules.
- YAML runmode: `autofp`.
- Добавляет NFQUEUE rule для queue `0`.
- `nftables` rules tagged SuriTuner comment и verified после insert.

### PCAP

- Не требует DPDK, AF_XDP или NFQ Suricata build capabilities.
- YAML runmode: `autofp`.
- YAML настраивает `pcap` interface entry для target interface.
- Config-only применяет только YAML.
- Full mode включает YAML, обычный OS/NIC tuning и systemd profile, использующий Suricata live PCAP capture с `-i <iface>`.

## Developer Guide

Дополнительные readiness и operations docs:

- [Production Readiness](docs/PRODUCTION_READINESS.md)
- [Operator Runbook](docs/OPERATOR_RUNBOOK.md)
- [Pre-Release Checklist](docs/PRE_RELEASE_CHECKLIST.md)
- [Target Acceptance Scenario](docs/TARGET_ACCEPTANCE_SCENARIO.md)

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
scripts/e2e_fake_cli.sh            non-root fake-host CLI/e2e scenario
scripts/package_release.sh         release tarball and checksum builder
scripts/production_acceptance.sh   target-host production readiness gate
scripts/traffic_live_loopback_lab.sh root tcpdump loopback traffic capture lab
scripts/traffic_pcap_lab.sh        non-root Suricata pcap traffic lab
scripts/e2e_real_smoke.sh          real-host smoke test
scripts/install_suricata.sh        Debian/Ubuntu Suricata setup helper
scripts/check_dpdk_prereqs.sh      safe DPDK tooling/preflight helper, no bind/unbind
```

### Local Checks

В этом workspace используйте локальный Go toolchain и writable caches:

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

Если `make` доступен:

```bash
make ci
make race
make ci-full
make release-snapshot
```

Fake e2e scenario проверяет JSON detect/plan/report paths и hard-block behavior без root и live system changes:

```bash
./scripts/e2e_fake_cli.sh
```

Если Suricata установлена локально, этот non-root traffic lab генерирует TCP/HTTP pcap и проверяет Suricata alert:

```bash
./scripts/traffic_pcap_lab.sh
```

Если доступны tcpdump privileges, этот lab отправляет реальный TCP traffic через loopback, captures it и проверяет Suricata alerting на captured pcap:

```bash
./scripts/traffic_live_loopback_lab.sh
```

Release artifacts собираются в `dist/`:

```bash
./scripts/package_release.sh --version snapshot
```

`golangci-lint` optional. Запускайте только если установлен:

```bash
golangci-lint run ./...
```

### Current Local Verification

Последняя локальная проверка в этом workspace:

- 2026-05-26 v1 completion checks:
  - `/home/vol/.local/go/bin/go test ./...`: PASS.
  - `CGO_ENABLED=1 CC="/home/vol/.local/zig/current/zig cc" CXX="/home/vol/.local/zig/current/zig c++" /home/vol/.local/go/bin/go test -race ./...`: PASS. Plain `go test -race` без cgo/toolchain env падает в этой VM, потому что `gcc` не установлен.
  - `/home/vol/.local/go/bin/go vet ./...`: PASS.
  - `/home/vol/.local/go/bin/gofmt -l .`: PASS, empty output.
  - `/home/vol/.local/go/bin/go build -o surituner ./cmd/surituner`: PASS.
  - `/home/vol/.local/go/bin/go mod verify`: PASS.
  - `bash -n scripts/*.sh`: PASS.
  - `golangci-lint`: не запускался, потому что binary не установлен.
- PCAP JSON checks на `ens37`: config-only и full plans parse with `jq empty`; config-only содержит только `yaml-tuning`; full включает YAML, OS/NIC actions и `systemd-profile` с `-i ens37`.
- Management guardrail check: `af-packet --iface ens33 --scope full` blocked на management interface, включая OS/NIC actions и `systemd-profile`.
- DPDK `ens37` full остается hard-blocked из-за missing IOMMU group/readiness в этой VM.
- Unsafe no-IOMMU DPDK lab на non-management `ens37`:
  - Установлены `dpdk-dev`, `meson`, `ninja-build`, `pkg-config`, `libpcap-dev` и `libnuma-dev`; system-wide `apt upgrade` не запускался.
  - `vfio` no-IOMMU mode временно включался, `ens37`/`0000:02:05.0` был bound to `vfio-pci`, HugePages настроены через `dpdk-hugepages.py --setup 1G`.
  - `dpdk-testpmd` с `--iova-mode=pa` открыл Port 0 через VFIO No-IOMMU, используя PMD `net_e1000_em`; `--iova-mode=va` failed, потому что этот PMD expected PA IOVA mode.
  - `dpdk-pdump` attached as secondary process и записал `/tmp/capture2-pa.pcap` (только header, потому что `ens37` имел `NO-CARRIER` и без packets).
  - Cleanup restored `ens37` to kernel driver `e1000`, cleared HugePages to zero, disabled/unloaded temporary VFIO state, default route remained on `ens33`.
  - Это записано только как VM lab evidence; SuriTuner все еще корректно hard-blocks DPDK full в этой VM из-за missing IOMMU group.
- `detect --iface ens37 --json` и `report --iface ens37 --json` parse with `jq empty`.
- Non-root `apply --profile pcap --iface ens37 --config-only --yes` refuses before planning with `this command requires root privileges`.
- Real safe PCAP config-only apply и rollback на `ens37`: `/var/lib/surituner/state/20260526T151125.997723793Z.json`, final status `rolled_back`, все rollback records `ok`; `suricata.service` remained `active`, and `suricata -T -c /etc/suricata/suricata.yaml` passes after rollback.
- AF_XDP `ens37` full now hard-blocked, потому что эта VM показывает kernel support, но no interface-specific XDP signal; hardware zero-copy остается hardware-verification only.
- `go version`: not available in `PATH`.
- `/home/vol/.local/go/bin/go version`: `go1.26.3 linux/amd64`.
- `make`: доступен в текущих проверках и используется для `make ci-full`.
- `go test ./...`: PASS with `GOCACHE=/tmp/go-build-cache`.
- `go test -race ./...`: PASS with Zig and caches under `/tmp`.
- `go vet ./...`: PASS.
- `gofmt -l .`: PASS, empty output.
- `go build ./cmd/surituner`: PASS.
- `plan --json | jq empty`: PASS.
- `report --json | jq empty`: PASS.
- non-root `apply`: exits with `this command requires root privileges`.
- `sudo ./scripts/e2e_real_smoke.sh --iface ens33`: PASS для safe config-only apply, rollback, JSON checks и management-interface guardrail assertion.
- `sudo ./scripts/production_acceptance.sh --profile af-packet --iface ens37 --allow-no-carrier --apply-full --traffic-ready --monitor-duration 0`: PASS в lab-mode; apply 8 actions, rollback 11 actions, no failed rollback records.
- `./scripts/traffic_pcap_lab.sh`: PASS.
- `./scripts/traffic_live_loopback_lab.sh`: PASS.
- `actionlint .github/workflows/*.yml`: PASS.
- Latest checked full apply/rollback states:
  - `/var/lib/surituner/state/20260617T152441.990970287Z.json`, status `rolled_back`, failed rollback records `0`.
  - `/var/lib/surituner/state/20260617T152253.703111258Z.json`, status `rolled_back`, failed rollback records `0`.
  - `/var/lib/surituner/state/20260617T152225.893003910Z.json`, status `rolled_back`, failed rollback records `0`.
  - `/var/lib/surituner/state/20260617T152112.894399263Z.json`, status `rolled_back`, failed rollback records `0`.
- Expected negative state:
  - `/var/lib/surituner/state/20260617T152425.020200554Z.json`, status `failed`, zero applied actions, failure before live changes because loopback has no parseable `ethtool -g` pre-state.
- Final service/config sanity:
  - `suricata.service`: `active`.
  - `sudo suricata -T -c /etc/suricata/suricata.yaml`: PASS.
  - `/etc/suricata/suricata.yaml` SHA256 after rollback: `6224bc7d0bc04d97c4282f54a71e0736341341aa82c530fe22aed3da28814d72`.

### Lab Veth Interface

Для non-management interface tests внутри VM можно создать временную veth-пару:

```bash
sudo ip link add suri0 type veth peer name suri1
sudo ip addr add 10.250.0.1/30 dev suri0
sudo ip addr add 10.250.0.2/30 dev suri1
sudo ip link set suri0 up
sudo ip link set suri1 up
```

Это полезно для guardrail и pre-state tests, но не заменяет второй PCI NIC:

- DPDK bind требует PCI-backed interface, `dpdk-devbind.py`, vfio-pci/IOMMU readiness и rollback driver knowledge.
- Full OS/NIC tuning требует hardware features вроде ring buffers и IRQ affinity; veth их не дает.
- AF_XDP можно исследовать на virtual interfaces только как ограниченный generic-XDP lab case, не как production zero-copy validation.

Удалить lab pair:

```bash
sudo ip link del suri0
```

### Test Coverage

Тесты сейчас покрывают:

- CLI scope resolution и root checks.
- Default config-only apply separation from OS/NIC tuning.
- PCAP profile parsing, help text, config-only/full planning, YAML `pcap` section tuning, systemd `-i <iface>` startup, config-only apply separation from OS/NIC tuning.
- OS-tuning separation from YAML validation/restart.
- Rollback `--state latest --yes`.
- Planner guardrails и `--force`.
- Management-risk detection for SSH interface or default route interface.
- Capability blockers для DPDK, AF_XDP, NFQ.
- AF_XDP split kernel/interface preflight и full-mode hard-blocking when interface XDP signal is absent.
- Scope-aware capability guards для config-only, os-tuning и full plans.
- Preservation of hard-block reasons when management-interface guardrails are also present.
- NFQ iptables/nftables behavior.
- YAML tuning для runmode, affinity, AF_PACKET cluster choice, DPDK interface, AF_XDP unaligned memory, exception policies.
- State save/load/latest, permissions и path confinement.
- Executor transaction ordering, YAML validation before write, backup before live write, pre-state validation before OS/NIC commands.
- Reverse-order rollback.
- Warning actions remaining in plans/state while not being counted as applied live actions.
- Refusal to execute unsupported rollback commands from state.
- JSON output validity и nil-slice normalization.
- Trusted root command lookup.
- Unsafe interface/path rejection.

### Adding a New Tuning Action

При добавлении нового action:

1. Добавьте `PlanAction` в `planner.go`.
2. Дайте stable `ID`, `Kind`, `RiskLevel`, reason, apply command, rollback command и metadata.
3. Добавьте capability blockers в `applyCapabilityGuards`, если action зависит от host support.
4. Добавьте management-interface blocking в `isManagementGuardedAction`, если action может нарушить network access.
5. Capture required rollback pre-state в `capturePreState`.
6. Enforce required pre-state в `validatePreStateForActions`.
7. Реализуйте apply handling в `Executor.Apply`.
8. Реализуйте typed rollback handling в `rollbackApplied`.
9. Не полагайтесь на arbitrary `RollbackExec` из state для нового privileged behavior.
10. Добавьте negative tests для missing pre-state, rollback failure, root behavior и guardrails.

### Real Host Acceptance

Перед production use запустите на disposable host или в maintenance window:

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

DPDK и AF_XDP full-mode tests запускайте только на hosts, где interface disruption, driver rebinding, HugePages changes и service restarts acceptable.

Для финальной target procedure используйте [Target Acceptance Scenario](docs/TARGET_ACCEPTANCE_SCENARIO.md).
