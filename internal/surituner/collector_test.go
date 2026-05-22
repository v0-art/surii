package surituner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type collectorRunner struct {
	results map[string]CommandResult
}

func (r collectorRunner) Run(args []string, _ time.Duration, _ bool) (CommandResult, error) {
	if res, ok := r.results[strings.Join(args, " ")]; ok {
		res.Args = append([]string(nil), args...)
		return res, nil
	}
	return CommandResult{Args: args, ExitCode: 0}, nil
}

func TestParseBuildInfoSupportHonorsExplicitNo(t *testing.T) {
	raw := `
Suricata Configuration:
  AF_XDP support:                          yes
  DPDK support:                            no
  NFQueue support:                         yes
  HWLOC support:                           no
`
	value, known := parseBuildInfoSupport(raw, "dpdk support")
	if !known || value {
		t.Fatalf("expected explicit DPDK support no, got value=%t known=%t", value, known)
	}
	value, known = parseBuildInfoSupport(raw, "af_xdp support")
	if !known || !value {
		t.Fatalf("expected explicit AF_XDP support yes, got value=%t known=%t", value, known)
	}
	value, known = parseBuildInfoSupport(raw, "hwloc support")
	if !known || value {
		t.Fatalf("expected explicit HWLOC support no, got value=%t known=%t", value, known)
	}
}

func TestCollectBuildCapabilities_DoesNotTreatDPDKNoAsSupported(t *testing.T) {
	c := NewCollector(collectorRunner{
		results: map[string]CommandResult{
			"suricata --build-info": {
				Stdout: "This is Suricata version 8.0.3 RELEASE\nSuricata Configuration:\n  DPDK support: no\n  AF_XDP support: yes\n  NFQueue support: yes\n",
			},
		},
	})
	got := c.collectBuildCapabilities()
	if got.SupportsDPDK {
		t.Fatalf("did not expect DPDK support when build-info says no")
	}
	if !got.SupportsAFXDP || !got.SupportsNFQ {
		t.Fatalf("expected AF_XDP/NFQ support, got %+v", got)
	}
}

func TestCollectDPDKPreflightAlreadyVFIOWarnsNoRollbackDriver(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "dpdk-devbind.py")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake dpdk-devbind: %v", err)
	}
	origPCIDevicesDir := pciDevicesSysfsDir
	defer func() { pciDevicesSysfsDir = origPCIDevicesDir }()
	pciDevicesSysfsDir = filepath.Join(dir, "pci-devices")
	deviceDir := filepath.Join(pciDevicesSysfsDir, "0000:01:00.0")
	groupDir := filepath.Join(dir, "iommu-groups", "42")
	if err := os.MkdirAll(deviceDir, 0755); err != nil {
		t.Fatalf("mkdir fake pci device: %v", err)
	}
	if err := os.MkdirAll(groupDir, 0755); err != nil {
		t.Fatalf("mkdir fake iommu group: %v", err)
	}
	if err := os.Symlink(groupDir, filepath.Join(deviceDir, "iommu_group")); err != nil {
		t.Fatalf("symlink fake iommu group: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	c := NewCollector(collectorRunner{
		results: map[string]CommandResult{
			"dpdk-devbind.py --status": {
				Stdout: "0000:01:00.0 'Intel X710' drv=vfio-pci unused=ixgbe",
			},
		},
	})
	var warnings []string
	got := c.collectDPDKPreflight("0000:01:00.0", "", &warnings)
	if !got.DevbindPresent || !got.CanBindVFIO || !got.BindReady {
		t.Fatalf("expected already-vfio NIC to be bind-ready without bind action, got %+v warnings=%v", got, warnings)
	}
	if got.CanRollbackBind {
		t.Fatalf("did not expect rollback bind driver when current driver is vfio-pci")
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "previous kernel driver is unknown") {
		t.Fatalf("expected previous-driver warning, got %v", warnings)
	}
}

func TestCollectDPDKPreflightAcceptsVFIOWhenDriverPathExists(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "dpdk-devbind.py")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake dpdk-devbind: %v", err)
	}
	vfioPath := filepath.Join(dir, "vfio-pci")
	if err := os.Mkdir(vfioPath, 0755); err != nil {
		t.Fatalf("mkdir fake vfio path: %v", err)
	}
	origVFIOPaths := vfioPCIAvailabilityPaths
	origPCIDevicesDir := pciDevicesSysfsDir
	defer func() { vfioPCIAvailabilityPaths = origVFIOPaths }()
	defer func() { pciDevicesSysfsDir = origPCIDevicesDir }()
	vfioPCIAvailabilityPaths = []string{vfioPath}
	pciDevicesSysfsDir = filepath.Join(dir, "pci-devices")
	deviceDir := filepath.Join(pciDevicesSysfsDir, "0000:01:00.0")
	groupDir := filepath.Join(dir, "iommu-groups", "42")
	if err := os.MkdirAll(deviceDir, 0755); err != nil {
		t.Fatalf("mkdir fake pci device: %v", err)
	}
	if err := os.MkdirAll(groupDir, 0755); err != nil {
		t.Fatalf("mkdir fake iommu group: %v", err)
	}
	if err := os.Symlink(groupDir, filepath.Join(deviceDir, "iommu_group")); err != nil {
		t.Fatalf("symlink fake iommu group: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	c := NewCollector(collectorRunner{
		results: map[string]CommandResult{
			"dpdk-devbind.py --status": {
				Stdout: "0000:01:00.0 'Intel X710' drv=ixgbe unused=vfio-pci",
			},
		},
	})
	var warnings []string
	got := c.collectDPDKPreflight("0000:01:00.0", "ixgbe", &warnings)
	if !got.CanBindVFIO || !got.CanRollbackBind || !got.BindReady {
		t.Fatalf("expected vfio-ready DPDK preflight, got %+v warnings=%v", got, warnings)
	}
	if got.IOMMUGroup != "42" || !got.IOMMUViable {
		t.Fatalf("expected IOMMU group 42, got %+v", got)
	}
}

func TestCollectDPDKPreflightRejectsVFIOWhenAvailabilityUnconfirmed(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "dpdk-devbind.py")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake dpdk-devbind: %v", err)
	}
	origVFIOPaths := vfioPCIAvailabilityPaths
	defer func() { vfioPCIAvailabilityPaths = origVFIOPaths }()
	vfioPCIAvailabilityPaths = []string{filepath.Join(dir, "missing-vfio-pci")}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	c := NewCollector(collectorRunner{
		results: map[string]CommandResult{
			"dpdk-devbind.py --status": {
				Stdout: "0000:01:00.0 'Intel X710' drv=ixgbe unused=vfio-pci",
			},
		},
	})
	var warnings []string
	got := c.collectDPDKPreflight("0000:01:00.0", "ixgbe", &warnings)
	if got.CanBindVFIO || got.BindReady {
		t.Fatalf("did not expect bind readiness when vfio availability is unconfirmed: %+v", got)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "availability was not confirmed") {
		t.Fatalf("expected vfio availability warning, got %v", warnings)
	}
}

func TestCollectDPDKPreflightRejectsWhenIOMMUGroupMissing(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "dpdk-devbind.py")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write fake dpdk-devbind: %v", err)
	}
	vfioPath := filepath.Join(dir, "vfio-pci")
	if err := os.Mkdir(vfioPath, 0755); err != nil {
		t.Fatalf("mkdir fake vfio path: %v", err)
	}
	origVFIOPaths := vfioPCIAvailabilityPaths
	origPCIDevicesDir := pciDevicesSysfsDir
	defer func() { vfioPCIAvailabilityPaths = origVFIOPaths }()
	defer func() { pciDevicesSysfsDir = origPCIDevicesDir }()
	vfioPCIAvailabilityPaths = []string{vfioPath}
	pciDevicesSysfsDir = filepath.Join(dir, "pci-devices")
	if err := os.MkdirAll(filepath.Join(pciDevicesSysfsDir, "0000:01:00.0"), 0755); err != nil {
		t.Fatalf("mkdir fake pci device: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	c := NewCollector(collectorRunner{
		results: map[string]CommandResult{
			"dpdk-devbind.py --status": {
				Stdout: "0000:01:00.0 'Intel X710' drv=ixgbe unused=vfio-pci",
			},
		},
	})
	var warnings []string
	got := c.collectDPDKPreflight("0000:01:00.0", "ixgbe", &warnings)
	if got.IOMMUViable || got.BindReady {
		t.Fatalf("did not expect bind-ready without IOMMU group: %+v", got)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "IOMMU group not found") {
		t.Fatalf("expected IOMMU group warning, got %v", warnings)
	}
}

func TestDPDKLineMatchesPCI(t *testing.T) {
	line := "0000:01:00.0 'Intel X710' if=eth0 drv=ixgbe unused=vfio-pci"
	if !dpdkLineMatchesPCI(line, "0000:01:00.0") {
		t.Fatalf("expected full PCI match")
	}
	if !dpdkLineMatchesPCI(line, "01:00.0") {
		t.Fatalf("expected short PCI match")
	}
	if dpdkLineMatchesPCI(line, "0000:02:00.0") {
		t.Fatalf("expected mismatch for different PCI")
	}
}

func TestParseDPDKStatusField(t *testing.T) {
	line := "0000:01:00.0 if=eth0 drv=ixgbe unused=vfio-pci,uio_pci_generic"
	if got := parseDPDKStatusField(line, "drv"); got != "ixgbe" {
		t.Fatalf("unexpected drv field: %q", got)
	}
	if got := parseDPDKStatusField(line, "unused"); got != "vfio-pci,uio_pci_generic" {
		t.Fatalf("unexpected unused field: %q", got)
	}
}

func TestParseDriverList(t *testing.T) {
	got := parseDriverList("vfio-pci, uio_pci_generic, vfio-pci, <none>")
	if len(got) != 2 {
		t.Fatalf("expected 2 unique drivers, got %d (%v)", len(got), got)
	}
	if got[0] != "vfio-pci" || got[1] != "uio_pci_generic" {
		t.Fatalf("unexpected driver list: %v", got)
	}
}

func TestIsRuleLine(t *testing.T) {
	if !isRuleLine(`alert tcp any any -> any any (msg:"x"; sid:1;)`) {
		t.Fatalf("expected alert rule to be detected")
	}
	if !isRuleLine(`drop ip any any -> any any (sid:2;)`) {
		t.Fatalf("expected drop rule to be detected")
	}
	if isRuleLine(`# comment`) {
		t.Fatalf("did not expect comment to be detected as rule")
	}
}

func TestParseRuleSources_IgnoresSuricataUpdateLogLines(t *testing.T) {
	raw := `
10/5/2026 -- 12:58:49 - <Warning> -- No enabled sources.
10/5/2026 -- 12:58:49 - <Info> -- Using data-directory /var/lib/suricata.
et/open
- custom/source
`
	got := parseRuleSources(raw)
	if len(got) != 2 {
		t.Fatalf("expected 2 sources, got %d (%v)", len(got), got)
	}
	if got[0] != "et/open" || got[1] != "custom/source" {
		t.Fatalf("unexpected sources: %v", got)
	}
}

func TestParseLatestSuricataStatsBlock(t *testing.T) {
	raw := `
Date: old
capture.kernel_packets                                      | Total                     | 1
---------------------------------------------------------------------------------------------------
Date: new
capture.kernel_packets                                      | Total                     | 10
capture.kernel_drops                                        | Total                     | 2
tcp.reassembly_gap                                          | Total                     | 0
`
	header, stats := parseLatestSuricataStatsBlock(raw)
	if header != "Date: new" {
		t.Fatalf("unexpected header: %q", header)
	}
	if stats["capture.kernel_packets"] != 10 || stats["capture.kernel_drops"] != 2 {
		t.Fatalf("unexpected stats: %v", stats)
	}
}

func TestParseEthtoolStats(t *testing.T) {
	stats := parseEthtoolStats(`
NIC statistics:
     rx_missed_errors: 0
     rx_dropped: 7
     non_numeric: n/a
`)
	if stats["rx_missed_errors"] != 0 {
		t.Fatalf("unexpected rx_missed_errors: %v", stats)
	}
	if stats["rx_dropped"] != 7 {
		t.Fatalf("unexpected rx_dropped: %v", stats)
	}
	if _, ok := stats["non_numeric"]; ok {
		t.Fatalf("did not expect non-numeric stat")
	}
}

func TestBuildAcceptanceObservations(t *testing.T) {
	observations := buildAcceptanceObservations(RuntimeMetrics{
		SuricataStats: map[string]int64{
			"capture.kernel_packets": 100,
			"capture.kernel_drops":   1,
			"tcp.reassembly_gap":     0,
			"memcap.pressure":        3,
		},
		EthtoolStats: map[string]int64{
			"rx_missed_errors": 0,
			"rx_dropped":       0,
		},
	})
	if len(observations) == 0 {
		t.Fatalf("expected observations")
	}
	if !strings.Contains(strings.Join(observations, "\n"), "drop_rate") {
		t.Fatalf("expected drop_rate observation, got %v", observations)
	}
}

func TestDetectRulesFilePath_UsesConfiguredRuleFiles(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	configPath := filepath.Join(dir, "suricata.yaml")
	config := `
default-rule-path: rules
rule-files:
  - custom.rules
  - suricata.rules
`
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	suriRules := filepath.Join(rulesDir, "suricata.rules")
	customRules := filepath.Join(rulesDir, "custom.rules")
	if err := os.WriteFile(customRules, []byte("alert tcp any any -> any any (sid:1;)\n"), 0644); err != nil {
		t.Fatalf("write custom rules: %v", err)
	}
	if err := os.WriteFile(suriRules, []byte("alert tcp any any -> any any (sid:2;)\n"), 0644); err != nil {
		t.Fatalf("write suricata rules: %v", err)
	}
	if got := detectRulesFilePath(configPath); got != suriRules {
		t.Fatalf("expected configured suricata.rules path %s, got %s", suriRules, got)
	}
}

func TestCollectRulesetHandlesLongRuleLines(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	configPath := filepath.Join(dir, "suricata.yaml")
	if err := os.WriteFile(configPath, []byte("default-rule-path: rules\nrule-files:\n  - suricata.rules\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	longMsg := strings.Repeat("x", 128*1024)
	rule := `alert tcp any any -> any any (msg:"` + longMsg + `"; pcre:"/abc/"; sid:42;)` + "\n"
	if err := os.WriteFile(filepath.Join(rulesDir, "suricata.rules"), []byte(rule), 0644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	c := NewCollector(collectorRunner{})
	inv := c.collectRuleset(configPath)
	if inv.TotalRules != 1 || inv.EnabledRules != 1 || inv.PCREHeavyRules != 1 {
		t.Fatalf("unexpected ruleset inventory: %+v", inv)
	}
	if len(inv.Warnings) != 0 {
		t.Fatalf("did not expect warnings for long rule line, got %v", inv.Warnings)
	}
}

func TestCollectRulesetWarnsWhenSuricataUpdateSourcesFail(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "suricata-update")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatalf("write fake suricata-update: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	configPath := filepath.Join(dir, "suricata.yaml")
	if err := os.WriteFile(configPath, []byte("default-rule-path: rules\nrule-files:\n  - suricata.rules\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "suricata.rules"), []byte("alert tcp any any -> any any (sid:1;)\n"), 0644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	c := NewCollector(collectorRunner{
		results: map[string]CommandResult{
			"suricata-update list-sources --enabled": {ExitCode: 1, Stderr: "failed"},
		},
	})
	inv := c.collectRuleset(configPath)
	if !inv.SuricataUpdatePresent {
		t.Fatalf("expected fake suricata-update to be detected")
	}
	if !strings.Contains(strings.Join(inv.Warnings, "\n"), "list-sources failed") {
		t.Fatalf("expected list-sources warning, got %v", inv.Warnings)
	}
}

func TestLinkDetailsIndicateXDPSupport(t *testing.T) {
	if !linkDetailsIndicateXDPSupport("2: eth0: <BROADCAST> mtu 1500\n    prog/xdp id 42 tag abc") {
		t.Fatalf("expected prog/xdp to indicate XDP support")
	}
	if !linkDetailsIndicateXDPSupport("2: eth0: <BROADCAST> mtu 1500\n    xdpdrv/id 42") {
		t.Fatalf("expected xdpdrv/id to indicate XDP support")
	}
	if linkDetailsIndicateXDPSupport("2: xdptest0: <BROADCAST> mtu 1500 qdisc noop") {
		t.Fatalf("interface name containing xdp should not be enough")
	}
}

func TestRSSOutputIndicatesSymmetricHash(t *testing.T) {
	if !rssOutputIndicatesSymmetricHash("RSS hash function: symmetric-toeplitz") {
		t.Fatalf("expected symmetric-toeplitz to prove symmetric RSS")
	}
	if rssOutputIndicatesSymmetricHash("RSS hash function: toeplitz") {
		t.Fatalf("plain toeplitz should not prove symmetric RSS")
	}
}

func TestCollectSymmetricRSSRequiresExplicitSymmetricHash(t *testing.T) {
	c := NewCollector(collectorRunner{
		results: map[string]CommandResult{
			"ethtool -x eth0": {Stdout: "RSS hash function: toeplitz\n"},
		},
	})
	var warnings []string
	if c.collectSymmetricRSS("eth0", 8, 8, &warnings) {
		t.Fatalf("did not expect queue parity alone to prove symmetric RSS")
	}
	if len(warnings) == 0 {
		t.Fatalf("expected warning when symmetric RSS is not proven")
	}

	c = NewCollector(collectorRunner{
		results: map[string]CommandResult{
			"ethtool -x eth0": {Stdout: "RSS hash function: symmetric-xor\n"},
		},
	})
	warnings = nil
	if !c.collectSymmetricRSS("eth0", 8, 8, &warnings) {
		t.Fatalf("expected explicit symmetric hash to prove symmetric RSS")
	}
}

func TestKernelSupportsAFXDP(t *testing.T) {
	tests := []struct {
		release string
		want    bool
	}{
		{release: "4.17.9", want: false},
		{release: "4.18.0", want: true},
		{release: "5.4.0-150-generic", want: true},
		{release: "6.8.12", want: true},
		{release: "not-a-kernel", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.release, func(t *testing.T) {
			if got := kernelSupportsAFXDP(tt.release); got != tt.want {
				t.Fatalf("kernelSupportsAFXDP(%q)=%t want %t", tt.release, got, tt.want)
			}
		})
	}
}

func TestDetectXDPSupportInfersFromKernelRelease(t *testing.T) {
	if _, err := os.Stat("/sys/class/net/lo"); err != nil {
		t.Skip("loopback interface is not present in sysfs")
	}
	c := NewCollector(collectorRunner{
		results: map[string]CommandResult{
			"ip -details link show lo": {Stdout: "1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue"},
			"uname -r":                 {Stdout: "6.8.12-test"},
		},
	})
	var warnings []string
	if !c.detectXDPSupport("lo", &warnings) {
		t.Fatalf("expected AF_XDP support inferred from kernel release, warnings=%v", warnings)
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "inferred from kernel release") {
		t.Fatalf("expected inference warning, got %v", warnings)
	}
}

func TestDetectXDPSupportRejectsOldKernel(t *testing.T) {
	if _, err := os.Stat("/sys/class/net/lo"); err != nil {
		t.Skip("loopback interface is not present in sysfs")
	}
	c := NewCollector(collectorRunner{
		results: map[string]CommandResult{
			"ip -details link show lo": {Stdout: "1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue"},
			"uname -r":                 {Stdout: "4.17.19"},
		},
	})
	var warnings []string
	if c.detectXDPSupport("lo", &warnings) {
		t.Fatalf("did not expect AF_XDP support for old kernel")
	}
	if !strings.Contains(strings.Join(warnings, "\n"), "kernel >= 4.18") {
		t.Fatalf("expected kernel requirement warning, got %v", warnings)
	}
}
