package surituner

import (
	"errors"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTuneSuricataYAML_AppliesCoreSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suricata.yaml")
	initial := `
runmode: autofp
threading:
  autopin: false
`
	if err := os.WriteFile(path, []byte(initial), 0644); err != nil {
		t.Fatalf("write temp yaml: %v", err)
	}

	backup, changes, err := TuneSuricataYAML(path, TuneOptions{
		Profile:       ProfileAFPacket,
		IPSMode:       IPSModeIDS,
		Iface:         "ens33",
		SupportsHWLOC: true,
		NICNUMA:       0,
		SymmetricRSS:  true,
		EnabledRules:  1000,
		TotalRAMMB:    8192,
	})
	if err != nil {
		t.Fatalf("TuneSuricataYAML error: %v", err)
	}
	if backup.BackupPath == "" {
		t.Fatalf("expected backup path")
	}
	backupInfo, err := os.Stat(backup.BackupPath)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if got := backupInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("expected backup file permissions 0600, got %o", got)
	}
	backupDirInfo, err := os.Stat(filepath.Dir(backup.BackupPath))
	if err != nil {
		t.Fatalf("stat backup dir: %v", err)
	}
	if got := backupDirInfo.Mode().Perm(); got != 0700 {
		t.Fatalf("expected backup dir permissions 0700, got %o", got)
	}
	if len(changes) == 0 {
		t.Fatalf("expected non-empty change list")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tuned yaml: %v", err)
	}
	if !strings.HasPrefix(string(raw), "%YAML 1.1\n---\n") {
		t.Fatalf("expected suricata YAML header, got:\n%s", string(raw[:min(len(raw), 80)]))
	}
	var cfg map[string]interface{}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse tuned yaml: %v", err)
	}
	if got := cfg["runmode"]; got != "workers" {
		t.Fatalf("expected runmode workers, got: %v", got)
	}
	threading, ok := cfg["threading"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected threading map")
	}
	if got := threading["autopin"]; got != true {
		t.Fatalf("expected threading.autopin=true, got %v", got)
	}
	if got := cfg["exception-policy"]; got != "ignore" {
		t.Fatalf("expected exception-policy ignore, got %v", got)
	}
	afPacket, ok := cfg["af-packet"].([]interface{})
	if !ok || len(afPacket) == 0 {
		t.Fatalf("expected af-packet array")
	}
	first, ok := afPacket[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected af-packet item map")
	}
	if got := first["interface"]; got != "ens33" {
		t.Fatalf("expected interface ens33, got %v", got)
	}
	if got := first["cluster-type"]; got != "cluster_qm" {
		t.Fatalf("expected cluster_qm, got %v", got)
	}
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestApplyTuneMap_SkipsRunAsWhenNoSystemIdentity(t *testing.T) {
	origLookupUser := lookupSystemUser
	origLookupGroup := lookupSystemGroup
	defer func() {
		lookupSystemUser = origLookupUser
		lookupSystemGroup = origLookupGroup
	}()
	lookupSystemUser = func(string) (*osuser.User, error) { return nil, errors.New("no user") }
	lookupSystemGroup = func(string) (*osuser.Group, error) { return nil, errors.New("no group") }

	cfg := map[string]interface{}{}
	changes := applyTuneMap(cfg, TuneOptions{
		Profile:       ProfileAFPacket,
		IPSMode:       IPSModeIDS,
		SupportsHWLOC: true,
		SymmetricRSS:  true,
		EnabledRules:  100,
		TotalRAMMB:    1024,
	})
	if _, exists := cfg["run-as"]; exists {
		t.Fatalf("did not expect run-as section when no system identity is available")
	}
	if !containsChange(changes, "skipped run-as hardening") {
		t.Fatalf("expected skip run-as change note, got: %v", changes)
	}
}

func TestApplyTuneMap_PreservesExistingRunAsWhenValid(t *testing.T) {
	origLookupUser := lookupSystemUser
	origLookupGroup := lookupSystemGroup
	defer func() {
		lookupSystemUser = origLookupUser
		lookupSystemGroup = origLookupGroup
	}()
	lookupSystemUser = func(name string) (*osuser.User, error) {
		if name == "suri" {
			return &osuser.User{Username: "suri"}, nil
		}
		return nil, errors.New("unknown user")
	}
	lookupSystemGroup = func(name string) (*osuser.Group, error) {
		if name == "suri" {
			return &osuser.Group{Name: "suri"}, nil
		}
		return nil, errors.New("unknown group")
	}

	cfg := map[string]interface{}{
		"run-as": map[string]interface{}{
			"user":  "suri",
			"group": "suri",
		},
	}
	_ = applyTuneMap(cfg, TuneOptions{
		Profile:       ProfileAFPacket,
		IPSMode:       IPSModeIDS,
		SupportsHWLOC: true,
		SymmetricRSS:  true,
		EnabledRules:  100,
		TotalRAMMB:    1024,
	})
	runAs, ok := cfg["run-as"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected run-as map")
	}
	if runAs["user"] != "suri" || runAs["group"] != "suri" {
		t.Fatalf("expected existing run-as preserved, got user=%v group=%v", runAs["user"], runAs["group"])
	}
}

func TestApplyTuneMap_UsesOfficialAFXDPUnalignedOption(t *testing.T) {
	cfg := map[string]interface{}{}
	_ = applyTuneMap(cfg, TuneOptions{
		Profile:       ProfileAFXDP,
		IPSMode:       IPSModeAvailability,
		Iface:         "ens33",
		SupportsHWLOC: true,
		EnabledRules:  100,
		TotalRAMMB:    1024,
	})

	afxdp, ok := cfg["af-xdp"].([]map[string]interface{})
	if !ok || len(afxdp) == 0 {
		t.Fatalf("expected af-xdp interface list")
	}
	if got := afxdp[0]["interface"]; got != "ens33" {
		t.Fatalf("expected af-xdp interface ens33, got %v", got)
	}
	if got := afxdp[0]["mem-unaligned"]; got != true {
		t.Fatalf("expected af-xdp.mem-unaligned=true, got %v", got)
	}
	if _, exists := afxdp[0]["use-unaligned-chunks"]; exists {
		t.Fatalf("did not expect unofficial af-xdp.use-unaligned-chunks key")
	}
	if got := cfg["exception-policy"]; got != "pass-flow" {
		t.Fatalf("expected official fail-open exception-policy pass-flow, got %v", got)
	}
}

func TestApplyTuneMap_AFPACKETUsesClusterFlowWhenRSSNotProven(t *testing.T) {
	cfg := map[string]interface{}{}
	_ = applyTuneMap(cfg, TuneOptions{
		Profile:       ProfileAFPacket,
		IPSMode:       IPSModeIDS,
		Iface:         "ens33",
		SupportsHWLOC: true,
		SymmetricRSS:  false,
		EnabledRules:  100,
		TotalRAMMB:    1024,
	})

	afPacket, ok := cfg["af-packet"].([]map[string]interface{})
	if !ok || len(afPacket) == 0 {
		t.Fatalf("expected af-packet array")
	}
	if got := afPacket[0]["cluster-type"]; got != "cluster_flow" {
		t.Fatalf("expected cluster_flow when symmetric RSS is not proven, got %v", got)
	}
}

func TestApplyTuneMap_ConfiguresDPDKInterfaceFromPCIAddress(t *testing.T) {
	cfg := map[string]interface{}{}
	_ = applyTuneMap(cfg, TuneOptions{
		Profile:       ProfileDPDK,
		IPSMode:       IPSModeIDS,
		Iface:         "ens33",
		NICPCIAddress: "0000:02:01.0",
		SupportsHWLOC: true,
		EnabledRules:  100,
		TotalRAMMB:    1024,
	})

	dpdk, ok := cfg["dpdk"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected dpdk map")
	}
	interfaces, ok := dpdk["interfaces"].([]map[string]interface{})
	if !ok || len(interfaces) == 0 {
		t.Fatalf("expected dpdk interfaces list")
	}
	if got := interfaces[0]["interface"]; got != "0000:02:01.0" {
		t.Fatalf("expected dpdk PCI interface, got %v", got)
	}
	if _, exists := dpdk["numa-aware-hugepages"]; exists {
		t.Fatalf("did not expect unofficial dpdk.numa-aware-hugepages key")
	}
}

func TestApplyTuneMap_ConfiguresExceptionPoliciesByIPSMode(t *testing.T) {
	tests := []struct {
		name            string
		mode            IPSMode
		wantPolicy      string
		wantNFQFailOpen bool
	}{
		{
			name:            "strict fail close drop flow",
			mode:            IPSModeStrict,
			wantPolicy:      "drop-flow",
			wantNFQFailOpen: false,
		},
		{
			name:            "availability fail open",
			mode:            IPSModeAvailability,
			wantPolicy:      "pass-flow",
			wantNFQFailOpen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := map[string]interface{}{}
			_ = applyTuneMap(cfg, TuneOptions{
				Profile:       ProfileNFQ,
				IPSMode:       tt.mode,
				SupportsHWLOC: true,
				EnabledRules:  100,
				TotalRAMMB:    1024,
			})
			if got := cfg["exception-policy"]; got != tt.wantPolicy {
				t.Fatalf("expected exception-policy %s, got %v", tt.wantPolicy, got)
			}
			nfq, ok := cfg["nfq"].(map[string]interface{})
			if !ok {
				t.Fatalf("expected nfq map")
			}
			if got := nfq["fail-open"]; got != tt.wantNFQFailOpen {
				t.Fatalf("expected nfq.fail-open=%t, got %v", tt.wantNFQFailOpen, got)
			}
		})
	}

	cfg := map[string]interface{}{
		"nfq": map[string]interface{}{
			"fail-open": true,
		},
	}
	_ = applyTuneMap(cfg, TuneOptions{
		Profile:       ProfileNFQ,
		IPSMode:       IPSModeIDS,
		SupportsHWLOC: true,
		EnabledRules:  100,
		TotalRAMMB:    1024,
	})
	if got := cfg["exception-policy"]; got != "ignore" {
		t.Fatalf("expected IDS exception-policy ignore, got %v", got)
	}
	nfq, ok := cfg["nfq"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected nfq map")
	}
	if _, exists := nfq["fail-open"]; exists {
		t.Fatalf("did not expect nfq.fail-open in IDS mode")
	}
}

func TestApplyTuneMap_FallbackAffinityUsesNUMATopology(t *testing.T) {
	cfg := map[string]interface{}{}
	_ = applyTuneMap(cfg, TuneOptions{
		Profile:       ProfileAFPacket,
		IPSMode:       IPSModeIDS,
		SupportsHWLOC: false,
		NICNUMA:       1,
		CoresByNUMA: map[string][]int{
			"0": {0, 1, 2, 3},
			"1": {6, 4, 5, 7},
		},
		EnabledRules: 100,
		TotalRAMMB:   1024,
	})

	threading, ok := cfg["threading"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected threading map")
	}
	affinity, ok := threading["cpu-affinity"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected cpu-affinity map")
	}
	workers, ok := affinity["worker-cpu-set"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected worker-cpu-set map")
	}
	cpus, ok := workers["cpu"].([]string)
	if !ok || len(cpus) != 1 {
		t.Fatalf("expected worker cpu list, got %#v", workers["cpu"])
	}
	if cpus[0] != "4-7" {
		t.Fatalf("expected NUMA-local cpu set 4-7, got %q", cpus[0])
	}
}

func containsChange(changes []string, substring string) bool {
	for _, change := range changes {
		if strings.Contains(change, substring) {
			return true
		}
	}
	return false
}
