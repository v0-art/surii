package surituner

import (
	"strings"
	"testing"
)

func TestBuildPlan_GuardrailsBlockCriticalOnManagementIface(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Build: BuildCapabilities{
			SupportsDPDK: true,
		},
		CPU: CPUInfo{
			LogicalCores: 8,
		},
		NIC: NICInfo{
			RSSCombinedCurrent: 4,
			RSSCombinedMax:     8,
			NUMANode:           0,
			PCIAddress:         "0000:01:00.0",
			DPDKStatusLine:     "0000:01:00.0 drv=ixgbe unused=vfio-pci",
			DPDKDevbindPresent: true,
			DPDKCanBindVFIO:    true,
			DPDKCanRollback:    true,
			DPDKBindReady:      true,
		},
		Safety: SafetyContext{
			IsManagementIface: true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileDPDK, ScopeFull, IPSModeStrict, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.Blocked {
		t.Fatalf("expected plan to be blocked on management iface")
	}
	foundBlocked := false
	for _, action := range plan.Actions {
		if action.RiskLevel == RiskCritical && action.BlockedByGuardrail {
			foundBlocked = true
			break
		}
	}
	if !foundBlocked {
		t.Fatalf("expected at least one blocked CRITICAL action")
	}
}

func TestBuildPlan_ForceDisablesGuardrailBlocks(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Build: BuildCapabilities{
			SupportsDPDK: true,
		},
		CPU: CPUInfo{
			LogicalCores: 8,
		},
		NIC: NICInfo{
			RSSCombinedCurrent: 4,
			RSSCombinedMax:     8,
			NUMANode:           0,
			PCIAddress:         "0000:01:00.0",
			DPDKStatusLine:     "0000:01:00.0 drv=ixgbe unused=vfio-pci",
			DPDKDevbindPresent: true,
			DPDKCanBindVFIO:    true,
			DPDKCanRollback:    true,
			DPDKBindReady:      true,
		},
		Safety: SafetyContext{
			IsManagementIface: true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileDPDK, ScopeFull, IPSModeStrict, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Blocked {
		t.Fatalf("expected force=true to bypass blocking")
	}
}

func TestBuildPlan_CapabilityGuardBlocksUnsupportedProfile(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Build: BuildCapabilities{
			SupportsDPDK: false,
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileDPDK, ScopeFull, IPSModeStrict, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.Blocked {
		t.Fatalf("expected capability guard to block unsupported dpdk profile")
	}
	if !plan.HardBlocked {
		t.Fatalf("expected hard block for unsupported capabilities")
	}
}

func TestBuildPlan_CapabilityGuardBlocksWhenDPDKBindNotReady(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Build: BuildCapabilities{
			SupportsDPDK: true,
		},
		NIC: NICInfo{
			PCIAddress:         "0000:01:00.0",
			DPDKStatusLine:     "0000:01:00.0 drv=ixgbe unused=vfio-pci",
			DPDKDevbindPresent: true,
			DPDKCanBindVFIO:    false,
			DPDKCanRollback:    true,
			DPDKBindReady:      false,
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileDPDK, ScopeFull, IPSModeStrict, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.Blocked || !plan.HardBlocked {
		t.Fatalf("expected hard block for dpdk bind readiness failure")
	}
	for _, action := range plan.Actions {
		if strings.Contains(action.RollbackCmd, "ixgbe") || strings.Contains(strings.Join(action.RollbackExec, " "), "ixgbe") {
			t.Fatalf("planner must not invent ixgbe rollback driver when current driver is unknown: %+v", action)
		}
	}
}

func TestBuildPlan_DPDKSkipsBindWhenAlreadyBoundToVFIO(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Build: BuildCapabilities{
			SupportsDPDK: true,
		},
		NIC: NICInfo{
			PCIAddress:         "0000:01:00.0",
			DPDKStatusLine:     "0000:01:00.0 drv=vfio-pci unused=ixgbe",
			DPDKDevbindPresent: true,
			DPDKCurrentDriver:  "vfio-pci",
			DPDKCanBindVFIO:    true,
			DPDKCanRollback:    false,
			DPDKBindReady:      true,
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileDPDK, ScopeFull, IPSModeStrict, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Blocked {
		t.Fatalf("did not expect already-vfio DPDK plan to be blocked: %v", plan.BlockingReasons)
	}
	for _, action := range plan.Actions {
		if action.ID == "dpdk-bind" {
			t.Fatalf("did not expect dpdk-bind action when NIC is already bound to vfio-pci")
		}
	}
}

func TestBuildPlan_NFQUsesNftWhenDetected(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface:    "eth0",
		Firewall: "nftables",
		Build: BuildCapabilities{
			SupportsNFQ: true,
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileNFQ, ScopeFull, IPSModeStrict, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, action := range plan.Actions {
		if action.ID != "nfq-queue-rules" {
			continue
		}
		found = true
		if action.ApplyExec[0] != "nft" {
			t.Fatalf("expected nft apply backend, got %v", action.ApplyExec)
		}
		if action.RollbackExec[0] != "nft" {
			t.Fatalf("expected nft rollback backend, got %v", action.RollbackExec)
		}
	}
	if !found {
		t.Fatalf("expected nfq-queue-rules action")
	}
}

func TestBuildPlan_ScopeConfigOnlyContainsOnlyYAML(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Build: BuildCapabilities{SupportsDPDK: true},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFPacket, ScopeConfigOnly, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Actions) != 1 {
		t.Fatalf("expected 1 action for config-only, got %d", len(plan.Actions))
	}
	if plan.Actions[0].Kind != "yaml" {
		t.Fatalf("expected only yaml action, got %s", plan.Actions[0].Kind)
	}
}

func TestBuildPlan_ScopeOSTuningExcludesYAMLAndAdvanced(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		CPU: CPUInfo{
			LogicalCores: 8,
		},
		NIC: NICInfo{
			RSSCombinedCurrent: 4,
			RSSCombinedMax:     8,
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileDPDK, ScopeOSTuning, IPSModeStrict, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, action := range plan.Actions {
		if action.Kind == "yaml" {
			t.Fatalf("did not expect yaml action in os-tuning scope")
		}
		if action.Kind == "dpdk-bind" || action.Kind == "node-hugepages" {
			t.Fatalf("did not expect advanced dpdk action in os-tuning scope: %s", action.Kind)
		}
	}
}

func TestBuildPlan_FullIncludesSystemdProfileAction(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface:      "ens33",
		ConfigPath: "/etc/suricata/suricata.yaml",
		Build: BuildCapabilities{
			SupportsNFQ: true,
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileNFQ, ScopeFull, IPSModeStrict, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, action := range plan.Actions {
		if action.ID != "systemd-profile" {
			continue
		}
		found = true
		if action.Kind != "systemd-profile" {
			t.Fatalf("unexpected kind: %s", action.Kind)
		}
		execStart, _ := action.Metadata["exec_start"].(string)
		if !strings.Contains(execStart, "-q 0") || !strings.Contains(execStart, "--runmode autofp") {
			t.Fatalf("unexpected NFQ ExecStart: %s", execStart)
		}
	}
	if !found {
		t.Fatalf("expected systemd-profile action in full plan")
	}
}

func TestBuildPlan_ConfigOnlyDoesNotIncludeSystemdProfileAction(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface:      "ens33",
		ConfigPath: "/etc/suricata/suricata.yaml",
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFPacket, ScopeConfigOnly, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, action := range plan.Actions {
		if action.ID == "systemd-profile" {
			t.Fatalf("did not expect systemd-profile action in config-only plan")
		}
	}
}

func TestBuildSuricataExecStart_QuotesSystemdArguments(t *testing.T) {
	execStart := buildSuricataExecStart(SystemSnapshot{
		Iface:      "capture 0",
		ConfigPath: "/tmp/suricata configs/suricata.yaml",
	}, ProfileAFPacket)
	if !strings.Contains(execStart, `"--af-packet=capture 0"`) {
		t.Fatalf("expected quoted af-packet argument, got: %s", execStart)
	}
	if !strings.Contains(execStart, `"/tmp/suricata configs/suricata.yaml"`) {
		t.Fatalf("expected quoted config path, got: %s", execStart)
	}
	if strings.Contains(execStart, "\n") {
		t.Fatalf("did not expect multiline ExecStart: %q", execStart)
	}
}
