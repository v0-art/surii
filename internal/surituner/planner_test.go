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
			DPDKIOMMUGroup:     "42",
			DPDKIOMMUViable:    true,
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

func TestBuildPlan_GuardrailsBlockOSActionsOnManagementIface(t *testing.T) {
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
			IsManagementIface: true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFPacket, ScopeFull, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.Blocked {
		t.Fatalf("expected full plan to be blocked on management iface")
	}
	for _, action := range plan.Actions {
		if action.Category != "os" {
			continue
		}
		if !action.BlockedByGuardrail {
			t.Fatalf("expected os action %s to be blocked on management iface", action.ID)
		}
	}
}

func TestBuildPlan_GuardrailsBlockDefaultRouteManagementIface(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "ens33",
		CPU:   CPUInfo{LogicalCores: 4},
		NIC: NICInfo{
			RSSCombinedCurrent: 2,
			RSSCombinedMax:     4,
		},
		Safety: SafetyContext{
			DefaultRouteIface:   "ens33",
			SSHIface:            "ens37",
			IsDefaultRouteIface: true,
			IsManagementIface:   true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFPacket, ScopeFull, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.Blocked {
		t.Fatalf("expected full plan on default-route management iface to be blocked")
	}
	for _, action := range plan.Actions {
		if isManagementGuardedAction(action) && !action.BlockedByGuardrail {
			t.Fatalf("expected guarded action %s to be blocked", action.ID)
		}
	}
}

func TestBuildPlan_GuardrailsBlockSSHManagementIface(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "ens37",
		CPU:   CPUInfo{LogicalCores: 4},
		NIC: NICInfo{
			RSSCombinedCurrent: 2,
			RSSCombinedMax:     4,
		},
		Safety: SafetyContext{
			DefaultRouteIface: "ens33",
			SSHIface:          "ens37",
			IsSSHIface:        true,
			IsManagementIface: true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFPacket, ScopeOSTuning, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.Blocked {
		t.Fatalf("expected os-tuning plan on SSH management iface to be blocked")
	}
	for _, action := range plan.Actions {
		if !action.BlockedByGuardrail {
			t.Fatalf("expected os-tuning action %s to be blocked", action.ID)
		}
	}
}

func TestBuildPlan_GuardrailsAllowWhenNoManagementMatch(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "ens38",
		CPU:   CPUInfo{LogicalCores: 4},
		NIC: NICInfo{
			RSSCombinedCurrent: 2,
			RSSCombinedMax:     4,
		},
		Safety: SafetyContext{
			DefaultRouteIface: "ens33",
			SSHIface:          "ens37",
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFPacket, ScopeFull, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Blocked {
		t.Fatalf("did not expect non-management plan to be blocked: %v", plan.BlockingReasons)
	}
	for _, action := range plan.Actions {
		if action.BlockedByGuardrail {
			t.Fatalf("did not expect action %s to be guardrail-blocked", action.ID)
		}
	}
}

func TestBuildPlan_GuardrailsPreserveHardBlockReasons(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Build: BuildCapabilities{
			SupportsDPDK: true,
		},
		NIC: NICInfo{
			Driver:     "ixgbe",
			PCIAddress: "0000:01:00.0",
		},
		Safety: SafetyContext{
			IsManagementIface: true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileDPDK, ScopeFull, IPSModeStrict, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.Blocked || !plan.HardBlocked {
		t.Fatalf("expected combined guardrail and hard block, got blocked=%t hard=%t", plan.Blocked, plan.HardBlocked)
	}
	reasons := strings.Join(plan.BlockingReasons, "\n")
	if !strings.Contains(reasons, "dpdk-devbind.py") {
		t.Fatalf("expected hard block reason to be preserved, got %v", plan.BlockingReasons)
	}
	if !strings.Contains(reasons, "guardrail blocked") {
		t.Fatalf("expected guardrail reason to be present, got %v", plan.BlockingReasons)
	}
}

func TestBuildPlan_GuardrailsAllowConfigOnlyOnManagementIface(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Safety: SafetyContext{
			IsManagementIface: true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFPacket, ScopeConfigOnly, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Blocked {
		t.Fatalf("did not expect config-only plan to be blocked on management iface: %v", plan.BlockingReasons)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != "yaml" {
		t.Fatalf("expected config-only plan to contain only yaml action, got %+v", plan.Actions)
	}
	if plan.Actions[0].BlockedByGuardrail {
		t.Fatalf("did not expect yaml action to be guardrail-blocked")
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
			DPDKIOMMUGroup:     "42",
			DPDKIOMMUViable:    true,
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

func TestBuildPlan_ForceDoesNotBypassHardBlockers(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Build: BuildCapabilities{
			SupportsDPDK: false,
		},
		Safety: SafetyContext{
			IsManagementIface: true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileDPDK, ScopeFull, IPSModeStrict, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.Blocked || !plan.HardBlocked {
		t.Fatalf("expected force=true to preserve hard blockers, blocked=%t hard=%t reasons=%v", plan.Blocked, plan.HardBlocked, plan.BlockingReasons)
	}
	for _, action := range plan.Actions {
		if action.BlockedByGuardrail {
			t.Fatalf("did not expect guardrail blockers with force=true: %+v", action)
		}
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
			DPDKIOMMUGroup:     "42",
			DPDKIOMMUViable:    true,
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

func TestBuildPlan_DPDKConfigOnlyDoesNotRequireBindPreflight(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Build: BuildCapabilities{
			SupportsDPDK: true,
		},
		NIC: NICInfo{
			PCIAddress: "0000:01:00.0",
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileDPDK, ScopeConfigOnly, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Blocked || plan.HardBlocked {
		t.Fatalf("did not expect config-only DPDK plan to require bind preflight, blocked=%t hard=%t reasons=%v", plan.Blocked, plan.HardBlocked, plan.BlockingReasons)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != "yaml" {
		t.Fatalf("expected only YAML action for config-only DPDK plan, got %+v", plan.Actions)
	}
}

func TestBuildPlan_DPDKOSTuningDoesNotRequireDPDKCapability(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		CPU: CPUInfo{
			LogicalCores: 4,
		},
		NIC: NICInfo{
			RSSCombinedCurrent: 2,
			RSSCombinedMax:     4,
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileDPDK, ScopeOSTuning, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.HardBlocked {
		t.Fatalf("did not expect os-tuning DPDK plan to require DPDK build/bind preflight: %v", plan.BlockingReasons)
	}
	for _, action := range plan.Actions {
		if action.Kind == "yaml" || action.Kind == "dpdk-bind" || action.Kind == "node-hugepages" {
			t.Fatalf("did not expect DPDK config/full action in os-tuning scope: %+v", action)
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
			DPDKIOMMUGroup:     "42",
			DPDKIOMMUViable:    true,
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

func TestBuildPlan_CapabilityGuardBlocksDPDKWithoutIOMMUGroup(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "eth0",
		Build: BuildCapabilities{
			SupportsDPDK: true,
		},
		NIC: NICInfo{
			PCIAddress:         "0000:01:00.0",
			DPDKStatusLine:     "0000:01:00.0 drv=ixgbe unused=vfio-pci",
			DPDKDevbindPresent: true,
			DPDKCanBindVFIO:    true,
			DPDKCanRollback:    true,
			DPDKBindReady:      false,
			DPDKIOMMUViable:    false,
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
		t.Fatalf("expected hard block without IOMMU group")
	}
	if !strings.Contains(strings.Join(plan.BlockingReasons, "\n"), "IOMMU group") {
		t.Fatalf("expected IOMMU group blocking reason, got %v", plan.BlockingReasons)
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
		if strings.Contains(action.RollbackCmd, "<surituner-owned-handle>") || strings.Contains(strings.Join(action.RollbackExec, " "), "<surituner-owned-handle>") {
			t.Fatalf("did not expect fake nft rollback handle placeholder: %+v", action)
		}
		if !strings.Contains(action.RollbackCmd, nfqNftRuleComment) {
			t.Fatalf("expected nft rollback command to identify owned rule comment, got %q", action.RollbackCmd)
		}
	}
	if !found {
		t.Fatalf("expected nfq-queue-rules action")
	}
}

func TestBuildPlan_NFQHardBlocksUnknownFirewallBackend(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface:    "eth0",
		Firewall: "unknown",
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
	if !plan.Blocked || !plan.HardBlocked {
		t.Fatalf("expected NFQ full plan to hard-block without firewall backend, got blocked=%t hard=%t reasons=%v", plan.Blocked, plan.HardBlocked, plan.BlockingReasons)
	}
	if !strings.Contains(strings.Join(plan.BlockingReasons, "\n"), "iptables or nftables") {
		t.Fatalf("expected firewall backend blocking reason, got %v", plan.BlockingReasons)
	}
}

func TestBuildPlan_NFQConfigOnlyDoesNotRequireFirewallBackend(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface:    "eth0",
		Firewall: "unknown",
		Build: BuildCapabilities{
			SupportsNFQ: true,
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileNFQ, ScopeConfigOnly, IPSModeStrict, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Blocked || plan.HardBlocked {
		t.Fatalf("did not expect config-only NFQ plan to require firewall backend, blocked=%t hard=%t reasons=%v", plan.Blocked, plan.HardBlocked, plan.BlockingReasons)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != "yaml" {
		t.Fatalf("expected only YAML action for config-only NFQ plan, got %+v", plan.Actions)
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

func TestBuildPlan_PCAPConfigOnlyContainsOnlyYAML(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "ens37",
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfilePCAP, ScopeConfigOnly, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Blocked || plan.HardBlocked {
		t.Fatalf("did not expect PCAP config-only blockers: %v", plan.BlockingReasons)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].ID != "yaml-tuning" {
		t.Fatalf("expected only YAML action for PCAP config-only, got %+v", plan.Actions)
	}
	if got := plan.Actions[0].Metadata["runmode"]; got != "autofp" {
		t.Fatalf("expected PCAP runmode metadata autofp, got %v", got)
	}
}

func TestBuildPlan_PCAPFullIncludesSystemdProfileAction(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface:      "ens37",
		ConfigPath: "/etc/suricata/suricata.yaml",
		CPU:        CPUInfo{LogicalCores: 4},
		NIC: NICInfo{
			RSSCombinedCurrent: 2,
			RSSCombinedMax:     4,
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfilePCAP, ScopeFull, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Blocked || plan.HardBlocked {
		t.Fatalf("did not expect PCAP full capability blockers: %v", plan.BlockingReasons)
	}
	if !containsAction(plan.Actions, "yaml-tuning") || !containsAction(plan.Actions, "systemd-profile") {
		t.Fatalf("expected PCAP full plan to include YAML and systemd-profile actions, got %+v", plan.Actions)
	}
}

func TestBuildPlan_AFXDPFullDoesNotIncludeNoopQueueAction(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "ens33",
		Build: BuildCapabilities{
			SupportsAFXDP: true,
		},
		NIC: NICInfo{
			XDPKernelSupported:         true,
			XDPInterfaceSignalDetected: true,
			XDPSupportDetected:         true,
			AFXDPZeroCopyProven:        false,
		},
		Safety: SafetyContext{
			IsManagementIface: false,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFXDP, ScopeFull, IPSModeAvailability, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, action := range plan.Actions {
		if action.ID == "af-xdp-queues" {
			t.Fatalf("did not expect no-op af-xdp queue action in full plan")
		}
	}
	if !containsAction(plan.Actions, "af-xdp-hugepages") {
		t.Fatalf("expected af-xdp hugepages action")
	}
	if !containsAction(plan.Actions, "af-xdp-interface-warning") {
		t.Fatalf("expected af-xdp critical warning action")
	}
}

func TestBuildPlan_AFXDPConfigOnlyAllowsKernelOnlyPreflight(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "ens33",
		Build: BuildCapabilities{
			SupportsAFXDP: true,
		},
		NIC: NICInfo{
			XDPKernelSupported: true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFXDP, ScopeConfigOnly, IPSModeIDS, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Blocked || plan.HardBlocked {
		t.Fatalf("did not expect AF_XDP config-only kernel-only preflight to block: %v", plan.BlockingReasons)
	}
}

func TestBuildPlan_AFXDPFullBlocksWithoutInterfaceSignal(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "ens33",
		Build: BuildCapabilities{
			SupportsAFXDP: true,
		},
		NIC: NICInfo{
			XDPKernelSupported: true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFXDP, ScopeFull, IPSModeIDS, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.Blocked || !plan.HardBlocked {
		t.Fatalf("expected AF_XDP full without interface signal to hard-block")
	}
	if !strings.Contains(strings.Join(plan.BlockingReasons, "\n"), "interface XDP support signal") {
		t.Fatalf("expected interface signal blocking reason, got %v", plan.BlockingReasons)
	}
}

func TestBuildPlan_AFXDPBlocksOldKernel(t *testing.T) {
	snapshot := SystemSnapshot{
		Iface: "ens33",
		Build: BuildCapabilities{
			SupportsAFXDP: true,
		},
		NIC: NICInfo{
			XDPInterfaceSignalDetected: true,
		},
	}
	plan, err := NewPlanner().BuildPlan(snapshot, ProfileAFXDP, ScopeConfigOnly, IPSModeIDS, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !plan.Blocked || !plan.HardBlocked {
		t.Fatalf("expected AF_XDP old/unknown kernel preflight to hard-block")
	}
	if !strings.Contains(strings.Join(plan.BlockingReasons, "\n"), "kernel") {
		t.Fatalf("expected kernel blocking reason, got %v", plan.BlockingReasons)
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

func TestBuildSuricataExecStart_PCAPQuotesSystemdArguments(t *testing.T) {
	execStart := buildSuricataExecStart(SystemSnapshot{
		Iface:      "capture 0",
		ConfigPath: "/tmp/suricata configs/suricata.yaml",
	}, ProfilePCAP)
	if !strings.Contains(execStart, `-i "capture 0"`) {
		t.Fatalf("expected quoted pcap interface argument, got: %s", execStart)
	}
	if !strings.Contains(execStart, `-c "/tmp/suricata configs/suricata.yaml"`) {
		t.Fatalf("expected quoted config path, got: %s", execStart)
	}
	if strings.Contains(execStart, "\n") {
		t.Fatalf("did not expect multiline ExecStart: %q", execStart)
	}
}

func containsAction(actions []PlanAction, id string) bool {
	for _, action := range actions {
		if action.ID == id {
			return true
		}
	}
	return false
}
