package surituner

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRenderPlanJSON_Valid(t *testing.T) {
	plan := Plan{
		GeneratedAt: time.Now().UTC(),
		Profile:     ProfileAFPacket,
		Scope:       ScopeConfigOnly,
		IPSMode:     IPSModeIDS,
		Snapshot:    SystemSnapshot{Iface: "eth0"},
		Actions: []PlanAction{
			{
				ID:          "yaml-tuning",
				Summary:     "Tune YAML",
				Reason:      "test",
				RiskLevel:   RiskLow,
				ApplyCmd:    "apply",
				RollbackCmd: "rollback",
			},
		},
	}
	raw, err := RenderPlanJSON(plan)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
}

func TestRenderReportJSON_Valid(t *testing.T) {
	report := Report{
		GeneratedAt: time.Now().UTC(),
		Snapshot:    SystemSnapshot{Iface: "eth0"},
	}
	raw, err := RenderReportJSON(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	for _, key := range []string{"warnings", "recommendations", "unsupported_options", "bottlenecks", "monitoring_recommendations", "planned_actions", "applied_actions"} {
		if _, ok := parsed[key].([]interface{}); !ok {
			t.Fatalf("expected %s to be a JSON array, got %T", key, parsed[key])
		}
	}
	runtimeMetrics, ok := parsed["runtime_metrics"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected runtime_metrics object")
	}
	for _, key := range []string{"suricata_stats", "ethtool_stats"} {
		if _, ok := runtimeMetrics[key].(map[string]interface{}); !ok {
			t.Fatalf("expected runtime_metrics.%s to be an object, got %T", key, runtimeMetrics[key])
		}
	}
}

func TestRenderReportJSON_NormalizesNestedNulls(t *testing.T) {
	report := Report{
		GeneratedAt: time.Now().UTC(),
		Snapshot: SystemSnapshot{
			Iface: "eth0",
		},
	}
	raw, err := RenderReportJSON(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	snapshot := parsed["snapshot"].(map[string]interface{})
	build := snapshot["build"].(map[string]interface{})
	if _, ok := build["warnings"].([]interface{}); !ok {
		t.Fatalf("expected snapshot.build.warnings to be an array, got %T", build["warnings"])
	}
	cpu := snapshot["cpu"].(map[string]interface{})
	if _, ok := cpu["warnings"].([]interface{}); !ok {
		t.Fatalf("expected snapshot.cpu.warnings to be an array, got %T", cpu["warnings"])
	}
	if _, ok := cpu["cores_by_numa"].(map[string]interface{}); !ok {
		t.Fatalf("expected snapshot.cpu.cores_by_numa to be an object, got %T", cpu["cores_by_numa"])
	}
	nic := snapshot["nic"].(map[string]interface{})
	if _, ok := nic["dpdk_unused_drivers"].([]interface{}); !ok {
		t.Fatalf("expected snapshot.nic.dpdk_unused_drivers to be an array, got %T", nic["dpdk_unused_drivers"])
	}
	if _, ok := nic["offload"].(map[string]interface{}); !ok {
		t.Fatalf("expected snapshot.nic.offload to be an object, got %T", nic["offload"])
	}
	ruleset := snapshot["ruleset"].(map[string]interface{})
	if _, ok := ruleset["rule_sources"].([]interface{}); !ok {
		t.Fatalf("expected snapshot.ruleset.rule_sources to be an array, got %T", ruleset["rule_sources"])
	}
}

func TestRenderPlanJSON_NormalizesBlockingReasons(t *testing.T) {
	raw, err := RenderPlanJSON(Plan{
		GeneratedAt: time.Now().UTC(),
		Profile:     ProfileAFPacket,
		Scope:       ScopeConfigOnly,
		IPSMode:     IPSModeIDS,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if _, ok := parsed["blocking_reasons"].([]interface{}); !ok {
		t.Fatalf("expected blocking_reasons to be an array, got %T", parsed["blocking_reasons"])
	}
	if _, ok := parsed["actions"].([]interface{}); !ok {
		t.Fatalf("expected actions to be an array, got %T", parsed["actions"])
	}
}

func TestBuildReportSections(t *testing.T) {
	snapshot := SystemSnapshot{
		Firewall: "unknown",
		Build: BuildCapabilities{
			SupportsDPDK:  false,
			SupportsAFXDP: false,
			SupportsNFQ:   false,
		},
		CPU: CPUInfo{
			LogicalCores: 8,
		},
		NIC: NICInfo{
			RSSCombinedCurrent: 2,
			Offload: map[string]string{
				"gro": "on",
				"lro": "on",
			},
		},
		Ruleset: RulesetInventory{
			PCREHeavyRules: 600,
		},
	}
	unsupported := BuildUnsupportedOptions(snapshot)
	if len(unsupported) == 0 {
		t.Fatalf("expected unsupported options")
	}
	bottlenecks := BuildBottlenecks(snapshot, RuntimeMetrics{
		SuricataStats: map[string]int64{"capture.kernel_drops": 1},
		EthtoolStats:  map[string]int64{"rx_missed_errors": 1},
	})
	if len(bottlenecks) == 0 {
		t.Fatalf("expected bottlenecks")
	}
	monitoring := BuildMonitoringRecommendations()
	if len(monitoring) == 0 {
		t.Fatalf("expected monitoring recommendations")
	}
}

func TestBuildBottlenecks_IncludesRuntimeCounters(t *testing.T) {
	bottlenecks := BuildBottlenecks(SystemSnapshot{}, RuntimeMetrics{
		SuricataStats: map[string]int64{
			"capture.kernel_drops": 1,
			"tcp.reassembly_gap":   2,
			"memcap.pressure":      3,
		},
		EthtoolStats: map[string]int64{
			"rx_dropped": 4,
		},
	})
	for _, want := range []string{"suricata_kernel_drops_present", "tcp_reassembly_gaps_present", "hardware_rx_drops_present", "suricata_memcap_pressure_present"} {
		if !containsString(bottlenecks, want) {
			t.Fatalf("expected bottleneck %s in %v", want, bottlenecks)
		}
	}
}
