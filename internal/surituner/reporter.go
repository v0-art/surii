package surituner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func RenderPlanHuman(plan Plan) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Plan generated: %s\n", plan.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "Profile: %s | Scope: %s | IPS mode: %s | Interface: %s\n", plan.Profile, plan.Scope, plan.IPSMode, plan.Snapshot.Iface)
	if plan.Blocked {
		fmt.Fprintf(&b, "Guardrail status: BLOCKED\n")
		if plan.HardBlocked {
			fmt.Fprintf(&b, "Blocking type: HARD (cannot be bypassed by --force)\n")
		}
		for _, reason := range plan.BlockingReasons {
			fmt.Fprintf(&b, "  - %s\n", reason)
		}
	} else {
		fmt.Fprintf(&b, "Guardrail status: OK\n")
	}
	fmt.Fprintf(&b, "\nActions:\n")
	for i, action := range plan.Actions {
		blocked := ""
		if action.BlockedByGuardrail {
			blocked = " [BLOCKED]"
		}
		fmt.Fprintf(&b, "%d. [%s]%s %s\n", i+1, action.RiskLevel, blocked, action.Summary)
		fmt.Fprintf(&b, "   Reason: %s\n", action.Reason)
		fmt.Fprintf(&b, "   Apply: %s\n", action.ApplyCmd)
		fmt.Fprintf(&b, "   Rollback: %s\n", action.RollbackCmd)
	}
	return b.String()
}

func RenderSnapshotHuman(snapshot SystemSnapshot) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Snapshot: %s\n", snapshot.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "Host: %s | User: %s | Interface: %s\n", snapshot.Hostname, snapshot.User, snapshot.Iface)
	fmt.Fprintf(&b, "Config: %s\n", snapshot.ConfigPath)
	fmt.Fprintf(&b, "Firewall backend: %s\n", emptyIf(snapshot.Firewall, "unknown"))
	fmt.Fprintf(&b, "Suricata: %s (DPDK=%t AF_XDP=%t NFQ=%t HWLOC=%t)\n",
		emptyIf(snapshot.Build.Version, "unknown"),
		snapshot.Build.SupportsDPDK,
		snapshot.Build.SupportsAFXDP,
		snapshot.Build.SupportsNFQ,
		snapshot.Build.SupportsHWLOC,
	)
	fmt.Fprintf(&b, "CPU: cores=%d numa_nodes=%d\n", snapshot.CPU.LogicalCores, snapshot.CPU.NUMANodes)
	fmt.Fprintf(&b, "NIC: driver=%s pci=%s numa=%d rss=%d/%d queues(rx/tx)=%d/%d symmetric_rss=%t xdp_support=%t promisc=%t\n",
		emptyIf(snapshot.NIC.Driver, "unknown"),
		emptyIf(snapshot.NIC.PCIAddress, "unknown"),
		snapshot.NIC.NUMANode,
		snapshot.NIC.RSSCombinedCurrent,
		snapshot.NIC.RSSCombinedMax,
		snapshot.NIC.RXQueues,
		snapshot.NIC.TXQueues,
		snapshot.NIC.SymmetricRSS,
		snapshot.NIC.XDPSupportDetected,
		snapshot.NIC.Promisc,
	)
	if strings.TrimSpace(snapshot.NIC.DPDKStatusLine) != "" {
		fmt.Fprintf(&b, "DPDK status: %s\n", snapshot.NIC.DPDKStatusLine)
	}
	fmt.Fprintf(&b, "DPDK preflight: devbind_present=%t bind_ready=%t current_driver=%s unused=%s\n",
		snapshot.NIC.DPDKDevbindPresent,
		snapshot.NIC.DPDKBindReady,
		emptyIf(snapshot.NIC.DPDKCurrentDriver, "unknown"),
		emptyIf(strings.Join(snapshot.NIC.DPDKUnusedDrivers, ","), "none"),
	)
	fmt.Fprintf(&b, "Ruleset: enabled=%d total=%d pcre-heavy=%d size=%d bytes\n",
		snapshot.Ruleset.EnabledRules,
		snapshot.Ruleset.TotalRules,
		snapshot.Ruleset.PCREHeavyRules,
		snapshot.Ruleset.RulesFileSizeBytes,
	)
	fmt.Fprintf(&b, "Safety: default_route=%s ssh_iface=%s management_iface=%t\n",
		emptyIf(snapshot.Safety.DefaultRouteIface, "unknown"),
		emptyIf(snapshot.Safety.SSHIface, "unknown"),
		snapshot.Safety.IsManagementIface,
	)
	warnings := dedupeStrings(append(snapshot.Warnings, snapshot.Safety.Warnings...))
	if len(warnings) > 0 {
		fmt.Fprintf(&b, "\nWarnings:\n")
		for _, warning := range warnings {
			fmt.Fprintf(&b, "  - %s\n", warning)
		}
	}
	return b.String()
}

func RenderReportJSON(report Report) (string, error) {
	report = normalizeReportSlices(report)
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func RenderPlanJSON(plan Plan) (string, error) {
	plan = normalizePlan(plan)
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func normalizeReportSlices(report Report) Report {
	report.Snapshot = normalizeSnapshot(report.Snapshot)
	report.Warnings = nonNilStrings(report.Warnings)
	report.Recommendations = nonNilStrings(report.Recommendations)
	report.UnsupportedOptions = nonNilStrings(report.UnsupportedOptions)
	report.Bottlenecks = nonNilStrings(report.Bottlenecks)
	report.MonitoringRecommendations = nonNilStrings(report.MonitoringRecommendations)
	report.PlannedActions = nonNilStrings(report.PlannedActions)
	report.AppliedActions = nonNilStrings(report.AppliedActions)
	report.RuntimeMetrics.SuricataStats = nonNilInt64Map(report.RuntimeMetrics.SuricataStats)
	report.RuntimeMetrics.EthtoolStats = nonNilInt64Map(report.RuntimeMetrics.EthtoolStats)
	report.RuntimeMetrics.Acceptance = nonNilStrings(report.RuntimeMetrics.Acceptance)
	report.RuntimeMetrics.Warnings = nonNilStrings(report.RuntimeMetrics.Warnings)
	return report
}

func normalizePlan(plan Plan) Plan {
	plan.Snapshot = normalizeSnapshot(plan.Snapshot)
	plan.BlockingReasons = nonNilStrings(plan.BlockingReasons)
	if plan.Actions == nil {
		plan.Actions = []PlanAction{}
	}
	for i := range plan.Actions {
		if plan.Actions[i].Metadata == nil {
			plan.Actions[i].Metadata = map[string]interface{}{}
		}
	}
	return plan
}

func normalizeSnapshot(snapshot SystemSnapshot) SystemSnapshot {
	snapshot.Build.Warnings = nonNilStrings(snapshot.Build.Warnings)
	snapshot.CPU.Warnings = nonNilStrings(snapshot.CPU.Warnings)
	snapshot.NIC.Warnings = nonNilStrings(snapshot.NIC.Warnings)
	snapshot.NIC.DPDKUnusedDrivers = nonNilStrings(snapshot.NIC.DPDKUnusedDrivers)
	snapshot.Ruleset.RuleSources = nonNilStrings(snapshot.Ruleset.RuleSources)
	snapshot.Ruleset.Warnings = nonNilStrings(snapshot.Ruleset.Warnings)
	snapshot.Safety.Warnings = nonNilStrings(snapshot.Safety.Warnings)
	snapshot.Warnings = nonNilStrings(snapshot.Warnings)
	if snapshot.CPU.CoresByNUMA == nil {
		snapshot.CPU.CoresByNUMA = map[string][]int{}
	}
	for node, cpus := range snapshot.CPU.CoresByNUMA {
		if cpus == nil {
			snapshot.CPU.CoresByNUMA[node] = []int{}
		}
	}
	if snapshot.NIC.Offload == nil {
		snapshot.NIC.Offload = map[string]string{}
	}
	return snapshot
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilInt64Map(values map[string]int64) map[string]int64 {
	if values == nil {
		return map[string]int64{}
	}
	return values
}

func BuildRecommendations(snapshot SystemSnapshot) []string {
	var recommendations []string
	if snapshot.NIC.Offload["gro"] != "off" {
		recommendations = append(recommendations, "disable GRO on capture interface")
	}
	if snapshot.NIC.Offload["lro"] != "off" {
		recommendations = append(recommendations, "disable LRO on capture interface")
	}
	if snapshot.Ruleset.PCREHeavyRules > 500 {
		recommendations = append(recommendations, "review PCRE-heavy rules to lower CPU spikes")
	}
	if snapshot.NIC.RSSCombinedCurrent < snapshot.CPU.LogicalCores && snapshot.NIC.RSSCombinedMax > snapshot.NIC.RSSCombinedCurrent {
		recommendations = append(recommendations, "increase RSS combined queues for better core utilization")
	}
	if snapshot.Safety.IsManagementIface {
		recommendations = append(recommendations, "avoid CRITICAL capture-driver changes on management interface unless --force")
	}
	if !snapshot.Build.SupportsDPDK {
		recommendations = append(recommendations, "DPDK profile is unsupported by current Suricata build")
	}
	if !snapshot.Build.SupportsAFXDP {
		recommendations = append(recommendations, "AF_XDP profile is unsupported by current Suricata build or kernel")
	}
	if !snapshot.Build.SupportsNFQ {
		recommendations = append(recommendations, "NFQ profile is unsupported by current Suricata build")
	}
	recommendations = append(recommendations, "monitor capture.kernel_drops, rx_dropped and tcp.reassembly_gap after apply")
	return dedupeStrings(recommendations)
}

func BuildUnsupportedOptions(snapshot SystemSnapshot) []string {
	var unsupported []string
	if !snapshot.Build.SupportsDPDK {
		unsupported = append(unsupported, "dpdk")
	}
	if !snapshot.Build.SupportsAFXDP {
		unsupported = append(unsupported, "af-xdp")
	}
	if !snapshot.Build.SupportsNFQ {
		unsupported = append(unsupported, "nfq")
	}
	if snapshot.Firewall == "unknown" {
		unsupported = append(unsupported, "nfq-firewall-backend")
	}
	return dedupeStrings(unsupported)
}

func BuildBottlenecks(snapshot SystemSnapshot, metrics RuntimeMetrics) []string {
	var bottlenecks []string
	if snapshot.NIC.RSSCombinedCurrent > 0 && snapshot.NIC.RSSCombinedCurrent < snapshot.CPU.LogicalCores {
		bottlenecks = append(bottlenecks, "rss_combined_queues_below_cpu_cores")
	}
	if snapshot.Ruleset.PCREHeavyRules > 500 {
		bottlenecks = append(bottlenecks, "high_pcre_rule_density")
	}
	if snapshot.NIC.Offload["gro"] != "off" || snapshot.NIC.Offload["lro"] != "off" {
		bottlenecks = append(bottlenecks, "offloading_may_reduce_ids_visibility")
	}
	if metrics.SuricataStats["capture.kernel_drops"] > 0 {
		bottlenecks = append(bottlenecks, "suricata_kernel_drops_present")
	}
	if metrics.SuricataStats["tcp.reassembly_gap"] > 0 {
		bottlenecks = append(bottlenecks, "tcp_reassembly_gaps_present")
	}
	if metrics.EthtoolStats["rx_missed_errors"] > 0 || metrics.EthtoolStats["rx_dropped"] > 0 {
		bottlenecks = append(bottlenecks, "hardware_rx_drops_present")
	}
	if metrics.SuricataStats["memcap.pressure"] > 0 {
		bottlenecks = append(bottlenecks, "suricata_memcap_pressure_present")
	}
	return dedupeStrings(bottlenecks)
}

func BuildMonitoringRecommendations() []string {
	return []string{
		"track capture.kernel_drops delta for at least 10 minutes after apply",
		"track ethtool -S counters rx_missed_errors and rx_dropped",
		"track tcp.reassembly_gap and correlate with checksum/memcap indicators",
		"verify worker CPU utilization is balanced and below sustained 100%",
	}
}

func emptyIf(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
