package surituner

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Planner struct{}

const nfqNftRuleComment = "surituner-nfq-0"

func NewPlanner() *Planner {
	return &Planner{}
}

func (p *Planner) BuildPlan(snapshot SystemSnapshot, profile CaptureProfile, scope ApplyScope, ipsMode IPSMode, force bool) (Plan, error) {
	if !profile.Valid() {
		return Plan{}, fmt.Errorf("invalid profile: %s", profile)
	}
	if !scope.Valid() {
		return Plan{}, fmt.Errorf("invalid scope: %s", scope)
	}
	if !ipsMode.Valid() {
		return Plan{}, fmt.Errorf("invalid ips mode: %s", ipsMode)
	}

	var actions []PlanAction
	if scope == ScopeConfigOnly || scope == ScopeFull {
		actions = append(actions, p.buildYAMLAction(snapshot, profile, ipsMode))
	}

	if scope == ScopeOSTuning || scope == ScopeFull {
		actions = append(actions, p.buildOSTuningActions(snapshot, profile)...)
	}
	if scope == ScopeFull {
		actions = append(actions, p.buildProfileAdvancedActions(snapshot, profile)...)
		actions = append(actions, p.buildServiceProfileAction(snapshot, profile))
	}

	plan := Plan{
		GeneratedAt: time.Now().UTC(),
		Profile:     profile,
		Scope:       scope,
		IPSMode:     ipsMode,
		Snapshot:    snapshot,
		Actions:     actions,
	}

	plan = applyCapabilityGuards(plan)
	plan = applyGuardrails(plan, force)
	return plan, nil
}

func (p *Planner) buildYAMLAction(snapshot SystemSnapshot, profile CaptureProfile, ipsMode IPSMode) PlanAction {
	mode := "workers"
	if profile == ProfileNFQ {
		mode = "autofp"
	}
	reason := "Align Suricata runmode, affinity and memory caps with hardware and ruleset size."
	if profile == ProfileNFQ {
		reason = "NFQ IPS path requires autofp and queue-aware exception policy."
	}
	return PlanAction{
		ID:           "yaml-tuning",
		Summary:      "Tune suricata.yaml profile settings",
		Reason:       reason,
		RiskLevel:    RiskLow,
		Category:     "config",
		Kind:         "yaml",
		ApplyCmd:     fmt.Sprintf("update suricata.yaml (profile=%s runmode=%s)", profile, mode),
		RollbackCmd:  "restore suricata.yaml from backup in state file",
		RequiresRoot: true,
		Metadata: map[string]interface{}{
			"profile":  profile,
			"runmode":  mode,
			"ips_mode": ipsMode,
		},
	}
}

func (p *Planner) buildServiceProfileAction(snapshot SystemSnapshot, profile CaptureProfile) PlanAction {
	execStart := buildSuricataExecStart(snapshot, profile)
	return PlanAction{
		ID:           "systemd-profile",
		Summary:      "Configure suricata.service capture startup mode",
		Reason:       "The packaged service may default to --af-packet; full profile apply must start Suricata with the selected capture backend.",
		RiskLevel:    RiskLow,
		Category:     "service",
		Kind:         "systemd-profile",
		ApplyCmd:     "write systemd drop-in for suricata.service and daemon-reload",
		RollbackCmd:  "restore previous SuriTuner systemd drop-in state and daemon-reload",
		RequiresRoot: true,
		Metadata: map[string]interface{}{
			"exec_start": execStart,
			"profile":    profile,
		},
	}
}

func buildSuricataExecStart(snapshot SystemSnapshot, profile CaptureProfile) string {
	configPath := strings.TrimSpace(snapshot.ConfigPath)
	if configPath == "" {
		configPath = "/etc/suricata/suricata.yaml"
	}
	configArg := systemdExecArg(configPath)
	iface := strings.TrimSpace(snapshot.Iface)
	switch profile {
	case ProfileDPDK:
		return fmt.Sprintf("/usr/bin/suricata -D --dpdk -c %s --pidfile /var/run/suricata/suricata.pid", configArg)
	case ProfileAFXDP:
		if iface != "" {
			return fmt.Sprintf("/usr/bin/suricata -D %s -c %s --pidfile /var/run/suricata/suricata.pid", systemdExecArg("--af-xdp="+iface), configArg)
		}
		return fmt.Sprintf("/usr/bin/suricata -D --af-xdp -c %s --pidfile /var/run/suricata/suricata.pid", configArg)
	case ProfileNFQ:
		return fmt.Sprintf("/usr/bin/suricata -D -q 0 --runmode autofp -c %s --pidfile /var/run/suricata/suricata.pid", configArg)
	default:
		if iface != "" {
			return fmt.Sprintf("/usr/bin/suricata -D %s -c %s --pidfile /var/run/suricata/suricata.pid", systemdExecArg("--af-packet="+iface), configArg)
		}
		return fmt.Sprintf("/usr/bin/suricata -D --af-packet -c %s --pidfile /var/run/suricata/suricata.pid", configArg)
	}
}

func systemdExecArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if strings.ContainsAny(arg, " \t\r\n\"'\\") {
		return strconv.Quote(arg)
	}
	return arg
}

func (p *Planner) buildOSTuningActions(snapshot SystemSnapshot, profile CaptureProfile) []PlanAction {
	iface := snapshot.Iface
	actions := []PlanAction{
		{
			ID:           "disable-gro",
			Summary:      "Disable GRO on capture interface",
			Reason:       "GRO can hide packet boundaries and degrade IDS visibility.",
			RiskLevel:    RiskMedium,
			Category:     "os",
			Kind:         "ethtool-k",
			ApplyCmd:     fmt.Sprintf("ethtool -K %s gro off", iface),
			RollbackCmd:  "restore GRO state from pre-state ethtool -k snapshot",
			ApplyExec:    []string{"ethtool", "-K", iface, "gro", "off"},
			RequiresRoot: true,
			Metadata: map[string]interface{}{
				"feature": "gro",
			},
		},
		{
			ID:           "disable-lro",
			Summary:      "Disable LRO on capture interface",
			Reason:       "LRO reduces packet fidelity for IDS workloads.",
			RiskLevel:    RiskMedium,
			Category:     "os",
			Kind:         "ethtool-k",
			ApplyCmd:     fmt.Sprintf("ethtool -K %s lro off", iface),
			RollbackCmd:  "restore LRO state from pre-state ethtool -k snapshot",
			ApplyExec:    []string{"ethtool", "-K", iface, "lro", "off"},
			RequiresRoot: true,
			Metadata: map[string]interface{}{
				"feature": "lro",
			},
		},
		{
			ID:           "ring-buffers",
			Summary:      "Increase NIC ring buffers",
			Reason:       "Larger RX/TX rings reduce drops during bursts.",
			RiskLevel:    RiskMedium,
			Category:     "os",
			Kind:         "ethtool-g",
			ApplyCmd:     fmt.Sprintf("ethtool -G %s rx 4096 tx 4096", iface),
			RollbackCmd:  "restore ethtool -g current ring values from state",
			ApplyExec:    []string{"ethtool", "-G", iface, "rx", "4096", "tx", "4096"},
			RequiresRoot: true,
		},
		{
			ID:           "sysctl-net-buffers",
			Summary:      "Expand kernel network buffers",
			Reason:       "Higher burst tolerance lowers kernel drops under load.",
			RiskLevel:    RiskMedium,
			Category:     "os",
			Kind:         "sysctl",
			ApplyCmd:     "sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728 net.core.netdev_max_backlog=250000",
			RollbackCmd:  "restore original net.core.{rmem_max,wmem_max,netdev_max_backlog} from state",
			ApplyExec:    []string{"sysctl", "-w", "net.core.rmem_max=134217728", "net.core.wmem_max=134217728", "net.core.netdev_max_backlog=250000"},
			RequiresRoot: true,
		},
		{
			ID:           "set-promisc-on",
			Summary:      "Enable promiscuous mode for IDS capture",
			Reason:       "Promisc mode is required for mirror/tap IDS scenarios.",
			RiskLevel:    RiskMedium,
			Category:     "os",
			Kind:         "ip-link",
			ApplyCmd:     fmt.Sprintf("ip link set dev %s promisc on", iface),
			RollbackCmd:  fmt.Sprintf("ip link set dev %s promisc off (if previously off)", iface),
			ApplyExec:    []string{"ip", "link", "set", "dev", iface, "promisc", "on"},
			RollbackExec: []string{"ip", "link", "set", "dev", iface, "promisc", "off"},
			RequiresRoot: true,
		},
	}

	if snapshot.NIC.RSSCombinedMax > 0 && snapshot.NIC.RSSCombinedCurrent > 0 {
		target := snapshot.NIC.RSSCombinedCurrent
		if snapshot.CPU.LogicalCores > target && snapshot.CPU.LogicalCores <= snapshot.NIC.RSSCombinedMax {
			target = snapshot.CPU.LogicalCores
		}
		if target > snapshot.NIC.RSSCombinedCurrent {
			actions = append(actions, PlanAction{
				ID:           "rss-combined-queues",
				Summary:      "Increase RSS combined queues",
				Reason:       "Better queue parallelism for worker thread distribution.",
				RiskLevel:    RiskHigh,
				Category:     "os",
				Kind:         "ethtool-l",
				ApplyCmd:     fmt.Sprintf("ethtool -L %s combined %d", snapshot.Iface, target),
				RollbackCmd:  fmt.Sprintf("ethtool -L %s combined %d", snapshot.Iface, snapshot.NIC.RSSCombinedCurrent),
				ApplyExec:    []string{"ethtool", "-L", snapshot.Iface, "combined", fmt.Sprintf("%d", target)},
				RollbackExec: []string{"ethtool", "-L", snapshot.Iface, "combined", fmt.Sprintf("%d", snapshot.NIC.RSSCombinedCurrent)},
				RequiresRoot: true,
			})
		}
	}

	actions = append(actions, PlanAction{
		ID:           "irq-affinity",
		Summary:      "Pin NIC IRQs to local NUMA CPUs",
		Reason:       "NUMA-aware IRQ pinning lowers cross-node memory traffic.",
		RiskLevel:    RiskHigh,
		Category:     "os",
		Kind:         "irq",
		ApplyCmd:     fmt.Sprintf("set_irq_affinity %s local-numa-cpus", snapshot.Iface),
		RollbackCmd:  "restore IRQ affinity map from state file",
		RequiresRoot: true,
	})

	return actions
}

func (p *Planner) buildProfileAdvancedActions(snapshot SystemSnapshot, profile CaptureProfile) []PlanAction {
	iface := snapshot.Iface
	switch profile {
	case ProfileDPDK:
		dpdkTarget := snapshot.NIC.PCIAddress
		if dpdkTarget == "" {
			dpdkTarget = iface
		}
		actions := []PlanAction{
			{
				ID:           "dpdk-hugepages-numa",
				Summary:      "Allocate NUMA-local hugepages for DPDK",
				Reason:       "DPDK requires explicit hugepage reservation close to NIC NUMA node.",
				RiskLevel:    RiskCritical,
				Category:     "os",
				Kind:         "node-hugepages",
				ApplyCmd:     fmt.Sprintf("echo 1024 > /sys/devices/system/node/node%d/hugepages/hugepages-2048kB/nr_hugepages", maxInt(snapshot.NIC.NUMANode, 0)),
				RollbackCmd:  "restore hugepages from state",
				RequiresRoot: true,
				Metadata: map[string]interface{}{
					"node":  maxInt(snapshot.NIC.NUMANode, 0),
					"value": 1024,
				},
			},
		}
		restoreDriver := strings.TrimSpace(snapshot.NIC.DPDKCurrentDriver)
		if restoreDriver == "" {
			restoreDriver = strings.TrimSpace(snapshot.NIC.Driver)
		}
		if restoreDriver != "" && !strings.EqualFold(restoreDriver, "vfio-pci") {
			actions = append(actions, PlanAction{
				ID:           "dpdk-bind",
				Summary:      "Rebind capture NIC for DPDK userspace driver",
				Reason:       "DPDK fast path needs userspace driver binding.",
				RiskLevel:    RiskCritical,
				Category:     "os",
				Kind:         "dpdk-bind",
				ApplyCmd:     fmt.Sprintf("dpdk-devbind.py --bind=vfio-pci %s", dpdkTarget),
				RollbackCmd:  fmt.Sprintf("dpdk-devbind.py --bind=%s %s", restoreDriver, dpdkTarget),
				ApplyExec:    []string{"dpdk-devbind.py", "--bind=vfio-pci", dpdkTarget},
				RollbackExec: []string{"dpdk-devbind.py", fmt.Sprintf("--bind=%s", restoreDriver), dpdkTarget},
				RequiresRoot: true,
			})
		}
		return actions
	case ProfileAFXDP:
		return []PlanAction{
			{
				ID:           "af-xdp-interface-warning",
				Summary:      "AF_XDP may reduce or remove standard kernel network use for this interface",
				Reason:       "XDP data paths can interfere with conventional interface usage on host management plane.",
				RiskLevel:    RiskCritical,
				Category:     "warning",
				Kind:         "warning",
				ApplyCmd:     "operator acknowledgement required",
				RollbackCmd:  "n/a",
				RequiresRoot: false,
			},
			{
				ID:           "af-xdp-hugepages",
				Summary:      "Reserve hugepages for AF_XDP unaligned chunks",
				Reason:       "Unaligned chunk mode benefits from dedicated hugepages.",
				RiskLevel:    RiskCritical,
				Category:     "os",
				Kind:         "hugepages",
				ApplyCmd:     "sysctl -w vm.nr_hugepages=512",
				RollbackCmd:  "restore vm.nr_hugepages from state",
				ApplyExec:    []string{"sysctl", "-w", "vm.nr_hugepages=512"},
				RequiresRoot: true,
			},
			{
				ID:          "af-xdp-queues",
				Summary:     "Enable aggressive queue tuning for AF_XDP",
				Reason:      "AF_XDP throughput relies on queue-level tuning.",
				RiskLevel:   RiskCritical,
				Category:    "os",
				Kind:        "af-xdp",
				ApplyCmd:    fmt.Sprintf("ethtool -L %s combined %d", iface, maxInt(snapshot.NIC.RSSCombinedCurrent, 1)),
				RollbackCmd: "restore channel settings from state",
				ApplyExec: []string{
					"ethtool",
					"-L",
					iface,
					"combined",
					fmt.Sprintf("%d", maxInt(snapshot.NIC.RSSCombinedCurrent, 1)),
				},
				RollbackExec: []string{
					"ethtool",
					"-L",
					iface,
					"combined",
					fmt.Sprintf("%d", maxInt(snapshot.NIC.RSSCombinedCurrent, 1)),
				},
				RequiresRoot: true,
			},
		}
	case ProfileNFQ:
		applyCmd := "iptables -I FORWARD -j NFQUEUE --queue-num 0"
		rollbackCmd := "iptables -D FORWARD -j NFQUEUE --queue-num 0"
		applyExec := []string{"iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"}
		rollbackExec := []string{"iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"}
		firewallBackend := snapshot.Firewall
		if firewallBackend == "nftables" {
			applyCmd = fmt.Sprintf("nft add rule inet filter forward queue num 0 comment %q", nfqNftRuleComment)
			rollbackCmd = "nft delete rule inet filter forward handle <surituner-owned-handle>"
			applyExec = []string{"nft", "add", "rule", "inet", "filter", "forward", "queue", "num", "0", "comment", nfqNftRuleComment}
			rollbackExec = []string{"nft", "delete", "rule", "inet", "filter", "forward", "handle", "<surituner-owned-handle>"}
		}
		return []PlanAction{
			{
				ID:           "nfq-queue-rules",
				Summary:      "Install NFQ forwarding rule",
				Reason:       "NFQ IPS mode requires traffic to be redirected into NFQUEUE.",
				RiskLevel:    RiskMedium,
				Category:     "os",
				Kind:         "nfq-rules",
				ApplyCmd:     applyCmd,
				RollbackCmd:  rollbackCmd,
				ApplyExec:    applyExec,
				RollbackExec: rollbackExec,
				RequiresRoot: true,
				Metadata: map[string]interface{}{
					"firewall_backend": firewallBackend,
					"nft_comment":      nfqNftRuleComment,
				},
			},
		}
	default:
		return nil
	}
}

func applyGuardrails(plan Plan, force bool) Plan {
	if !plan.Snapshot.Safety.IsManagementIface {
		return plan
	}
	for idx := range plan.Actions {
		action := &plan.Actions[idx]
		if action.RiskLevel == RiskCritical || strings.EqualFold(action.Kind, "irq") || strings.EqualFold(action.Kind, "ethtool-l") {
			action.BlockedByGuardrail = !force
		}
	}
	if force {
		return plan
	}
	var reasons []string
	for _, action := range plan.Actions {
		if action.BlockedByGuardrail {
			reasons = append(reasons, fmt.Sprintf("guardrail blocked %s on management interface %s", action.ID, plan.Snapshot.Iface))
		}
	}
	if len(reasons) > 0 {
		plan.Blocked = true
		plan.BlockingReasons = dedupeStrings(reasons)
	}
	return plan
}

func applyCapabilityGuards(plan Plan) Plan {
	switch plan.Profile {
	case ProfileDPDK:
		if !plan.Snapshot.Build.SupportsDPDK {
			plan.Blocked = true
			plan.HardBlocked = true
			plan.BlockingReasons = append(plan.BlockingReasons, "suricata build does not indicate DPDK support")
		}
		if strings.TrimSpace(plan.Snapshot.NIC.PCIAddress) == "" {
			plan.Blocked = true
			plan.HardBlocked = true
			plan.BlockingReasons = append(plan.BlockingReasons, "dpdk profile requires NIC PCI address preflight")
		}
		if !plan.Snapshot.NIC.DPDKDevbindPresent {
			plan.Blocked = true
			plan.HardBlocked = true
			plan.BlockingReasons = append(plan.BlockingReasons, "dpdk-devbind.py is required for DPDK bind/unbind preflight")
		}
		if strings.TrimSpace(plan.Snapshot.NIC.DPDKStatusLine) == "" {
			plan.Blocked = true
			plan.HardBlocked = true
			plan.BlockingReasons = append(plan.BlockingReasons, "dpdk-devbind status entry not found; bind/unbind preflight failed")
		}
		if !plan.Snapshot.NIC.DPDKCanBindVFIO {
			plan.Blocked = true
			plan.HardBlocked = true
			plan.BlockingReasons = append(plan.BlockingReasons, "vfio-pci bind preflight failed")
		}
		if !plan.Snapshot.NIC.DPDKCanRollback && !strings.EqualFold(plan.Snapshot.NIC.DPDKCurrentDriver, "vfio-pci") {
			plan.Blocked = true
			plan.HardBlocked = true
			plan.BlockingReasons = append(plan.BlockingReasons, "rollback bind preflight failed (current kernel driver unknown)")
		}
		if !plan.Snapshot.NIC.DPDKBindReady {
			plan.Blocked = true
			plan.HardBlocked = true
			plan.BlockingReasons = append(plan.BlockingReasons, "dpdk bind/unbind readiness preflight failed")
		}
	case ProfileAFXDP:
		if !plan.Snapshot.Build.SupportsAFXDP {
			plan.Blocked = true
			plan.HardBlocked = true
			plan.BlockingReasons = append(plan.BlockingReasons, "suricata build does not indicate AF_XDP support")
		}
		if !plan.Snapshot.NIC.XDPSupportDetected {
			plan.Blocked = true
			plan.HardBlocked = true
			plan.BlockingReasons = append(plan.BlockingReasons, "AF_XDP profile requires kernel/interface XDP support preflight")
		}
	case ProfileNFQ:
		if !plan.Snapshot.Build.SupportsNFQ {
			plan.Blocked = true
			plan.HardBlocked = true
			plan.BlockingReasons = append(plan.BlockingReasons, "suricata build does not indicate NFQ support")
		}
	}
	plan.BlockingReasons = dedupeStrings(plan.BlockingReasons)
	return plan
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
