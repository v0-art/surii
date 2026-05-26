package surituner

import "time"

type CaptureProfile string

const (
	ProfileAFPacket CaptureProfile = "af-packet"
	ProfileDPDK     CaptureProfile = "dpdk"
	ProfileAFXDP    CaptureProfile = "af-xdp"
	ProfileNFQ      CaptureProfile = "nfq"
	ProfilePCAP     CaptureProfile = "pcap"
)

func (p CaptureProfile) Valid() bool {
	switch p {
	case ProfileAFPacket, ProfileDPDK, ProfileAFXDP, ProfileNFQ, ProfilePCAP:
		return true
	default:
		return false
	}
}

type ApplyScope string

const (
	ScopeConfigOnly ApplyScope = "config-only"
	ScopeOSTuning   ApplyScope = "os-tuning"
	ScopeFull       ApplyScope = "full"
)

func (s ApplyScope) Valid() bool {
	switch s {
	case ScopeConfigOnly, ScopeOSTuning, ScopeFull:
		return true
	default:
		return false
	}
}

type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

type IPSMode string

const (
	IPSModeStrict       IPSMode = "strict"
	IPSModeAvailability IPSMode = "availability"
	IPSModeIDS          IPSMode = "ids"
)

func (m IPSMode) Valid() bool {
	switch m {
	case IPSModeStrict, IPSModeAvailability, IPSModeIDS:
		return true
	default:
		return false
	}
}

type BuildCapabilities struct {
	Version       string   `json:"version"`
	SupportsDPDK  bool     `json:"supports_dpdk"`
	SupportsAFXDP bool     `json:"supports_af_xdp"`
	SupportsNFQ   bool     `json:"supports_nfq"`
	SupportsHWLOC bool     `json:"supports_hwloc"`
	RawExcerpt    string   `json:"raw_excerpt"`
	Warnings      []string `json:"warnings"`
}

type CPUInfo struct {
	LogicalCores int              `json:"logical_cores"`
	NUMANodes    int              `json:"numa_nodes"`
	CoresByNUMA  map[string][]int `json:"cores_by_numa"`
	Warnings     []string         `json:"warnings"`
}

type NICInfo struct {
	Iface                      string            `json:"iface"`
	Driver                     string            `json:"driver"`
	PCIAddress                 string            `json:"pci_address"`
	RSSCombinedCurrent         int               `json:"rss_combined_current"`
	RSSCombinedMax             int               `json:"rss_combined_max"`
	RXQueues                   int               `json:"rx_queues"`
	TXQueues                   int               `json:"tx_queues"`
	SymmetricRSS               bool              `json:"symmetric_rss"`
	DPDKStatusLine             string            `json:"dpdk_status_line"`
	DPDKDevbindPresent         bool              `json:"dpdk_devbind_present"`
	DPDKCurrentDriver          string            `json:"dpdk_current_driver"`
	DPDKUnusedDrivers          []string          `json:"dpdk_unused_drivers"`
	DPDKCanBindVFIO            bool              `json:"dpdk_can_bind_vfio"`
	DPDKCanRollback            bool              `json:"dpdk_can_rollback"`
	DPDKBindReady              bool              `json:"dpdk_bind_ready"`
	DPDKIOMMUGroup             string            `json:"dpdk_iommu_group"`
	DPDKIOMMUViable            bool              `json:"dpdk_iommu_viable"`
	XDPKernelSupported         bool              `json:"xdp_kernel_supported"`
	XDPInterfaceSignalDetected bool              `json:"xdp_interface_signal_detected"`
	XDPSupportDetected         bool              `json:"xdp_support_detected"`
	AFXDPZeroCopyProven        bool              `json:"af_xdp_zero_copy_proven"`
	NUMANode                   int               `json:"numa_node"`
	Promisc                    bool              `json:"promisc"`
	Offload                    map[string]string `json:"offload"`
	Warnings                   []string          `json:"warnings"`
}

type RulesetInventory struct {
	SuricataUpdatePresent bool     `json:"suricata_update_present"`
	TotalRules            int      `json:"total_rules"`
	EnabledRules          int      `json:"enabled_rules"`
	PCREHeavyRules        int      `json:"pcre_heavy_rules"`
	RuleSources           []string `json:"rule_sources"`
	RulesFilePath         string   `json:"rules_file_path"`
	RulesFileSizeBytes    int64    `json:"rules_file_size_bytes"`
	RulesLastUpdated      string   `json:"rules_last_updated"`
	Warnings              []string `json:"warnings"`
}

type SafetyContext struct {
	DefaultRouteIface   string   `json:"default_route_iface"`
	SSHIface            string   `json:"ssh_iface"`
	IsDefaultRouteIface bool     `json:"is_default_route_iface"`
	IsSSHIface          bool     `json:"is_ssh_iface"`
	IsManagementIface   bool     `json:"is_management_iface"`
	DetectionMethod     string   `json:"detection_method"`
	Warnings            []string `json:"warnings"`
}

type SystemSnapshot struct {
	Timestamp  time.Time         `json:"timestamp"`
	Hostname   string            `json:"hostname"`
	User       string            `json:"user"`
	UID        int               `json:"uid"`
	Iface      string            `json:"iface"`
	ConfigPath string            `json:"config_path"`
	TotalRAMMB int               `json:"total_ram_mb"`
	Firewall   string            `json:"firewall_backend"`
	Build      BuildCapabilities `json:"build"`
	CPU        CPUInfo           `json:"cpu"`
	NIC        NICInfo           `json:"nic"`
	Ruleset    RulesetInventory  `json:"ruleset"`
	Safety     SafetyContext     `json:"safety"`
	Warnings   []string          `json:"warnings"`
}

type PlanAction struct {
	ID                 string                 `json:"id"`
	Summary            string                 `json:"summary"`
	Reason             string                 `json:"reason"`
	RiskLevel          RiskLevel              `json:"risk_level"`
	Category           string                 `json:"category"`
	Kind               string                 `json:"kind"`
	ApplyCmd           string                 `json:"apply_cmd"`
	RollbackCmd        string                 `json:"rollback_cmd"`
	ApplyExec          []string               `json:"apply_exec,omitempty"`
	RollbackExec       []string               `json:"rollback_exec,omitempty"`
	BlockedByGuardrail bool                   `json:"blocked_by_guardrail"`
	RequiresRoot       bool                   `json:"requires_root"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

type Plan struct {
	GeneratedAt     time.Time      `json:"generated_at"`
	Profile         CaptureProfile `json:"profile"`
	Scope           ApplyScope     `json:"scope"`
	IPSMode         IPSMode        `json:"ips_mode"`
	Snapshot        SystemSnapshot `json:"snapshot"`
	Actions         []PlanAction   `json:"actions"`
	Blocked         bool           `json:"blocked"`
	HardBlocked     bool           `json:"hard_blocked"`
	BlockingReasons []string       `json:"blocking_reasons"`
}

type HostFingerprint struct {
	Hostname  string `json:"hostname"`
	MachineID string `json:"machine_id"`
	UID       int    `json:"uid"`
}

type YAMLBackup struct {
	OriginalPath string `json:"original_path"`
	BackupPath   string `json:"backup_path"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
	SavedAt      string `json:"saved_at"`
}

type FileBackup struct {
	OriginalPath string `json:"original_path"`
	BackupPath   string `json:"backup_path,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	SizeBytes    int64  `json:"size_bytes"`
	SavedAt      string `json:"saved_at"`
	Existed      bool   `json:"existed"`
}

type PreState struct {
	EthtoolK         string            `json:"ethtool_k"`
	EthtoolG         string            `json:"ethtool_g"`
	EthtoolL         string            `json:"ethtool_l"`
	Sysctl           map[string]string `json:"sysctl"`
	IRQAffinity      map[string]string `json:"irq_affinity"`
	IRQBalanceStatus string            `json:"irqbalance_status"`
	Promisc          bool              `json:"promisc"`
	PromiscKnown     bool              `json:"promisc_known"`
	HugePages        map[string]string `json:"hugepages"`
	NodeHugePages    map[string]string `json:"node_hugepages"`
	SystemdStatus    string            `json:"systemd_status"`
	Warnings         []string          `json:"warnings"`
}

type CommandRecord struct {
	Index    int      `json:"index"`
	ActionID string   `json:"action_id"`
	Command  []string `json:"command"`
	Status   string   `json:"status"`
	Error    string   `json:"error,omitempty"`
}

type StateFile struct {
	Version         string          `json:"version"`
	CreatedAt       time.Time       `json:"created_at"`
	HostFingerprint HostFingerprint `json:"host_fingerprint"`
	Profile         CaptureProfile  `json:"profile"`
	Scope           ApplyScope      `json:"scope"`
	IPSMode         IPSMode         `json:"ips_mode"`
	Iface           string          `json:"iface"`
	ConfigPath      string          `json:"config_path"`
	Snapshot        SystemSnapshot  `json:"snapshot"`
	YAMLBackup      *YAMLBackup     `json:"yaml_backup,omitempty"`
	ServiceDropIn   *FileBackup     `json:"service_dropin,omitempty"`
	PreState        PreState        `json:"pre_state"`
	PlanActions     []PlanAction    `json:"plan_actions"`
	Applied         []CommandRecord `json:"applied"`
	Rollback        []CommandRecord `json:"rollback"`
	Status          string          `json:"status"`
	Error           string          `json:"error,omitempty"`
}

type Report struct {
	GeneratedAt               time.Time      `json:"generated_at"`
	Snapshot                  SystemSnapshot `json:"snapshot"`
	LatestState               string         `json:"latest_state,omitempty"`
	RuntimeMetrics            RuntimeMetrics `json:"runtime_metrics"`
	Warnings                  []string       `json:"warnings"`
	Recommendations           []string       `json:"recommendations"`
	UnsupportedOptions        []string       `json:"unsupported_options"`
	Bottlenecks               []string       `json:"bottlenecks"`
	MonitoringRecommendations []string       `json:"monitoring_recommendations"`
	PlannedActions            []string       `json:"planned_actions"`
	AppliedActions            []string       `json:"applied_actions"`
}

type RuntimeMetrics struct {
	StatsLogPath    string           `json:"stats_log_path"`
	SuricataStats   map[string]int64 `json:"suricata_stats"`
	EthtoolStats    map[string]int64 `json:"ethtool_stats"`
	Acceptance      []string         `json:"acceptance"`
	Warnings        []string         `json:"warnings"`
	LastStatsHeader string           `json:"last_stats_header,omitempty"`
}
