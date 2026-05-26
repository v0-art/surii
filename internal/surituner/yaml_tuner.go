package surituner

import (
	"crypto/sha256"
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var lookupSystemUser = osuser.Lookup
var lookupSystemGroup = osuser.LookupGroup

type TuneOptions struct {
	Profile       CaptureProfile
	IPSMode       IPSMode
	Iface         string
	SupportsHWLOC bool
	NICNUMA       int
	NICPCIAddress string
	SymmetricRSS  bool
	EnabledRules  int
	TotalRAMMB    int
	CoresByNUMA   map[string][]int
}

// BuildTunedYAML reads the source config and returns original+tuned bytes without
// modifying on-disk files. This is used to run suricata -T before applying changes.
func BuildTunedYAML(path string, opts TuneOptions) ([]byte, []byte, []string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read yaml: %w", err)
	}
	var cfg map[string]interface{}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, nil, nil, fmt.Errorf("parse yaml: %w", err)
	}

	changes := applyTuneMap(cfg, opts)
	updated, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal tuned yaml: %w", err)
	}
	updated = ensureSuricataYAMLHeader(updated)
	return raw, updated, changes, nil
}

// PrepareYAMLBackup creates the rollback artifact before the live config is
// changed. The caller must persist the returned metadata into state before
// calling WriteTunedYAML.
func PrepareYAMLBackup(path string, original []byte) (YAMLBackup, error) {
	backupPath, backupSHA, err := backupConfig(path, original)
	if err != nil {
		return YAMLBackup{}, err
	}
	return YAMLBackup{
		OriginalPath: path,
		BackupPath:   backupPath,
		SHA256:       backupSHA,
		SizeBytes:    int64(len(original)),
		SavedAt:      time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// WriteTunedYAML atomically writes the tuned configuration after validation and
// after backup metadata has been persisted.
func WriteTunedYAML(path string, tuned []byte) error {
	stat, statErr := os.Stat(path)
	mode := os.FileMode(0640)
	if statErr == nil {
		mode = stat.Mode().Perm()
	}
	tmpPath := fmt.Sprintf("%s.surituner.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, tuned, mode); err != nil {
		return fmt.Errorf("write temp tuned yaml: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace tuned yaml: %w", err)
	}
	return nil
}

// ApplyTunedYAML creates backup and atomically writes the tuned configuration.
func ApplyTunedYAML(path string, original []byte, tuned []byte) (YAMLBackup, error) {
	backup, err := PrepareYAMLBackup(path, original)
	if err != nil {
		return YAMLBackup{}, err
	}
	if err := WriteTunedYAML(path, tuned); err != nil {
		return YAMLBackup{}, err
	}
	return backup, nil
}

func TuneSuricataYAML(path string, opts TuneOptions) (YAMLBackup, []string, error) {
	original, tuned, changes, err := BuildTunedYAML(path, opts)
	if err != nil {
		return YAMLBackup{}, nil, err
	}
	backup, err := ApplyTunedYAML(path, original, tuned)
	if err != nil {
		return YAMLBackup{}, nil, err
	}
	return backup, changes, nil
}

func ensureSuricataYAMLHeader(content []byte) []byte {
	body := strings.TrimLeft(string(content), "\r\n\t ")
	body = strings.TrimPrefix(body, "%YAML 1.1\n")
	body = strings.TrimPrefix(body, "---\n")
	body = strings.TrimPrefix(body, "---\r\n")
	const header = "%YAML 1.1\n---\n"
	return []byte(header + body)
}

func resolveRunAsIdentity(cfg map[string]interface{}) (string, string, bool) {
	// Prefer existing run-as from config when valid on current host.
	if existingUser, existingGroup, ok := extractRunAsIdentity(cfg); ok {
		if existingGroup == "" {
			existingGroup = existingUser
		}
		if isValidSystemIdentity(existingUser, existingGroup) {
			return existingUser, existingGroup, true
		}
	}

	// Fallback candidates used by common Suricata package layouts.
	candidates := []string{"suricata", "_suricata", "suri"}
	for _, candidate := range candidates {
		if isValidSystemIdentity(candidate, candidate) {
			return candidate, candidate, true
		}
	}
	return "", "", false
}

func extractRunAsIdentity(cfg map[string]interface{}) (string, string, bool) {
	raw, ok := cfg["run-as"]
	if !ok {
		return "", "", false
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return "", "", false
	}
	userRaw, _ := m["user"].(string)
	groupRaw, _ := m["group"].(string)
	userRaw = strings.TrimSpace(userRaw)
	groupRaw = strings.TrimSpace(groupRaw)
	if userRaw == "" && groupRaw == "" {
		return "", "", false
	}
	return userRaw, groupRaw, true
}

func isValidSystemIdentity(userName string, groupName string) bool {
	userName = strings.TrimSpace(userName)
	groupName = strings.TrimSpace(groupName)
	if userName == "" || groupName == "" {
		return false
	}
	if _, err := lookupSystemUser(userName); err != nil {
		return false
	}
	if _, err := lookupSystemGroup(groupName); err != nil {
		return false
	}
	return true
}

func applyTuneMap(cfg map[string]interface{}, opts TuneOptions) []string {
	var changes []string
	if cfg == nil {
		cfg = map[string]interface{}{}
	}

	runmode := "workers"
	switch opts.Profile {
	case ProfileNFQ, ProfilePCAP:
		runmode = "autofp"
	}
	setNested(cfg, []string{"runmode"}, runmode)
	changes = append(changes, fmt.Sprintf("set runmode=%s", runmode))

	threading := ensureMap(cfg, "threading")
	if opts.SupportsHWLOC {
		threading["autopin"] = true
		changes = append(changes, "enabled threading.autopin=true (hwloc detected)")
	} else {
		cpuAffinity := buildCPUAffinityFallback(opts.NICNUMA, opts.CoresByNUMA)
		setNested(cfg, []string{"threading", "cpu-affinity"}, cpuAffinity)
		changes = append(changes, "set threading.cpu-affinity fallback map")
	}

	setNested(cfg, []string{"max-pending-packets"}, calcMaxPending(opts.EnabledRules))
	changes = append(changes, "adjusted max-pending-packets by ruleset size")

	memcaps := calcMemCaps(opts.TotalRAMMB, opts.EnabledRules)
	setNested(cfg, []string{"stream", "memcap"}, memcaps["stream"])
	setNested(cfg, []string{"reassembly", "memcap"}, memcaps["reassembly"])
	setNested(cfg, []string{"host", "memcap"}, memcaps["host"])
	setNested(cfg, []string{"flow", "memcap"}, memcaps["flow"])
	changes = append(changes, "updated stream/reassembly/host/flow memcaps")

	exceptionPolicy := mapIPSModeToExceptionPolicy(opts.Profile, opts.IPSMode)
	setNested(cfg, []string{"exception-policy"}, exceptionPolicy)
	changes = append(changes, fmt.Sprintf("set exception-policy=%s", exceptionPolicy))

	if runAsUser, runAsGroup, ok := resolveRunAsIdentity(cfg); ok {
		runAs := ensureMap(cfg, "run-as")
		runAs["user"] = runAsUser
		runAs["group"] = runAsGroup
		changes = append(changes, fmt.Sprintf("configured run-as user/group = %s/%s", runAsUser, runAsGroup))
	} else {
		changes = append(changes, "skipped run-as hardening: no valid system user/group found")
	}

	switch opts.Profile {
	case ProfileAFPacket:
		entries := ensureArrayMap(cfg, "af-packet")
		if len(entries) == 0 {
			iface := "default"
			if strings.TrimSpace(opts.Iface) != "" {
				iface = strings.TrimSpace(opts.Iface)
			}
			entries = append(entries, map[string]interface{}{"interface": iface})
		}
		if strings.TrimSpace(opts.Iface) != "" {
			entries[0]["interface"] = strings.TrimSpace(opts.Iface)
			changes = append(changes, fmt.Sprintf("af-packet interface=%s", strings.TrimSpace(opts.Iface)))
		}
		clusterType := "cluster_flow"
		if opts.SymmetricRSS {
			clusterType = "cluster_qm"
		}
		entries[0]["cluster-type"] = clusterType
		cfg["af-packet"] = entries
		changes = append(changes, fmt.Sprintf("af-packet cluster-type=%s", clusterType))
	case ProfileDPDK:
		dpdk := ensureMap(cfg, "dpdk")
		entries := ensureArrayMap(dpdk, "interfaces")
		if len(entries) == 0 {
			entries = append(entries, map[string]interface{}{})
		}
		dpdkInterface := strings.TrimSpace(opts.NICPCIAddress)
		if dpdkInterface == "" {
			dpdkInterface = strings.TrimSpace(opts.Iface)
		}
		if dpdkInterface != "" {
			entries[0]["interface"] = dpdkInterface
			changes = append(changes, fmt.Sprintf("dpdk interface=%s", dpdkInterface))
		}
		if _, ok := entries[0]["threads"]; !ok {
			entries[0]["threads"] = "auto"
		}
		dpdk["interfaces"] = entries
	case ProfileAFXDP:
		entries := ensureArrayMap(cfg, "af-xdp")
		if len(entries) == 0 {
			entries = append(entries, map[string]interface{}{})
		}
		iface := strings.TrimSpace(opts.Iface)
		if iface != "" {
			entries[0]["interface"] = iface
			changes = append(changes, fmt.Sprintf("af-xdp interface=%s", iface))
		}
		entries[0]["mem-unaligned"] = true
		cfg["af-xdp"] = entries
		changes = append(changes, "enabled af-xdp.mem-unaligned")
	case ProfileNFQ:
		nfq := ensureMap(cfg, "nfq")
		nfq["mode"] = "accept"
		nfq["batchcount"] = 20
		switch opts.IPSMode {
		case IPSModeStrict:
			nfq["fail-open"] = false
			changes = append(changes, "configured nfq fail-open=false (fail-close)")
		case IPSModeAvailability:
			nfq["fail-open"] = true
			changes = append(changes, "configured nfq fail-open=true (fail-open)")
		default:
			delete(nfq, "fail-open")
		}
		changes = append(changes, "configured nfq mode/batchcount")
	case ProfilePCAP:
		entries := ensureArrayMap(cfg, "pcap")
		if len(entries) == 0 {
			entries = append(entries, map[string]interface{}{})
		}
		iface := strings.TrimSpace(opts.Iface)
		if iface != "" {
			entries[0]["interface"] = iface
			changes = append(changes, fmt.Sprintf("pcap interface=%s", iface))
		}
		cfg["pcap"] = entries
	}
	return changes
}

func buildCPUAffinityFallback(nicNUMA int, coresByNUMA map[string][]int) map[string]interface{} {
	node := 0
	if nicNUMA >= 0 {
		node = nicNUMA
	}
	cpus := cpuSetForNUMANode(node, coresByNUMA)
	if cpus == "" {
		cpus = "0-3"
	}
	return map[string]interface{}{
		"management-cpu-set": map[string]interface{}{"cpu": []string{cpus}},
		"worker-cpu-set":     map[string]interface{}{"cpu": []string{cpus}},
	}
}

func cpuSetForNUMANode(node int, coresByNUMA map[string][]int) string {
	if len(coresByNUMA) == 0 {
		return ""
	}
	cpus := append([]int(nil), coresByNUMA[strconv.Itoa(node)]...)
	if len(cpus) == 0 && node != 0 {
		cpus = append([]int(nil), coresByNUMA["0"]...)
	}
	if len(cpus) == 0 {
		return ""
	}
	sort.Ints(cpus)
	uniq := cpus[:0]
	last := -1
	for _, cpu := range cpus {
		if cpu < 0 || cpu == last {
			continue
		}
		uniq = append(uniq, cpu)
		last = cpu
	}
	if len(uniq) == 0 {
		return ""
	}
	var ranges []string
	start := uniq[0]
	prev := uniq[0]
	for _, cpu := range uniq[1:] {
		if cpu == prev+1 {
			prev = cpu
			continue
		}
		ranges = append(ranges, formatCPURange(start, prev))
		start = cpu
		prev = cpu
	}
	ranges = append(ranges, formatCPURange(start, prev))
	return strings.Join(ranges, ",")
}

func formatCPURange(start int, end int) string {
	if start == end {
		return strconv.Itoa(start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func calcMaxPending(enabledRules int) int {
	base := 1024
	extra := enabledRules / 100
	if extra < 128 {
		extra = 128
	}
	if extra > 4096 {
		extra = 4096
	}
	return base + extra
}

func calcMemCaps(totalRAMMB int, enabledRules int) map[string]string {
	if totalRAMMB <= 0 {
		totalRAMMB = 4096
	}

	// Keep memcaps bounded and proportional to RAM so startup remains stable.
	baseBudget := totalRAMMB / 5 // target around 20% of RAM for these four pools
	if baseBudget < 512 {
		baseBudget = 512
	}
	if baseBudget > 4096 {
		baseBudget = 4096
	}

	rulesFactor := 1.0
	switch {
	case enabledRules >= 50000:
		rulesFactor = 1.35
	case enabledRules >= 30000:
		rulesFactor = 1.25
	case enabledRules >= 10000:
		rulesFactor = 1.15
	case enabledRules >= 5000:
		rulesFactor = 1.08
	}

	budget := int(float64(baseBudget) * rulesFactor)
	ramHardCap := totalRAMMB / 2
	if ramHardCap < 512 {
		ramHardCap = 512
	}
	if budget > ramHardCap {
		budget = ramHardCap
	}

	stream := int(float64(budget) * 0.40)
	reassembly := int(float64(budget) * 0.25)
	flow := int(float64(budget) * 0.25)
	host := budget - stream - reassembly - flow

	if stream < 128 {
		stream = 128
	}
	if reassembly < 128 {
		reassembly = 128
	}
	if flow < 64 {
		flow = 64
	}
	if host < 64 {
		host = 64
	}

	if stream > 2048 {
		stream = 2048
	}
	if reassembly > 1536 {
		reassembly = 1536
	}
	if flow > 1024 {
		flow = 1024
	}
	if host > 512 {
		host = 512
	}

	return map[string]string{
		"stream":     strconv.Itoa(maxInt(stream, 256)) + "mb",
		"reassembly": strconv.Itoa(maxInt(reassembly, 128)) + "mb",
		"host":       strconv.Itoa(maxInt(host, 128)) + "mb",
		"flow":       strconv.Itoa(maxInt(flow, 128)) + "mb",
	}
}

func mapIPSModeToExceptionPolicy(_ CaptureProfile, mode IPSMode) string {
	switch mode {
	case IPSModeStrict:
		return "drop-flow"
	case IPSModeAvailability:
		return "pass-flow"
	case IPSModeIDS:
		return "ignore"
	default:
		return "ignore"
	}
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func ensureMap(root map[string]interface{}, key string) map[string]interface{} {
	if value, ok := root[key]; ok {
		if asMap, mapOK := value.(map[string]interface{}); mapOK {
			return asMap
		}
	}
	m := map[string]interface{}{}
	root[key] = m
	return m
}

func ensureArrayMap(root map[string]interface{}, key string) []map[string]interface{} {
	value, ok := root[key]
	if !ok {
		root[key] = []map[string]interface{}{}
		return []map[string]interface{}{}
	}
	switch typed := value.(type) {
	case []map[string]interface{}:
		return typed
	case []interface{}:
		var out []map[string]interface{}
		for _, item := range typed {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return []map[string]interface{}{}
	}
}

func setNested(root map[string]interface{}, path []string, value interface{}) {
	if len(path) == 0 {
		return
	}
	current := root
	for i := 0; i < len(path)-1; i++ {
		key := path[i]
		next, ok := current[key]
		if !ok {
			newMap := map[string]interface{}{}
			current[key] = newMap
			current = newMap
			continue
		}
		nextMap, ok := next.(map[string]interface{})
		if !ok {
			newMap := map[string]interface{}{}
			current[key] = newMap
			current = newMap
			continue
		}
		current = nextMap
	}
	current[path[len(path)-1]] = value
}

func backupConfig(path string, raw []byte) (string, string, error) {
	sum := sha256.Sum256(raw)
	sha := fmt.Sprintf("%x", sum)
	baseDir := filepath.Dir(path)
	backupDir := filepath.Join(baseDir, ".surituner-backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", "", fmt.Errorf("create backup dir: %w", err)
	}
	name := fmt.Sprintf("%s.%d.bak", filepath.Base(path), time.Now().UnixNano())
	backupPath := filepath.Join(backupDir, name)
	if err := os.WriteFile(backupPath, raw, 0600); err != nil {
		return "", "", fmt.Errorf("write backup: %w", err)
	}
	return backupPath, strings.TrimSpace(sha), nil
}
