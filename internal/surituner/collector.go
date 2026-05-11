package surituner

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	reDefaultRouteDev = regexp.MustCompile(`\bdev\s+(\S+)`)
	reVersion         = regexp.MustCompile(`(?i)suricata.*version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
	reCombinedCurrent = regexp.MustCompile(`(?i)combined:\s+([0-9]+)`)
	reRuleAction      = regexp.MustCompile(`(?i)^(alert|drop|reject|rejectsrc|rejectdst|rejectboth|pass|sdrop)\s+`)
	reDateToken       = regexp.MustCompile(`^\d{1,2}/\d{1,2}/\d{4}$`)
)

type Collector struct {
	Runner CommandRunner
}

type dpdkPreflightResult struct {
	StatusLine      string
	DevbindPresent  bool
	CurrentDriver   string
	UnusedDrivers   []string
	CanBindVFIO     bool
	CanRollbackBind bool
	BindReady       bool
}

func NewCollector(runner CommandRunner) *Collector {
	return &Collector{Runner: runner}
}

func (c *Collector) Collect(iface string, configPath string) (SystemSnapshot, error) {
	if strings.TrimSpace(iface) == "" {
		return SystemSnapshot{}, errors.New("iface is required")
	}
	host, _ := os.Hostname()
	currentUser, _ := user.Current()
	uid := os.Geteuid()
	username := "unknown"
	if currentUser != nil {
		username = currentUser.Username
	}

	resolvedConfig, warnings := resolveConfigPath(configPath)
	build := c.collectBuildCapabilities()
	cpu := c.collectCPUInfo()
	nic := c.collectNICInfo(iface)
	rules := c.collectRuleset(resolvedConfig)
	safety := c.collectSafety(iface)
	firewallBackend, firewallWarnings := c.detectFirewallBackend()
	totalRAMMB := collectTotalRAMMB()

	allWarnings := append([]string{}, warnings...)
	allWarnings = append(allWarnings, build.Warnings...)
	allWarnings = append(allWarnings, cpu.Warnings...)
	allWarnings = append(allWarnings, nic.Warnings...)
	allWarnings = append(allWarnings, rules.Warnings...)
	allWarnings = append(allWarnings, safety.Warnings...)
	allWarnings = append(allWarnings, firewallWarnings...)

	return SystemSnapshot{
		Timestamp:  time.Now().UTC(),
		Hostname:   host,
		User:       username,
		UID:        uid,
		Iface:      iface,
		ConfigPath: resolvedConfig,
		TotalRAMMB: totalRAMMB,
		Firewall:   firewallBackend,
		Build:      build,
		CPU:        cpu,
		NIC:        nic,
		Ruleset:    rules,
		Safety:     safety,
		Warnings:   dedupeStrings(allWarnings),
	}, nil
}

func resolveConfigPath(explicit string) (string, []string) {
	var warnings []string
	candidates := []string{
		"/etc/suricata/suricata.yaml",
		"/usr/local/etc/suricata/suricata.yaml",
		"/opt/suricata/etc/suricata.yaml",
	}
	if explicit != "" {
		if fileExists(explicit) {
			return explicit, warnings
		}
		warnings = append(warnings, fmt.Sprintf("explicit config path does not exist: %s", explicit))
		return explicit, warnings
	}
	for _, path := range candidates {
		if fileExists(path) {
			return path, warnings
		}
	}
	warnings = append(warnings, "suricata.yaml was not found in known locations")
	return candidates[0], warnings
}

func (c *Collector) collectBuildCapabilities() BuildCapabilities {
	cap := BuildCapabilities{}
	res, err := c.Runner.Run([]string{"suricata", "--build-info"}, 12*time.Second, true)
	if err != nil {
		cap.Warnings = append(cap.Warnings, fmt.Sprintf("suricata --build-info unavailable: %v", err))
		return cap
	}
	raw := res.Stdout + "\n" + res.Stderr
	text := strings.ToLower(raw)
	cap.RawExcerpt = strings.TrimSpace(firstNLines(res.Stdout, 25))
	if match := reVersion.FindStringSubmatch(res.Stdout); len(match) > 1 {
		cap.Version = match[1]
	}
	if value, known := parseBuildInfoSupport(raw, "dpdk support"); known {
		cap.SupportsDPDK = value
	} else {
		cap.SupportsDPDK = strings.Contains(text, "dpdk")
	}
	if value, known := parseBuildInfoSupport(raw, "af_xdp support", "af-xdp support"); known {
		cap.SupportsAFXDP = value
	} else {
		cap.SupportsAFXDP = strings.Contains(text, "af_xdp") || strings.Contains(text, "af-xdp")
	}
	if value, known := parseBuildInfoSupport(raw, "nfqueue support", "nfq support"); known {
		cap.SupportsNFQ = value
	} else {
		cap.SupportsNFQ = strings.Contains(text, "nfqueue") || strings.Contains(text, "nfq")
	}
	if value, known := parseBuildInfoSupport(raw, "hwloc support"); known {
		cap.SupportsHWLOC = value
	} else {
		cap.SupportsHWLOC = strings.Contains(text, "hwloc")
	}
	return cap
}

func (c *Collector) collectCPUInfo() CPUInfo {
	info := CPUInfo{
		LogicalCores: runtime.NumCPU(),
		NUMANodes:    1,
		CoresByNUMA:  map[string][]int{"0": []int{}},
	}
	for i := 0; i < runtime.NumCPU(); i++ {
		info.CoresByNUMA["0"] = append(info.CoresByNUMA["0"], i)
	}

	res, err := c.Runner.Run([]string{"lscpu", "-p=CPU,NODE"}, 8*time.Second, true)
	if err != nil || res.Stdout == "" {
		info.Warnings = append(info.Warnings, "lscpu parse unavailable, using runtime.NumCPU fallback")
		return info
	}

	nodes := map[string][]int{}
	sc := bufio.NewScanner(strings.NewReader(res.Stdout))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			continue
		}
		cpuID, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		nodeID := strings.TrimSpace(parts[1])
		if err1 != nil {
			continue
		}
		if nodeID == "" || nodeID == "-1" {
			nodeID = "0"
		}
		nodes[nodeID] = append(nodes[nodeID], cpuID)
	}
	if len(nodes) == 0 {
		info.Warnings = append(info.Warnings, "unable to parse lscpu NUMA layout, using fallback")
		return info
	}
	for k := range nodes {
		sort.Ints(nodes[k])
	}
	info.CoresByNUMA = nodes
	info.NUMANodes = len(nodes)
	total := 0
	for _, cpus := range nodes {
		total += len(cpus)
	}
	info.LogicalCores = total
	return info
}

func parseBuildInfoSupport(raw string, labels ...string) (bool, bool) {
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" {
			continue
		}
		for _, label := range labels {
			if !strings.Contains(line, strings.ToLower(label)) {
				continue
			}
			fields := strings.Fields(line)
			for _, field := range fields {
				value := strings.Trim(field, ":,;()[]{}")
				switch value {
				case "yes", "enabled", "true":
					return true, true
				case "no", "disabled", "false":
					return false, true
				}
			}
			return false, true
		}
	}
	return false, false
}

func (c *Collector) collectNICInfo(iface string) NICInfo {
	nic := NICInfo{
		Iface:    iface,
		NUMANode: -1,
		Offload:  map[string]string{},
	}
	driverLink := filepath.Join("/sys/class/net", iface, "device/driver")
	if link, err := os.Readlink(driverLink); err == nil {
		nic.Driver = filepath.Base(link)
	} else {
		nic.Warnings = append(nic.Warnings, "unable to detect NIC driver from sysfs")
	}
	deviceLink := filepath.Join("/sys/class/net", iface, "device")
	if link, err := os.Readlink(deviceLink); err == nil {
		nic.PCIAddress = filepath.Base(link)
	} else {
		nic.Warnings = append(nic.Warnings, "unable to detect NIC PCI address from sysfs")
	}

	numaNodePath := filepath.Join("/sys/class/net", iface, "device/numa_node")
	if raw, err := os.ReadFile(numaNodePath); err == nil {
		if value, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); convErr == nil {
			nic.NUMANode = value
		}
	}

	offload, offloadWarnings := c.collectOffloadFlags(iface)
	nic.Offload = offload
	nic.Warnings = append(nic.Warnings, offloadWarnings...)

	nic.RSSCombinedCurrent, nic.RSSCombinedMax = c.collectRSSChannels(iface, &nic.Warnings)
	nic.RXQueues, nic.TXQueues = collectQueueCounts(iface)
	nic.SymmetricRSS = nic.RXQueues > 1 && nic.RXQueues == nic.TXQueues
	dpdkPreflight := c.collectDPDKPreflight(nic.PCIAddress, nic.Driver, &nic.Warnings)
	nic.DPDKStatusLine = dpdkPreflight.StatusLine
	nic.DPDKDevbindPresent = dpdkPreflight.DevbindPresent
	nic.DPDKCurrentDriver = dpdkPreflight.CurrentDriver
	nic.DPDKUnusedDrivers = dpdkPreflight.UnusedDrivers
	nic.DPDKCanBindVFIO = dpdkPreflight.CanBindVFIO
	nic.DPDKCanRollback = dpdkPreflight.CanRollbackBind
	nic.DPDKBindReady = dpdkPreflight.BindReady
	nic.XDPSupportDetected = c.detectXDPSupport(iface, &nic.Warnings)

	res, err := c.Runner.Run([]string{"ip", "-o", "link", "show", iface}, 5*time.Second, true)
	if err == nil && strings.Contains(res.Stdout, "PROMISC") {
		nic.Promisc = true
	}

	return nic
}

func (c *Collector) detectXDPSupport(iface string, warnings *[]string) bool {
	res, err := c.Runner.Run([]string{"ip", "-details", "link", "show", iface}, 5*time.Second, true)
	if err != nil || res.Stdout == "" {
		*warnings = append(*warnings, "unable to probe XDP support with ip -details link show")
		return false
	}
	lower := strings.ToLower(res.Stdout)
	if linkDetailsIndicateXDPSupport(lower) {
		return true
	}
	*warnings = append(*warnings, "XDP support was not detected from interface details")
	return false
}

func linkDetailsIndicateXDPSupport(raw string) bool {
	lower := strings.ToLower(raw)
	for _, needle := range []string{
		"xdp/id",
		"xdpdrv",
		"xdpgeneric",
		"xdpoffload",
		"prog/xdp",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func (c *Collector) collectDPDKPreflight(pciAddress string, nicDriver string, warnings *[]string) dpdkPreflightResult {
	out := dpdkPreflightResult{}
	if pciAddress == "" {
		*warnings = append(*warnings, "dpdk preflight requires NIC PCI address")
		return out
	}
	if _, err := exec.LookPath("dpdk-devbind.py"); err != nil {
		*warnings = append(*warnings, "dpdk-devbind.py not found for DPDK bind preflight")
		return out
	}
	out.DevbindPresent = true
	res, err := c.Runner.Run([]string{"dpdk-devbind.py", "--status"}, 10*time.Second, true)
	if err != nil {
		*warnings = append(*warnings, "dpdk-devbind.py --status unavailable")
		return out
	}
	sc := bufio.NewScanner(strings.NewReader(res.Stdout))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !dpdkLineMatchesPCI(line, pciAddress) {
			continue
		}
		out.StatusLine = line
		break
	}
	if out.StatusLine == "" {
		*warnings = append(*warnings, fmt.Sprintf("dpdk-devbind status has no entry for %s", pciAddress))
		return out
	}

	out.CurrentDriver = strings.TrimSpace(parseDPDKStatusField(out.StatusLine, "drv"))
	out.UnusedDrivers = parseDriverList(parseDPDKStatusField(out.StatusLine, "unused"))
	if out.CurrentDriver == "" {
		*warnings = append(*warnings, "dpdk-devbind status line missing drv= field")
	}

	if strings.EqualFold(out.CurrentDriver, "vfio-pci") {
		out.CanBindVFIO = true
	} else if containsString(out.UnusedDrivers, "vfio-pci") {
		if _, err := os.Stat("/sys/module/vfio_pci"); err != nil {
			*warnings = append(*warnings, "vfio_pci kernel module not loaded; DPDK bind may fail")
		} else {
			out.CanBindVFIO = true
		}
	}
	if !out.CanBindVFIO {
		*warnings = append(*warnings, "vfio-pci is not available for bind according to dpdk-devbind status")
	}

	out.CanRollbackBind = strings.TrimSpace(out.CurrentDriver) != ""
	if strings.EqualFold(out.CurrentDriver, "vfio-pci") {
		out.CanRollbackBind = false
		*warnings = append(*warnings, "NIC is already bound to vfio-pci; previous kernel driver is unknown for bind rollback")
	}
	if !out.CanRollbackBind {
		*warnings = append(*warnings, "unable to infer current kernel driver for rollback bind")
	}
	if strings.TrimSpace(nicDriver) != "" && out.CurrentDriver != "" && !strings.EqualFold(nicDriver, out.CurrentDriver) && !strings.EqualFold(out.CurrentDriver, "vfio-pci") {
		*warnings = append(*warnings, fmt.Sprintf("sysfs driver (%s) differs from dpdk-devbind drv (%s)", nicDriver, out.CurrentDriver))
	}

	out.BindReady = out.DevbindPresent && out.StatusLine != "" && out.CanBindVFIO && (out.CanRollbackBind || strings.EqualFold(out.CurrentDriver, "vfio-pci"))
	return out
}

func (c *Collector) collectOffloadFlags(iface string) (map[string]string, []string) {
	flags := map[string]string{
		"gro": "unknown",
		"lro": "unknown",
	}
	var warnings []string
	res, err := c.Runner.Run([]string{"ethtool", "-k", iface}, 8*time.Second, true)
	if err != nil {
		warnings = append(warnings, "ethtool -k unavailable")
		return flags, warnings
	}
	sc := bufio.NewScanner(strings.NewReader(res.Stdout))
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if strings.HasPrefix(line, "generic-receive-offload:") {
			flags["gro"] = strings.TrimSpace(strings.TrimPrefix(line, "generic-receive-offload:"))
		}
		if strings.HasPrefix(line, "large-receive-offload:") {
			flags["lro"] = strings.TrimSpace(strings.TrimPrefix(line, "large-receive-offload:"))
		}
	}
	return flags, warnings
}

func (c *Collector) collectRSSChannels(iface string, warnings *[]string) (int, int) {
	res, err := c.Runner.Run([]string{"ethtool", "-l", iface}, 8*time.Second, true)
	if err != nil {
		*warnings = append(*warnings, "ethtool -l unavailable")
		return 0, 0
	}
	lines := strings.Split(res.Stdout, "\n")
	current := 0
	maximum := 0
	section := ""
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		lower := strings.ToLower(line)
		if strings.Contains(lower, "pre-set maximums") {
			section = "max"
			continue
		}
		if strings.Contains(lower, "current hardware settings") {
			section = "current"
			continue
		}
		if strings.HasPrefix(lower, "combined:") {
			match := reCombinedCurrent.FindStringSubmatch(lower)
			if len(match) != 2 {
				continue
			}
			value, err := strconv.Atoi(match[1])
			if err != nil {
				continue
			}
			if section == "max" {
				maximum = value
			}
			if section == "current" {
				current = value
			}
		}
	}
	return current, maximum
}

func collectQueueCounts(iface string) (int, int) {
	queuesDir := filepath.Join("/sys/class/net", iface, "queues")
	entries, err := os.ReadDir(queuesDir)
	if err != nil {
		return 0, 0
	}
	rx := 0
	tx := 0
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "rx-") {
			rx++
		}
		if strings.HasPrefix(name, "tx-") {
			tx++
		}
	}
	return rx, tx
}

func (c *Collector) collectRuleset(configPath string) RulesetInventory {
	inv := RulesetInventory{
		RuleSources: []string{},
		Warnings:    []string{},
	}
	if _, err := exec.LookPath("suricata-update"); err == nil {
		inv.SuricataUpdatePresent = true
		res, err := c.Runner.Run([]string{"suricata-update", "list-sources", "--enabled"}, 8*time.Second, true)
		if err == nil && res.ExitCode == 0 {
			inv.RuleSources = nonNilStrings(parseRuleSources(res.Stdout))
		} else if err != nil {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("suricata-update list-sources failed: %v", err))
		} else {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("suricata-update list-sources failed with exit=%d", res.ExitCode))
		}
	} else {
		inv.Warnings = append(inv.Warnings, "suricata-update not found")
	}

	inv.RulesFilePath = detectRulesFilePath(configPath)
	stat, err := os.Stat(inv.RulesFilePath)
	if err != nil {
		inv.Warnings = append(inv.Warnings, fmt.Sprintf("rules file not found: %s", inv.RulesFilePath))
		return inv
	}
	inv.RulesFileSizeBytes = stat.Size()
	inv.RulesLastUpdated = stat.ModTime().UTC().Format(time.RFC3339)

	file, err := os.Open(inv.RulesFilePath)
	if err != nil {
		inv.Warnings = append(inv.Warnings, fmt.Sprintf("unable to read rules file: %v", err))
		return inv
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			uncommented := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if isRuleLine(uncommented) {
				inv.TotalRules++
				if strings.Contains(strings.ToLower(uncommented), "pcre:") {
					inv.PCREHeavyRules++
				}
			} else if strings.Contains(strings.ToLower(line), "pcre") {
				inv.PCREHeavyRules++
			}
			continue
		}
		if isRuleLine(line) {
			inv.TotalRules++
			inv.EnabledRules++
			if strings.Contains(strings.ToLower(line), "pcre:") {
				inv.PCREHeavyRules++
			}
		}
	}
	if err := sc.Err(); err != nil {
		inv.Warnings = append(inv.Warnings, fmt.Sprintf("rules file scan failed: %v", err))
	}
	return inv
}

func (c *Collector) CollectRuntimeMetrics(iface string) RuntimeMetrics {
	metrics := RuntimeMetrics{
		StatsLogPath:  "/var/log/suricata/stats.log",
		SuricataStats: map[string]int64{},
		EthtoolStats:  map[string]int64{},
		Acceptance:    []string{},
		Warnings:      []string{},
	}
	raw, err := os.ReadFile(metrics.StatsLogPath)
	if err != nil {
		metrics.Warnings = append(metrics.Warnings, fmt.Sprintf("stats.log unavailable: %v", err))
	} else {
		header, stats := parseLatestSuricataStatsBlock(string(raw))
		metrics.LastStatsHeader = header
		metrics.SuricataStats = stats
	}

	res, err := c.Runner.Run([]string{"ethtool", "-S", iface}, 8*time.Second, true)
	if err != nil {
		metrics.Warnings = append(metrics.Warnings, fmt.Sprintf("ethtool -S unavailable: %v", err))
	} else {
		metrics.EthtoolStats = parseEthtoolStats(res.Stdout)
	}
	metrics.Acceptance = buildAcceptanceObservations(metrics)
	return metrics
}

func parseLatestSuricataStatsBlock(raw string) (string, map[string]int64) {
	stats := map[string]int64{}
	lines := strings.Split(raw, "\n")
	start := -1
	header := ""
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "Date:") {
			start = i
			header = strings.TrimSpace(lines[i])
			break
		}
	}
	if start == -1 {
		return "", stats
	}
	for _, line := range lines[start+1:] {
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		valueRaw := strings.TrimSpace(parts[2])
		if name == "" || valueRaw == "" || name == "Counter" {
			continue
		}
		value, err := strconv.ParseInt(valueRaw, 10, 64)
		if err != nil {
			continue
		}
		stats[name] = value
	}
	return header, stats
}

func parseEthtoolStats(raw string) map[string]int64 {
	stats := map[string]int64{}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasSuffix(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		valueRaw := strings.TrimSpace(parts[1])
		value, err := strconv.ParseInt(valueRaw, 10, 64)
		if err != nil {
			continue
		}
		stats[name] = value
	}
	return stats
}

func buildAcceptanceObservations(metrics RuntimeMetrics) []string {
	var out []string
	kernelDrops := metrics.SuricataStats["capture.kernel_drops"]
	kernelPackets := metrics.SuricataStats["capture.kernel_packets"]
	if kernelPackets > 0 {
		rate := float64(kernelDrops) / float64(kernelPackets)
		out = append(out, fmt.Sprintf("kernel_drops=%d kernel_packets=%d drop_rate=%.6f", kernelDrops, kernelPackets, rate))
	} else if kernelDrops > 0 {
		out = append(out, fmt.Sprintf("kernel_drops=%d kernel_packets=unknown", kernelDrops))
	}
	if gap, ok := metrics.SuricataStats["tcp.reassembly_gap"]; ok {
		out = append(out, fmt.Sprintf("tcp.reassembly_gap=%d", gap))
	}
	for _, key := range []string{"rx_missed_errors", "rx_dropped", "rx_no_buffer_count", "tx_dropped"} {
		if value, ok := metrics.EthtoolStats[key]; ok {
			out = append(out, fmt.Sprintf("%s=%d", key, value))
		}
	}
	if pressure, ok := metrics.SuricataStats["memcap.pressure"]; ok {
		out = append(out, fmt.Sprintf("memcap.pressure=%d", pressure))
	}
	if len(out) == 0 {
		out = append(out, "runtime acceptance counters unavailable")
	}
	return out
}

func detectRulesFilePath(configPath string) string {
	if strings.TrimSpace(configPath) != "" && fileExists(configPath) {
		configured := rulesFileCandidatesFromConfig(configPath)
		for _, path := range configured {
			if fileExists(path) {
				return path
			}
		}
		if len(configured) > 0 {
			return configured[0]
		}
	}
	candidates := []string{
		"/var/lib/suricata/rules/suricata.rules",
		"/etc/suricata/rules/suricata.rules",
	}
	for _, path := range candidates {
		if fileExists(path) {
			return path
		}
	}
	if configPath == "" {
		return candidates[0]
	}
	dir := filepath.Dir(configPath)
	custom := filepath.Join(dir, "rules", "suricata.rules")
	return custom
}

func rulesFileCandidatesFromConfig(configPath string) []string {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}
	var cfg struct {
		DefaultRulePath string   `yaml:"default-rule-path"`
		RuleFiles       []string `yaml:"rule-files"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil
	}
	base := strings.TrimSpace(cfg.DefaultRulePath)
	if base == "" {
		base = filepath.Join(filepath.Dir(configPath), "rules")
	} else if !filepath.IsAbs(base) {
		base = filepath.Join(filepath.Dir(configPath), base)
	}

	var candidates []string
	for _, item := range cfg.RuleFiles {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if filepath.IsAbs(item) {
			candidates = append(candidates, item)
			continue
		}
		candidates = append(candidates, filepath.Join(base, item))
	}
	if len(candidates) == 0 {
		candidates = append(candidates, filepath.Join(base, "suricata.rules"))
	}
	return preferSuricataRules(candidates)
}

func preferSuricataRules(candidates []string) []string {
	if len(candidates) < 2 {
		return candidates
	}
	var preferred []string
	var rest []string
	for _, path := range candidates {
		if filepath.Base(path) == "suricata.rules" {
			preferred = append(preferred, path)
		} else {
			rest = append(rest, path)
		}
	}
	return append(preferred, rest...)
}

func parseRuleSources(raw string) []string {
	var sources []string
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isSuricataUpdateLogLine(line) {
			continue
		}
		if strings.Contains(strings.ToLower(line), "no enabled sources") {
			continue
		}
		line = strings.TrimPrefix(line, "- ")
		fields := strings.Fields(line)
		if len(fields) > 0 {
			source := strings.Trim(fields[0], "[],:")
			if isLikelyRuleSourceName(source) {
				sources = append(sources, source)
			}
		}
	}
	return dedupeStrings(sources)
}

func isSuricataUpdateLogLine(line string) bool {
	if strings.Contains(line, " -- ") || strings.Contains(line, "<Info>") || strings.Contains(line, "<Warning>") || strings.Contains(line, "<Error>") {
		return true
	}
	if len(line) >= 8 && line[1] == '/' {
		return true
	}
	return false
}

func isLikelyRuleSourceName(value string) bool {
	if value == "" {
		return false
	}
	if reDateToken.MatchString(value) {
		return false
	}
	lower := strings.ToLower(value)
	if lower == "name" || lower == "source" || lower == "enabled" {
		return false
	}
	return true
}

func (c *Collector) collectSafety(iface string) SafetyContext {
	safety := SafetyContext{
		DetectionMethod: "default-route + ssh-connection-correlation",
	}
	res, err := c.Runner.Run([]string{"ip", "route", "show", "default"}, 4*time.Second, true)
	if err == nil {
		if match := reDefaultRouteDev.FindStringSubmatch(res.Stdout); len(match) == 2 {
			safety.DefaultRouteIface = match[1]
		}
	}
	if safety.DefaultRouteIface == "" {
		safety.Warnings = append(safety.Warnings, "default route interface not detected")
	}

	sshConnection := os.Getenv("SSH_CONNECTION")
	if sshConnection != "" {
		parts := strings.Fields(sshConnection)
		if len(parts) >= 1 {
			remoteIP := parts[0]
			routeRes, routeErr := c.Runner.Run([]string{"ip", "route", "get", remoteIP}, 4*time.Second, true)
			if routeErr == nil {
				if match := reDefaultRouteDev.FindStringSubmatch(routeRes.Stdout); len(match) == 2 {
					safety.SSHIface = match[1]
					safety.DetectionMethod = "ssh_connection + ip route get"
				}
			}
		}
	}
	if safety.SSHIface == "" {
		remoteIP := c.detectRemoteIPViaSS()
		if remoteIP != "" {
			routeRes, routeErr := c.Runner.Run([]string{"ip", "route", "get", remoteIP}, 4*time.Second, true)
			if routeErr == nil {
				if match := reDefaultRouteDev.FindStringSubmatch(routeRes.Stdout); len(match) == 2 {
					safety.SSHIface = match[1]
					safety.DetectionMethod = "ss + ip route get"
				}
			}
		}
	}
	if safety.SSHIface == "" {
		safety.SSHIface = safety.DefaultRouteIface
		safety.Warnings = append(safety.Warnings, "ssh interface not confidently detected, fallback to default route interface")
	}
	safety.IsManagementIface = safety.SSHIface != "" && safety.SSHIface == iface
	return safety
}

func (c *Collector) detectFirewallBackend() (string, []string) {
	if _, err := exec.LookPath("nft"); err == nil {
		return "nftables", nil
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return "iptables", nil
	}
	return "unknown", []string{"neither nft nor iptables was detected in PATH"}
}

func (c *Collector) detectRemoteIPViaSS() string {
	res, err := c.Runner.Run([]string{"ss", "-tnp"}, 5*time.Second, true)
	if err != nil || res.Stdout == "" {
		return ""
	}
	sc := bufio.NewScanner(strings.NewReader(res.Stdout))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.Contains(line, ":22") || !strings.Contains(line, "ESTAB") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		remote := fields[4]
		if remoteIP := extractHost(remote); remoteIP != "" {
			return remoteIP
		}
	}
	return ""
}

func extractHost(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	if strings.HasPrefix(endpoint, "[") && strings.Contains(endpoint, "]") {
		right := strings.Index(endpoint, "]")
		return endpoint[1:right]
	}
	lastColon := strings.LastIndex(endpoint, ":")
	if lastColon <= 0 {
		return endpoint
	}
	return endpoint[:lastColon]
}

func dpdkLineMatchesPCI(line string, pciAddress string) bool {
	line = strings.ToLower(strings.TrimSpace(line))
	pciAddress = strings.ToLower(strings.TrimSpace(pciAddress))
	if line == "" || pciAddress == "" {
		return false
	}
	if strings.Contains(line, pciAddress) {
		return true
	}
	if short := trimPCIDomain(pciAddress); short != "" && strings.Contains(line, short) {
		return true
	}
	return false
}

func trimPCIDomain(pciAddress string) string {
	pciAddress = strings.TrimSpace(pciAddress)
	if strings.HasPrefix(strings.ToLower(pciAddress), "0000:") {
		return pciAddress[5:]
	}
	return pciAddress
}

func parseDPDKStatusField(line string, field string) string {
	prefix := strings.ToLower(strings.TrimSpace(field)) + "="
	for _, token := range strings.Fields(line) {
		lower := strings.ToLower(token)
		if strings.HasPrefix(lower, prefix) {
			value := token[len(prefix):]
			value = strings.Trim(value, "\"' ")
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func parseDriverList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "<none>" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(strings.Trim(part, "\"'"))
		if part == "" || part == "<none>" {
			continue
		}
		out = append(out, part)
	}
	return dedupeStrings(out)
}

func containsString(items []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, item := range items {
		if strings.ToLower(strings.TrimSpace(item)) == target {
			return true
		}
	}
	return false
}

func collectTotalRAMMB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.Atoi(fields[1])
				if err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 0
}

func fileExists(path string) bool {
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !stat.IsDir()
}

func firstNLines(raw string, n int) string {
	if n <= 0 {
		return ""
	}
	lines := strings.Split(raw, "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:n], "\n")
}

func isRuleLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	return reRuleAction.MatchString(line)
}

func dedupeStrings(input []string) []string {
	if len(input) == 0 {
		return input
	}
	seen := map[string]struct{}{}
	var out []string
	for _, item := range input {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
