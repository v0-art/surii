package surituner

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type mockRunner struct {
	calls [][]string
}

func (m *mockRunner) Run(args []string, _ time.Duration, _ bool) (CommandResult, error) {
	m.calls = append(m.calls, append([]string(nil), args...))
	return CommandResult{Args: args, ExitCode: 0}, nil
}

type failOnCommandRunner struct {
	calls   [][]string
	failCmd string
}

func (m *failOnCommandRunner) Run(args []string, _ time.Duration, _ bool) (CommandResult, error) {
	m.calls = append(m.calls, append([]string(nil), args...))
	if len(args) > 0 && args[0] == m.failCmd {
		return CommandResult{Args: args, ExitCode: 1, Stderr: "simulated failure"}, errors.New("simulated failure")
	}
	return CommandResult{Args: args, ExitCode: 0}, nil
}

type nonZeroRunner struct {
	calls   [][]string
	failCmd string
}

func (m *nonZeroRunner) Run(args []string, _ time.Duration, _ bool) (CommandResult, error) {
	m.calls = append(m.calls, append([]string(nil), args...))
	if len(args) > 0 && args[0] == m.failCmd {
		return CommandResult{Args: args, ExitCode: 1, Stderr: "simulated non-zero"}, nil
	}
	return CommandResult{Args: args, ExitCode: 0}, nil
}

type scriptedRunner struct {
	calls   [][]string
	results map[string]CommandResult
	errors  map[string]error
}

func (m *scriptedRunner) Run(args []string, _ time.Duration, _ bool) (CommandResult, error) {
	m.calls = append(m.calls, append([]string(nil), args...))
	key := strings.Join(args, " ")
	if err := m.errors[key]; err != nil {
		return CommandResult{Args: args, ExitCode: 1, Stderr: err.Error()}, err
	}
	if res, ok := m.results[key]; ok {
		res.Args = append([]string(nil), args...)
		return res, nil
	}
	return CommandResult{Args: args, ExitCode: 0}, nil
}

type sequenceRunner struct {
	calls   [][]string
	results map[string][]CommandResult
	errors  map[string][]error
}

func (m *sequenceRunner) Run(args []string, _ time.Duration, _ bool) (CommandResult, error) {
	m.calls = append(m.calls, append([]string(nil), args...))
	key := strings.Join(args, " ")
	if queue := m.errors[key]; len(queue) > 0 {
		err := queue[0]
		m.errors[key] = queue[1:]
		if err != nil {
			return CommandResult{Args: args, ExitCode: 1, Stderr: err.Error()}, err
		}
	}
	if queue := m.results[key]; len(queue) > 0 {
		res := queue[0]
		m.results[key] = queue[1:]
		res.Args = append([]string(nil), args...)
		return res, nil
	}
	return CommandResult{Args: args, ExitCode: 0}, nil
}

func TestParseCurrentRing(t *testing.T) {
	raw := `
Ring parameters for eth0:
Pre-set maximums:
RX:             4096
TX:             4096
Current hardware settings:
RX:             512
TX:             512
`
	rx, tx, ok := parseCurrentRing(raw)
	if !ok {
		t.Fatalf("expected parse success")
	}
	if rx != 512 || tx != 512 {
		t.Fatalf("unexpected values rx=%d tx=%d", rx, tx)
	}
}

func TestRequireRoot(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()

	getEUID = func() int { return 1000 }
	if err := requireRoot(); err == nil {
		t.Fatalf("expected root check error")
	}
	getEUID = func() int { return 0 }
	if err := requireRoot(); err != nil {
		t.Fatalf("expected root check success: %v", err)
	}
}

func TestRollbackApplied_ReverseOrder(t *testing.T) {
	r := &mockRunner{}
	ex := &Executor{Runner: r}
	state := StateFile{
		PreState: PreState{
			Sysctl: map[string]string{
				"net.core.rmem_max": "1",
			},
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "a0"},
			{Index: 2, ActionID: "a2"},
			{Index: 1, ActionID: "a1"},
		},
	}
	actions := map[string]PlanAction{
		"a0": {ID: "a0", Kind: "sysctl", ApplyExec: []string{"sysctl", "-w", "net.core.rmem_max=10"}},
		"a1": {ID: "a1", Kind: "sysctl", ApplyExec: []string{"sysctl", "-w", "net.core.rmem_max=20"}},
		"a2": {ID: "a2", Kind: "sysctl", ApplyExec: []string{"sysctl", "-w", "net.core.rmem_max=30"}},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 3 {
		t.Fatalf("expected 3 rollback records, got %d", len(records))
	}
	got := []string{records[0].ActionID, records[1].ActionID, records[2].ActionID}
	want := []string{"rollback-a2", "rollback-a1", "rollback-a0"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected rollback order: got %v want %v", got, want)
	}
}

func TestRollbackApplied_NonZeroExitIsFailure(t *testing.T) {
	r := &nonZeroRunner{failCmd: "sysctl"}
	ex := &Executor{Runner: r}
	state := StateFile{
		PreState: PreState{
			Sysctl: map[string]string{
				"net.core.rmem_max": "1",
			},
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "a0"},
		},
	}
	actions := map[string]PlanAction{
		"a0": {ID: "a0", Kind: "sysctl", ApplyExec: []string{"sysctl", "-w", "net.core.rmem_max=10"}},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 1 {
		t.Fatalf("expected one rollback record, got %d", len(records))
	}
	if records[0].Status != "failed" {
		t.Fatalf("expected failed rollback record for non-zero exit, got %+v", records[0])
	}
	if !strings.Contains(records[0].Error, "simulated non-zero") {
		t.Fatalf("expected command stderr in rollback error, got %q", records[0].Error)
	}
}

func TestRollbackApplied_RefusesUnsupportedRollbackExecFromState(t *testing.T) {
	r := &mockRunner{}
	ex := &Executor{Runner: r}
	state := StateFile{
		Applied: []CommandRecord{
			{Index: 0, ActionID: "evil"},
		},
	}
	actions := map[string]PlanAction{
		"evil": {
			ID:           "evil",
			Kind:         "",
			RollbackExec: []string{"sh", "-c", "touch /tmp/surituner-owned"},
		},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 1 {
		t.Fatalf("expected one rollback record, got %d", len(records))
	}
	if records[0].Status != "failed" {
		t.Fatalf("expected unsupported rollback command to fail closed, got %+v", records[0])
	}
	if !strings.Contains(records[0].Error, "refusing to execute") {
		t.Fatalf("expected refusing-to-execute error, got %q", records[0].Error)
	}
	if len(r.calls) != 0 {
		t.Fatalf("did not expect unsupported rollback command to execute, calls=%v", r.calls)
	}
}

func TestFailAndRollback_MarksPartialWhenRollbackCommandFails(t *testing.T) {
	dir := t.TempDir()
	r := &nonZeroRunner{failCmd: "sysctl"}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	state := StateFile{
		Version: "v1",
		Iface:   "eth0",
		PreState: PreState{
			Sysctl: map[string]string{
				"net.core.rmem_max": "1",
			},
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "a0", Status: "ok"},
		},
	}
	statePath, err := ex.StateStore.Save(state)
	if err != nil {
		t.Fatalf("save state: %v", err)
	}
	actions := map[string]PlanAction{
		"a0": {ID: "a0", Kind: "sysctl", ApplyExec: []string{"sysctl", "-w", "net.core.rmem_max=10"}},
	}

	result, err := ex.failAndRollback(statePath, &state, actions, "apply failed")
	if err == nil {
		t.Fatalf("expected failAndRollback to return original failure")
	}
	if !result.RolledBack {
		t.Fatalf("expected rollback attempt")
	}
	if len(result.Warnings) == 0 {
		t.Fatalf("expected rollback warning for failed rollback command")
	}
	loaded, err := ex.StateStore.Load(statePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if loaded.Status != "rollback_partial_after_failure" {
		t.Fatalf("expected partial rollback status, got %s", loaded.Status)
	}
}

func TestApply_ValidateTempConfigBeforeRestart(t *testing.T) {
	origEUID := getEUID
	defer func() { getEUID = origEUID }()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "suricata.yaml")
	if err := os.WriteFile(configPath, []byte("runmode: autofp\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	r := &mockRunner{}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	plan := Plan{
		Profile: ProfileAFPacket,
		Scope:   ScopeConfigOnly,
		IPSMode: IPSModeIDS,
		Snapshot: SystemSnapshot{
			Iface:      "eth0",
			ConfigPath: configPath,
			Ruleset: RulesetInventory{
				EnabledRules: 12000,
			},
			Build: BuildCapabilities{
				SupportsHWLOC: true,
			},
			NIC: NICInfo{
				NUMANode:     0,
				SymmetricRSS: true,
			},
		},
		Actions: []PlanAction{
			{
				ID:        "yaml-tuning",
				Kind:      "yaml",
				ApplyCmd:  "update yaml",
				RiskLevel: RiskLow,
			},
		},
	}

	if _, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	}); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	suricataT := -1
	restart := -1
	for i, call := range r.calls {
		joined := strings.Join(call, " ")
		if strings.Contains(joined, "suricata -T") {
			suricataT = i
		}
		if strings.Contains(joined, "systemctl restart suricata.service") {
			restart = i
		}
	}
	if suricataT == -1 {
		t.Fatalf("expected suricata -T call")
	}
	if restart == -1 {
		t.Fatalf("expected systemctl restart call")
	}
	if suricataT > restart {
		t.Fatalf("expected suricata -T before restart, got t=%d restart=%d", suricataT, restart)
	}
}

func TestSuricataServiceRestartTimeout(t *testing.T) {
	if got := suricataServiceRestartTimeout(100); got != 90*time.Second {
		t.Fatalf("unexpected service restart timeout for small ruleset: %s", got)
	}
	if got := suricataServiceRestartTimeout(12000); got != 2*time.Minute {
		t.Fatalf("unexpected service restart timeout for mid ruleset: %s", got)
	}
	if got := suricataServiceRestartTimeout(50000); got != 3*time.Minute {
		t.Fatalf("unexpected service restart timeout for large ruleset: %s", got)
	}
}

func TestParseEthtoolFeatureState(t *testing.T) {
	raw := `
Features for eth0:
generic-receive-offload: off
large-receive-offload: on [fixed]
`
	value, ok := parseEthtoolFeatureState(raw, "gro")
	if !ok || value != "off" {
		t.Fatalf("expected gro=off, got value=%q ok=%t", value, ok)
	}
	value, ok = parseEthtoolFeatureState(raw, "lro")
	if !ok || value != "on" {
		t.Fatalf("expected lro=on, got value=%q ok=%t", value, ok)
	}
}

func TestRestoreYAMLFromBackup_VerifiesSHA256(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "suricata.yaml")
	backupPath := filepath.Join(dir, "suricata.yaml.bak")
	if err := os.WriteFile(configPath, []byte("runmode: workers\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(backupPath, []byte("runmode: autofp\n"), 0600); err != nil {
		t.Fatalf("write backup: %v", err)
	}
	err := restoreYAMLFromBackup(&YAMLBackup{
		OriginalPath: configPath,
		BackupPath:   backupPath,
		SHA256:       "deadbeef",
	})
	if err == nil {
		t.Fatalf("expected sha mismatch error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "sha256 mismatch") {
		t.Fatalf("expected sha mismatch error, got %v", err)
	}
	raw, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read config: %v", readErr)
	}
	if string(raw) != "runmode: workers\n" {
		t.Fatalf("expected config to remain unchanged after sha mismatch, got %q", string(raw))
	}
}

func TestRollbackApplied_YAMLMissingBackupFails(t *testing.T) {
	r := &mockRunner{}
	ex := &Executor{Runner: r}
	state := StateFile{
		Applied: []CommandRecord{
			{Index: 0, ActionID: "yaml-tuning", Status: "ok"},
		},
	}
	actions := map[string]PlanAction{
		"yaml-tuning": {ID: "yaml-tuning", Kind: "yaml"},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 1 {
		t.Fatalf("expected one rollback record, got %d", len(records))
	}
	if records[0].Status != "failed" {
		t.Fatalf("expected missing YAML backup to fail, got %+v", records[0])
	}
	if !strings.Contains(records[0].Error, "missing YAML backup") {
		t.Fatalf("expected missing backup error, got %q", records[0].Error)
	}
}

func TestRollbackApplied_RestoresEthtoolKFromPreState(t *testing.T) {
	r := &mockRunner{}
	ex := &Executor{Runner: r}
	state := StateFile{
		Iface: "eth0",
		PreState: PreState{
			EthtoolK: "Features for eth0:\n\tgeneric-receive-offload: off\n",
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "disable-gro"},
		},
	}
	actions := map[string]PlanAction{
		"disable-gro": {
			ID:       "disable-gro",
			Kind:     "ethtool-k",
			Metadata: map[string]interface{}{"feature": "gro"},
		},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 1 {
		t.Fatalf("expected one rollback record, got %d", len(records))
	}
	if records[0].Status != "ok" {
		t.Fatalf("expected rollback status ok, got %s (%s)", records[0].Status, records[0].Error)
	}
	if len(r.calls) == 0 {
		t.Fatalf("expected ethtool rollback command call")
	}
	got := strings.Join(r.calls[0], " ")
	want := "ethtool -K eth0 gro off"
	if got != want {
		t.Fatalf("unexpected rollback command: got %q want %q", got, want)
	}
}

func TestRollbackApplied_RestoresSysctlFromPreState(t *testing.T) {
	r := &mockRunner{}
	ex := &Executor{Runner: r}
	state := StateFile{
		Iface: "eth0",
		PreState: PreState{
			Sysctl: map[string]string{
				"net.core.rmem_max":           "212992",
				"net.core.wmem_max":           "212992",
				"net.core.netdev_max_backlog": "1000",
			},
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "sysctl-net-buffers"},
		},
	}
	actions := map[string]PlanAction{
		"sysctl-net-buffers": {
			ID:        "sysctl-net-buffers",
			Kind:      "sysctl",
			ApplyExec: []string{"sysctl", "-w", "net.core.rmem_max=134217728", "net.core.wmem_max=134217728", "net.core.netdev_max_backlog=250000"},
		},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 1 {
		t.Fatalf("expected one rollback record, got %d", len(records))
	}
	if records[0].Status != "ok" {
		t.Fatalf("expected rollback status ok, got %s (%s)", records[0].Status, records[0].Error)
	}
	got := strings.Join(r.calls[0], " ")
	want := "sysctl -w net.core.netdev_max_backlog=1000 net.core.rmem_max=212992 net.core.wmem_max=212992"
	if got != want {
		t.Fatalf("unexpected sysctl rollback command: got %q want %q", got, want)
	}
}

func TestRollbackApplied_RestoresRSSCombinedFromPreState(t *testing.T) {
	r := &mockRunner{}
	ex := &Executor{Runner: r}
	state := StateFile{
		Iface: "eth0",
		PreState: PreState{
			EthtoolL: `
Channel parameters for eth0:
Pre-set maximums:
Combined: 8
Current hardware settings:
Combined: 2
`,
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "rss-combined-queues"},
		},
	}
	actions := map[string]PlanAction{
		"rss-combined-queues": {
			ID:           "rss-combined-queues",
			Kind:         "ethtool-l",
			RollbackExec: []string{"ethtool", "-L", "eth0", "combined", "4"},
		},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 1 {
		t.Fatalf("expected one rollback record, got %d", len(records))
	}
	if records[0].Status != "ok" {
		t.Fatalf("expected rollback status ok, got %s (%s)", records[0].Status, records[0].Error)
	}
	got := strings.Join(r.calls[0], " ")
	want := "ethtool -L eth0 combined 2"
	if got != want {
		t.Fatalf("unexpected RSS rollback command: got %q want %q", got, want)
	}
}

func TestRollbackApplied_RestoresHugepagesFromSysctlPreState(t *testing.T) {
	r := &mockRunner{}
	ex := &Executor{Runner: r}
	state := StateFile{
		PreState: PreState{
			Sysctl: map[string]string{
				"vm.nr_hugepages": "8",
			},
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "af-xdp-hugepages"},
		},
	}
	actions := map[string]PlanAction{
		"af-xdp-hugepages": {
			ID:        "af-xdp-hugepages",
			Kind:      "hugepages",
			ApplyExec: []string{"sysctl", "-w", "vm.nr_hugepages=512"},
		},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 1 {
		t.Fatalf("expected one rollback record, got %d", len(records))
	}
	if records[0].Status != "ok" {
		t.Fatalf("expected rollback status ok, got %s (%s)", records[0].Status, records[0].Error)
	}
	got := strings.Join(r.calls[0], " ")
	want := "sysctl -w vm.nr_hugepages=8"
	if got != want {
		t.Fatalf("unexpected hugepages rollback command: got %q want %q", got, want)
	}
}

func TestApply_PersistsYAMLBackupBeforeLiveWrite(t *testing.T) {
	origEUID := getEUID
	origWriteTunedYAML := writeTunedYAMLFunc
	defer func() {
		getEUID = origEUID
		writeTunedYAMLFunc = origWriteTunedYAML
	}()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "suricata.yaml")
	if err := os.WriteFile(configPath, []byte("runmode: autofp\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	r := &mockRunner{}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	backupWasPersisted := false
	writeTunedYAMLFunc = func(path string, tuned []byte) error {
		latest, err := ex.StateStore.Latest()
		if err != nil {
			t.Fatalf("expected state before YAML write: %v", err)
		}
		state, err := ex.StateStore.Load(latest)
		if err != nil {
			t.Fatalf("load state before YAML write: %v", err)
		}
		if state.YAMLBackup == nil || state.YAMLBackup.BackupPath == "" {
			t.Fatalf("expected YAML backup metadata persisted before live write")
		}
		if _, err := os.Stat(state.YAMLBackup.BackupPath); err != nil {
			t.Fatalf("expected YAML backup file before live write: %v", err)
		}
		backupWasPersisted = true
		return errors.New("simulated live yaml write failure")
	}

	plan := Plan{
		Profile: ProfileAFPacket,
		Scope:   ScopeConfigOnly,
		IPSMode: IPSModeIDS,
		Snapshot: SystemSnapshot{
			Iface:      "eth0",
			ConfigPath: configPath,
			Build: BuildCapabilities{
				SupportsHWLOC: true,
			},
			NIC: NICInfo{
				NUMANode:     0,
				SymmetricRSS: true,
			},
		},
		Actions: []PlanAction{
			{ID: "yaml-tuning", Kind: "yaml", ApplyCmd: "update yaml", RiskLevel: RiskLow},
		},
	}

	_, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	})
	if err == nil {
		t.Fatalf("expected simulated YAML write failure")
	}
	if !backupWasPersisted {
		t.Fatalf("expected write hook to verify persisted backup")
	}
	raw, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read config: %v", readErr)
	}
	if string(raw) != "runmode: autofp\n" {
		t.Fatalf("expected live config unchanged after write failure, got %q", string(raw))
	}
}

func TestRollbackApplied_RestoresPromiscFromPreState(t *testing.T) {
	r := &mockRunner{}
	ex := &Executor{Runner: r}
	state := StateFile{
		Iface: "eth0",
		PreState: PreState{
			Promisc: true,
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "set-promisc-on"},
		},
	}
	actions := map[string]PlanAction{
		"set-promisc-on": {
			ID:           "set-promisc-on",
			Kind:         "ip-link",
			RollbackExec: []string{"ip", "link", "set", "dev", "eth0", "promisc", "off"},
		},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 1 {
		t.Fatalf("expected one rollback record, got %d", len(records))
	}
	if records[0].Status != "ok" {
		t.Fatalf("expected rollback status ok, got %s (%s)", records[0].Status, records[0].Error)
	}
	got := strings.Join(r.calls[0], " ")
	want := "ip link set dev eth0 promisc on"
	if got != want {
		t.Fatalf("unexpected promisc rollback command: got %q want %q", got, want)
	}
}

func TestIRQAffinityRestorePath_UsesHexMaskFileForCapturedPreState(t *testing.T) {
	if got := filepath.Base(irqAffinityRestorePath("19", "3f")); got != "smp_affinity" {
		t.Fatalf("expected hex mask to restore via smp_affinity, got %s", got)
	}
	if got := filepath.Base(irqAffinityRestorePath("19", "0-5")); got != "smp_affinity_list" {
		t.Fatalf("expected cpu list to restore via smp_affinity_list, got %s", got)
	}
}

func TestRollbackApplied_NodeHugePagesFailsWithoutPreState(t *testing.T) {
	r := &mockRunner{}
	ex := &Executor{Runner: r}
	state := StateFile{
		Iface: "eth0",
		PreState: PreState{
			NodeHugePages: map[string]string{},
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "dpdk-hugepages-numa"},
		},
	}
	actions := map[string]PlanAction{
		"dpdk-hugepages-numa": {
			ID:   "dpdk-hugepages-numa",
			Kind: "node-hugepages",
		},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 1 {
		t.Fatalf("expected one rollback record, got %d", len(records))
	}
	if records[0].ActionID != "rollback-dpdk-hugepages-numa" {
		t.Fatalf("unexpected action id: %s", records[0].ActionID)
	}
	if records[0].Status != "failed" {
		t.Fatalf("expected failed rollback status, got %s (%s)", records[0].Status, records[0].Error)
	}
	if !strings.Contains(records[0].Error, "pre-state") {
		t.Fatalf("expected missing pre-state error, got %q", records[0].Error)
	}
}

func TestApply_RequiresRootBeforeStateWrite(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 1000 }

	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	ex := NewExecutor(&mockRunner{}, stateDir)
	plan := Plan{
		Profile: ProfileAFPacket,
		Scope:   ScopeConfigOnly,
		IPSMode: IPSModeIDS,
		Snapshot: SystemSnapshot{
			Iface:      "eth0",
			ConfigPath: filepath.Join(dir, "suricata.yaml"),
		},
		Actions: []PlanAction{
			{ID: "yaml-tuning", Kind: "yaml", RiskLevel: RiskLow},
		},
	}
	_, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	})
	if err == nil {
		t.Fatalf("expected root privileges error")
	}
	if _, statErr := os.Stat(stateDir); !os.IsNotExist(statErr) {
		t.Fatalf("expected no state dir creation when root check fails")
	}
}

func TestApply_OSTuningDoesNotCallSuricataValidationOrRestart(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	r := &scriptedRunner{
		results: map[string]CommandResult{
			"sysctl -n net.core.rmem_max": {Stdout: "1"},
		},
	}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	plan := Plan{
		Profile: ProfileAFPacket,
		Scope:   ScopeOSTuning,
		IPSMode: IPSModeIDS,
		Snapshot: SystemSnapshot{
			Iface: "eth0",
		},
		Actions: []PlanAction{
			{
				ID:        "sysctl-net-buffers",
				Kind:      "sysctl",
				ApplyExec: []string{"sysctl", "-w", "net.core.rmem_max=123"},
				RiskLevel: RiskMedium,
			},
		},
	}
	if _, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	}); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	joined := flattenCalls(r.calls)
	if strings.Contains(joined, "suricata -T") {
		t.Fatalf("did not expect suricata -T in os-tuning scope")
	}
	if strings.Contains(joined, "systemctl restart suricata.service") {
		t.Fatalf("did not expect suricata restart in os-tuning scope")
	}
}

func TestApply_PreStateValidationBlocksOSTuningBeforeLiveCommand(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	r := &scriptedRunner{}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	plan := Plan{
		Profile: ProfileAFPacket,
		Scope:   ScopeOSTuning,
		IPSMode: IPSModeIDS,
		Snapshot: SystemSnapshot{
			Iface: "eth0",
		},
		Actions: []PlanAction{
			{
				ID:        "disable-gro",
				Kind:      "ethtool-k",
				ApplyExec: []string{"ethtool", "-K", "eth0", "gro", "off"},
				RiskLevel: RiskMedium,
				Metadata:  map[string]interface{}{"feature": "gro"},
			},
		},
	}
	_, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	})
	if err == nil {
		t.Fatalf("expected pre-state validation error")
	}
	if !strings.Contains(err.Error(), "pre-state") {
		t.Fatalf("expected pre-state error, got %v", err)
	}
	if strings.Contains(flattenCalls(r.calls), "ethtool -K eth0 gro off") {
		t.Fatalf("did not expect live ethtool command after pre-state validation failure, calls:\n%s", flattenCalls(r.calls))
	}
}

func TestApply_NFQSkipsExistingIptablesRule(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	r := &scriptedRunner{
		results: map[string]CommandResult{
			"iptables -C FORWARD -j NFQUEUE --queue-num 0": {ExitCode: 0},
		},
	}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	plan := Plan{
		Profile: ProfileNFQ,
		Scope:   ScopeFull,
		IPSMode: IPSModeStrict,
		Snapshot: SystemSnapshot{
			Iface: "eth0",
		},
		Actions: []PlanAction{
			{
				ID:           "nfq-queue-rules",
				Kind:         "nfq-rules",
				ApplyExec:    []string{"iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"},
				RollbackExec: []string{"iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"},
				RiskLevel:    RiskMedium,
				Metadata:     map[string]interface{}{"firewall_backend": "iptables"},
			},
		},
	}

	result, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if result.AppliedCount != 0 {
		t.Fatalf("expected no applied action for pre-existing NFQ rule, got %d", result.AppliedCount)
	}
	if strings.Contains(flattenCalls(r.calls), "iptables -I FORWARD") {
		t.Fatalf("did not expect duplicate iptables insert, calls:\n%s", flattenCalls(r.calls))
	}
}

func TestApply_NFQInsertsMissingIptablesRule(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	r := &scriptedRunner{
		results: map[string]CommandResult{
			"iptables -C FORWARD -j NFQUEUE --queue-num 0": {ExitCode: 1, Stderr: "not found"},
		},
	}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	plan := Plan{
		Profile: ProfileNFQ,
		Scope:   ScopeFull,
		IPSMode: IPSModeStrict,
		Snapshot: SystemSnapshot{
			Iface: "eth0",
		},
		Actions: []PlanAction{
			{
				ID:           "nfq-queue-rules",
				Kind:         "nfq-rules",
				ApplyExec:    []string{"iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"},
				RollbackExec: []string{"iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"},
				RiskLevel:    RiskMedium,
				Metadata:     map[string]interface{}{"firewall_backend": "iptables"},
			},
		},
	}

	result, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if result.AppliedCount != 1 {
		t.Fatalf("expected one applied action for inserted NFQ rule, got %d", result.AppliedCount)
	}
	if !strings.Contains(flattenCalls(r.calls), "iptables -I FORWARD -j NFQUEUE --queue-num 0") {
		t.Fatalf("expected iptables insert, calls:\n%s", flattenCalls(r.calls))
	}
}

func TestRollbackApplied_NFQSkipsDeleteWhenIptablesRuleAbsent(t *testing.T) {
	r := &scriptedRunner{
		results: map[string]CommandResult{
			"iptables -C FORWARD -j NFQUEUE --queue-num 0": {ExitCode: 1, Stderr: "not found"},
		},
	}
	ex := &Executor{Runner: r}
	state := StateFile{
		Iface: "eth0",
		Applied: []CommandRecord{
			{Index: 0, ActionID: "nfq-queue-rules"},
		},
	}
	actions := map[string]PlanAction{
		"nfq-queue-rules": {
			ID:           "nfq-queue-rules",
			Kind:         "nfq-rules",
			ApplyExec:    []string{"iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"},
			RollbackExec: []string{"iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"},
			Metadata:     map[string]interface{}{"firewall_backend": "iptables"},
		},
	}
	records := ex.rollbackApplied(state, actions)
	if len(records) != 1 {
		t.Fatalf("expected one rollback record, got %d", len(records))
	}
	if records[0].Status != "ok" {
		t.Fatalf("expected absent NFQ rule rollback to be ok, got %+v", records[0])
	}
	if strings.Contains(flattenCalls(r.calls), "iptables -D FORWARD") {
		t.Fatalf("did not expect iptables delete when rule is already absent, calls:\n%s", flattenCalls(r.calls))
	}
}

func TestParseNFQNftRuleHandle(t *testing.T) {
	raw := `
table inet filter {
	chain forward {
		queue num 0 comment "surituner-nfq-0" # handle 12
		queue num 1 comment "other" # handle 13
	}
}
`
	handle, ok := parseNFQNftRuleHandle(raw, nfqNftRuleComment)
	if !ok || handle != "12" {
		t.Fatalf("expected nft handle 12, got handle=%q ok=%t", handle, ok)
	}
}

func TestApplyNFQRule_NftVerifiesOwnedHandleAfterInsert(t *testing.T) {
	r := &sequenceRunner{
		results: map[string][]CommandResult{
			"nft -a list chain inet filter forward": {
				{ExitCode: 0, Stdout: "table inet filter { chain forward { } }"},
				{ExitCode: 0, Stdout: `queue num 0 comment "surituner-nfq-0" # handle 12`},
			},
		},
	}
	ex := &Executor{Runner: r}
	applied, err := ex.applyNFQRule(PlanAction{
		ID:        "nfq-queue-rules",
		Kind:      "nfq-rules",
		ApplyExec: []string{"nft", "add", "rule", "inet", "filter", "forward", "queue", "num", "0", "comment", nfqNftRuleComment},
		Metadata:  map[string]interface{}{"firewall_backend": "nftables", "nft_comment": nfqNftRuleComment},
	})
	if err != nil {
		t.Fatalf("applyNFQRule failed: %v", err)
	}
	if !applied {
		t.Fatalf("expected nft rule to be applied")
	}
	joined := flattenCalls(r.calls)
	if !strings.Contains(joined, "nft add rule inet filter forward queue num 0 comment surituner-nfq-0") {
		t.Fatalf("expected nft add rule call, got:\n%s", joined)
	}
	if count := strings.Count(joined, "nft -a list chain inet filter forward"); count != 2 {
		t.Fatalf("expected pre/post nft list verification, got %d calls:\n%s", count, joined)
	}
}

func TestApplyNFQRule_NftCleansUpWhenPostInsertVerificationFails(t *testing.T) {
	r := &sequenceRunner{
		results: map[string][]CommandResult{
			"nft -a list chain inet filter forward": {
				{ExitCode: 0, Stdout: "table inet filter { chain forward { } }"},
				{ExitCode: 0, Stdout: "table inet filter { chain forward { } }"},
				{ExitCode: 0, Stdout: `queue num 0 comment "surituner-nfq-0" # handle 12`},
			},
		},
	}
	ex := &Executor{Runner: r}
	applied, err := ex.applyNFQRule(PlanAction{
		ID:        "nfq-queue-rules",
		Kind:      "nfq-rules",
		ApplyExec: []string{"nft", "add", "rule", "inet", "filter", "forward", "queue", "num", "0", "comment", nfqNftRuleComment},
		Metadata:  map[string]interface{}{"firewall_backend": "nftables", "nft_comment": nfqNftRuleComment},
	})
	if err == nil {
		t.Fatalf("expected verification failure")
	}
	if applied {
		t.Fatalf("did not expect applied=true after cleanup")
	}
	joined := flattenCalls(r.calls)
	if !strings.Contains(joined, "nft delete rule inet filter forward handle 12") {
		t.Fatalf("expected cleanup delete by resolved handle, got:\n%s", joined)
	}
}

func TestApply_DPDKBindRejectsUnsafeRollbackDriver(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	r := &scriptedRunner{}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	plan := Plan{
		Profile: ProfileDPDK,
		Scope:   ScopeFull,
		IPSMode: IPSModeIDS,
		Snapshot: SystemSnapshot{
			Iface: "eth0",
		},
		Actions: []PlanAction{
			{
				ID:           "dpdk-bind",
				Kind:         "dpdk-bind",
				ApplyExec:    []string{"dpdk-devbind.py", "--bind=vfio-pci", "0000:01:00.0"},
				RollbackExec: []string{"dpdk-devbind.py", "--bind=vfio-pci", "0000:01:00.0"},
				RiskLevel:    RiskCritical,
			},
		},
	}
	_, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	})
	if err == nil {
		t.Fatalf("expected unsafe dpdk rollback driver to fail")
	}
	if strings.Contains(flattenCalls(r.calls), "dpdk-devbind.py --bind=vfio-pci 0000:01:00.0") {
		t.Fatalf("did not expect dpdk bind command after validation failure, calls:\n%s", flattenCalls(r.calls))
	}
}

func TestApply_FullAppliesSystemdProfileBeforeRestart(t *testing.T) {
	origEUID := getEUID
	origDropIn := serviceProfileDropInPath
	defer func() {
		getEUID = origEUID
		serviceProfileDropInPath = origDropIn
	}()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	serviceProfileDropInPath = filepath.Join(dir, "suricata.service.d", "surituner-profile.conf")
	configPath := filepath.Join(dir, "suricata.yaml")
	if err := os.WriteFile(configPath, []byte("runmode: autofp\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	r := &mockRunner{}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	plan := Plan{
		Profile: ProfileAFPacket,
		Scope:   ScopeFull,
		IPSMode: IPSModeIDS,
		Snapshot: SystemSnapshot{
			Iface:      "ens33",
			ConfigPath: configPath,
			Build: BuildCapabilities{
				SupportsHWLOC: true,
			},
			NIC: NICInfo{
				NUMANode:     0,
				SymmetricRSS: true,
			},
		},
		Actions: []PlanAction{
			{
				ID:        "yaml-tuning",
				Kind:      "yaml",
				ApplyCmd:  "update yaml",
				RiskLevel: RiskLow,
			},
			{
				ID:        "systemd-profile",
				Kind:      "systemd-profile",
				ApplyCmd:  "write systemd drop-in",
				RiskLevel: RiskLow,
				Metadata: map[string]interface{}{
					"exec_start": "/usr/bin/suricata -D --af-packet=ens33 -c " + configPath + " --pidfile /var/run/suricata/suricata.pid",
				},
			},
		},
	}

	if _, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	}); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	raw, err := os.ReadFile(serviceProfileDropInPath)
	if err != nil {
		t.Fatalf("read drop-in: %v", err)
	}
	if !strings.Contains(string(raw), "ExecStart=/usr/bin/suricata -D --af-packet=ens33") {
		t.Fatalf("drop-in does not contain expected ExecStart:\n%s", string(raw))
	}
	daemonReload := -1
	restart := -1
	for i, call := range r.calls {
		joined := strings.Join(call, " ")
		if joined == "systemctl daemon-reload" && daemonReload == -1 {
			daemonReload = i
		}
		if strings.Contains(joined, "systemctl restart suricata.service") {
			restart = i
		}
	}
	if daemonReload == -1 {
		t.Fatalf("expected systemctl daemon-reload call")
	}
	if restart == -1 {
		t.Fatalf("expected service restart call")
	}
	if daemonReload > restart {
		t.Fatalf("expected daemon-reload before restart, got daemon=%d restart=%d", daemonReload, restart)
	}
}

func TestValidateSystemdExecStartRejectsMultiline(t *testing.T) {
	if err := validateSystemdExecStart("/usr/bin/suricata -D\nExecStart=/bin/sh"); err == nil {
		t.Fatalf("expected multiline ExecStart validation error")
	}
	if err := validateSystemdExecStart("/usr/bin/suricata -D --af-packet=ens33"); err != nil {
		t.Fatalf("expected valid ExecStart, got %v", err)
	}
}

func TestApply_ConfigOnlyFailsWhenSuricataValidationUnavailable(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "suricata.yaml")
	if err := os.WriteFile(configPath, []byte("runmode: autofp\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	r := &failOnCommandRunner{failCmd: "suricata"}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	plan := Plan{
		Profile: ProfileAFPacket,
		Scope:   ScopeConfigOnly,
		IPSMode: IPSModeIDS,
		Snapshot: SystemSnapshot{
			Iface:      "eth0",
			ConfigPath: configPath,
			Build: BuildCapabilities{
				SupportsHWLOC: true,
			},
			NIC: NICInfo{
				NUMANode:     0,
				SymmetricRSS: true,
			},
		},
		Actions: []PlanAction{
			{
				ID:        "yaml-tuning",
				Kind:      "yaml",
				ApplyCmd:  "update yaml",
				RiskLevel: RiskLow,
			},
		},
	}
	_, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	})
	if err == nil {
		t.Fatalf("expected error when suricata -T is unavailable")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "simulated failure") {
		t.Fatalf("expected detailed validation error, got: %v", err)
	}
	joined := flattenCalls(r.calls)
	if !strings.Contains(joined, "suricata -T") {
		t.Fatalf("expected suricata -T call before failure")
	}
	if strings.Contains(joined, "systemctl restart suricata.service") {
		t.Fatalf("did not expect restart when suricata -T fails")
	}
}

func TestApply_ConfigOnlyFailsBeforeYAMLWriteWhenSystemctlUnavailable(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "suricata.yaml")
	initial := []byte("runmode: autofp\n")
	if err := os.WriteFile(configPath, initial, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	r := &scriptedRunner{
		errors: map[string]error{
			"systemctl --version": errors.New("systemctl unavailable"),
		},
	}
	ex := NewExecutor(r, filepath.Join(dir, "state"))
	plan := Plan{
		Profile: ProfileAFPacket,
		Scope:   ScopeConfigOnly,
		IPSMode: IPSModeIDS,
		Snapshot: SystemSnapshot{
			Iface:      "eth0",
			ConfigPath: configPath,
			Build: BuildCapabilities{
				SupportsHWLOC: true,
			},
			NIC: NICInfo{
				NUMANode:     0,
				SymmetricRSS: true,
			},
		},
		Actions: []PlanAction{
			{
				ID:        "yaml-tuning",
				Kind:      "yaml",
				ApplyCmd:  "update yaml",
				RiskLevel: RiskLow,
			},
		},
	}

	_, err := ex.Apply(plan, ApplyOptions{
		AssumeYes: true,
		Input:     strings.NewReader(""),
		Output:    io.Discard,
	})
	if err == nil {
		t.Fatalf("expected systemctl preflight error")
	}
	if !strings.Contains(err.Error(), "before applying changes") {
		t.Fatalf("expected pre-change systemctl failure context, got %v", err)
	}
	raw, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatalf("read config: %v", readErr)
	}
	if string(raw) != string(initial) {
		t.Fatalf("expected config unchanged before systemd preflight failure, got %q", string(raw))
	}
	if strings.Contains(flattenCalls(r.calls), "suricata -T") {
		t.Fatalf("did not expect suricata validation after systemd preflight failure")
	}
}

func flattenCalls(calls [][]string) string {
	var out []string
	for _, call := range calls {
		out = append(out, strings.Join(call, " "))
	}
	return strings.Join(out, "\n")
}

func TestSuricataValidationTimeout(t *testing.T) {
	if got := suricataValidationTimeout(100); got != 90*time.Second {
		t.Fatalf("unexpected timeout for small ruleset: %s", got)
	}
	if got := suricataValidationTimeout(6000); got != 2*time.Minute {
		t.Fatalf("unexpected timeout for mid ruleset: %s", got)
	}
	if got := suricataValidationTimeout(15000); got != 3*time.Minute {
		t.Fatalf("unexpected timeout for large ruleset: %s", got)
	}
	if got := suricataValidationTimeout(50000); got != 5*time.Minute {
		t.Fatalf("unexpected timeout for very large ruleset: %s", got)
	}
}

func TestBuildValidationDiag(t *testing.T) {
	diag := buildValidationDiag(
		errors.New("command timed out"),
		CommandResult{
			Stdout: "i: suricata: This is Suricata version 8.0.3 RELEASE running in SYSTEM mode",
			Stderr: "E: conf-yaml-loader: Invalid configuration file",
		},
	)
	if !strings.Contains(diag, "command timed out") {
		t.Fatalf("expected error details in diag, got: %s", diag)
	}
	if !strings.Contains(diag, "Invalid configuration file") {
		t.Fatalf("expected stderr details in diag, got: %s", diag)
	}
	if !strings.Contains(diag, "This is Suricata version") {
		t.Fatalf("expected stdout details in diag, got: %s", diag)
	}
}
