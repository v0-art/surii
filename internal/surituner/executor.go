package surituner

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ApplyOptions struct {
	Scope     ApplyScope
	Force     bool
	AssumeYes bool
	Input     io.Reader
	Output    io.Writer
	StateDir  string
}

type ApplyResult struct {
	StatePath      string
	AppliedCount   int
	RolledBack     bool
	RollbackReason string
	Warnings       []string
}

type Executor struct {
	Runner     CommandRunner
	StateStore *StateStore
}

var getEUID = os.Geteuid

func NewExecutor(runner CommandRunner, stateDir string) *Executor {
	return &Executor{
		Runner:     runner,
		StateStore: NewStateStore(stateDir),
	}
}

func (e *Executor) Apply(plan Plan, opts ApplyOptions) (ApplyResult, error) {
	if opts.Input == nil {
		opts.Input = os.Stdin
	}
	if opts.Output == nil {
		opts.Output = os.Stdout
	}
	if plan.HardBlocked {
		return ApplyResult{}, fmt.Errorf("plan has non-overridable blockers: %s", strings.Join(plan.BlockingReasons, "; "))
	}
	if plan.Blocked && !opts.Force {
		return ApplyResult{}, fmt.Errorf("plan is blocked by guardrails: %s", strings.Join(plan.BlockingReasons, "; "))
	}
	if err := requireRoot(); err != nil {
		return ApplyResult{}, err
	}

	state := StateFile{
		Version:         "v1",
		CreatedAt:       time.Now().UTC(),
		HostFingerprint: BuildHostFingerprint(),
		Profile:         plan.Profile,
		Scope:           plan.Scope,
		IPSMode:         plan.IPSMode,
		Iface:           plan.Snapshot.Iface,
		ConfigPath:      plan.Snapshot.ConfigPath,
		Snapshot:        plan.Snapshot,
		PreState:        e.capturePreState(plan.Snapshot.Iface),
		PlanActions:     plan.Actions,
		Status:          "pending",
	}
	statePath, err := e.StateStore.Save(state)
	if err != nil {
		return ApplyResult{}, err
	}

	confirmNeeded := hasHighOrCritical(plan.Actions)
	if confirmNeeded && !opts.AssumeYes {
		ok := askConfirmation(opts.Input, opts.Output, "HIGH/CRITICAL actions detected. Continue apply? [y/N]: ")
		if !ok {
			state.Status = "aborted"
			if updateErr := e.updateState(statePath, state); updateErr != nil {
				return ApplyResult{StatePath: statePath}, fmt.Errorf("apply aborted by user and state update failed: %w", updateErr)
			}
			return ApplyResult{StatePath: statePath}, errors.New("apply aborted by user")
		}
	}

	if applyRequiresSystemd(plan.Actions, opts.Force) {
		if err := e.ensureSystemctlAvailable(); err != nil {
			state.Status = "failed"
			state.Error = err.Error()
			if updateErr := e.updateState(statePath, state); updateErr != nil {
				return ApplyResult{StatePath: statePath}, fmt.Errorf("systemd preflight failed: %v; state update failed: %w", err, updateErr)
			}
			return ApplyResult{StatePath: statePath}, fmt.Errorf("systemd preflight failed: %w", err)
		}
	}

	// Build and validate tuned YAML before touching system state.
	var preparedOriginalYAML []byte
	var preparedTunedYAML []byte
	var preparedYAMLChanges []string
	yamlActionEnabled := false
	for _, action := range plan.Actions {
		if action.ID == "yaml-tuning" && !(action.BlockedByGuardrail && !opts.Force) {
			yamlActionEnabled = true
			break
		}
	}
	if yamlActionEnabled {
		original, tuned, changes, err := BuildTunedYAML(plan.Snapshot.ConfigPath, TuneOptions{
			Profile:       plan.Profile,
			IPSMode:       plan.IPSMode,
			Iface:         plan.Snapshot.Iface,
			SupportsHWLOC: plan.Snapshot.Build.SupportsHWLOC,
			NICNUMA:       plan.Snapshot.NIC.NUMANode,
			NICPCIAddress: plan.Snapshot.NIC.PCIAddress,
			SymmetricRSS:  plan.Snapshot.NIC.SymmetricRSS,
			EnabledRules:  plan.Snapshot.Ruleset.EnabledRules,
			TotalRAMMB:    plan.Snapshot.TotalRAMMB,
		})
		if err != nil {
			state.Status = "failed"
			state.Error = err.Error()
			if updateErr := e.updateState(statePath, state); updateErr != nil {
				return ApplyResult{StatePath: statePath}, fmt.Errorf("yaml preparation failed: %v; state update failed: %w", err, updateErr)
			}
			return ApplyResult{StatePath: statePath}, fmt.Errorf("yaml preparation failed: %w", err)
		}
		tempPath, cleanup, err := writeTempConfig(tuned)
		if err != nil {
			state.Status = "failed"
			state.Error = err.Error()
			if updateErr := e.updateState(statePath, state); updateErr != nil {
				return ApplyResult{StatePath: statePath}, fmt.Errorf("yaml temp config failed: %v; state update failed: %w", err, updateErr)
			}
			return ApplyResult{StatePath: statePath}, fmt.Errorf("yaml temp config failed: %w", err)
		}
		defer cleanup()
		validationTimeout := suricataValidationTimeout(plan.Snapshot.Ruleset.EnabledRules)
		res, err := e.Runner.Run([]string{"suricata", "-T", "-c", tempPath}, validationTimeout, false)
		if err != nil {
			diag := buildValidationDiag(err, res)
			state.Status = "failed"
			state.Error = fmt.Sprintf("suricata -T validation failed: %s", diag)
			if updateErr := e.updateState(statePath, state); updateErr != nil {
				return ApplyResult{StatePath: statePath}, fmt.Errorf("%s; state update failed: %w", state.Error, updateErr)
			}
			return ApplyResult{StatePath: statePath}, errors.New(state.Error)
		}
		preparedOriginalYAML = original
		preparedTunedYAML = tuned
		preparedYAMLChanges = changes
	}

	var warnings []string
	appliedActions := map[string]PlanAction{}
	for idx, action := range plan.Actions {
		if action.BlockedByGuardrail && !opts.Force {
			continue
		}

		switch action.Kind {
		case "yaml":
			backup, err := ApplyTunedYAML(plan.Snapshot.ConfigPath, preparedOriginalYAML, preparedTunedYAML)
			if err != nil {
				state.Status = "failed"
				state.Error = err.Error()
				return e.failAndRollback(statePath, &state, appliedActions, fmt.Sprintf("yaml apply failed: %v", err))
			}
			state.YAMLBackup = &backup
			record := CommandRecord{
				Index:    idx,
				ActionID: action.ID,
				Command:  []string{action.ApplyCmd},
				Status:   "ok",
			}
			state.Applied = append(state.Applied, record)
			appliedActions[action.ID] = action
			if len(preparedYAMLChanges) > 0 {
				warnings = append(warnings, preparedYAMLChanges...)
			}
		case "warning":
			record := CommandRecord{
				Index:    idx,
				ActionID: action.ID,
				Command:  []string{action.ApplyCmd},
				Status:   "ok",
			}
			state.Applied = append(state.Applied, record)
			appliedActions[action.ID] = action
		case "node-hugepages":
			err := applyNodeHugepagesFromAction(action)
			record := CommandRecord{
				Index:    idx,
				ActionID: action.ID,
				Command:  []string{action.ApplyCmd},
				Status:   "ok",
			}
			if err != nil {
				record.Status = "failed"
				record.Error = err.Error()
				state.Applied = append(state.Applied, record)
				state.Status = "failed"
				state.Error = err.Error()
				return e.failAndRollback(statePath, &state, appliedActions, fmt.Sprintf("node hugepages failed: %v", err))
			}
			state.Applied = append(state.Applied, record)
			appliedActions[action.ID] = action
		case "irq":
			err := e.applyIRQAffinity(plan.Snapshot, state.PreState.IRQAffinity)
			record := CommandRecord{
				Index:    idx,
				ActionID: action.ID,
				Command:  []string{action.ApplyCmd},
				Status:   "ok",
			}
			if err != nil {
				record.Status = "failed"
				record.Error = err.Error()
				state.Applied = append(state.Applied, record)
				state.Status = "failed"
				state.Error = err.Error()
				return e.failAndRollback(statePath, &state, appliedActions, fmt.Sprintf("irq affinity failed: %v", err))
			}
			state.Applied = append(state.Applied, record)
			appliedActions[action.ID] = action
		case "systemd-profile":
			backup, err := e.applyServiceProfileDropIn(action)
			record := CommandRecord{
				Index:    idx,
				ActionID: action.ID,
				Command:  []string{action.ApplyCmd},
				Status:   "ok",
			}
			if err != nil {
				record.Status = "failed"
				record.Error = err.Error()
				state.Applied = append(state.Applied, record)
				state.Status = "failed"
				state.Error = err.Error()
				return e.failAndRollback(statePath, &state, appliedActions, fmt.Sprintf("systemd profile failed: %v", err))
			}
			state.ServiceDropIn = &backup
			state.Applied = append(state.Applied, record)
			appliedActions[action.ID] = action
		case "nfq-rules":
			applied, err := e.applyNFQRule(action)
			record := CommandRecord{
				Index:    idx,
				ActionID: action.ID,
				Command:  action.ApplyExec,
				Status:   "ok",
			}
			if err != nil {
				record.Status = "failed"
				record.Error = err.Error()
				state.Applied = append(state.Applied, record)
				state.Status = "failed"
				state.Error = err.Error()
				return e.failAndRollback(statePath, &state, appliedActions, fmt.Sprintf("nfq rule apply failed: %v", err))
			}
			if !applied {
				warnings = append(warnings, "nfq rule already present; no change applied")
				break
			}
			state.Applied = append(state.Applied, record)
			appliedActions[action.ID] = action
		case "dpdk-bind":
			err := validateDPDKBindAction(action)
			record := CommandRecord{
				Index:    idx,
				ActionID: action.ID,
				Command:  action.ApplyExec,
				Status:   "ok",
			}
			if err == nil {
				_, err = e.Runner.Run(action.ApplyExec, 20*time.Second, false)
			}
			if err != nil {
				record.Status = "failed"
				record.Error = err.Error()
				state.Applied = append(state.Applied, record)
				state.Status = "failed"
				state.Error = err.Error()
				return e.failAndRollback(statePath, &state, appliedActions, fmt.Sprintf("dpdk bind failed: %v", err))
			}
			state.Applied = append(state.Applied, record)
			appliedActions[action.ID] = action
		default:
			if len(action.ApplyExec) == 0 {
				warnings = append(warnings, fmt.Sprintf("action %s has no executable command, skipped", action.ID))
				continue
			}
			res, err := e.Runner.Run(action.ApplyExec, 20*time.Second, false)
			record := CommandRecord{
				Index:    idx,
				ActionID: action.ID,
				Command:  action.ApplyExec,
				Status:   "ok",
			}
			if err != nil {
				record.Status = "failed"
				record.Error = err.Error()
				state.Applied = append(state.Applied, record)
				state.Status = "failed"
				state.Error = err.Error()
				return e.failAndRollback(statePath, &state, appliedActions, fmt.Sprintf("action %s failed: %s", action.ID, buildValidationDiag(err, res)))
			}
			state.Applied = append(state.Applied, record)
			appliedActions[action.ID] = action
		}
		if err := e.StateStore.Update(statePath, state); err != nil {
			return e.failAndRollback(statePath, &state, appliedActions, fmt.Sprintf("state update failed after action %s: %v", action.ID, err))
		}
	}

	// Restart and verify service only when YAML has been changed.
	if hasAction(plan.Actions, "yaml-tuning") && state.YAMLBackup != nil {
		_, _ = e.Runner.Run([]string{"systemctl", "reset-failed", "suricata.service"}, 10*time.Second, true)
		restartTimeout := suricataServiceRestartTimeout(plan.Snapshot.Ruleset.EnabledRules)
		res, err := e.Runner.Run([]string{"systemctl", "restart", "suricata.service"}, restartTimeout, false)
		if err != nil {
			state.Status = "failed"
			state.Error = fmt.Sprintf("systemctl restart suricata.service failed: %s", e.buildServiceFailureDiag(err, res))
			return e.failAndRollback(statePath, &state, appliedActions, state.Error)
		}
		if _, err := e.Runner.Run([]string{"systemctl", "is-active", "--quiet", "suricata.service"}, 10*time.Second, false); err != nil {
			state.Status = "failed"
			statusDiag, _ := e.Runner.Run([]string{"systemctl", "status", "suricata.service", "--no-pager", "-l"}, 15*time.Second, true)
			state.Error = fmt.Sprintf("suricata.service is not active after restart: %s", strings.TrimSpace(statusDiag.Stdout))
			return e.failAndRollback(statePath, &state, appliedActions, state.Error)
		}
	}

	state.Status = "applied"
	if err := e.StateStore.Update(statePath, state); err != nil {
		return ApplyResult{StatePath: statePath}, err
	}
	return ApplyResult{
		StatePath:    statePath,
		AppliedCount: len(state.Applied),
		Warnings:     dedupeStrings(warnings),
	}, nil
}

func (e *Executor) failAndRollback(statePath string, state *StateFile, actions map[string]PlanAction, reason string) (ApplyResult, error) {
	rollbackRecords := e.rollbackApplied(*state, actions)
	state.Rollback = append(state.Rollback, rollbackRecords...)
	preStateRecords := e.restorePreStateBestEffort(*state)
	state.Rollback = append(state.Rollback, preStateRecords...)

	rollbackErrors := failedCommandRecords(append(append([]CommandRecord{}, rollbackRecords...), preStateRecords...))
	state.Status = "rolled_back_after_failure"
	state.Error = reason
	if len(rollbackErrors) > 0 {
		state.Status = "rollback_partial_after_failure"
		state.Error = fmt.Sprintf("%s; rollback incomplete: %s", reason, strings.Join(rollbackErrors, "; "))
	}
	result := ApplyResult{
		StatePath:      statePath,
		AppliedCount:   len(state.Applied),
		RolledBack:     true,
		RollbackReason: state.Error,
		Warnings:       rollbackErrors,
	}
	if updateErr := e.updateState(statePath, *state); updateErr != nil {
		return result, fmt.Errorf("%s; state update failed: %w", reason, updateErr)
	}
	return result, errors.New(state.Error)
}

func writeTempConfig(content []byte) (string, func(), error) {
	file, err := os.CreateTemp("", "surituner-suricata-*.yaml")
	if err != nil {
		return "", nil, err
	}
	path := file.Name()
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, err
	}
	cleanup := func() { _ = os.Remove(path) }
	return path, cleanup, nil
}

func (e *Executor) rollbackApplied(state StateFile, actions map[string]PlanAction) []CommandRecord {
	var records []CommandRecord
	applied := append([]CommandRecord(nil), state.Applied...)
	sort.SliceStable(applied, func(i, j int) bool { return applied[i].Index > applied[j].Index })
	for _, entry := range applied {
		action, ok := actions[entry.ActionID]
		if !ok {
			continue
		}
		if action.Kind == "ip-link" {
			cmd := promiscRestoreCommand(state.Iface, state.PreState.Promisc)
			err := e.runBestEffort(cmd, 5*time.Second)
			status := "ok"
			msg := ""
			if err != nil {
				status = "failed"
				msg = err.Error()
			}
			records = append(records, CommandRecord{
				Index:    entry.Index,
				ActionID: "rollback-" + action.ID,
				Command:  cmd,
				Status:   status,
				Error:    msg,
			})
			continue
		}
		if action.Kind == "nfq-rules" {
			cmd, err := e.rollbackNFQRule(action)
			status := "ok"
			msg := ""
			if err != nil {
				status = "failed"
				msg = err.Error()
			}
			records = append(records, CommandRecord{
				Index:    entry.Index,
				ActionID: "rollback-" + action.ID,
				Command:  cmd,
				Status:   status,
				Error:    msg,
			})
			continue
		}
		if action.Kind == "yaml" {
			err := restoreYAMLFromBackup(state.YAMLBackup)
			status := "ok"
			msg := ""
			if err != nil {
				status = "failed"
				msg = err.Error()
			}
			records = append(records, CommandRecord{
				Index:    entry.Index,
				ActionID: "rollback-" + action.ID,
				Command:  []string{"restore suricata.yaml from backup"},
				Status:   status,
				Error:    msg,
			})
			continue
		}
		if action.Kind == "irq" {
			err := e.restoreIRQAffinity(state.PreState.IRQAffinity)
			status := "ok"
			msg := ""
			if err != nil {
				status = "failed"
				msg = err.Error()
			}
			records = append(records, CommandRecord{
				Index:    entry.Index,
				ActionID: "rollback-" + action.ID,
				Command:  []string{"restore irq affinity map"},
				Status:   status,
				Error:    msg,
			})
			continue
		}
		if action.Kind == "ethtool-g" {
			err := e.restoreRingBuffers(state.Iface, state.PreState.EthtoolG)
			status := "ok"
			msg := ""
			if err != nil {
				status = "failed"
				msg = err.Error()
			}
			records = append(records, CommandRecord{
				Index:    entry.Index,
				ActionID: "rollback-" + action.ID,
				Command:  []string{"restore ring buffers from state"},
				Status:   status,
				Error:    msg,
			})
			continue
		}
		if action.Kind == "node-hugepages" {
			err := restoreNodeHugePages(state.PreState.NodeHugePages)
			status := "ok"
			msg := ""
			if err != nil {
				status = "failed"
				msg = err.Error()
			}
			records = append(records, CommandRecord{
				Index:    entry.Index,
				ActionID: "rollback-" + action.ID,
				Command:  []string{"restore per-node hugepages from pre-state"},
				Status:   status,
				Error:    msg,
			})
			continue
		}
		if action.Kind == "ethtool-k" {
			feature := featureFromAction(action)
			err := e.restoreEthtoolFeatureFromPreState(state.Iface, feature, state.PreState.EthtoolK)
			status := "ok"
			msg := ""
			if err != nil {
				status = "failed"
				msg = err.Error()
			}
			records = append(records, CommandRecord{
				Index:    entry.Index,
				ActionID: "rollback-" + action.ID,
				Command:  []string{"restore ethtool feature from pre-state"},
				Status:   status,
				Error:    msg,
			})
			continue
		}
		if action.Kind == "systemd-profile" {
			err := e.restoreServiceProfileDropIn(state.ServiceDropIn)
			status := "ok"
			msg := ""
			if err != nil {
				status = "failed"
				msg = err.Error()
			}
			records = append(records, CommandRecord{
				Index:    entry.Index,
				ActionID: "rollback-" + action.ID,
				Command:  []string{"restore systemd drop-in state"},
				Status:   status,
				Error:    msg,
			})
			continue
		}
		if len(action.RollbackExec) == 0 {
			continue
		}
		err := e.runBestEffort(action.RollbackExec, 20*time.Second)
		status := "ok"
		msg := ""
		if err != nil {
			status = "failed"
			msg = err.Error()
		}
		records = append(records, CommandRecord{
			Index:    entry.Index,
			ActionID: "rollback-" + action.ID,
			Command:  action.RollbackExec,
			Status:   status,
			Error:    msg,
		})
	}
	return records
}

func restoreYAMLFromBackup(backup *YAMLBackup) error {
	if backup == nil {
		return nil
	}
	raw, err := os.ReadFile(backup.BackupPath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(backup.SHA256) != "" {
		sum := sha256.Sum256(raw)
		actual := fmt.Sprintf("%x", sum)
		if !strings.EqualFold(strings.TrimSpace(backup.SHA256), actual) {
			return fmt.Errorf("backup sha256 mismatch: state=%s actual=%s", backup.SHA256, actual)
		}
	}
	mode := os.FileMode(0640)
	if stat, statErr := os.Stat(backup.OriginalPath); statErr == nil {
		mode = stat.Mode().Perm()
	}
	return os.WriteFile(backup.OriginalPath, raw, mode)
}

var serviceProfileDropInPath = "/etc/systemd/system/suricata.service.d/surituner-profile.conf"

func (e *Executor) applyServiceProfileDropIn(action PlanAction) (FileBackup, error) {
	execStart := metadataString(action.Metadata, "exec_start", "")
	if strings.TrimSpace(execStart) == "" {
		return FileBackup{}, errors.New("missing systemd ExecStart metadata")
	}
	if err := validateSystemdExecStart(execStart); err != nil {
		return FileBackup{}, err
	}
	backup, err := backupFileForReplace(serviceProfileDropInPath)
	if err != nil {
		return FileBackup{}, err
	}
	content := renderServiceProfileDropIn(execStart)
	if err := os.MkdirAll(filepath.Dir(serviceProfileDropInPath), 0755); err != nil {
		return backup, fmt.Errorf("create systemd drop-in dir: %w", err)
	}
	if err := os.WriteFile(serviceProfileDropInPath, []byte(content), 0644); err != nil {
		return backup, fmt.Errorf("write systemd drop-in: %w", err)
	}
	if _, err := e.Runner.Run([]string{"systemctl", "daemon-reload"}, 20*time.Second, false); err != nil {
		_ = restoreFileBackup(&backup)
		return backup, fmt.Errorf("systemctl daemon-reload after drop-in write failed: %w", err)
	}
	return backup, nil
}

func (e *Executor) restoreServiceProfileDropIn(backup *FileBackup) error {
	if err := restoreFileBackup(backup); err != nil {
		return err
	}
	if err := e.runBestEffort([]string{"systemctl", "daemon-reload"}, 20*time.Second); err != nil {
		return fmt.Errorf("systemctl daemon-reload after drop-in restore failed: %w", err)
	}
	return nil
}

func renderServiceProfileDropIn(execStart string) string {
	return fmt.Sprintf(`[Service]
ExecStart=
ExecStart=%s
TimeoutStartSec=5min
`, strings.TrimSpace(execStart))
}

func validateSystemdExecStart(execStart string) error {
	execStart = strings.TrimSpace(execStart)
	if execStart == "" {
		return errors.New("empty systemd ExecStart")
	}
	if strings.ContainsAny(execStart, "\r\n") {
		return errors.New("systemd ExecStart must be a single line")
	}
	if !strings.HasPrefix(execStart, "/") {
		return errors.New("systemd ExecStart must start with an absolute executable path")
	}
	return nil
}

func backupFileForReplace(path string) (FileBackup, error) {
	backup := FileBackup{
		OriginalPath: path,
		SavedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return backup, nil
		}
		return backup, fmt.Errorf("read existing file for backup: %w", err)
	}
	sum := sha256.Sum256(raw)
	backup.Existed = true
	backup.SHA256 = fmt.Sprintf("%x", sum)
	backup.SizeBytes = int64(len(raw))
	backupDir := filepath.Join(filepath.Dir(path), ".surituner-backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return backup, fmt.Errorf("create service backup dir: %w", err)
	}
	backup.BackupPath = filepath.Join(backupDir, fmt.Sprintf("%s.%d.bak", filepath.Base(path), time.Now().UnixNano()))
	if err := os.WriteFile(backup.BackupPath, raw, 0600); err != nil {
		return backup, fmt.Errorf("write service drop-in backup: %w", err)
	}
	return backup, nil
}

func restoreFileBackup(backup *FileBackup) error {
	if backup == nil {
		return nil
	}
	if !backup.Existed {
		if err := os.Remove(backup.OriginalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove generated file %s: %w", backup.OriginalPath, err)
		}
		return nil
	}
	raw, err := os.ReadFile(backup.BackupPath)
	if err != nil {
		return fmt.Errorf("read backup %s: %w", backup.BackupPath, err)
	}
	if strings.TrimSpace(backup.SHA256) != "" {
		sum := sha256.Sum256(raw)
		actual := fmt.Sprintf("%x", sum)
		if !strings.EqualFold(strings.TrimSpace(backup.SHA256), actual) {
			return fmt.Errorf("backup sha256 mismatch: state=%s actual=%s", backup.SHA256, actual)
		}
	}
	return os.WriteFile(backup.OriginalPath, raw, 0644)
}

func (e *Executor) capturePreState(iface string) PreState {
	sysctlKeys := []string{
		"net.core.rmem_max",
		"net.core.wmem_max",
		"net.core.netdev_max_backlog",
		"vm.nr_hugepages",
	}
	sysctlMap := map[string]string{}
	for _, key := range sysctlKeys {
		res, err := e.Runner.Run([]string{"sysctl", "-n", key}, 3*time.Second, true)
		if err == nil {
			sysctlMap[key] = strings.TrimSpace(res.Stdout)
		}
	}
	irqMap := readIRQAffinityForIface(iface)
	irqbalance := "unknown"
	if res, err := e.Runner.Run([]string{"systemctl", "is-active", "irqbalance"}, 3*time.Second, true); err == nil {
		irqbalance = strings.TrimSpace(res.Stdout)
	}
	systemdStatus := "unknown"
	if res, err := e.Runner.Run([]string{"systemctl", "is-active", "suricata.service"}, 3*time.Second, true); err == nil {
		systemdStatus = strings.TrimSpace(res.Stdout)
	}
	pre := PreState{
		Sysctl:           sysctlMap,
		IRQAffinity:      irqMap,
		IRQBalanceStatus: irqbalance,
		Promisc:          false,
		HugePages:        readHugePages(),
		NodeHugePages:    readNodeHugePages(),
		SystemdStatus:    systemdStatus,
	}
	if res, err := e.Runner.Run([]string{"ethtool", "-k", iface}, 6*time.Second, true); err == nil {
		pre.EthtoolK = res.Stdout
	}
	if res, err := e.Runner.Run([]string{"ethtool", "-g", iface}, 6*time.Second, true); err == nil {
		pre.EthtoolG = res.Stdout
	}
	if res, err := e.Runner.Run([]string{"ethtool", "-l", iface}, 6*time.Second, true); err == nil {
		pre.EthtoolL = res.Stdout
	}
	if res, err := e.Runner.Run([]string{"ip", "-o", "link", "show", iface}, 5*time.Second, true); err == nil {
		pre.Promisc = strings.Contains(res.Stdout, "PROMISC")
	}
	return pre
}

func readHugePages() map[string]string {
	out := map[string]string{
		"HugePages_Total": "unknown",
		"HugePages_Free":  "unknown",
	}
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "HugePages_Total:") {
			out["HugePages_Total"] = strings.TrimSpace(strings.TrimPrefix(line, "HugePages_Total:"))
		}
		if strings.HasPrefix(line, "HugePages_Free:") {
			out["HugePages_Free"] = strings.TrimSpace(strings.TrimPrefix(line, "HugePages_Free:"))
		}
	}
	return out
}

func readNodeHugePages() map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir("/sys/devices/system/node")
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "node") {
			continue
		}
		nodeName := entry.Name()
		path := filepath.Join("/sys/devices/system/node", nodeName, "hugepages", "hugepages-2048kB", "nr_hugepages")
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			continue
		}
		out[nodeName] = strings.TrimSpace(string(raw))
	}
	return out
}

func readIRQAffinityForIface(iface string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile("/proc/interrupts")
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, iface) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		irq := strings.TrimSuffix(fields[0], ":")
		path := filepath.Join("/proc/irq", irq, "smp_affinity")
		if value, err := os.ReadFile(path); err == nil {
			out[irq] = strings.TrimSpace(string(value))
		}
	}
	return out
}

func (e *Executor) applyIRQAffinity(snapshot SystemSnapshot, current map[string]string) error {
	if len(current) == 0 {
		return errors.New("no IRQ affinity entries captured for interface")
	}
	targetCPUs := pickLocalNUMACPUs(snapshot)
	if targetCPUs == "" {
		targetCPUs = "0"
	}
	for irq := range current {
		path := filepath.Join("/proc/irq", irq, "smp_affinity_list")
		if err := os.WriteFile(path, []byte(targetCPUs), 0644); err != nil {
			return fmt.Errorf("set IRQ %s affinity to %s: %w", irq, targetCPUs, err)
		}
	}
	return nil
}

func (e *Executor) restoreIRQAffinity(previous map[string]string) error {
	if len(previous) == 0 {
		return errors.New("no IRQ affinity pre-state captured")
	}
	for irq, value := range previous {
		path := irqAffinityRestorePath(irq, value)
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			return fmt.Errorf("restore IRQ %s affinity via %s: %w", irq, filepath.Base(path), err)
		}
	}
	return nil
}

func irqAffinityRestorePath(irq string, value string) string {
	fileName := "smp_affinity_list"
	if looksLikeIRQAffinityHexMask(value) {
		fileName = "smp_affinity"
	}
	return filepath.Join("/proc/irq", irq, fileName)
}

func looksLikeIRQAffinityHexMask(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	hasHexDigit := false
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			hasHexDigit = true
		case r >= 'a' && r <= 'f':
			hasHexDigit = true
		case r >= 'A' && r <= 'F':
			hasHexDigit = true
		case r == ',':
		default:
			return false
		}
	}
	return hasHexDigit
}

func pickLocalNUMACPUs(snapshot SystemSnapshot) string {
	nodeID := snapshot.NIC.NUMANode
	if nodeID < 0 {
		nodeID = 0
	}
	key := strconv.Itoa(nodeID)
	cpus := snapshot.CPU.CoresByNUMA[key]
	if len(cpus) == 0 {
		cpus = snapshot.CPU.CoresByNUMA["0"]
	}
	if len(cpus) == 0 {
		return ""
	}
	var out []string
	for _, cpu := range cpus {
		out = append(out, strconv.Itoa(cpu))
	}
	return strings.Join(out, ",")
}

func (e *Executor) restoreRingBuffers(iface string, ethtoolG string) error {
	rx, tx, ok := parseCurrentRing(ethtoolG)
	if !ok {
		return errors.New("unable to parse ring settings from pre-state")
	}
	return e.runBestEffort([]string{"ethtool", "-G", iface, "rx", strconv.Itoa(rx), "tx", strconv.Itoa(tx)}, 10*time.Second)
}

func parseCurrentRing(raw string) (int, int, bool) {
	lines := strings.Split(raw, "\n")
	inCurrent := false
	rx := -1
	tx := -1
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "current hardware settings") {
			inCurrent = true
			continue
		}
		if !inCurrent {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(trimmed), "RX:") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				if value, err := strconv.Atoi(fields[1]); err == nil {
					rx = value
				}
			}
		}
		if strings.HasPrefix(strings.ToUpper(trimmed), "TX:") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				if value, err := strconv.Atoi(fields[1]); err == nil {
					tx = value
				}
			}
		}
	}
	if rx <= 0 || tx <= 0 {
		return 0, 0, false
	}
	return rx, tx, true
}

func (e *Executor) restoreEthtoolFeatureFromPreState(iface string, feature string, ethtoolK string) error {
	if strings.TrimSpace(feature) == "" {
		return errors.New("missing ethtool feature name in action metadata")
	}
	desired, ok := parseEthtoolFeatureState(ethtoolK, feature)
	if !ok {
		return fmt.Errorf("unable to parse %s from pre-state ethtool -k output", feature)
	}
	return e.runBestEffort([]string{"ethtool", "-K", iface, feature, desired}, 10*time.Second)
}

func parseEthtoolFeatureState(raw string, feature string) (string, bool) {
	feature = strings.ToLower(strings.TrimSpace(feature))
	if strings.TrimSpace(raw) == "" || feature == "" {
		return "", false
	}
	labels := map[string][]string{
		"gro": {"generic-receive-offload:", "gro:"},
		"lro": {"large-receive-offload:", "lro:"},
	}
	candidates := labels[feature]
	if len(candidates) == 0 {
		candidates = []string{feature + ":"}
	}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		for _, candidate := range candidates {
			if !strings.HasPrefix(line, candidate) {
				continue
			}
			rest := strings.TrimSpace(strings.TrimPrefix(line, candidate))
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				return "", false
			}
			value := fields[0]
			if value == "on" || value == "off" {
				return value, true
			}
			return "", false
		}
	}
	return "", false
}

func metadataString(meta map[string]interface{}, key string, fallback string) string {
	if meta == nil {
		return fallback
	}
	raw, ok := meta[key]
	if !ok {
		return fallback
	}
	switch typed := raw.(type) {
	case string:
		return typed
	default:
		return fallback
	}
}

func featureFromAction(action PlanAction) string {
	feature := metadataString(action.Metadata, "feature", "")
	if strings.TrimSpace(feature) != "" {
		return feature
	}
	if len(action.ApplyExec) >= 4 && action.ApplyExec[0] == "ethtool" && action.ApplyExec[1] == "-K" {
		return action.ApplyExec[3]
	}
	return ""
}

func applyNodeHugepagesFromAction(action PlanAction) error {
	node := metadataInt(action.Metadata, "node", 0)
	value := metadataInt(action.Metadata, "value", 1024)
	path := fmt.Sprintf("/sys/devices/system/node/node%d/hugepages/hugepages-2048kB/nr_hugepages", node)
	return os.WriteFile(path, []byte(strconv.Itoa(value)), 0644)
}

func restoreNodeHugePages(previous map[string]string) error {
	if len(previous) == 0 {
		return errors.New("no per-node hugepages pre-state captured")
	}
	for nodeName, value := range previous {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		path := filepath.Join("/sys/devices/system/node", nodeName, "hugepages", "hugepages-2048kB", "nr_hugepages")
		if err := os.WriteFile(path, []byte(value), 0644); err != nil {
			return fmt.Errorf("restore %s hugepages: %w", nodeName, err)
		}
	}
	return nil
}

func metadataInt(meta map[string]interface{}, key string, fallback int) int {
	if meta == nil {
		return fallback
	}
	value, ok := meta[key]
	if !ok {
		return fallback
	}
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return fallback
	}
}

func (e *Executor) restorePreStateBestEffort(state StateFile) []CommandRecord {
	var records []CommandRecord
	if len(state.PreState.IRQAffinity) > 0 {
		err := e.restoreIRQAffinity(state.PreState.IRQAffinity)
		records = append(records, CommandRecord{
			Index:    -1,
			ActionID: "prestate-irq-affinity",
			Command:  []string{"restore irq affinity from pre-state"},
			Status:   statusFromErr(err),
			Error:    errString(err),
		})
	}
	if state.PreState.EthtoolG != "" {
		err := e.restoreRingBuffers(state.Iface, state.PreState.EthtoolG)
		records = append(records, CommandRecord{
			Index:    -1,
			ActionID: "prestate-ring-buffers",
			Command:  []string{"restore ring buffers from pre-state"},
			Status:   statusFromErr(err),
			Error:    errString(err),
		})
	}

	promiscCmd := promiscRestoreCommand(state.Iface, state.PreState.Promisc)
	promiscErr := e.runBestEffort(promiscCmd, 5*time.Second)
	records = append(records, CommandRecord{
		Index:    -1,
		ActionID: "prestate-promisc",
		Command:  promiscCmd,
		Status:   statusFromErr(promiscErr),
		Error:    errString(promiscErr),
	})

	var sysctlKeys []string
	for key := range state.PreState.Sysctl {
		sysctlKeys = append(sysctlKeys, key)
	}
	sort.Strings(sysctlKeys)
	for _, key := range sysctlKeys {
		value := state.PreState.Sysctl[key]
		cmd := []string{"sysctl", "-w", fmt.Sprintf("%s=%s", key, value)}
		err := e.runBestEffort(cmd, 5*time.Second)
		records = append(records, CommandRecord{
			Index:    -1,
			ActionID: "prestate-sysctl-" + key,
			Command:  cmd,
			Status:   statusFromErr(err),
			Error:    errString(err),
		})
	}

	if len(state.PreState.NodeHugePages) > 0 {
		err := restoreNodeHugePages(state.PreState.NodeHugePages)
		records = append(records, CommandRecord{
			Index:    -1,
			ActionID: "prestate-node-hugepages",
			Command:  []string{"restore per-node hugepages from pre-state"},
			Status:   statusFromErr(err),
			Error:    errString(err),
		})
	}

	if state.PreState.IRQBalanceStatus == "active" || state.PreState.IRQBalanceStatus == "inactive" {
		serviceCmd := []string{"systemctl", "start", "irqbalance"}
		if state.PreState.IRQBalanceStatus == "inactive" {
			serviceCmd = []string{"systemctl", "stop", "irqbalance"}
		}
		err := e.runBestEffort(serviceCmd, 5*time.Second)
		records = append(records, CommandRecord{
			Index:    -1,
			ActionID: "prestate-irqbalance",
			Command:  serviceCmd,
			Status:   statusFromErr(err),
			Error:    errString(err),
		})
	}

	if state.PreState.SystemdStatus == "active" || state.PreState.SystemdStatus == "inactive" {
		serviceCmd := []string{"systemctl", "start", "suricata.service"}
		if state.PreState.SystemdStatus == "inactive" {
			serviceCmd = []string{"systemctl", "stop", "suricata.service"}
		}
		err := e.runBestEffort(serviceCmd, 10*time.Second)
		records = append(records, CommandRecord{
			Index:    -1,
			ActionID: "prestate-suricata-service",
			Command:  serviceCmd,
			Status:   statusFromErr(err),
			Error:    errString(err),
		})
	}
	return records
}

func promiscRestoreCommand(iface string, previous bool) []string {
	promiscValue := "off"
	if previous {
		promiscValue = "on"
	}
	return []string{"ip", "link", "set", "dev", iface, "promisc", promiscValue}
}

func (e *Executor) applyNFQRule(action PlanAction) (bool, error) {
	backend := metadataString(action.Metadata, "firewall_backend", "iptables")
	switch backend {
	case "iptables":
		checkCmd := iptablesCheckCommand(action.ApplyExec)
		res, err := e.Runner.Run(checkCmd, 5*time.Second, true)
		if err != nil {
			return false, err
		}
		if res.ExitCode == 0 {
			return false, nil
		}
		if _, err := e.Runner.Run(action.ApplyExec, 10*time.Second, false); err != nil {
			return false, err
		}
		return true, nil
	case "nftables":
		handle, err := e.findNFQNftRuleHandle(action)
		if err != nil {
			return false, err
		}
		if handle != "" {
			return false, nil
		}
		if _, err := e.Runner.Run(action.ApplyExec, 10*time.Second, false); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported NFQ firewall backend: %s", backend)
	}
}

func (e *Executor) rollbackNFQRule(action PlanAction) ([]string, error) {
	backend := metadataString(action.Metadata, "firewall_backend", "iptables")
	switch backend {
	case "iptables":
		checkCmd := iptablesCheckCommand(action.ApplyExec)
		res, err := e.Runner.Run(checkCmd, 5*time.Second, true)
		if err != nil {
			return checkCmd, err
		}
		if res.ExitCode != 0 {
			return checkCmd, nil
		}
		return action.RollbackExec, e.runBestEffort(action.RollbackExec, 10*time.Second)
	case "nftables":
		handle, err := e.findNFQNftRuleHandle(action)
		if err != nil {
			return []string{"nft", "-a", "list", "chain", "inet", "filter", "forward"}, err
		}
		if handle == "" {
			return []string{"nft", "-a", "list", "chain", "inet", "filter", "forward"}, nil
		}
		cmd := []string{"nft", "delete", "rule", "inet", "filter", "forward", "handle", handle}
		return cmd, e.runBestEffort(cmd, 10*time.Second)
	default:
		return nil, fmt.Errorf("unsupported NFQ firewall backend: %s", backend)
	}
}

func iptablesCheckCommand(applyExec []string) []string {
	check := append([]string(nil), applyExec...)
	if len(check) > 1 && check[0] == "iptables" {
		check[1] = "-C"
	}
	return check
}

func (e *Executor) findNFQNftRuleHandle(action PlanAction) (string, error) {
	comment := metadataString(action.Metadata, "nft_comment", nfqNftRuleComment)
	cmd := []string{"nft", "-a", "list", "chain", "inet", "filter", "forward"}
	res, err := e.Runner.Run(cmd, 5*time.Second, true)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", commandResultError(res, nil)
	}
	handle, _ := parseNFQNftRuleHandle(res.Stdout, comment)
	return handle, nil
}

func parseNFQNftRuleHandle(raw string, comment string) (string, bool) {
	comment = strings.TrimSpace(comment)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "queue num 0") || !strings.Contains(line, comment) {
			continue
		}
		fields := strings.Fields(line)
		for i, field := range fields {
			if field == "handle" && i+1 < len(fields) {
				return strings.Trim(fields[i+1], "\"'"), true
			}
		}
	}
	return "", false
}

func validateDPDKBindAction(action PlanAction) error {
	if len(action.ApplyExec) < 3 || action.ApplyExec[0] != "dpdk-devbind.py" {
		return errors.New("invalid dpdk bind apply command")
	}
	driver := dpdkRollbackDriver(action.RollbackExec)
	if driver == "" {
		return errors.New("dpdk bind rollback driver is missing")
	}
	if strings.ContainsAny(driver, "<> \t\r\n") {
		return fmt.Errorf("dpdk bind rollback driver is invalid: %s", driver)
	}
	if strings.EqualFold(driver, "vfio-pci") {
		return errors.New("dpdk bind rollback driver must be the previous kernel driver, not vfio-pci")
	}
	return nil
}

func dpdkRollbackDriver(rollbackExec []string) string {
	for _, arg := range rollbackExec {
		if strings.HasPrefix(arg, "--bind=") {
			return strings.TrimSpace(strings.TrimPrefix(arg, "--bind="))
		}
	}
	return ""
}

func statusFromErr(err error) string {
	if err != nil {
		return "failed"
	}
	return "ok"
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (e *Executor) runBestEffort(args []string, timeout time.Duration) error {
	res, err := e.Runner.Run(args, timeout, true)
	return commandResultError(res, err)
}

func commandResultError(res CommandResult, err error) error {
	if err != nil {
		return err
	}
	if res.ExitCode == 0 {
		return nil
	}
	details := strings.TrimSpace(res.Stderr)
	if details == "" {
		details = strings.TrimSpace(res.Stdout)
	}
	cmd := strings.Join(res.Args, " ")
	if details != "" {
		return fmt.Errorf("command failed (exit=%d): %s: %s", res.ExitCode, cmd, details)
	}
	return fmt.Errorf("command failed (exit=%d): %s", res.ExitCode, cmd)
}

func failedCommandRecords(records []CommandRecord) []string {
	var out []string
	for _, record := range records {
		if record.Status != "failed" {
			continue
		}
		if record.Error != "" {
			out = append(out, fmt.Sprintf("%s: %s", record.ActionID, record.Error))
			continue
		}
		out = append(out, fmt.Sprintf("%s failed", record.ActionID))
	}
	return out
}

func askConfirmation(input io.Reader, output io.Writer, prompt string) bool {
	fmt.Fprint(output, prompt)
	reader := bufio.NewReader(input)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

func hasHighOrCritical(actions []PlanAction) bool {
	for _, action := range actions {
		if action.RiskLevel == RiskHigh || action.RiskLevel == RiskCritical {
			return true
		}
	}
	return false
}

func hasAction(actions []PlanAction, id string) bool {
	for _, action := range actions {
		if action.ID == id {
			return true
		}
	}
	return false
}

func applyRequiresSystemd(actions []PlanAction, force bool) bool {
	for _, action := range actions {
		if action.BlockedByGuardrail && !force {
			continue
		}
		if action.ID == "yaml-tuning" || action.Kind == "systemd-profile" {
			return true
		}
	}
	return false
}

func (e *Executor) ensureSystemctlAvailable() error {
	if _, err := e.Runner.Run([]string{"systemctl", "--version"}, 5*time.Second, false); err != nil {
		return fmt.Errorf("systemctl unavailable or not functional: %w", err)
	}
	return nil
}

func suricataValidationTimeout(enabledRules int) time.Duration {
	switch {
	case enabledRules >= 30000:
		return 5 * time.Minute
	case enabledRules >= 10000:
		return 3 * time.Minute
	case enabledRules >= 5000:
		return 2 * time.Minute
	default:
		return 90 * time.Second
	}
}

func suricataServiceRestartTimeout(enabledRules int) time.Duration {
	switch {
	case enabledRules >= 30000:
		return 3 * time.Minute
	case enabledRules >= 10000:
		return 2 * time.Minute
	default:
		return 90 * time.Second
	}
}

func buildValidationDiag(err error, res CommandResult) string {
	var parts []string
	if err != nil {
		parts = append(parts, strings.TrimSpace(err.Error()))
	}
	if stderr := strings.TrimSpace(res.Stderr); stderr != "" {
		parts = append(parts, stderr)
	}
	if stdout := strings.TrimSpace(res.Stdout); stdout != "" {
		parts = append(parts, stdout)
	}
	return strings.Join(dedupeStrings(parts), " | ")
}

func (e *Executor) buildServiceFailureDiag(err error, res CommandResult) string {
	parts := []string{buildValidationDiag(err, res)}
	if status, statusErr := e.Runner.Run([]string{"systemctl", "status", "suricata.service", "--no-pager", "-l"}, 15*time.Second, true); statusErr == nil {
		if text := strings.TrimSpace(status.Stdout + "\n" + status.Stderr); text != "" {
			parts = append(parts, "systemctl status:\n"+lastNLines(text, 45))
		}
	}
	if raw, readErr := os.ReadFile("/var/log/suricata/suricata.log"); readErr == nil {
		if text := strings.TrimSpace(string(raw)); text != "" {
			parts = append(parts, "suricata.log tail:\n"+lastNLines(text, 80))
		}
	}
	return strings.Join(dedupeStrings(parts), "\n\n")
}

func lastNLines(text string, n int) string {
	if n <= 0 {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

func (e *Executor) updateState(path string, state StateFile) error {
	if err := e.StateStore.Update(path, state); err != nil {
		return fmt.Errorf("update state file %s: %w", path, err)
	}
	return nil
}

func requireRoot() error {
	if getEUID() != 0 {
		return errors.New("this command requires root privileges")
	}
	return nil
}
