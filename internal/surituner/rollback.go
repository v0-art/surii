package surituner

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

type RollbackResult struct {
	StatePath    string
	RestoredYAML bool
	Executed     int
	Errors       []string
}

func (e *Executor) Rollback(statePath string) (RollbackResult, error) {
	if err := requireRoot(); err != nil {
		return RollbackResult{}, err
	}
	resolvedStatePath, err := e.StateStore.ResolvePath(statePath)
	if err != nil {
		return RollbackResult{}, err
	}
	state, err := e.StateStore.Load(resolvedStatePath)
	if err != nil {
		return RollbackResult{}, err
	}
	if err := ValidateHostFingerprint(state.HostFingerprint); err != nil {
		return RollbackResult{}, err
	}

	actionsByID := map[string]PlanAction{}
	for _, action := range state.PlanActions {
		actionsByID[action.ID] = action
	}

	applied := append([]CommandRecord(nil), state.Applied...)
	sort.SliceStable(applied, func(i, j int) bool {
		return applied[i].Index > applied[j].Index
	})

	result := RollbackResult{
		StatePath: resolvedStatePath,
	}
	yamlRestored := false
	yamlAttempted := false

	for _, record := range applied {
		action, ok := actionsByID[record.ActionID]
		if !ok {
			continue
		}
		if action.Kind == "ip-link" {
			cmd := promiscRestoreCommand(state.Iface, state.PreState.Promisc)
			err := e.runBestEffort(cmd, 5*time.Second)
			rollbackRecord := CommandRecord{
				Index:    record.Index,
				ActionID: "rollback-" + action.ID,
				Command:  cmd,
				Status:   "ok",
			}
			if err != nil {
				rollbackRecord.Status = "failed"
				rollbackRecord.Error = err.Error()
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", action.ID, err))
			} else {
				result.Executed++
			}
			state.Rollback = append(state.Rollback, rollbackRecord)
			continue
		}
		if action.Kind == "nfq-rules" {
			cmd, err := e.rollbackNFQRule(action)
			rollbackRecord := CommandRecord{
				Index:    record.Index,
				ActionID: "rollback-" + action.ID,
				Command:  cmd,
				Status:   "ok",
			}
			if err != nil {
				rollbackRecord.Status = "failed"
				rollbackRecord.Error = err.Error()
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", action.ID, err))
			} else {
				result.Executed++
			}
			state.Rollback = append(state.Rollback, rollbackRecord)
			continue
		}
		if len(action.RollbackExec) == 0 {
			if action.Kind == "yaml" {
				yamlAttempted = true
				err := restoreYAMLFromBackup(state.YAMLBackup)
				rollbackRecord := CommandRecord{
					Index:    record.Index,
					ActionID: "rollback-" + action.ID,
					Command:  []string{"restore suricata.yaml from backup"},
					Status:   "ok",
				}
				if err != nil {
					rollbackRecord.Status = "failed"
					rollbackRecord.Error = err.Error()
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", action.ID, err))
				} else {
					yamlRestored = true
					result.RestoredYAML = true
					result.Executed++
				}
				state.Rollback = append(state.Rollback, rollbackRecord)
				continue
			}
			if action.Kind == "irq" {
				err := e.restoreIRQAffinity(state.PreState.IRQAffinity)
				rollbackRecord := CommandRecord{
					Index:    record.Index,
					ActionID: "rollback-" + action.ID,
					Command:  []string{"restore irq affinity map"},
					Status:   "ok",
				}
				if err != nil {
					rollbackRecord.Status = "failed"
					rollbackRecord.Error = err.Error()
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", action.ID, err))
				} else {
					result.Executed++
				}
				state.Rollback = append(state.Rollback, rollbackRecord)
			}
			if action.Kind == "ethtool-g" {
				err := e.restoreRingBuffers(state.Iface, state.PreState.EthtoolG)
				rollbackRecord := CommandRecord{
					Index:    record.Index,
					ActionID: "rollback-" + action.ID,
					Command:  []string{"restore ring buffers from state"},
					Status:   "ok",
				}
				if err != nil {
					rollbackRecord.Status = "failed"
					rollbackRecord.Error = err.Error()
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", action.ID, err))
				} else {
					result.Executed++
				}
				state.Rollback = append(state.Rollback, rollbackRecord)
			}
			if action.Kind == "ethtool-k" {
				feature := featureFromAction(action)
				err := e.restoreEthtoolFeatureFromPreState(state.Iface, feature, state.PreState.EthtoolK)
				rollbackRecord := CommandRecord{
					Index:    record.Index,
					ActionID: "rollback-" + action.ID,
					Command:  []string{"restore ethtool feature from pre-state"},
					Status:   "ok",
				}
				if err != nil {
					rollbackRecord.Status = "failed"
					rollbackRecord.Error = err.Error()
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", action.ID, err))
				} else {
					result.Executed++
				}
				state.Rollback = append(state.Rollback, rollbackRecord)
			}
			if action.Kind == "node-hugepages" {
				err := restoreNodeHugePages(state.PreState.NodeHugePages)
				rollbackRecord := CommandRecord{
					Index:    record.Index,
					ActionID: "rollback-" + action.ID,
					Command:  []string{"restore per-node hugepages from pre-state"},
					Status:   "ok",
				}
				if err != nil {
					rollbackRecord.Status = "failed"
					rollbackRecord.Error = err.Error()
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", action.ID, err))
				} else {
					result.Executed++
				}
				state.Rollback = append(state.Rollback, rollbackRecord)
			}
			if action.Kind == "systemd-profile" {
				err := e.restoreServiceProfileDropIn(state.ServiceDropIn)
				rollbackRecord := CommandRecord{
					Index:    record.Index,
					ActionID: "rollback-" + action.ID,
					Command:  []string{"restore systemd drop-in state"},
					Status:   "ok",
				}
				if err != nil {
					rollbackRecord.Status = "failed"
					rollbackRecord.Error = err.Error()
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", action.ID, err))
				} else {
					result.Executed++
				}
				state.Rollback = append(state.Rollback, rollbackRecord)
			}
			continue
		}
		err := e.runBestEffort(action.RollbackExec, 20*time.Second)
		rollbackRecord := CommandRecord{
			Index:    record.Index,
			ActionID: "rollback-" + action.ID,
			Command:  action.RollbackExec,
			Status:   "ok",
		}
		if err != nil {
			rollbackRecord.Status = "failed"
			rollbackRecord.Error = err.Error()
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", action.ID, err))
		} else {
			result.Executed++
		}
		state.Rollback = append(state.Rollback, rollbackRecord)
	}

	if state.YAMLBackup != nil && !yamlAttempted && !yamlRestored {
		err := restoreYAMLFromBackup(state.YAMLBackup)
		rollbackRecord := CommandRecord{
			Index:    -1,
			ActionID: "rollback-yaml-legacy",
			Command:  []string{"restore suricata.yaml from backup"},
			Status:   "ok",
		}
		if err != nil {
			rollbackRecord.Status = "failed"
			rollbackRecord.Error = err.Error()
			result.Errors = append(result.Errors, fmt.Sprintf("yaml legacy restore failed: %v", err))
		} else {
			result.RestoredYAML = true
			result.Executed++
		}
		state.Rollback = append(state.Rollback, rollbackRecord)
	}

	preStateRecords := e.restorePreStateBestEffort(state)
	state.Rollback = append(state.Rollback, preStateRecords...)
	for _, record := range preStateRecords {
		if record.Status == "ok" {
			result.Executed++
			continue
		}
		if record.Error != "" {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", record.ActionID, record.Error))
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("%s failed", record.ActionID))
		}
	}

	if len(result.Errors) > 0 {
		state.Status = "rollback_partial"
		state.Error = "rollback finished with errors"
		if updateErr := e.updateState(resolvedStatePath, state); updateErr != nil {
			return result, fmt.Errorf("%s; state update failed: %w", state.Error, updateErr)
		}
		return result, errors.New(state.Error)
	}
	state.Status = "rolled_back"
	state.Error = ""
	if updateErr := e.updateState(resolvedStatePath, state); updateErr != nil {
		return result, updateErr
	}
	return result, nil
}
