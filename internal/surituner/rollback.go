package surituner

import (
	"errors"
	"fmt"
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

	result := RollbackResult{
		StatePath: resolvedStatePath,
	}

	rollbackRecords := e.rollbackApplied(state, actionsByID)
	state.Rollback = append(state.Rollback, rollbackRecords...)
	yamlAttempted := false
	for _, record := range rollbackRecords {
		if record.Status == "ok" {
			result.Executed++
		}
		if record.Status == "failed" {
			if record.Error != "" {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", record.ActionID, record.Error))
			} else {
				result.Errors = append(result.Errors, fmt.Sprintf("%s failed", record.ActionID))
			}
		}
		if record.ActionID == "rollback-yaml-tuning" {
			yamlAttempted = true
			if record.Status == "ok" {
				result.RestoredYAML = true
			}
		}
	}

	if state.YAMLBackup != nil && !yamlAttempted && !result.RestoredYAML {
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
	if result.RestoredYAML {
		serviceRecords := e.restoreSuricataServiceAfterYAMLRollback(state)
		state.Rollback = append(state.Rollback, serviceRecords...)
		for _, record := range serviceRecords {
			if record.Status == "ok" {
				result.Executed++
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", record.ActionID, record.Error))
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
