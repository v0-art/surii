package surituner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRollback_RequiresRoot(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 1000 }

	ex := NewExecutor(&mockRunner{}, filepath.Join(t.TempDir(), "state"))
	_, err := ex.Rollback("latest")
	if err == nil {
		t.Fatalf("expected root privileges error for rollback")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "root") {
		t.Fatalf("expected root-related error, got %v", err)
	}
}

func TestRollback_RestoresAppliedActionsInReverseOrderIncludingYAML(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 0 }

	dir := t.TempDir()
	configPath := filepath.Join(dir, "suricata.yaml")
	backupPath := filepath.Join(dir, "suricata.yaml.bak")
	if err := os.WriteFile(configPath, []byte("runmode: workers\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(backupPath, []byte("runmode: autofp\n"), 0600); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	ex := NewExecutor(&mockRunner{}, filepath.Join(dir, "state"))
	state := StateFile{
		Version:    "v1",
		Iface:      "eth0",
		ConfigPath: configPath,
		YAMLBackup: &YAMLBackup{
			OriginalPath: configPath,
			BackupPath:   backupPath,
		},
		PlanActions: []PlanAction{
			{ID: "yaml-tuning", Kind: "yaml"},
			{ID: "sysctl-net-buffers", Kind: "sysctl", RollbackExec: []string{"sysctl", "-w", "net.core.rmem_max=1"}},
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "yaml-tuning", Status: "ok"},
			{Index: 1, ActionID: "sysctl-net-buffers", Status: "ok"},
		},
		Status: "applied",
	}
	statePath, err := ex.StateStore.Save(state)
	if err != nil {
		t.Fatalf("save state: %v", err)
	}

	result, err := ex.Rollback(statePath)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !result.RestoredYAML {
		t.Fatalf("expected YAML restore")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(raw) != "runmode: autofp\n" {
		t.Fatalf("expected config restored from backup, got %q", string(raw))
	}
	loaded, err := ex.StateStore.Load(statePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(loaded.Rollback) < 2 {
		t.Fatalf("expected rollback records, got %d", len(loaded.Rollback))
	}
	if loaded.Rollback[0].ActionID != "rollback-sysctl-net-buffers" {
		t.Fatalf("expected sysctl rollback first, got %s", loaded.Rollback[0].ActionID)
	}
	if loaded.Rollback[1].ActionID != "rollback-yaml-tuning" {
		t.Fatalf("expected yaml rollback second, got %s", loaded.Rollback[1].ActionID)
	}
}
