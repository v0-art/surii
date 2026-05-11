package surituner

import (
	"os"
	"testing"
)

func TestStateStore_SaveLoadLatest(t *testing.T) {
	dir := t.TempDir()
	store := NewStateStore(dir)
	state := StateFile{
		Version: "v1",
		Status:  "pending",
	}
	path, err := store.Save(state)
	if err != nil {
		t.Fatalf("save state: %v", err)
	}
	if path == "" {
		t.Fatalf("expected path")
	}

	latest, err := store.Latest()
	if err != nil {
		t.Fatalf("latest state: %v", err)
	}
	if latest != path {
		t.Fatalf("expected latest=%s, got %s", path, latest)
	}

	loaded, err := store.Load("latest")
	if err != nil {
		t.Fatalf("load latest: %v", err)
	}
	if loaded.Version != "v1" {
		t.Fatalf("unexpected version: %s", loaded.Version)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("expected 0600 state file permissions, got %o", got)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat state dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0700 {
		t.Fatalf("expected 0700 state dir permissions, got %o", got)
	}
}
