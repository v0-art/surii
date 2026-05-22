package surituner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveExecutable_RootUsesTrustedDirectory(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "ip")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write trusted tool: %v", err)
	}
	orig := trustedCommandDirs
	defer func() { trustedCommandDirs = orig }()
	trustedCommandDirs = []string{dir}

	got, err := resolveExecutable("ip", true)
	if err != nil {
		t.Fatalf("resolve executable: %v", err)
	}
	if got != tool {
		t.Fatalf("expected trusted path %s, got %s", tool, got)
	}
}

func TestResolveExecutable_RootRejectsRelativePathAndMissingTrustedTool(t *testing.T) {
	orig := trustedCommandDirs
	defer func() { trustedCommandDirs = orig }()
	trustedCommandDirs = []string{t.TempDir()}

	if _, err := resolveExecutable("./ip", true); err == nil {
		t.Fatalf("expected relative executable path to be rejected")
	}
	if _, err := resolveExecutable("ip", true); err == nil {
		t.Fatalf("expected missing trusted executable to fail")
	}
}

func TestResolveExecutable_NonRootAllowsPATHLookupName(t *testing.T) {
	got, err := resolveExecutable("ip", false)
	if err != nil {
		t.Fatalf("resolve non-root executable: %v", err)
	}
	if got != "ip" {
		t.Fatalf("expected non-root command name to be unchanged, got %s", got)
	}
}

func TestExecutableAvailableUsesTrustedDirectoryForRootLookup(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "suricata-update")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write trusted tool: %v", err)
	}
	orig := trustedCommandDirs
	defer func() { trustedCommandDirs = orig }()
	trustedCommandDirs = []string{dir}

	if _, err := resolveTrustedExecutable("suricata-update"); err != nil {
		t.Fatalf("expected trusted executable: %v", err)
	}
}
