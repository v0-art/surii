package surituner

import (
	"bytes"
	"strings"
	"testing"
)

func TestResolveApplyScope(t *testing.T) {
	scope, err := resolveApplyScope(false, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scope != ScopeConfigOnly {
		t.Fatalf("expected default scope config-only, got %s", scope)
	}

	scope, err = resolveApplyScope(false, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scope != ScopeOSTuning {
		t.Fatalf("expected os-tuning, got %s", scope)
	}

	_, err = resolveApplyScope(true, true, false)
	if err == nil {
		t.Fatalf("expected mutually-exclusive flags error")
	}
}

func TestResolveIPSMode(t *testing.T) {
	mode, err := resolveIPSMode("", ProfileNFQ)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != IPSModeStrict {
		t.Fatalf("expected strict for nfq default, got %s", mode)
	}

	mode, err = resolveIPSMode("", ProfileAFPacket)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mode != IPSModeIDS {
		t.Fatalf("expected ids default, got %s", mode)
	}

	_, err = resolveIPSMode("unsupported", ProfileAFPacket)
	if err == nil {
		t.Fatalf("expected invalid mode error")
	}
}

func TestRunCLIApplyRejectsNonRootBeforePlanning(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 1000 }

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := RunCLI([]string{"apply", "--profile", "af-packet", "--iface", "definitely-missing0", "--yes"}, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("expected non-root apply to fail, got exit code %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut.String()), "root") {
		t.Fatalf("expected root error, got stderr=%q", errOut.String())
	}
	if strings.Contains(out.String(), "Plan generated") {
		t.Fatalf("did not expect plan output before root check, got stdout=%q", out.String())
	}
}

func TestRunCLIRollbackRejectsNonRootBeforePrompt(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 1000 }

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := RunCLI([]string{"rollback", "--state", "latest"}, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("expected non-root rollback to fail, got exit code %d", code)
	}
	if !strings.Contains(strings.ToLower(errOut.String()), "root") {
		t.Fatalf("expected root error, got stderr=%q", errOut.String())
	}
	if strings.Contains(out.String(), "Continue?") {
		t.Fatalf("did not expect confirmation prompt before root check, got stdout=%q", out.String())
	}
}
