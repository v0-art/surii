package surituner

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateIfaceArgRejectsUnsafeNames(t *testing.T) {
	for _, value := range []string{"eth0;reboot", "../eth0", "eth0\nx", "eth0 x", ""} {
		if err := validateIfaceArg(value); err == nil {
			t.Fatalf("expected invalid iface %q to be rejected", value)
		}
	}
	for _, value := range []string{"eth0", "ens33", "bond0.100", "0000:01:00.0"} {
		if err := validateIfaceArg(value); err != nil {
			t.Fatalf("expected iface %q to be valid: %v", value, err)
		}
	}
}

func TestValidatePathArgRejectsControlCharactersAndRelativeWhenRequired(t *testing.T) {
	if err := validatePathArg("--config-path", "/etc/suricata/suricata.yaml\nbad", false); err == nil {
		t.Fatalf("expected control character path rejection")
	}
	if err := validatePathArg("--state-dir", "relative/state", true); err == nil {
		t.Fatalf("expected relative path rejection")
	}
	abs := filepath.Join(t.TempDir(), "state")
	if err := validatePathArg("--state-dir", abs, true); err != nil {
		t.Fatalf("expected absolute path to be valid: %v", err)
	}
}

func TestRunCLIPlanRejectsUnsafeIface(t *testing.T) {
	var out strings.Builder
	var errOut strings.Builder
	code := RunCLI([]string{"plan", "--profile", "af-packet", "--iface", "eth0;reboot"}, strings.NewReader(""), &out, &errOut)
	if code == 0 {
		t.Fatalf("expected unsafe iface to fail")
	}
	if !strings.Contains(errOut.String(), "invalid --iface") {
		t.Fatalf("expected invalid iface error, got %q", errOut.String())
	}
}
