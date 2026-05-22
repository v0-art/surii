package surituner

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestRunCLIApplyDefaultConfigOnlyDoesNotRunOSTuning(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 0 }

	dir, configPath, logPath := setupFakeCLIHost(t)
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := RunCLI([]string{
		"apply",
		"--profile", "af-packet",
		"--iface", "lo",
		"--config-path", configPath,
		"--state-dir", filepath.Join(dir, "state"),
		"--yes",
	}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("expected config-only apply success, code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	log := readCommandLog(t, logPath)
	if !strings.Contains(log, "suricata -T -c") {
		t.Fatalf("expected config validation in config-only apply, log:\n%s", log)
	}
	if !strings.Contains(log, "systemctl restart suricata.service") {
		t.Fatalf("expected service restart in config-only apply, log:\n%s", log)
	}
	for _, forbidden := range []string{
		"ethtool -K",
		"ethtool -G",
		"sysctl -w net.core",
		"ip link set dev lo promisc on",
	} {
		if strings.Contains(log, forbidden) {
			t.Fatalf("did not expect OS/NIC tuning command %q in default config-only apply, log:\n%s", forbidden, log)
		}
	}
}

func TestRunCLIApplyOSTuningDoesNotValidateYAMLOrRestart(t *testing.T) {
	orig := getEUID
	defer func() { getEUID = orig }()
	getEUID = func() int { return 0 }

	dir, configPath, logPath := setupFakeCLIHost(t)
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := RunCLI([]string{
		"apply",
		"--profile", "af-packet",
		"--iface", "lo",
		"--config-path", configPath,
		"--state-dir", filepath.Join(dir, "state"),
		"--os-tuning",
		"--yes",
	}, strings.NewReader(""), &out, &errOut)
	if code != 1 {
		t.Fatalf("expected os-tuning apply to fail on missing loopback IRQ pre-state in test host, code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	log := readCommandLog(t, logPath)
	if strings.Contains(log, "suricata -T -c") {
		t.Fatalf("did not expect YAML validation in os-tuning apply, log:\n%s", log)
	}
	if strings.Contains(log, "systemctl restart suricata.service") {
		t.Fatalf("did not expect service restart in os-tuning apply, log:\n%s", log)
	}
	if strings.Contains(log, "ethtool -K lo gro off") {
		t.Fatalf("did not expect live OS/NIC tuning after pre-state validation failure, log:\n%s", log)
	}
	if !strings.Contains(strings.ToLower(errOut.String()), "pre-state") {
		t.Fatalf("expected pre-state validation error, got stderr=%q", errOut.String())
	}
}

func TestRunCLIRollbackLatestYesRestoresYAML(t *testing.T) {
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

	stateDir := filepath.Join(dir, "state")
	store := NewStateStore(stateDir)
	_, err := store.Save(StateFile{
		Version:         "v1",
		HostFingerprint: BuildHostFingerprint(),
		Iface:           "eth0",
		ConfigPath:      configPath,
		YAMLBackup: &YAMLBackup{
			OriginalPath: configPath,
			BackupPath:   backupPath,
		},
		PlanActions: []PlanAction{
			{ID: "yaml-tuning", Kind: "yaml"},
		},
		Applied: []CommandRecord{
			{Index: 0, ActionID: "yaml-tuning", Status: "ok"},
		},
		Status: "applied",
	})
	if err != nil {
		t.Fatalf("save state: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := RunCLI([]string{"rollback", "--state", "latest", "--state-dir", stateDir, "--yes"}, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("expected rollback latest success, code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(raw) != "runmode: autofp\n" {
		t.Fatalf("expected YAML restored from latest state backup, got %q", string(raw))
	}
}

func setupFakeCLIHost(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0755); err != nil {
		t.Fatalf("mkdir fake bin: %v", err)
	}
	logPath := filepath.Join(dir, "commands.log")
	t.Setenv("SURITUNER_TEST_LOG", logPath)
	t.Setenv("PATH", binDir)
	for _, name := range []string{"suricata", "lscpu", "ethtool", "ip", "sysctl", "systemctl", "ss", "nft", "uname"} {
		writeFakeCLITool(t, filepath.Join(binDir, name))
	}

	rulesDir := filepath.Join(dir, "rules")
	if err := os.Mkdir(rulesDir, 0755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	configPath := filepath.Join(dir, "suricata.yaml")
	config := "default-rule-path: rules\nrule-files:\n  - suricata.rules\nrunmode: autofp\n"
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	rules := "alert tcp any any -> any any (msg:\"x\"; sid:1;)\n"
	if err := os.WriteFile(filepath.Join(rulesDir, "suricata.rules"), []byte(rules), 0644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	return dir, configPath, logPath
}

func writeFakeCLITool(t *testing.T, path string) {
	t.Helper()
	script := `#!/bin/sh
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$SURITUNER_TEST_LOG"
case "$name" in
  suricata)
    if [ "$1" = "--build-info" ]; then
      cat <<'EOF'
This is Suricata version 8.0.3 RELEASE
Suricata Configuration:
  AF_XDP support: yes
  DPDK support: no
  NFQueue support: yes
  HWLOC support: yes
EOF
    fi
    exit 0
    ;;
  lscpu)
    printf '# CPU,NODE\n0,0\n1,0\n'
    exit 0
    ;;
  ethtool)
    case "$1" in
      -k)
        printf 'Features for %s:\ngeneric-receive-offload: on\nlarge-receive-offload: on\n' "$2"
        ;;
	      -l)
	        cat <<'EOF'
Channel parameters for lo:
Pre-set maximums:
Combined: 1
Current hardware settings:
Combined: 1
EOF
	        ;;
	      -x)
	        printf 'RSS hash function: toeplitz\n'
	        ;;
      -g)
        cat <<'EOF'
Ring parameters for lo:
Pre-set maximums:
RX: 4096
TX: 4096
Current hardware settings:
RX: 512
TX: 512
EOF
        ;;
      -S)
        printf 'NIC statistics:\nrx_dropped: 0\n'
        ;;
    esac
    exit 0
    ;;
  ip)
    if [ "$1" = "route" ] && [ "$2" = "show" ]; then
      printf 'default via 192.0.2.1 dev ens33 proto dhcp\n'
      exit 0
    fi
    if [ "$1" = "route" ] && [ "$2" = "get" ]; then
      printf '%s dev ens33 src 192.0.2.10\n' "$3"
      exit 0
    fi
    if [ "$1" = "-details" ]; then
      printf '1: lo: <LOOPBACK,UP> mtu 65536 qdisc noqueue\n'
      exit 0
    fi
    if [ "$1" = "-o" ]; then
      printf '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n'
      exit 0
    fi
    exit 0
    ;;
  sysctl)
    if [ "$1" = "-n" ]; then
      printf '1\n'
    fi
    exit 0
    ;;
  systemctl)
    if [ "$1" = "--version" ]; then
      printf 'systemd 255\n'
      exit 0
    fi
    if [ "$1" = "is-active" ]; then
      printf 'active\n'
      exit 0
    fi
    exit 0
    ;;
  uname)
    printf '6.8.12-test\n'
    exit 0
    ;;
  ss|nft)
    exit 0
    ;;
esac
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatalf("write fake tool %s: %v", path, err)
	}
}

func readCommandLog(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	return string(raw)
}
