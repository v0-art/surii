package surituner

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func RunCLI(args []string, in io.Reader, out io.Writer, errOut io.Writer) int {
	if len(args) == 0 {
		printRootHelp(out)
		return 0
	}

	switch args[0] {
	case "detect":
		if err := runDetect(args[1:], out); err != nil {
			fmt.Fprintln(errOut, "error:", err)
			return 1
		}
		return 0
	case "plan":
		if err := runPlan(args[1:], out); err != nil {
			fmt.Fprintln(errOut, "error:", err)
			return 1
		}
		return 0
	case "apply":
		if err := runApply(args[1:], in, out); err != nil {
			fmt.Fprintln(errOut, "error:", err)
			return 1
		}
		return 0
	case "rollback":
		if err := runRollback(args[1:], in, out); err != nil {
			fmt.Fprintln(errOut, "error:", err)
			return 1
		}
		return 0
	case "report":
		if err := runReport(args[1:], out); err != nil {
			fmt.Fprintln(errOut, "error:", err)
			return 1
		}
		return 0
	case "help", "-h", "--help":
		printRootHelp(out)
		return 0
	default:
		fmt.Fprintf(errOut, "unknown command: %s\n\n", args[0])
		printRootHelp(errOut)
		return 1
	}
}

func printRootHelp(out io.Writer) {
	fmt.Fprintln(out, "surituner - Safe Decision Engine for Suricata tuning")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  surituner detect --iface <name> [--json]")
	fmt.Fprintln(out, "  surituner plan --profile <af-packet|dpdk|af-xdp|nfq> --iface <name> [--ips-mode <strict|availability|ids>] [--config-path <path>] [--json] [--force]")
	fmt.Fprintln(out, "  surituner apply --profile <...> --iface <name> [--ips-mode <strict|availability|ids>] [--config-path <path>] [--config-only|--os-tuning|--full] [--yes] [--force]")
	fmt.Fprintln(out, "  surituner rollback --state <path|latest> [--yes]")
	fmt.Fprintln(out, "  surituner report --iface <name> [--config-path <path>] [--json]")
}

func runDetect(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	iface := fs.String("iface", "", "Capture interface name")
	jsonOut := fs.Bool("json", false, "Output JSON")
	configPath := fs.String("config-path", "", "Path to suricata.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*iface) == "" {
		return errors.New("--iface is required")
	}
	collector := NewCollector(NewExecRunner(false))
	snapshot, err := collector.Collect(*iface, *configPath)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		snapshot.Warnings = append(snapshot.Warnings, "running without root: some diagnostics may be incomplete")
	}
	if *jsonOut {
		report := Report{
			GeneratedAt: time.Now().UTC(),
			Snapshot:    snapshot,
		}
		raw, err := RenderReportJSON(report)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, raw)
		return nil
	}
	fmt.Fprintln(out, RenderSnapshotHuman(snapshot))
	return nil
}

func runPlan(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profileRaw := fs.String("profile", "", "Capture profile")
	iface := fs.String("iface", "", "Capture interface name")
	configPath := fs.String("config-path", "", "Path to suricata.yaml")
	jsonOut := fs.Bool("json", false, "Output JSON")
	force := fs.Bool("force", false, "Bypass management guardrails")
	ipsModeRaw := fs.String("ips-mode", "", "Exception policy mode: strict|availability|ids")
	scopeRaw := fs.String("scope", string(ScopeFull), "Scope for plan: config-only|os-tuning|full")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*iface) == "" {
		return errors.New("--iface is required")
	}
	profile, err := parseProfile(*profileRaw)
	if err != nil {
		return err
	}
	ipsMode, err := resolveIPSMode(*ipsModeRaw, profile)
	if err != nil {
		return err
	}
	scope := ApplyScope(*scopeRaw)
	if !scope.Valid() {
		return fmt.Errorf("invalid --scope: %s", *scopeRaw)
	}
	collector := NewCollector(NewExecRunner(false))
	snapshot, err := collector.Collect(*iface, *configPath)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		snapshot.Warnings = append(snapshot.Warnings, "running without root: some diagnostics may be incomplete")
	}
	plan, err := NewPlanner().BuildPlan(snapshot, profile, scope, ipsMode, *force)
	if err != nil {
		return err
	}
	if *jsonOut {
		raw, err := RenderPlanJSON(plan)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, raw)
		return nil
	}
	fmt.Fprintln(out, RenderPlanHuman(plan))
	return nil
}

func runApply(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profileRaw := fs.String("profile", "", "Capture profile")
	iface := fs.String("iface", "", "Capture interface name")
	configPath := fs.String("config-path", "", "Path to suricata.yaml")
	configOnly := fs.Bool("config-only", false, "Apply only suricata.yaml changes (default)")
	osTuning := fs.Bool("os-tuning", false, "Apply only OS tuning")
	full := fs.Bool("full", false, "Apply full profile")
	ipsModeRaw := fs.String("ips-mode", "", "Exception policy mode: strict|availability|ids")
	yes := fs.Bool("yes", false, "Skip confirmation")
	force := fs.Bool("force", false, "Bypass management guardrails")
	stateDir := fs.String("state-dir", DefaultStateDir, "State files directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*iface) == "" {
		return errors.New("--iface is required")
	}
	profile, err := parseProfile(*profileRaw)
	if err != nil {
		return err
	}
	ipsMode, err := resolveIPSMode(*ipsModeRaw, profile)
	if err != nil {
		return err
	}
	scope, err := resolveApplyScope(*configOnly, *osTuning, *full)
	if err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	collector := NewCollector(NewExecRunner(false))
	snapshot, err := collector.Collect(*iface, *configPath)
	if err != nil {
		return err
	}
	plan, err := NewPlanner().BuildPlan(snapshot, profile, scope, ipsMode, *force)
	if err != nil {
		return err
	}

	fmt.Fprintln(out, RenderPlanHuman(plan))
	executor := NewExecutor(NewExecRunner(false), *stateDir)
	result, err := executor.Apply(plan, ApplyOptions{
		Scope:     scope,
		Force:     *force,
		AssumeYes: *yes,
		Input:     in,
		Output:    out,
		StateDir:  *stateDir,
	})
	if err != nil {
		if result.StatePath != "" {
			fmt.Fprintf(out, "Apply failed. State: %s\n", result.StatePath)
		} else {
			fmt.Fprintln(out, "Apply failed.")
		}
		if result.RolledBack {
			fmt.Fprintf(out, "Auto-rollback executed: %s\n", result.RollbackReason)
		}
		return err
	}
	fmt.Fprintf(out, "Apply completed successfully.\nState file: %s\nApplied actions: %d\n", result.StatePath, result.AppliedCount)
	return nil
}

func runRollback(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	statePath := fs.String("state", "latest", "State file path or 'latest'")
	yes := fs.Bool("yes", false, "Skip confirmation")
	stateDir := fs.String("state-dir", DefaultStateDir, "State files directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if !*yes {
		if !askConfirmation(in, out, "Rollback will modify system settings. Continue? [y/N]: ") {
			return errors.New("rollback aborted by user")
		}
	}
	executor := NewExecutor(NewExecRunner(false), *stateDir)
	result, err := executor.Rollback(*statePath)
	if err != nil {
		fmt.Fprintf(out, "Rollback finished with errors. Executed=%d\n", result.Executed)
		if len(result.Errors) > 0 {
			for _, item := range result.Errors {
				fmt.Fprintf(out, "  - %s\n", item)
			}
		}
		return err
	}
	fmt.Fprintf(out, "Rollback successful.\nState: %s\nExecuted rollback actions: %d\n", result.StatePath, result.Executed)
	return nil
}

func runReport(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	iface := fs.String("iface", "", "Capture interface name")
	configPath := fs.String("config-path", "", "Path to suricata.yaml")
	jsonOut := fs.Bool("json", false, "Output JSON")
	stateDir := fs.String("state-dir", DefaultStateDir, "State files directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*iface) == "" {
		return errors.New("--iface is required")
	}
	collector := NewCollector(NewExecRunner(false))
	snapshot, err := collector.Collect(*iface, *configPath)
	if err != nil {
		return err
	}
	runtimeMetrics := collector.CollectRuntimeMetrics(*iface)
	report := Report{
		GeneratedAt:               time.Now().UTC(),
		Snapshot:                  snapshot,
		RuntimeMetrics:            runtimeMetrics,
		Recommendations:           BuildRecommendations(snapshot),
		UnsupportedOptions:        BuildUnsupportedOptions(snapshot),
		Bottlenecks:               BuildBottlenecks(snapshot, runtimeMetrics),
		MonitoringRecommendations: BuildMonitoringRecommendations(),
		Warnings:                  dedupeStrings(append(snapshot.Warnings, runtimeMetrics.Warnings...)),
	}
	store := NewStateStore(*stateDir)
	if latest, err := store.Latest(); err == nil {
		report.LatestState = latest
		if state, loadErr := store.Load(latest); loadErr == nil {
			for _, action := range state.PlanActions {
				report.PlannedActions = append(report.PlannedActions, action.ID)
			}
			for _, applied := range state.Applied {
				report.AppliedActions = append(report.AppliedActions, applied.ActionID)
			}
		} else {
			report.Warnings = append(report.Warnings, "latest state exists but cannot be parsed")
		}
	} else {
		report.Warnings = append(report.Warnings, "state files not found yet")
	}

	if *jsonOut {
		raw, err := RenderReportJSON(report)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, raw)
		return nil
	}
	fmt.Fprintln(out, RenderSnapshotHuman(snapshot))
	if report.LatestState != "" {
		fmt.Fprintf(out, "\nLatest state: %s\n", report.LatestState)
	}
	if len(report.Recommendations) > 0 {
		fmt.Fprintf(out, "\nRecommendations:\n")
		for _, rec := range report.Recommendations {
			fmt.Fprintf(out, "  - %s\n", rec)
		}
	}
	if len(report.UnsupportedOptions) > 0 {
		fmt.Fprintf(out, "\nUnsupported Options:\n")
		for _, item := range report.UnsupportedOptions {
			fmt.Fprintf(out, "  - %s\n", item)
		}
	}
	if len(report.Bottlenecks) > 0 {
		fmt.Fprintf(out, "\nDetected Bottlenecks:\n")
		for _, item := range report.Bottlenecks {
			fmt.Fprintf(out, "  - %s\n", item)
		}
	}
	if len(report.MonitoringRecommendations) > 0 {
		fmt.Fprintf(out, "\nMonitoring Recommendations:\n")
		for _, item := range report.MonitoringRecommendations {
			fmt.Fprintf(out, "  - %s\n", item)
		}
	}
	if len(report.RuntimeMetrics.Acceptance) > 0 {
		fmt.Fprintf(out, "\nRuntime Acceptance Signals:\n")
		for _, item := range report.RuntimeMetrics.Acceptance {
			fmt.Fprintf(out, "  - %s\n", item)
		}
	}
	if len(report.PlannedActions) > 0 {
		fmt.Fprintf(out, "\nLatest Planned Actions:\n")
		for _, actionID := range report.PlannedActions {
			fmt.Fprintf(out, "  - %s\n", actionID)
		}
	}
	if len(report.AppliedActions) > 0 {
		fmt.Fprintf(out, "\nLatest Applied Actions:\n")
		for _, actionID := range report.AppliedActions {
			fmt.Fprintf(out, "  - %s\n", actionID)
		}
	}
	return nil
}

func parseProfile(raw string) (CaptureProfile, error) {
	profile := CaptureProfile(strings.ToLower(strings.TrimSpace(raw)))
	if !profile.Valid() {
		return "", fmt.Errorf("invalid --profile: %s", raw)
	}
	return profile, nil
}

func resolveApplyScope(configOnly bool, osTuning bool, full bool) (ApplyScope, error) {
	count := 0
	if configOnly {
		count++
	}
	if osTuning {
		count++
	}
	if full {
		count++
	}
	if count > 1 {
		return "", errors.New("only one of --config-only, --os-tuning, --full can be set")
	}
	if count == 0 {
		return ScopeConfigOnly, nil
	}
	if configOnly {
		return ScopeConfigOnly, nil
	}
	if osTuning {
		return ScopeOSTuning, nil
	}
	return ScopeFull, nil
}

func resolveIPSMode(raw string, profile CaptureProfile) (IPSMode, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		if profile == ProfileNFQ {
			return IPSModeStrict, nil
		}
		return IPSModeIDS, nil
	}
	mode := IPSMode(value)
	if !mode.Valid() {
		return "", fmt.Errorf("invalid --ips-mode: %s", raw)
	}
	return mode, nil
}
