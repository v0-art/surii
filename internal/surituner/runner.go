package surituner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type CommandResult struct {
	Args       []string `json:"args"`
	ExitCode   int      `json:"exit_code"`
	Stdout     string   `json:"stdout"`
	Stderr     string   `json:"stderr"`
	DurationMS int64    `json:"duration_ms"`
}

type CommandRunner interface {
	Run(args []string, timeout time.Duration, allowFailure bool) (CommandResult, error)
}

type ExecRunner struct {
	DryRun bool
}

var trustedCommandDirs = []string{
	"/usr/sbin",
	"/usr/bin",
	"/sbin",
	"/bin",
	"/usr/local/sbin",
	"/usr/local/bin",
}

func NewExecRunner(dryRun bool) *ExecRunner {
	return &ExecRunner{DryRun: dryRun}
}

func (r *ExecRunner) Run(args []string, timeout time.Duration, allowFailure bool) (CommandResult, error) {
	res := CommandResult{Args: append([]string(nil), args...)}
	if len(args) == 0 {
		return res, errors.New("empty command")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if r.DryRun {
		return res, nil
	}
	executable, err := resolveExecutable(args[0], os.Geteuid() == 0)
	if err != nil {
		return res, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, executable, args[1:]...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err = cmd.Run()
	res.DurationMS = time.Since(start).Milliseconds()
	res.Stdout = strings.TrimSpace(stdout.String())
	res.Stderr = strings.TrimSpace(stderr.String())
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return res, fmt.Errorf("command timed out after %s: %s", timeout.String(), strings.Join(args, " "))
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			if allowFailure {
				return res, nil
			}
			details := strings.TrimSpace(res.Stderr)
			if details == "" {
				details = strings.TrimSpace(res.Stdout)
			}
			return res, fmt.Errorf("command failed (exit=%d): %s: %s", res.ExitCode, strings.Join(args, " "), details)
		}
		return res, fmt.Errorf("run command %s: %w", strings.Join(args, " "), err)
	}
	res.ExitCode = 0
	return res, nil
}

func resolveExecutable(name string, root bool) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("empty executable")
	}
	if filepath.IsAbs(name) {
		return name, nil
	}
	if strings.ContainsRune(name, filepath.Separator) {
		return "", fmt.Errorf("relative executable paths are not allowed: %s", name)
	}
	if root {
		resolved, err := resolveTrustedExecutable(name)
		if err != nil {
			return "", err
		}
		return resolved, nil
	}
	return name, nil
}

func resolveTrustedExecutable(name string) (string, error) {
	for _, dir := range trustedCommandDirs {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		if info.Mode().Perm()&0111 == 0 {
			continue
		}
		return path, nil
	}
	return "", fmt.Errorf("trusted executable not found for root command: %s", name)
}

func executableAvailable(name string) bool {
	if os.Geteuid() == 0 {
		_, err := resolveTrustedExecutable(name)
		return err == nil
	}
	_, err := exec.LookPath(name)
	return err == nil
}
