package surituner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
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
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
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
