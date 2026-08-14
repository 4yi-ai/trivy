// Package engine wraps the Semgrep and Trivy CLIs: it builds argument arrays
// (never shell strings — plan §9), runs them over a source directory, and
// normalizes their JSON output into store.Finding rows. Each engine reports
// Available() so a missing CLI is skipped rather than failing the job.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// maxOutputBytes caps a tool's captured stdout so a pathological run can't
// balloon memory. 256 MiB is far above any realistic JSON report.
const maxOutputBytes = 256 << 20

// runJSON executes name+args, returning stdout (the JSON report). Stderr is
// captured for error messages only. A non-zero exit is NOT automatically an
// error for scanners that use exit codes to signal "findings present"; callers
// decide via allowExit.
func runJSON(ctx context.Context, allowExit map[int]bool, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && allowExit[exitErr.ExitCode()] {
			err = nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %v: %s", name, err, tail(stderr.String()))
	}
	if stdout.Len() > maxOutputBytes {
		return nil, fmt.Errorf("%s: output exceeded %d bytes", name, maxOutputBytes)
	}
	return stdout.Bytes(), nil
}

// available reports whether a CLI is on PATH.
func available(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// normSeverity maps a tool's severity token to codescan's canonical set.
func normSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "critical"
	case "HIGH", "ERROR":
		return "high"
	case "MEDIUM", "WARNING":
		return "medium"
	case "LOW":
		return "low"
	default: // INFO, UNKNOWN, NOTE, "" ...
		return "info"
	}
}

// tail returns the last ~500 chars of s (tool errors are usually at the end).
func tail(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		return "..." + s[len(s)-500:]
	}
	return s
}
