package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/4yi-ai/codescan/internal/store"
)

// Semgrep runs the Semgrep SAST CLI. Rules come from a vendored directory so the
// scan works offline (the 4YI pod has restricted egress — plan §2). If the
// directory has no rule files it falls back to the "p/default" registry pack,
// which needs network and is intended only for local dev.
type Semgrep struct {
	rulesDir string
	maxMemMB int
}

// NewSemgrep builds the engine. rulesDir is CODESCAN_RULES_DIR.
func NewSemgrep(rulesDir string) *Semgrep {
	return &Semgrep{rulesDir: rulesDir, maxMemMB: 2048}
}

func (e *Semgrep) Name() string { return "semgrep" }

func (e *Semgrep) Available() bool { return available("semgrep") }

func (e *Semgrep) Scan(ctx context.Context, dir string) ([]store.Finding, error) {
	config := e.configArg()

	// --metrics=off: no phone-home. --json: machine output. --max-memory /
	// --timeout: resource guards (plan §6). Skip heavy vendored trees.
	args := []string{
		"scan",
		"--config", config,
		"--json",
		"--quiet",
		"--metrics=off",
		fmt.Sprintf("--max-memory=%d", e.maxMemMB),
		"--timeout=0", // per-rule timeout off; the job-level ctx bounds total time
		"--exclude=node_modules", "--exclude=vendor", "--exclude=.git",
		dir,
	}
	// semgrep exits 1 when findings are present; that is success for us.
	out, err := runJSON(ctx, map[int]bool{0: true, 1: true}, "semgrep", args...)
	if err != nil {
		return nil, err
	}
	return parseSemgrep(out, dir)
}

// configArg picks the vendored rules dir if it holds rule files, else p/default.
func (e *Semgrep) configArg() string {
	if e.rulesDir != "" && hasRuleFiles(e.rulesDir) {
		return e.rulesDir
	}
	return "p/default"
}

func hasRuleFiles(dir string) bool {
	var found bool
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if !d.IsDir() {
			switch strings.ToLower(filepath.Ext(d.Name())) {
			case ".yml", ".yaml":
				found = true
			}
		}
		return nil
	})
	return found
}

// semgrepReport is the subset of `semgrep --json` we consume.
type semgrepReport struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Metadata struct {
				CWE any `json:"cwe"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
}

func parseSemgrep(data []byte, dir string) ([]store.Finding, error) {
	var rep semgrepReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse semgrep json: %w", err)
	}
	out := make([]store.Finding, 0, len(rep.Results))
	for _, r := range rep.Results {
		out = append(out, store.Finding{
			Tool:     "semgrep",
			Category: "sast",
			Severity: normSeverity(r.Extra.Severity),
			RuleID:   r.CheckID,
			Title:    shortRuleTitle(r.CheckID),
			Message:  strings.TrimSpace(r.Extra.Message),
			FilePath: relPath(dir, r.Path),
			Line:     r.Start.Line,
		})
	}
	return out, nil
}

// shortRuleTitle turns a dotted check_id into its last, human-ish segment.
func shortRuleTitle(checkID string) string {
	if i := strings.LastIndex(checkID, "."); i >= 0 && i < len(checkID)-1 {
		return checkID[i+1:]
	}
	return checkID
}

// relPath makes p relative to dir when possible (findings should be repo-relative).
func relPath(dir, p string) string {
	if rel, err := filepath.Rel(dir, p); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return p
}
