package source

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// SanitizeGitURL validates a git URL against the SSRF guard: https only, a
// host on the allowlist, no embedded credentials, default port. It returns the
// cleaned URL (safe to persist as source_ref — never contains a token).
func SanitizeGitURL(raw string, g Guards) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid git URL: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("git URL must be https (got %q)", u.Scheme)
	}
	if u.User != nil {
		return "", fmt.Errorf("git URL must not embed credentials")
	}
	if u.Port() != "" {
		return "", fmt.Errorf("git URL must use the default port")
	}
	host := strings.ToLower(u.Hostname())
	if !slices.Contains(g.AllowedHosts, host) {
		return "", fmt.Errorf("host %q is not allowed (allowed: %s)", host, strings.Join(g.AllowedHosts, ", "))
	}
	// Rebuild from validated parts so nothing odd (fragments, opaque) survives.
	clean := &url.URL{Scheme: "https", Host: host, Path: u.Path}
	return clean.String(), nil
}

// branchRe allows conservative git branch/tag names: letters, digits, and
// . _ / - (covers "main", "release/1.2", "feature-x", "v1.0.0"). It deliberately
// forbids anything that could be an option, a shell metacharacter, or a path
// escape.
var branchRe = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// validateBranch rejects branch names that could inject a git option or contain
// unsafe characters. Empty is allowed (clone the repo default).
func validateBranch(branch string) error {
	if branch == "" {
		return nil
	}
	if strings.HasPrefix(branch, "-") {
		return fmt.Errorf("invalid branch name %q", branch)
	}
	if len(branch) > 255 || !branchRe.MatchString(branch) {
		return fmt.Errorf("invalid branch name %q", branch)
	}
	return nil
}

// CloneGit shallow-clones cleanURL into dir. If token is non-empty it is
// injected into the clone URL for this one command and never stored elsewhere;
// the caller must have already zeroed its own copy. cleanURL must come from
// SanitizeGitURL.
//
// The token is passed via the URL userinfo of an argument array (never a shell
// string), and git is told not to prompt so a bad token fails fast instead of
// hanging.
func CloneGit(ctx context.Context, cleanURL, token, branch, dir string, g Guards) error {
	if err := mustCtx(ctx); err != nil {
		return err
	}
	if err := ensureEmptyDir(dir); err != nil {
		return err
	}
	branch = strings.TrimSpace(branch)
	if err := validateBranch(branch); err != nil {
		return err
	}

	cloneURL := cleanURL
	if token != "" {
		u, err := url.Parse(cleanURL)
		if err != nil {
			return fmt.Errorf("re-parse clean URL: %w", err)
		}
		// x-access-token works for GitHub PATs; GitLab accepts token as password.
		u.User = url.UserPassword("x-access-token", token)
		cloneURL = u.String()
	}

	args := []string{"clone", "--depth", "1", "--single-branch", "--no-tags"}
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	// "--" stops git from reading cloneURL/dir as options even if they were
	// somehow crafted to start with a dash.
	args = append(args, "--", cloneURL, dir)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(cmd.Environ(),
		"GIT_TERMINAL_PROMPT=0", // never block on a credential prompt
		"GIT_CONFIG_NOSYSTEM=1",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		// Scrub the token from any error output before it can be logged/stored.
		msg := string(out)
		if token != "" {
			msg = strings.ReplaceAll(msg, token, "***")
		}
		return fmt.Errorf("git clone failed: %v: %s", err, strings.TrimSpace(lastLine(msg)))
	}

	// Delete .git BEFORE scanning: `git clone <token>@host` writes the tokenized
	// URL into .git/config, and Trivy's secret scanner would otherwise read it
	// and persist the user's use-once token into the findings DB. The git
	// metadata is useless for SAST/SCA anyway.
	if err := os.RemoveAll(filepath.Join(dir, ".git")); err != nil {
		return fmt.Errorf("strip .git after clone: %w", err)
	}

	return enforceSize(dir, g)
}

// lastLine returns the last non-empty line of s (git's real error is usually last).
func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return lines[i]
		}
	}
	return s
}
