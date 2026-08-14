package source

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
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

// CloneGit shallow-clones cleanURL into dir. If token is non-empty it is
// injected into the clone URL for this one command and never stored elsewhere;
// the caller must have already zeroed its own copy. cleanURL must come from
// SanitizeGitURL.
//
// The token is passed via the URL userinfo of an argument array (never a shell
// string), and git is told not to prompt so a bad token fails fast instead of
// hanging.
func CloneGit(ctx context.Context, cleanURL, token, dir string, g Guards) error {
	if err := mustCtx(ctx); err != nil {
		return err
	}
	if err := ensureEmptyDir(dir); err != nil {
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

	cmd := exec.CommandContext(ctx, "git",
		"clone", "--depth", "1", "--single-branch", "--no-tags",
		cloneURL, dir)
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
