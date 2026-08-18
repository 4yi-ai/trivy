package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/4yi-ai/codescan/internal/store"
)

// TrivyFS runs `trivy fs` with the vuln, secret and misconfig scanners in one
// pass (license scanning is off — see Scan). The vulnerability DB is cached via
// TRIVY_CACHE_DIR (set in the environment), so it is not re-downloaded per scan.
type TrivyFS struct{}

// NewTrivyFS builds the engine.
func NewTrivyFS() *TrivyFS { return &TrivyFS{} }

func (e *TrivyFS) Name() string { return "trivy" }

func (e *TrivyFS) Available() bool { return available("trivy") }

func (e *TrivyFS) Scan(ctx context.Context, dir string) ([]store.Finding, error) {
	args := []string{
		"fs",
		// license scanning is intentionally OFF: it emits one finding per
		// dependency license (mostly MIT/ISC/etc. — compliance info, not security)
		// and on a real project drowns out the actual vulnerabilities. Security
		// scanners only. (Re-add "license" here if a compliance view is wanted.)
		"--scanners", "vuln,secret,misconfig",
		"--format", "json",
		"--quiet",
		"--no-progress",
		// --offline-scan: never reach out to external registries (e.g. Maven
		// Central) to resolve dependencies. The 4YI pod has restricted egress and
		// external repos rate-limit (429) the shared IP; offline keeps SCA working
		// from local lockfiles/manifests instead of failing the whole scan.
		"--offline-scan",
		dir,
	}
	// trivy returns 0 even with findings (default exit-code); accept 0 only.
	out, err := runJSON(ctx, map[int]bool{0: true}, "trivy", args...)
	if err != nil {
		return nil, err
	}
	return parseTrivy(out, dir)
}

// trivyReport is the subset of `trivy fs --format json` we consume.
type trivyReport struct {
	Results []struct {
		Target string `json:"Target"`
		Class  string `json:"Class"`
		// Packages carries the dependency graph metadata; Relationship tells us
		// whether a package is a direct dependency or pulled in transitively.
		Packages []struct {
			ID           string `json:"ID"`
			Name         string `json:"Name"`
			Version      string `json:"Version"`
			Relationship string `json:"Relationship"` // direct | indirect | root | workspace | ...
		} `json:"Packages"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgID            string `json:"PkgID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
		} `json:"Vulnerabilities"`
		Secrets []struct {
			RuleID    string `json:"RuleID"`
			Severity  string `json:"Severity"`
			Title     string `json:"Title"`
			StartLine int    `json:"StartLine"`
		} `json:"Secrets"`
		Misconfigurations []struct {
			ID            string `json:"ID"`
			Title         string `json:"Title"`
			Description   string `json:"Description"`
			Severity      string `json:"Severity"`
			Message       string `json:"Message"`
			CauseMetadata struct {
				StartLine int `json:"StartLine"`
			} `json:"CauseMetadata"`
		} `json:"Misconfigurations"`
		Licenses []struct {
			Severity string `json:"Severity"`
			PkgName  string `json:"PkgName"`
			Name     string `json:"Name"`
			FilePath string `json:"FilePath"`
			Category string `json:"Category"`
		} `json:"Licenses"`
	} `json:"Results"`
}

func parseTrivy(data []byte, dir string) ([]store.Finding, error) {
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	var out []store.Finding
	for _, res := range rep.Results {
		target := relPath(dir, res.Target)

		// Build a package -> direct/indirect map for this result. Key by PkgID
		// (e.g. "tar@6.1.0") and by name@version as a fallback.
		rel := make(map[string]string, len(res.Packages))
		for _, p := range res.Packages {
			r := normRelationship(p.Relationship)
			if r == "" {
				continue
			}
			if p.ID != "" {
				rel[p.ID] = r
			}
			if p.Name != "" && p.Version != "" {
				rel[p.Name+"@"+p.Version] = r
			}
		}

		for _, v := range res.Vulnerabilities {
			r := rel[v.PkgID]
			if r == "" {
				r = rel[v.PkgName+"@"+v.InstalledVersion]
			}
			out = append(out, store.Finding{
				Tool:         "trivy",
				Category:     "sca",
				Severity:     normSeverity(v.Severity),
				RuleID:       v.VulnerabilityID,
				CVE:          v.VulnerabilityID,
				Title:        firstNonEmpty(v.Title, v.VulnerabilityID),
				Message:      strings.TrimSpace(v.Description),
				FilePath:     target,
				PkgName:      v.PkgName,
				PkgVer:       v.InstalledVersion,
				FixedVer:     v.FixedVersion,
				Relationship: r,
			})
		}
		for _, s := range res.Secrets {
			out = append(out, store.Finding{
				Tool:     "trivy",
				Category: "secret",
				Severity: normSeverity(s.Severity),
				RuleID:   s.RuleID,
				Title:    firstNonEmpty(s.Title, s.RuleID),
				FilePath: target,
				Line:     s.StartLine,
			})
		}
		for _, m := range res.Misconfigurations {
			out = append(out, store.Finding{
				Tool:     "trivy",
				Category: "iac",
				Severity: normSeverity(m.Severity),
				RuleID:   m.ID,
				Title:    firstNonEmpty(m.Title, m.ID),
				Message:  firstNonEmpty(strings.TrimSpace(m.Message), strings.TrimSpace(m.Description)),
				FilePath: target,
				Line:     m.CauseMetadata.StartLine,
			})
		}
		for _, l := range res.Licenses {
			path := target
			if l.FilePath != "" {
				path = relPath(dir, l.FilePath)
			}
			out = append(out, store.Finding{
				Tool:     "trivy",
				Category: "license",
				Severity: normSeverity(l.Severity),
				RuleID:   l.Name,
				Title:    firstNonEmpty(l.Name, "license"),
				Message:  strings.TrimSpace(l.Category),
				FilePath: path,
				PkgName:  l.PkgName,
			})
		}
	}
	return out, nil
}

// normRelationship maps Trivy's Relationship enum to codescan's direct/indirect.
// root and workspace packages are top-level, so treat them as direct.
func normRelationship(r string) string {
	switch strings.ToLower(strings.TrimSpace(r)) {
	case "direct", "root", "workspace":
		return "direct"
	case "indirect":
		return "indirect"
	default:
		return ""
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
