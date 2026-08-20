package scan

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/4yi-ai/codescan/internal/reach"
	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
)

// Engine is one scanning tool (semgrep, trivy fs) run over a source directory.
// Available lets the runner skip a tool that isn't installed (e.g. a dev laptop
// without trivy) instead of failing the whole job.
type Engine interface {
	Name() string
	Available() bool
	Scan(ctx context.Context, dir string) ([]store.Finding, error)
}

// realRunner fetches the source then runs each available engine, normalizing
// results into findings + a summary. It replaces stubRunner from M2 onward.
type realRunner struct {
	store   *store.Store
	jobsDir string
	guards  source.Guards
	engines []Engine
}

// NewRunner builds the production Runner.
func NewRunner(st *store.Store, jobsDir string, guards source.Guards, engines ...Engine) Runner {
	return &realRunner{store: st, jobsDir: jobsDir, guards: guards, engines: engines}
}

func (r *realRunner) Run(ctx context.Context, job *store.Job, sec Secret) error {
	srcDir := filepath.Join(r.jobsDir, job.ID, "src")

	// ---- fetch phase ----
	if err := r.store.SetStatus(ctx, job.ID, store.StatusFetching, "fetching source"); err != nil {
		return err
	}
	if err := r.fetch(ctx, job, sec, srcDir); err != nil {
		return err
	}

	// ---- scan phase ----
	if err := r.store.SetStatus(ctx, job.ID, store.StatusScanning, "scanning"); err != nil {
		return err
	}
	var all []store.Finding
	var engineErrs []string
	ran := 0
	for _, e := range r.engines {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !e.Available() {
			log.Printf("job %s: engine %s unavailable, skipping", job.ID, e.Name())
			continue
		}
		_ = r.store.SetStatus(ctx, job.ID, store.StatusScanning, "running "+e.Name())
		found, err := e.Scan(ctx, srcDir)
		if err != nil {
			// One engine failing must not discard the other engine's results:
			// record the error and keep going (plan: scanner should be resilient).
			// If the context was canceled/timed out, that's fatal for the whole job.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("job %s: engine %s failed: %v", job.ID, e.Name(), err)
			engineErrs = append(engineErrs, fmt.Sprintf("%s: %v", e.Name(), err))
			continue
		}
		ran++
		for i := range found {
			found[i].JobID = job.ID
		}
		all = append(all, found...)
	}

	// ---- reachability (lightweight) + persist ----
	tagReachability(srcDir, all)
	all = dedupe(all)
	if err := r.store.InsertFindings(ctx, all); err != nil {
		return err
	}
	if err := r.store.SetSummary(ctx, job.ID, summarize(all)); err != nil {
		return err
	}

	switch {
	case ran == 0 && len(engineErrs) > 0:
		// Every engine failed → the scan failed.
		return fmt.Errorf("%s", strings.Join(engineErrs, "; "))
	case len(engineErrs) > 0:
		// Partial success: keep the results we have, but surface a warning so the
		// user knows one scanner did not complete.
		return r.store.SetError(ctx, job.ID, "some scanners did not complete: "+strings.Join(engineErrs, "; "))
	}
	return nil
}

// fetch materializes the source into srcDir per job.SourceType.
func (r *realRunner) fetch(ctx context.Context, job *store.Job, sec Secret, srcDir string) error {
	switch job.SourceType {
	case store.SourceGit:
		return source.CloneGit(ctx, job.SourceRef, sec.Token, sec.Branch, srcDir, r.guards)
	case store.SourceZip:
		if sec.UploadPath == "" {
			return fmt.Errorf("no uploaded archive for zip job")
		}
		return source.ExtractArchive(ctx, sec.UploadPath, srcDir, r.guards)
	case store.SourceImage:
		return fmt.Errorf("image scanning is deferred to v2")
	default:
		return fmt.Errorf("unknown source type %q", job.SourceType)
	}
}

// tagReachability marks each DIRECT npm-dependency finding as "used" or
// "unused_suspected" by checking whether the package is imported anywhere in the
// project's own source. Best-effort and package-level only (see internal/reach);
// on any error it leaves findings untagged. Only direct deps are tagged —
// transitive deps are never imported directly, so "unused" is meaningless there.
func tagReachability(srcDir string, fs []store.Finding) {
	need := false
	for i := range fs {
		if isDirectNPM(&fs[i]) {
			need = true
			break
		}
	}
	if !need {
		return
	}
	used, err := reach.UsedNPMPackages(srcDir)
	if err != nil {
		return
	}
	for i := range fs {
		f := &fs[i]
		if !isDirectNPM(f) {
			continue
		}
		if used[f.PkgName] {
			f.Usage = "used"
		} else {
			f.Usage = "unused_suspected"
		}
	}
}

func isDirectNPM(f *store.Finding) bool {
	return f.Relationship == "direct" && f.PkgName != "" && reach.IsNPMLockPath(f.FilePath)
}

// dedupe collapses redundant findings while preserving distinct ones:
//   - dependency findings (have a package) are keyed by CVE+package+version and
//     the containing DIRECTORY, so the same dep listed in two lockfiles side by
//     side (e.g. package-lock.json + yarn.lock) counts once, while the same
//     package in a different sub-project stays separate.
//   - code/secret/IaC findings are keyed by rule + exact file:line.
//
// It keeps the first occurrence and preserves order.
func dedupe(fs []store.Finding) []store.Finding {
	seen := make(map[string]struct{}, len(fs))
	out := fs[:0:0] // new backing array, don't mutate the input
	for _, f := range fs {
		var key string
		if f.PkgName != "" {
			key = "pkg\x00" + f.Category + "\x00" + f.RuleID + "\x00" +
				f.PkgName + "\x00" + f.PkgVer + "\x00" + dirOf(f.FilePath)
		} else {
			key = "code\x00" + f.Category + "\x00" + f.RuleID + "\x00" +
				f.FilePath + "\x00" + strconv.Itoa(f.Line)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

// dirOf returns the directory portion of a slash- or backslash-separated path.
func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[:i]
	}
	return ""
}

// summarize counts findings by severity.
func summarize(fs []store.Finding) store.Summary {
	var s store.Summary
	for _, f := range fs {
		switch strings.ToLower(f.Severity) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}
