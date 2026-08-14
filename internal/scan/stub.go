package scan

import (
	"context"
	"time"

	"github.com/4yi-ai/codescan/internal/store"
)

// stubRunner is the M1 placeholder: it drives a job through the real state
// machine (fetching→scanning→done) with no actual fetch or engine work, so the
// async core, polling API, and UI can be built and tested end-to-end before the
// M2/M3 implementations land. It writes an empty summary and no findings.
type stubRunner struct {
	store *store.Store
}

func (r *stubRunner) Run(ctx context.Context, job *store.Job, _ Secret) error {
	steps := []struct {
		status   string
		progress string
	}{
		{store.StatusFetching, "fetching source (stub)"},
		{store.StatusScanning, "running semgrep (stub)"},
		{store.StatusScanning, "running trivy (stub)"},
	}
	for _, s := range steps {
		if err := r.store.SetStatus(ctx, job.ID, s.status, s.progress); err != nil {
			return err
		}
		if err := sleep(ctx, 300*time.Millisecond); err != nil {
			return err
		}
	}
	// No real findings yet; record an empty summary so the UI has something.
	return r.store.SetSummary(ctx, job.ID, store.Summary{})
}

// sleep waits d, but returns early with ctx.Err() if the context is canceled or
// times out.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
