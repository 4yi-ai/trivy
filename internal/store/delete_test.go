package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestDeleteJob(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// A finished job with findings deletes cleanly, taking its findings with it.
	if _, err := st.CreateJob(ctx, "job-done", SourceZip, "a.zip"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.SetStatus(ctx, "job-done", StatusDone, ""); err != nil {
		t.Fatalf("set status: %v", err)
	}
	if err := st.InsertFindings(ctx, []Finding{
		{JobID: "job-done", Tool: "trivy", Category: "sca", Severity: "high", RuleID: "CVE-1"},
		{JobID: "job-done", Tool: "trivy", Category: "sca", Severity: "low", RuleID: "CVE-2"},
	}); err != nil {
		t.Fatalf("insert findings: %v", err)
	}

	if err := st.DeleteJob(ctx, "job-done"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetJob(ctx, "job-done"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("job still present after delete: %v", err)
	}
	fs, err := st.ListFindings(ctx, "job-done", FindingFilter{})
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("findings orphaned after delete: got %d", len(fs))
	}

	// A running job cannot be deleted (its working dir may be in use).
	if _, err := st.CreateJob(ctx, "job-running", SourceZip, "b.zip"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.SetStatus(ctx, "job-running", StatusScanning, ""); err != nil {
		t.Fatalf("set status: %v", err)
	}
	if err := st.DeleteJob(ctx, "job-running"); !errors.Is(err, ErrInProgress) {
		t.Fatalf("expected ErrInProgress for running job, got %v", err)
	}
	if _, err := st.GetJob(ctx, "job-running"); err != nil {
		t.Fatalf("running job wrongly removed: %v", err)
	}

	// An unknown id is ErrNotFound.
	if err := st.DeleteJob(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
