package scan

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/4yi-ai/codescan/internal/store"
)

// openStore spins up a fresh SQLite store in a temp dir.
func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "scan.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// pollStatus waits until the job reaches one of want (or times out).
func pollStatus(t *testing.T, st *store.Store, id string, want ...string) *store.Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		job, err := st.GetJob(context.Background(), id)
		if err != nil {
			t.Fatalf("get job: %v", err)
		}
		for _, w := range want {
			if job.Status == w {
				return job
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job %s did not reach %v in time", id, want)
	return nil
}

// TestManagerDrivesJobToDone exercises the whole async core: enqueue → worker
// picks it up → stub runner walks the state machine → job ends "done" with a
// summary.
func TestManagerDrivesJobToDone(t *testing.T) {
	st := openStore(t)
	mgr := NewManager(st, Config{JobsDir: t.TempDir()})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)

	job, err := st.CreateJob(context.Background(), "job-done", store.SourceGit, "https://example.com/repo.git")
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	if err := mgr.Enqueue(job.ID, Secret{}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	done := pollStatus(t, st, job.ID, store.StatusDone)
	if done.Summary == nil {
		t.Errorf("expected a summary on done job, got nil")
	}
	if done.StartedAt == 0 || done.FinishedAt == 0 {
		t.Errorf("expected started_at and finished_at stamped, got %d / %d", done.StartedAt, done.FinishedAt)
	}
}

// TestCancelBeforeStart verifies a job canceled while queued never runs.
func TestCancelBeforeStart(t *testing.T) {
	st := openStore(t)
	// Runner that would fail the test if it ever ran.
	mgr := NewManager(st, Config{JobsDir: t.TempDir()})
	mgr.SetRunner(runnerFunc(func(ctx context.Context, job *store.Job, _ Secret) error {
		t.Errorf("runner ran for a job canceled before start")
		return nil
	}))

	job, err := st.CreateJob(context.Background(), "job-cancel", store.SourceGit, "https://example.com/repo.git")
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	// Cancel first, then enqueue and start the worker.
	if _, err := st.Cancel(context.Background(), job.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := mgr.Enqueue(job.ID, Secret{}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)

	// Give the worker time to pick up and skip the job.
	time.Sleep(200 * time.Millisecond)
	got := pollStatus(t, st, job.ID, store.StatusCanceled)
	if got.Status != store.StatusCanceled {
		t.Errorf("status = %q, want canceled", got.Status)
	}
}

// TestRunnerErrorFailsJob verifies a runner error marks the job failed.
func TestRunnerErrorFailsJob(t *testing.T) {
	st := openStore(t)
	mgr := NewManager(st, Config{JobsDir: t.TempDir()})
	mgr.SetRunner(runnerFunc(func(ctx context.Context, job *store.Job, _ Secret) error {
		return context.DeadlineExceeded
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)

	job, _ := st.CreateJob(context.Background(), "job-fail", store.SourceGit, "https://example.com/repo.git")
	if err := mgr.Enqueue(job.ID, Secret{}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	failed := pollStatus(t, st, job.ID, store.StatusFailed)
	if failed.Error == "" {
		t.Errorf("expected an error message on failed job")
	}
}

// runnerFunc adapts a func to the Runner interface for tests.
type runnerFunc func(ctx context.Context, job *store.Job, sec Secret) error

func (f runnerFunc) Run(ctx context.Context, job *store.Job, sec Secret) error {
	return f(ctx, job, sec)
}
