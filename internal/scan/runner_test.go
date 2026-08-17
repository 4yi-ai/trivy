package scan

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
)

// mockEngine implements Engine for tests.
type mockEngine struct {
	name     string
	findings []store.Finding
	err      error
}

func (m mockEngine) Name() string    { return m.name }
func (m mockEngine) Available() bool { return true }
func (m mockEngine) Scan(ctx context.Context, dir string) ([]store.Finding, error) {
	return m.findings, m.err
}

func makeZip(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "src.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	w, err := zw.Create("app.py")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("print(1)\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRunnerResilientToEngineFailure: one engine fails, the other succeeds — the
// scan keeps the good results and records a warning instead of failing outright.
func TestRunnerResilientToEngineFailure(t *testing.T) {
	st := openStore(t)
	zipPath := makeZip(t)

	good := mockEngine{name: "good", findings: []store.Finding{
		{Tool: "good", Category: "sast", Severity: "high", Title: "x"},
	}}
	bad := mockEngine{name: "trivy", err: fmt.Errorf("remote Maven repo returned 429")}
	runner := NewRunner(st, t.TempDir(), source.DefaultGuards(), good, bad)

	job, err := st.CreateJob(context.Background(), "job-partial", store.SourceZip, "src.zip")
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background(), job, Secret{UploadPath: zipPath}); err != nil {
		t.Fatalf("Run returned error, want nil (partial success): %v", err)
	}

	fs, _ := st.ListFindings(context.Background(), job.ID, store.FindingFilter{})
	if len(fs) != 1 {
		t.Errorf("want 1 finding from the good engine, got %d", len(fs))
	}
	got, _ := st.GetJob(context.Background(), job.ID)
	if got.Error == "" {
		t.Errorf("expected a partial-failure warning recorded in Error")
	}
}

// TestRunnerAllEnginesFail: when every engine fails, the scan fails.
func TestRunnerAllEnginesFail(t *testing.T) {
	st := openStore(t)
	zipPath := makeZip(t)
	runner := NewRunner(st, t.TempDir(), source.DefaultGuards(),
		mockEngine{name: "a", err: fmt.Errorf("boom1")},
		mockEngine{name: "b", err: fmt.Errorf("boom2")},
	)
	job, _ := st.CreateJob(context.Background(), "job-allfail", store.SourceZip, "src.zip")
	if err := runner.Run(context.Background(), job, Secret{UploadPath: zipPath}); err == nil {
		t.Fatal("expected Run to error when all engines fail")
	}
}
