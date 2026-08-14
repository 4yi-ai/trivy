// Package scan owns the async execution core: a bounded in-memory queue and a
// single background worker (concurrency 1) that drives each job through its
// state machine. The actual fetch + engine work lives behind the Runner seam so
// M2 (sources) and M3 (engines) can be dropped in without touching this file.
// See docs/codescan-v1-plan.md §6.
package scan

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/4yi-ai/codescan/internal/store"
)

// ErrQueueFull is returned by Enqueue when the bounded queue is saturated.
var ErrQueueFull = errors.New("scan queue is full")

// Secret carries the per-job data that must NEVER touch the database: a
// use-once git token and/or the local path of an uploaded archive. It lives in
// the Manager's memory only from Enqueue until the worker picks the job up.
type Secret struct {
	Token      string // use-once git token; dropped after clone
	UploadPath string // local path of an uploaded zip/tar (zip source)
}

// Runner performs the fetch + engine work for one job. It reports progress and
// findings back through the store. Returning an error marks the job failed;
// returning nil marks it done. M1 ships stubRunner; M2/M3 install realRunner.
type Runner interface {
	Run(ctx context.Context, job *store.Job, sec Secret) error
}

// Config tunes the manager.
type Config struct {
	JobsDir    string        // working dir root: <JobsDir>/<id>/
	QueueSize  int           // bounded queue capacity (default 64)
	JobTimeout time.Duration // per-job hard timeout (default 15m)
}

// Manager is the queue + worker.
type Manager struct {
	store  *store.Store
	runner Runner
	cfg    Config
	queue  chan string

	mu      sync.Mutex
	secrets map[string]Secret // id → in-memory secret, popped on pickup
}

// NewManager builds a Manager with the default stub runner. Call SetRunner to
// install the real one (M2/M3).
func NewManager(st *store.Store, cfg Config) *Manager {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 64
	}
	if cfg.JobTimeout <= 0 {
		cfg.JobTimeout = 15 * time.Minute
	}
	m := &Manager{
		store:   st,
		cfg:     cfg,
		queue:   make(chan string, cfg.QueueSize),
		secrets: make(map[string]Secret),
	}
	m.runner = &stubRunner{store: st}
	return m
}

// SetRunner swaps the work implementation (used by M2/M3 wiring). Call before Start.
func (m *Manager) SetRunner(r Runner) { m.runner = r }

// JobsDir returns the working-directory root.
func (m *Manager) JobsDir() string { return m.cfg.JobsDir }

// Enqueue puts a job id (with its in-memory secret) on the queue. Non-blocking:
// returns ErrQueueFull rather than stalling the HTTP handler.
func (m *Manager) Enqueue(id string, sec Secret) error {
	m.mu.Lock()
	m.secrets[id] = sec
	m.mu.Unlock()

	select {
	case m.queue <- id:
		return nil
	default:
		m.mu.Lock()
		delete(m.secrets, id)
		m.mu.Unlock()
		return ErrQueueFull
	}
}

// takeSecret pops and removes a job's secret (so the token is not retained).
func (m *Manager) takeSecret(id string) Secret {
	m.mu.Lock()
	defer m.mu.Unlock()
	sec := m.secrets[id]
	delete(m.secrets, id)
	return sec
}

// Start launches the single worker goroutine. It stops when ctx is canceled.
func (m *Manager) Start(ctx context.Context) {
	go m.loop(ctx)
}

func (m *Manager) loop(ctx context.Context) {
	log.Printf("scan worker started (queue=%d, timeout=%s)", m.cfg.QueueSize, m.cfg.JobTimeout)
	for {
		select {
		case <-ctx.Done():
			log.Println("scan worker stopping")
			return
		case id := <-m.queue:
			m.process(ctx, id)
		}
	}
}

// process runs one job end-to-end. It never panics the worker: a runner panic
// or error becomes a failed job, and the loop continues with the next id. The
// per-job working directory is always removed afterward (results live in the DB).
func (m *Manager) process(parent context.Context, id string) {
	sec := m.takeSecret(id)
	defer m.cleanup(id)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("job %s panicked: %v", id, r)
			_ = m.store.Fail(context.Background(), id, "internal error")
		}
	}()

	// A cancel may have landed while the job sat in the queue.
	job, err := m.store.GetJob(parent, id)
	if err != nil {
		log.Printf("job %s: load failed: %v", id, err)
		return
	}
	if job.Status == store.StatusCanceled {
		log.Printf("job %s canceled before start", id)
		return
	}

	ctx, cancel := context.WithTimeout(parent, m.cfg.JobTimeout)
	defer cancel()

	if err := m.store.SetStatus(ctx, id, store.StatusFetching, "starting"); err != nil {
		log.Printf("job %s: set fetching: %v", id, err)
		return
	}

	err = m.runner.Run(ctx, job, sec)

	// If the job was canceled mid-run, honor that over any runner error.
	if canceled, _ := m.store.IsCanceled(context.Background(), id); canceled {
		log.Printf("job %s canceled during run", id)
		return
	}

	switch {
	case err != nil && errors.Is(err, context.DeadlineExceeded):
		_ = m.store.Fail(context.Background(), id, "timed out")
		log.Printf("job %s timed out", id)
	case err != nil:
		_ = m.store.Fail(context.Background(), id, err.Error())
		log.Printf("job %s failed: %v", id, err)
	default:
		if err := m.store.SetStatus(context.Background(), id, store.StatusDone, "complete"); err != nil {
			log.Printf("job %s: set done: %v", id, err)
		}
	}
}

// cleanup removes the job's working directory. Best-effort: a failure to clean
// is logged but does not affect the job result.
func (m *Manager) cleanup(id string) {
	if m.cfg.JobsDir == "" {
		return
	}
	dir := filepath.Join(m.cfg.JobsDir, id)
	if err := os.RemoveAll(dir); err != nil {
		log.Printf("job %s: cleanup %s: %v", id, dir, err)
	}
}
