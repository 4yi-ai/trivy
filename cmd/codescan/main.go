// Command codescan is the single public service: an HTTP API + server-rendered
// UI that runs Semgrep and Trivy scans in a background worker. See
// docs/codescan-v1-plan.md.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/4yi-ai/codescan/internal/api"
	"github.com/4yi-ai/codescan/internal/engine"
	"github.com/4yi-ai/codescan/internal/scan"
	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
	"github.com/4yi-ai/codescan/web"
)

func main() {
	host := env("HOST", "0.0.0.0")
	port := env("PORT", "8080")
	dataDir := env("DATA_DIR", "./data")

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("create data dir %s: %v", dataDir, err)
	}

	st, err := store.Open(filepath.Join(dataDir, "scan.db"))
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	// Jobs left mid-flight by a previous crash/restart can never resume (the
	// in-memory queue is gone), so mark them failed before serving traffic.
	if n, err := st.RecoverOrphans(context.Background()); err != nil {
		log.Printf("recover orphaned jobs: %v", err)
	} else if n > 0 {
		log.Printf("recovered %d orphaned job(s) → failed", n)
	}

	// Background scan worker (concurrency 1). Started before the HTTP server so
	// enqueues from the first request are picked up immediately.
	jobsDir := filepath.Join(dataDir, "jobs")
	guards := source.DefaultGuards()
	mgr := scan.NewManager(st, scan.Config{JobsDir: jobsDir})

	// Install the real fetch+engine runner. Engines self-report availability, so
	// a missing CLI (e.g. on a dev machine) is skipped rather than fatal.
	rulesDir := env("CODESCAN_RULES_DIR", "./rules")
	engines := []scan.Engine{
		engine.NewSemgrep(rulesDir),
		engine.NewTrivyFS(),
	}
	mgr.SetRunner(scan.NewRunner(st, jobsDir, guards, engines...))

	workerCtx, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	mgr.Start(workerCtx)

	// Warm the Trivy vulnerability DB in the background so the first scan is fast
	// and the DB isn't re-downloaded per scan. Deliberately off the request path:
	// it must never delay /healthz or a cold start would 502 (plan §6).
	go engine.PrewarmTrivy(workerCtx)

	srv := &http.Server{
		Addr:              host + ":" + port,
		Handler:           api.NewServer(st, mgr, guards, web.FS).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM (the platform sends SIGTERM on
	// pod termination; drain in-flight requests before exiting).
	go func() {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		<-ctx.Done()
		log.Println("shutdown signal received, draining...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}()

	log.Printf("codescan listening on %s (data dir: %s)", srv.Addr, dataDir)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
	}
	log.Println("codescan stopped")
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
