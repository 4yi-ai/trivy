package engine

import (
	"context"
	"log"
	"os/exec"
	"time"
)

// PrewarmTrivy downloads the Trivy vulnerability DB into the cache
// (TRIVY_CACHE_DIR, on the persistent volume) so the FIRST real scan doesn't pay
// the multi-hundred-MB download and so it isn't re-fetched per scan. It is meant
// to run in a background goroutine at startup and must NEVER block /healthz
// (plan §6) — the caller launches it with `go`.
//
// It is best-effort: a failure (no egress, trivy absent) is logged and the app
// keeps serving; scans will download the DB lazily instead.
func PrewarmTrivy(ctx context.Context) {
	if !available("trivy") {
		log.Println("trivy prewarm: trivy not installed, skipping")
		return
	}
	log.Println("trivy prewarm: downloading vulnerability DB in background...")
	start := time.Now()

	// Generous timeout: the DB is large and the first pull can be slow, but we
	// don't want a hung download to leak forever.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	// --download-db-only fetches the DB without scanning anything. Cache location
	// comes from TRIVY_CACHE_DIR in the environment.
	cmd := exec.CommandContext(ctx, "trivy", "image", "--download-db-only", "--no-progress")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("trivy prewarm: failed (%v): %s — scans will fetch the DB lazily", err, tail(string(out)))
		return
	}
	log.Printf("trivy prewarm: DB ready in %s", time.Since(start).Round(time.Second))
}
