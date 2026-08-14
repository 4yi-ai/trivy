// Package source fetches scan inputs into a local working directory: a public
// (or use-once-token) git repo, or an uploaded zip/tar archive. It enforces the
// safety guards from plan §6/§9 — SSRF host allowlist, zip-slip rejection, and
// a post-fetch size cap — before any engine runs. Tokens are used once and never
// returned, stored, or logged.
package source

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Guards bounds a fetch. Zero values fall back to defaults in DefaultGuards.
type Guards struct {
	MaxBytes     int64    // reject once the fetched tree exceeds this
	AllowedHosts []string // git host allowlist (exact host match)
}

// DefaultGuards returns the v1 limits: 2 GiB, github.com/gitlab.com only.
func DefaultGuards() Guards {
	return Guards{
		MaxBytes:     2 << 30, // 2 GiB
		AllowedHosts: []string{"github.com", "gitlab.com"},
	}
}

// ErrTooLarge is returned when a fetched tree exceeds Guards.MaxBytes.
var ErrTooLarge = errors.New("source exceeds size limit")

// dirSize sums the byte size of all regular files under root. It stops early
// (returning ErrTooLarge) once the running total passes max, so a decompression
// bomb can't force a full walk.
func dirSize(root string, max int64) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			total += info.Size()
			if max > 0 && total > max {
				return ErrTooLarge
			}
		}
		return nil
	})
	if errors.Is(err, ErrTooLarge) {
		return total, ErrTooLarge
	}
	return total, err
}

// enforceSize checks the tree at dir against g.MaxBytes.
func enforceSize(dir string, g Guards) error {
	if g.MaxBytes <= 0 {
		return nil
	}
	if _, err := dirSize(dir, g.MaxBytes); err != nil {
		if errors.Is(err, ErrTooLarge) {
			return fmt.Errorf("%w (limit %d bytes)", ErrTooLarge, g.MaxBytes)
		}
		return err
	}
	return nil
}

// mustCtx returns ctx.Err() if already done, so long steps bail fast.
func mustCtx(ctx context.Context) error { return ctx.Err() }

// ensureEmptyDir creates dir (and parents), failing if it already has contents.
func ensureEmptyDir(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("work dir %s is not empty", dir)
	}
	return nil
}
