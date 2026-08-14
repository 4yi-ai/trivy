package source

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ErrZipSlip is returned when an archive entry would extract outside destDir.
var ErrZipSlip = errors.New("archive entry escapes destination (zip-slip)")

// ExtractArchive unpacks the archive at srcPath into destDir, auto-detecting
// zip vs tar/tar.gz. It enforces zip-slip protection and a total-uncompressed
// cap (g.MaxBytes) so a decompression bomb can't fill the disk. Symlinks and
// non-regular entries are skipped, not extracted.
func ExtractArchive(ctx context.Context, srcPath, destDir string, g Guards) error {
	if err := ensureEmptyDir(destDir); err != nil {
		return err
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Sniff the first bytes: "PK\x03\x04" → zip, "\x1f\x8b" → gzip(tar).
	var magic [4]byte
	n, _ := io.ReadFull(f, magic[:])
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	switch {
	case n >= 4 && magic[0] == 'P' && magic[1] == 'K':
		return extractZip(ctx, srcPath, destDir, g)
	case n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		return extractTar(ctx, f, destDir, g, true)
	default:
		// Assume uncompressed tar; extractTar will error if it isn't.
		return extractTar(ctx, f, destDir, g, false)
	}
}

// safeJoin joins destDir and an archive entry name, REJECTING (not sanitizing)
// any absolute path or ".." traversal — the plan calls for rejecting "../"
// rather than silently rewriting it. Archive entries always use forward slashes.
func safeJoin(destDir, name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "/") || filepath.IsAbs(name) {
		return "", fmt.Errorf("%w: %q", ErrZipSlip, name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("%w: %q", ErrZipSlip, name)
		}
	}
	target := filepath.Join(destDir, filepath.FromSlash(name))
	// Defense in depth: confirm the joined path stays under destDir.
	rel, err := filepath.Rel(destDir, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("%w: %q", ErrZipSlip, name)
	}
	return target, nil
}

func extractZip(ctx context.Context, srcPath, destDir string, g Guards) error {
	zr, err := zip.OpenReader(srcPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()

	var written int64
	for _, zf := range zr.File {
		if err := mustCtx(ctx); err != nil {
			return err
		}
		target, err := safeJoin(destDir, zf.Name)
		if err != nil {
			return err
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
			continue
		}
		if !zf.FileInfo().Mode().IsRegular() {
			continue // skip symlinks/devices
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		written, err = writeFileCapped(target, rc, written, g.MaxBytes)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTar(ctx context.Context, r io.Reader, destDir string, g Guards, gzipped bool) error {
	if gzipped {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return fmt.Errorf("open gzip: %w", err)
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	var written int64
	for {
		if err := mustCtx(ctx); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		target, err := safeJoin(destDir, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			written, err = writeFileCapped(target, tr, written, g.MaxBytes)
			if err != nil {
				return err
			}
		default:
			// skip symlinks, hardlinks, devices, fifos
		}
	}
}

// writeFileCapped writes r to path, creating parent dirs, and returns the new
// running total. It aborts with ErrTooLarge if the total would exceed max.
func writeFileCapped(path string, r io.Reader, running, max int64) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return running, err
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return running, err
	}
	defer out.Close()

	var limit io.Reader = r
	if max > 0 {
		// +1 so hitting exactly max is fine but exceeding trips the guard.
		limit = io.LimitReader(r, max-running+1)
	}
	n, err := io.Copy(out, limit)
	if err != nil {
		return running, err
	}
	running += n
	if max > 0 && running > max {
		return running, fmt.Errorf("%w (limit %d bytes)", ErrTooLarge, max)
	}
	return running, nil
}
