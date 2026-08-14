package source

import (
	"archive/zip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeGitURL(t *testing.T) {
	g := DefaultGuards()
	ok := []string{
		"https://github.com/foo/bar.git",
		"https://gitlab.com/foo/bar",
		"HTTPS://GitHub.com/Foo/Bar.git",
	}
	for _, u := range ok {
		if _, err := SanitizeGitURL(u, g); err != nil {
			t.Errorf("SanitizeGitURL(%q) unexpected error: %v", u, err)
		}
	}

	bad := []string{
		"http://github.com/foo/bar",            // not https
		"https://evil.com/foo/bar",             // host not allowed
		"https://user:pass@github.com/foo/bar", // embedded creds
		"https://github.com:8443/foo/bar",      // non-default port
		"file:///etc/passwd",                   // scheme
		"https://169.254.169.254/latest",       // metadata IP, not allowlisted
		"ssh://git@github.com/foo/bar",         // scheme
	}
	for _, u := range bad {
		if _, err := SanitizeGitURL(u, g); err == nil {
			t.Errorf("SanitizeGitURL(%q) should have errored", u)
		}
	}
}

func TestSanitizeStripsToken(t *testing.T) {
	// A clean URL never carries userinfo, so it is safe to store as source_ref.
	clean, err := SanitizeGitURL("https://github.com/foo/bar.git", DefaultGuards())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(clean, "@") {
		t.Errorf("clean URL should not contain credentials: %q", clean)
	}
}

func TestExtractZipRejectsZipSlip(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "evil.zip")
	writeZip(t, archive, map[string]string{
		"../escape.txt": "pwned",
	})

	dest := filepath.Join(dir, "out")
	err := ExtractArchive(context.Background(), archive, dest, DefaultGuards())
	if err == nil {
		t.Fatal("expected zip-slip rejection")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "escape.txt")); statErr == nil {
		t.Fatal("zip-slip wrote a file outside the destination")
	}
}

func TestExtractZipHappyPath(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "ok.zip")
	writeZip(t, archive, map[string]string{
		"src/main.go":    "package main",
		"README.md":      "# hi",
		"deep/a/b/c.txt": "x",
	})
	dest := filepath.Join(dir, "out")
	if err := ExtractArchive(context.Background(), archive, dest, DefaultGuards()); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "src", "main.go"))
	if err != nil || string(got) != "package main" {
		t.Fatalf("extracted content wrong: %q err=%v", got, err)
	}
}

func TestExtractZipSizeCap(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "big.zip")
	writeZip(t, archive, map[string]string{
		"a.txt": strings.Repeat("A", 4096),
	})
	dest := filepath.Join(dir, "out")
	g := Guards{MaxBytes: 1024} // smaller than the entry
	if err := ExtractArchive(context.Background(), archive, dest, g); err == nil {
		t.Fatal("expected size-cap rejection")
	}
}

// TestCloneStripsGitDir clones a local repo (file://, no network) and verifies
// the working files land while .git is removed — the fix that keeps a tokenized
// remote URL out of the scanned tree.
func TestCloneStripsGitDir(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	origin := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = origin
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(origin, "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "init")

	dest := filepath.Join(t.TempDir(), "src")
	if err := CloneGit(context.Background(), "file://"+origin, "", dest, DefaultGuards()); err != nil {
		t.Fatalf("clone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "main.go")); err != nil {
		t.Errorf("cloned working file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, ".git")); !os.IsNotExist(err) {
		t.Errorf(".git should have been stripped after clone (err=%v)", err)
	}
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}
