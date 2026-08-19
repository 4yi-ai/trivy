package reach

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPackageOf(t *testing.T) {
	cases := map[string]string{
		"tar":              "tar",
		"tar/lib/pack":     "tar",
		"@nuxt/devtools":   "@nuxt/devtools",
		"@nuxt/devtools/x": "@nuxt/devtools",
		"./util":           "",
		"../a/b":           "",
		"/abs/path":        "",
		"@scope":           "",
	}
	for in, want := range cases {
		if got := PackageOf(in); got != want {
			t.Errorf("PackageOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUsedNPMPackages(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("src/app.js", `const tar = require('tar');
import swiper from 'swiper/vue';
import { x } from "@nuxt/devtools";
const local = require('./helper');`)
	write("src/Comp.vue", "<script>import axios from 'axios'</script>")
	// node_modules must be ignored, or every dep looks used.
	write("node_modules/lodash/index.js", "require('should-not-count')")

	used, err := UsedNPMPackages(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range []string{"tar", "swiper", "@nuxt/devtools", "axios"} {
		if !used[pkg] {
			t.Errorf("expected %q to be detected as used", pkg)
		}
	}
	if used["should-not-count"] {
		t.Errorf("node_modules should have been skipped")
	}
	if used["helper"] {
		t.Errorf("relative import should not be a package")
	}
}
