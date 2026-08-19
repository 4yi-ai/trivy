// Package reach does lightweight, package-level reachability for the npm/JS
// ecosystem: it scans a project's own source for import/require statements and
// returns the set of packages actually referenced. It is NOT function-level
// reachability (that needs a call graph + a CVE→vulnerable-function DB); it only
// answers "is this package imported anywhere in the source at all?". Used to flag
// a DIRECT dependency that sits in the lockfile but is never imported as
// "suspected unused" so it can be deprioritized. See docs/codescan-v2-plan.md.
package reach

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// jsExts are the source extensions we look inside for imports.
var jsExts = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".mjs": true, ".cjs": true, ".vue": true,
}

// skipDirs are never scanned: installed deps and build output would make every
// package look "used" (deps import each other) and defeat the purpose.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "dist": true, "build": true,
	"vendor": true, "coverage": true, ".next": true, ".nuxt": true, ".output": true,
}

// module specifier extractors: require('x'), import ... from 'x', import 'x',
// import('x'), export ... from 'x'.
var specifierRes = []*regexp.Regexp{
	regexp.MustCompile(`require\(\s*['"]([^'"]+)['"]`),
	regexp.MustCompile(`(?:from|import)\s*\(?\s*['"]([^'"]+)['"]`),
}

const maxFileBytes = 2 << 20 // don't read files larger than 2 MiB

// UsedNPMPackages walks dir (skipping installed deps / build output) and returns
// the set of npm package names referenced by the project's own source.
func UsedNPMPackages(dir string) (map[string]bool, error) {
	used := make(map[string]bool)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep going
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !jsExts[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		if info, e := d.Info(); e == nil && info.Size() > maxFileBytes {
			return nil
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return nil
		}
		for _, re := range specifierRes {
			for _, m := range re.FindAllStringSubmatch(string(data), -1) {
				if pkg := PackageOf(m[1]); pkg != "" {
					used[pkg] = true
				}
			}
		}
		return nil
	})
	return used, err
}

// PackageOf turns an import specifier into its npm package name, or "" for a
// relative/local import. Handles scoped packages and subpath imports:
//
//	"tar"              -> "tar"
//	"tar/lib/pack"     -> "tar"
//	"@nuxt/devtools"   -> "@nuxt/devtools"
//	"@nuxt/devtools/x" -> "@nuxt/devtools"
//	"./util" / "/abs"  -> ""  (local, not a package)
func PackageOf(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return ""
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return ""
	}
	return parts[0]
}

// IsNPMLockPath reports whether a finding's file path points at an npm ecosystem
// manifest, so package-level import reachability applies to it.
func IsNPMLockPath(p string) bool {
	base := strings.ToLower(filepath.Base(p))
	switch base {
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "package.json":
		return true
	}
	return false
}
