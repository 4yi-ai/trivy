package engine

import "testing"

func TestParseSemgrep(t *testing.T) {
	data := []byte(`{
	  "results": [
	    {"check_id":"python.lang.security.audit.dangerous-exec","path":"/work/src/app.py",
	     "start":{"line":42},"end":{"line":42},
	     "extra":{"message":"exec() is dangerous","severity":"ERROR","metadata":{}}}
	  ],
	  "errors": []
	}`)
	fs, err := parseSemgrep(data, "/work/src")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Severity != "high" {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.FilePath != "app.py" {
		t.Errorf("file = %q, want app.py (repo-relative)", f.FilePath)
	}
	if f.Line != 42 || f.Category != "sast" || f.Tool != "semgrep" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.Title != "dangerous-exec" {
		t.Errorf("title = %q, want dangerous-exec", f.Title)
	}
}

func TestParseTrivy(t *testing.T) {
	data := []byte(`{
	  "Results": [
	    {"Target":"go.mod","Class":"lang-pkgs","Type":"gomod",
	     "Vulnerabilities":[
	       {"VulnerabilityID":"CVE-2024-1234","PkgName":"golang.org/x/net",
	        "InstalledVersion":"0.1.0","FixedVersion":"0.2.0","Severity":"HIGH",
	        "Title":"net vuln","Description":"bad"}]},
	    {"Target":"config.yaml","Class":"config",
	     "Misconfigurations":[
	       {"ID":"KSV001","Title":"root container","Severity":"MEDIUM",
	        "Message":"runs as root","CauseMetadata":{"StartLine":7}}]},
	    {"Target":"secrets.env","Class":"secret",
	     "Secrets":[{"RuleID":"aws-access-key","Severity":"CRITICAL",
	        "Title":"AWS key","StartLine":3}]}
	  ]
	}`)
	fs, err := parseTrivy(data, "/work/src")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(fs) != 3 {
		t.Fatalf("want 3 findings, got %d", len(fs))
	}

	byCat := map[string]struct{}{}
	for _, f := range fs {
		byCat[f.Category] = struct{}{}
		if f.Tool != "trivy" {
			t.Errorf("tool = %q, want trivy", f.Tool)
		}
	}
	for _, want := range []string{"sca", "iac", "secret"} {
		if _, ok := byCat[want]; !ok {
			t.Errorf("missing category %q", want)
		}
	}

	// Spot-check the vuln mapping.
	var vuln *struct{ sev, cve, fixed, pkg string }
	for _, f := range fs {
		if f.Category == "sca" {
			vuln = &struct{ sev, cve, fixed, pkg string }{f.Severity, f.CVE, f.FixedVer, f.PkgName}
		}
	}
	if vuln == nil {
		t.Fatal("no sca finding")
	}
	if vuln.sev != "high" || vuln.cve != "CVE-2024-1234" || vuln.fixed != "0.2.0" || vuln.pkg != "golang.org/x/net" {
		t.Errorf("vuln mapping wrong: %+v", *vuln)
	}
}

func TestParseTrivyRelationship(t *testing.T) {
	data := []byte(`{
	  "Results": [
	    {"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm",
	     "Packages":[
	       {"ID":"tar@6.1.0","Name":"tar","Version":"6.1.0","Relationship":"direct"},
	       {"ID":"minimist@1.2.0","Name":"minimist","Version":"1.2.0","Relationship":"indirect"}],
	     "Vulnerabilities":[
	       {"VulnerabilityID":"CVE-A","PkgID":"tar@6.1.0","PkgName":"tar","InstalledVersion":"6.1.0","Severity":"HIGH"},
	       {"VulnerabilityID":"CVE-B","PkgID":"minimist@1.2.0","PkgName":"minimist","InstalledVersion":"1.2.0","Severity":"MEDIUM"},
	       {"VulnerabilityID":"CVE-C","PkgName":"orphan","InstalledVersion":"9.9","Severity":"LOW"}]}
	  ]
	}`)
	fs, err := parseTrivy(data, "/work")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rel := map[string]string{}
	for _, f := range fs {
		rel[f.CVE] = f.Relationship
	}
	if rel["CVE-A"] != "direct" {
		t.Errorf("tar should be direct, got %q", rel["CVE-A"])
	}
	if rel["CVE-B"] != "indirect" {
		t.Errorf("minimist should be indirect, got %q", rel["CVE-B"])
	}
	if rel["CVE-C"] != "" {
		t.Errorf("orphan pkg (no Packages entry) should have empty relationship, got %q", rel["CVE-C"])
	}
}

func TestNormSeverity(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical", "HIGH": "high", "ERROR": "high",
		"WARNING": "medium", "MEDIUM": "medium", "LOW": "low",
		"INFO": "info", "UNKNOWN": "info", "": "info",
	}
	for in, want := range cases {
		if got := normSeverity(in); got != want {
			t.Errorf("normSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
