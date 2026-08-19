package api

import (
	"os"
	"testing"

	"github.com/4yi-ai/codescan/internal/store"
)

// TestBuildPDFPriority renders a report with custom-rule findings mixed into a
// large SCA list and writes it to CODESCAN_PDF_OUT (if set) for visual review.
// It asserts the PDF is produced non-empty; the layout is checked by eye.
func TestBuildPDFPriority(t *testing.T) {
	job := &store.Job{
		ID:         "e9505ce6-9fbc-4f06-ae44-ffd4f60570cc",
		SourceType: "zip",
		SourceRef:  "bieases-shop-develop.zip",
		Status:     "done",
		Summary:    &store.Summary{Critical: 6, High: 170, Medium: 311, Low: 23, Info: 62},
	}

	var findings []store.Finding
	// Custom-rule (priority) findings — the ones the top box should surface.
	custom := []struct {
		rule, path string
		line       int
	}{
		{"rules.custom.idor-user-controlled-userid-fallback", "bieases-shop-develop/tigshop-service/.../o2o/impl/UserPickupInfoServiceImpl.java", 72},
		{"rules.custom.idor-user-controlled-userid-fallback", "bieases-shop-develop/tigshop-service/.../order/impl/OrderCheckServiceImpl.java", 3039},
		{"rules.custom.idor-user-controlled-userid-fallback", "bieases-shop-develop/tigshop-service/.../user/impl/UserAddressServiceImpl.java", 159},
		{"rules.custom.idor-user-controlled-userid-fallback", "bieases-shop-develop/tigshop-service/.../user/impl/UserCouponServiceImpl.java", 274},
		{"rules.custom.sqli-orderby-dynamic-column", "bieases-shop-develop/tigshop-service/.../panel/impl/StatisticsUserServiceImpl.java", 212},
		{"rules.custom.sqli-orderby-dynamic-column", "bieases-shop-develop/tigshop-service/.../product/impl/ProductServiceImpl.java", 312},
		{"rules.custom.ssrf-outbound-fetch-dynamic-url", "bieases-shop-develop/tigshop-service/.../decorate/impl/DecorateShareServiceImpl.java", 166},
		{"rules.custom.ssrf-outbound-fetch-dynamic-url", "bieases-shop-develop/tigshop-service/.../setting/impl/ConfigServiceImpl.java", 1573},
	}
	for _, c := range custom {
		findings = append(findings, store.Finding{
			Tool: "semgrep", Category: "sast", Severity: "high",
			RuleID: c.rule, Title: c.rule, FilePath: c.path, Line: c.line,
			Message: "Business-logic issue found by a CodeScan custom rule.",
		})
	}
	// P2: direct-dependency highs (fixable by the user).
	for i := 0; i < 8; i++ {
		findings = append(findings, store.Finding{
			Tool: "trivy", Category: "sca", Severity: "high",
			RuleID: "CVE-2026-4448" + string(rune('0'+i%10)),
			Title:  "axios prototype pollution", FilePath: "view/admin/package-lock.json",
			PkgName: "axios", PkgVer: "1.13.2", FixedVer: "1.16.0", Relationship: "direct", Usage: "used",
			Message: "Axios is a promise based HTTP client. Prototype pollution ...",
		})
	}
	findings = append(findings, store.Finding{
		Tool: "trivy", Category: "sca", Severity: "critical",
		RuleID: "CVE-2026-27212", Title: "swiper prototype pollution",
		FilePath: "view/admin/package-lock.json", PkgName: "swiper", PkgVer: "11.2.10",
		FixedVer: "12.1.2", Relationship: "direct", Usage: "used", Message: "Swiper ... RCE.",
	})
	// P3: config + secret + generic SAST.
	findings = append(findings,
		store.Finding{Tool: "trivy", Category: "iac", Severity: "medium", RuleID: "DS-0002",
			Title: "missing USER", FilePath: "tigshop-api/Dockerfile", Message: "Specify a non-root USER."},
		store.Finding{Tool: "trivy", Category: "secret", Severity: "high", RuleID: "generic-secret",
			Title: "Generic Secret detected", FilePath: "tigshop-api/src/main/resources/application.yaml", Line: 224},
		store.Finding{Tool: "semgrep", Category: "sast", Severity: "info",
			RuleID: "rules.registry.python.lang.best-practice.arbitrary-sleep",
			Title:  "arbitrary-sleep", FilePath: "database/scripts/x.py", Line: 56, Message: "time.sleep() call."},
	)
	// P4: transitive dependencies.
	for i := 0; i < 6; i++ {
		findings = append(findings, store.Finding{
			Tool: "trivy", Category: "sca", Severity: "high",
			RuleID: "CVE-2026-2790" + string(rune('0'+i%10)),
			Title:  "minimatch ReDoS", FilePath: "view/Tigshop-o2o-Pc/package-lock.json",
			PkgName: "minimatch", PkgVer: "3.1.2", FixedVer: "10.2.3", Relationship: "indirect",
			Message: "minimatch ReDoS via crafted glob ...",
		})
	}

	pdf, err := buildPDF(job, findings)
	if err != nil {
		t.Fatalf("buildPDF: %v", err)
	}
	if len(pdf) < 1000 {
		t.Fatalf("PDF suspiciously small: %d bytes", len(pdf))
	}
	if out := os.Getenv("CODESCAN_PDF_OUT"); out != "" {
		if err := os.WriteFile(out, pdf, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		t.Logf("wrote %d bytes to %s", len(pdf), out)
	}
}
