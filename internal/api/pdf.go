package api

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/go-pdf/fpdf"

	"github.com/4yi-ai/codescan/internal/store"
)

// severity display order + colors for the PDF report.
type sevStyle struct {
	key     string
	label   string // short tag shown on each finding (tiers mix severities)
	r, g, b int
}

var pdfSeverities = []sevStyle{
	{"critical", "CRIT", 220, 53, 69},
	{"high", "HIGH", 255, 140, 66},
	{"medium", "MED", 214, 170, 30},
	{"low", "LOW", 90, 170, 210},
	{"info", "INFO", 140, 140, 140},
}

// sevRank orders severities most-severe first; unknown sorts last.
func sevRank(sev string) int {
	for i, s := range pdfSeverities {
		if s.key == strings.ToLower(sev) {
			return i
		}
	}
	return len(pdfSeverities)
}

func sevStyleOf(sev string) sevStyle {
	for _, s := range pdfSeverities {
		if s.key == strings.ToLower(sev) {
			return s
		}
	}
	return sevStyle{"info", "INFO", 140, 140, 140}
}

// priorityTier is a top-level report section. Findings are bucketed into these
// (most-actionable first) instead of grouped by severity, so the code
// vulnerabilities and the deps you can fix yourself aren't buried under
// hundreds of transitive CVEs. Chosen ordering: type-based priority tiers.
type priorityTier struct {
	label    string
	subtitle string
	r, g, b  int
}

var priorityTiers = []priorityTier{
	{"P1  CODE VULNERABILITIES (verified)",
		"Business-logic bugs found by CodeScan's own rules (access-control/IDOR, SQL injection, SSRF). NOT dependency CVEs - fix these first.",
		150, 32, 44},
	{"P2  CODE ISSUES (SAST scan)",
		"Static-analysis findings in your own code (injection, weak crypto, insecure TLS, best-practice). Sorted by severity.",
		196, 76, 52},
	{"P3  DIRECT DEPENDENCIES",
		"Vulnerable packages you declared yourself - fix by bumping the version. Sorted by severity.",
		56, 110, 200},
	{"P4  SECRETS & CONFIG",
		"Exposed secrets/keys and IaC (Dockerfile) misconfig. Rotate leaked secrets; harden config.",
		200, 150, 40},
	{"P5  TRANSITIVE DEPENDENCIES",
		"Pulled in indirectly by other packages - usually fixed by bumping a parent dependency. Sorted by severity.",
		140, 140, 140},
}

// isCustomRule reports whether a finding came from CodeScan's own hand-written
// rules (rules/custom/*), i.e. the verified business-logic code vulnerabilities.
func isCustomRule(f *store.Finding) bool {
	return strings.HasPrefix(f.RuleID, "rules.custom.")
}

// tierOf buckets a finding into one of the 4 priority tiers (1-based).
func tierOf(f *store.Finding) int {
	cat := strings.ToLower(f.Category)
	switch {
	case cat == "sast" && isCustomRule(f):
		return 1 // verified code vuln (custom rules)
	case cat == "sast":
		return 2 // generic code scan (community SAST rules)
	case cat == "sca" && f.Relationship == "direct":
		return 3 // direct dependency
	case cat == "secret" || cat == "iac":
		return 4 // exposed secrets + IaC config
	default:
		return 5 // transitive / unclassified dependency
	}
}

// buildPDF renders a human-readable security report for a scan. It uses a
// pure-Go PDF library (no headless browser), so it works offline in the pod.
// Layout: summary badges -> stats table (category x severity) -> findings in
// type-based priority tiers (most actionable first).
func buildPDF(job *store.Job, findings []store.Finding) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 15)
	pdf.AddPage()

	// Title
	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(25, 28, 35)
	pdf.Cell(0, 10, "CodeScan Security Report")
	pdf.Ln(11)

	// Metadata
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(90, 96, 105)
	for _, m := range []string{
		"Source:  " + job.SourceRef,
		"Type:  " + job.SourceType + "        Status:  " + job.Status,
		"Scan ID:  " + job.ID,
	} {
		pdf.Cell(0, 5, pdfSafe(m))
		pdf.Ln(5)
	}
	pdf.Ln(3)

	// Summary badges
	sum := job.Summary
	if sum == nil {
		sum = &store.Summary{}
	}
	drawSummary(pdf, sum, len(findings))
	pdf.Ln(10)

	if len(findings) == 0 {
		pdf.SetFont("Helvetica", "", 11)
		pdf.SetTextColor(60, 120, 80)
		pdf.Cell(0, 8, "No findings. The scanned source is clean.")
		return output(pdf)
	}

	// Stats table: category (SCA/SAST/IaC/Secret) x severity.
	drawStatsTable(pdf, findings)
	pdf.Ln(8)

	// Bucket findings into priority tiers, each sorted by severity.
	tiers := map[int][]store.Finding{}
	for _, f := range findings {
		t := tierOf(&f)
		tiers[t] = append(tiers[t], f)
	}
	for t := range tiers {
		fs := tiers[t]
		sort.SliceStable(fs, func(i, j int) bool {
			return sevRank(fs[i].Severity) < sevRank(fs[j].Severity)
		})
		tiers[t] = fs
	}

	for i, tier := range priorityTiers {
		fs := tiers[i+1]
		if len(fs) == 0 {
			continue
		}
		drawTierHeader(pdf, tier, len(fs))
		for j := range fs {
			renderFinding(pdf, &fs[j])
		}
		pdf.Ln(4)
	}

	return output(pdf)
}

func output(pdf *fpdf.Fpdf) ([]byte, error) {
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func drawSummary(pdf *fpdf.Fpdf, s *store.Summary, total int) {
	pdf.SetFont("Helvetica", "B", 10)
	items := []struct {
		label   string
		n       int
		r, g, b int
	}{
		{"Critical", s.Critical, 220, 53, 69},
		{"High", s.High, 255, 140, 66},
		{"Medium", s.Medium, 214, 170, 30},
		{"Low", s.Low, 90, 170, 210},
		{"Info", s.Info, 140, 140, 140},
	}
	for _, it := range items {
		pdf.SetFillColor(it.r, it.g, it.b)
		pdf.SetTextColor(255, 255, 255)
		txt := fmt.Sprintf(" %d %s ", it.n, it.label)
		w := pdf.GetStringWidth(txt) + 3
		pdf.CellFormat(w, 7, txt, "", 0, "C", true, 0, "")
		pdf.CellFormat(2, 7, "", "", 0, "L", false, 0, "")
	}
	pdf.SetTextColor(120, 120, 120)
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(0, 7, fmt.Sprintf("  %d total", total), "", 0, "L", false, 0, "")
}

// drawStatsTable renders a category x severity count matrix so the reader sees
// the shape of the report (how many SCA vs SAST vs IaC, at each severity) before
// the detail.
func drawStatsTable(pdf *fpdf.Fpdf, findings []store.Finding) {
	// rows in display order; only shown if they have any findings.
	rows := []struct{ key, label string }{
		{"sca", "SCA  (dependencies)"},
		{"sast", "SAST  (code)"},
		{"iac", "IaC  (config)"},
		{"secret", "Secret"},
	}
	// counts[category][severityKey]
	counts := map[string]map[string]int{}
	for _, f := range findings {
		cat := strings.ToLower(f.Category)
		if counts[cat] == nil {
			counts[cat] = map[string]int{}
		}
		counts[cat][strings.ToLower(f.Severity)]++
	}

	const (
		wLabel = 55.0
		wCell  = 21.0
	)
	sevCols := []sevStyle{
		{"critical", "Critical", 220, 53, 69},
		{"high", "High", 255, 140, 66},
		{"medium", "Medium", 214, 170, 30},
		{"low", "Low", 90, 170, 210},
		{"info", "Info", 140, 140, 140},
	}

	// Header row.
	pdf.SetFont("Helvetica", "B", 8.5)
	pdf.SetFillColor(238, 240, 243)
	pdf.SetTextColor(70, 74, 82)
	pdf.CellFormat(wLabel, 6.5, " Category", "", 0, "L", true, 0, "")
	for _, c := range sevCols {
		pdf.CellFormat(wCell, 6.5, c.label, "", 0, "C", true, 0, "")
	}
	pdf.CellFormat(wCell, 6.5, "Total", "", 1, "C", true, 0, "")

	// Data rows.
	pdf.SetFont("Helvetica", "", 8.5)
	for _, r := range rows {
		cc := counts[r.key]
		if cc == nil {
			continue
		}
		rowTotal := 0
		pdf.SetTextColor(45, 48, 55)
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.CellFormat(wLabel, 6, " "+r.label, "B", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8.5)
		for _, c := range sevCols {
			n := cc[c.key]
			rowTotal += n
			if n > 0 {
				pdf.SetTextColor(c.r, c.g, c.b)
				pdf.SetFont("Helvetica", "B", 8.5)
			} else {
				pdf.SetTextColor(190, 193, 198)
				pdf.SetFont("Helvetica", "", 8.5)
			}
			pdf.CellFormat(wCell, 6, cell(n), "B", 0, "C", false, 0, "")
		}
		pdf.SetTextColor(45, 48, 55)
		pdf.SetFont("Helvetica", "B", 8.5)
		pdf.CellFormat(wCell, 6, cell(rowTotal), "B", 1, "C", false, 0, "")
	}
}

func cell(n int) string {
	if n == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", n)
}

// drawTierHeader draws a colored banner + subtitle for a priority tier.
func drawTierHeader(pdf *fpdf.Fpdf, t priorityTier, n int) {
	pdf.SetFillColor(t.r, t.g, t.b)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 8, pdfSafe(fmt.Sprintf("  %s  (%d)", t.label, n)), "", 1, "L", true, 0, "")
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(90, 96, 105)
	pdf.MultiCell(0, 4, pdfSafe(t.subtitle), "", "L", false)
	pdf.Ln(1.5)
}

// depPill draws a small inline tag (severity / DIRECT / transitive). It advances
// the cursor on the same line so the finding title can follow.
func depPill(pdf *fpdf.Fpdf, label string, r, g, b int, filled bool) {
	pdf.SetFont("Helvetica", "B", 6.5)
	txt := " " + label + " "
	w := pdf.GetStringWidth(txt) + 1.5
	if filled {
		pdf.SetFillColor(r, g, b)
		pdf.SetTextColor(255, 255, 255)
		pdf.CellFormat(w, 4.4, txt, "", 0, "C", true, 0, "")
	} else {
		pdf.SetTextColor(r, g, b)
		pdf.CellFormat(w, 4.4, txt, "", 0, "C", false, 0, "")
	}
	pdf.CellFormat(1.5, 4.4, "", "", 0, "L", false, 0, "")
}

func renderFinding(pdf *fpdf.Fpdf, f *store.Finding) {
	o := sevStyleOf(f.Severity)

	// Colored left keyline for the severity.
	y := pdf.GetY()
	pdf.SetFillColor(o.r, o.g, o.b)
	pdf.Rect(15, y, 1.2, 4, "F")

	// Header line: severity pill + DIRECT/transitive pill + [category] rule/CVE.
	rule := f.RuleID
	if rule == "" {
		rule = f.Title
	}
	pdf.SetX(18)
	depPill(pdf, o.label, o.r, o.g, o.b, true) // severity tag (tiers mix severities)
	switch f.Relationship {
	case "direct":
		depPill(pdf, "DIRECT", 56, 132, 255, true)
		if f.Usage == "unused_suspected" {
			depPill(pdf, "unused?", 190, 150, 40, false)
		}
	case "indirect":
		depPill(pdf, "transitive", 150, 150, 150, false)
	}
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetTextColor(35, 38, 45)
	pdf.MultiCell(0, 5, pdfSafe(fmt.Sprintf("[%s] %s", f.Category, rule)), "", "L", false)

	// Location + package line
	loc := f.FilePath
	if f.Line > 0 {
		loc += fmt.Sprintf(":%d", f.Line)
	}
	if f.PkgName != "" {
		loc += "    " + f.PkgName
		if f.PkgVer != "" {
			loc += "@" + f.PkgVer
		}
		if f.FixedVer != "" {
			loc += "  ->  fix " + f.FixedVer
		}
	}
	if strings.TrimSpace(loc) != "" {
		pdf.SetX(18)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(120, 125, 135)
		pdf.MultiCell(0, 4, pdfSafe(loc), "", "L", false)
	}

	// Detail message
	msg := f.Message
	if msg == "" {
		msg = f.Title
	}
	if strings.TrimSpace(msg) != "" && msg != rule {
		pdf.SetX(18)
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(70, 74, 82)
		pdf.MultiCell(0, 4, pdfSafe(msg), "", "L", false)
	}
	pdf.Ln(2.5)
}

// pdfSafe keeps printable ASCII (the core PDF fonts are Latin-1), replacing
// anything else with a space so exotic characters in CVE text can't corrupt the
// output.
func pdfSafe(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}
