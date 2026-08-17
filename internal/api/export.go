package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/4yi-ai/codescan/internal/store"
)

// handleExport streams a job's findings as JSON or SARIF 2.1.0.
//
//	GET /api/scans/{id}/export?format=json|sarif
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, err := s.store.GetJob(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load job")
		return
	}
	findings, err := s.store.ListFindings(r.Context(), id, store.FindingFilter{})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list findings")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	switch format {
	case "json":
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="codescan-%s.json"`, id))
		writeJSON(w, http.StatusOK, map[string]any{"scan": job, "findings": findings})
	case "sarif":
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="codescan-%s.sarif"`, id))
		writeJSON(w, http.StatusOK, toSARIF(findings))
	case "pdf":
		data, err := buildPDF(job, findings)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not build PDF report")
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="codescan-%s.pdf"`, id))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	default:
		writeErr(w, http.StatusBadRequest, "format must be json, sarif, or pdf")
	}
}

// toSARIF builds a minimal but valid SARIF 2.1.0 log from findings. Each tool
// (semgrep, trivy) becomes its own run; findings become results with a rule ref
// and one physical location.
func toSARIF(findings []store.Finding) map[string]any {
	// Group by tool so each run reports its own rules.
	type runAcc struct {
		rules   map[string]map[string]any // ruleID → rule object
		ruleIdx []string                  // stable order
		results []map[string]any
	}
	runs := map[string]*runAcc{}
	order := []string{}

	for _, f := range findings {
		acc := runs[f.Tool]
		if acc == nil {
			acc = &runAcc{rules: map[string]map[string]any{}}
			runs[f.Tool] = acc
			order = append(order, f.Tool)
		}
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = f.Category
		}
		if _, ok := acc.rules[ruleID]; !ok {
			acc.rules[ruleID] = map[string]any{
				"id":   ruleID,
				"name": firstNonEmptyStr(f.Title, ruleID),
			}
			acc.ruleIdx = append(acc.ruleIdx, ruleID)
		}

		result := map[string]any{
			"ruleId":  ruleID,
			"level":   sarifLevel(f.Severity),
			"message": map[string]any{"text": firstNonEmptyStr(f.Message, f.Title, ruleID)},
			"properties": map[string]any{
				"severity": f.Severity,
				"category": f.Category,
				"cve":      f.CVE,
				"package":  f.PkgName,
			},
		}
		if f.FilePath != "" {
			region := map[string]any{}
			if f.Line > 0 {
				region["startLine"] = f.Line
			}
			loc := map[string]any{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": f.FilePath},
				},
			}
			if len(region) > 0 {
				loc["physicalLocation"].(map[string]any)["region"] = region
			}
			result["locations"] = []any{loc}
		}
		acc.results = append(acc.results, result)
	}

	sarifRuns := make([]map[string]any, 0, len(order))
	for _, tool := range order {
		acc := runs[tool]
		rules := make([]map[string]any, 0, len(acc.ruleIdx))
		for _, rid := range acc.ruleIdx {
			rules = append(rules, acc.rules[rid])
		}
		sarifRuns = append(sarifRuns, map[string]any{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":  tool,
					"rules": rules,
				},
			},
			"results": acc.results,
		})
	}
	if len(sarifRuns) == 0 {
		// A valid SARIF log needs at least an empty run set is fine, but include
		// a codescan run so consumers see the source.
		sarifRuns = append(sarifRuns, map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "codescan"}},
			"results": []any{},
		})
	}

	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs":    sarifRuns,
	}
}

// sarifLevel maps codescan severity to SARIF's level enum.
func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "warning"
	}
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
