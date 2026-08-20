package api

import (
	"bytes"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"strings"

	"github.com/4yi-ai/codescan/internal/store"
)

// pages holds the parsed HTML templates. Each page is base.html + its own body,
// executed via the "base" template.
type pages struct {
	index *template.Template
	scan  *template.Template
}

// parsePages parses the embedded templates once at startup. It panics on a parse
// error because the templates are compiled into the binary — a failure is a
// build-time bug, not a runtime condition.
func parsePages(webFS fs.FS) *pages {
	must := func(name string) *template.Template {
		t, err := template.ParseFS(webFS, "templates/base.html", "templates/"+name)
		if err != nil {
			panic("parse templates (" + name + "): " + err.Error())
		}
		return t
	}
	return &pages{
		index: must("index.html"),
		scan:  must("scan.html"),
	}
}

// render executes t's "base" template into a buffer first, so a template error
// produces a 500 instead of a half-written 200 response.
func (s *Server) render(w http.ResponseWriter, t *template.Template, data any) {
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// handleIndex renders the new-scan page with the recent-scans list.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.store.ListJobs(r.Context(), 50)
	if err != nil {
		http.Error(w, "could not load scans", http.StatusInternalServerError)
		return
	}
	s.render(w, s.pages.index, map[string]any{
		"Scans":        jobs,
		"AllowedHosts": strings.Join(s.guards.AllowedHosts, ", "),
	})
}

// handleScanPage renders one scan's result page.
func (s *Server) handleScanPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, err := s.store.GetJob(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "could not load scan", http.StatusInternalServerError)
		return
	}
	findings, err := s.store.ListFindings(r.Context(), id, store.FindingFilter{})
	if err != nil {
		http.Error(w, "could not load findings", http.StatusInternalServerError)
		return
	}
	s.render(w, s.pages.scan, map[string]any{
		"Job":      job,
		"Findings": findings,
		"Stats":    buildStats(findings),
		"Tiers":    buildTiers(findings),
	})
}
