package api

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/4yi-ai/codescan/internal/scan"
	"github.com/4yi-ai/codescan/internal/source"
	"github.com/4yi-ai/codescan/internal/store"
)

// createScanRequest is the JSON POST /api/scans body (git source).
type createScanRequest struct {
	SourceType string `json:"source_type"`     // git (image → v2)
	SourceRef  string `json:"source_ref"`      // repo url
	Token      string `json:"token,omitempty"` // use-once; never stored/logged
}

// maxUploadBytes caps an uploaded archive (compressed). The uncompressed tree is
// separately capped by the source guards during extraction.
const maxUploadBytes = 200 << 20 // 200 MiB

// handleCreateScan creates a job and enqueues it, then returns immediately
// (202). It NEVER runs the scan synchronously — a big repo or cold start would
// blow past the platform gateway timeout and 502 (plan §5).
//
// Two content types:
//   - application/json  → git source (source_ref + optional use-once token)
//   - multipart/form-data → zip/tar upload (file field "archive")
func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		s.createZipScan(w, r)
		return
	}
	s.createGitScan(w, r)
}

// createGitScan handles the JSON path: validate + sanitize the URL (SSRF
// allowlist), keep the token in memory only, enqueue.
func (s *Server) createGitScan(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	req.SourceType = strings.TrimSpace(req.SourceType)

	switch req.SourceType {
	case store.SourceGit:
		// ok
	case store.SourceImage:
		writeErr(w, http.StatusNotImplemented, "image scanning is deferred to v2")
		return
	default:
		writeErr(w, http.StatusBadRequest, "source_type must be \"git\" (or upload a zip via multipart)")
		return
	}

	// SSRF guard: only https + allowlisted host, no embedded creds. The returned
	// URL is token-free and safe to persist as source_ref.
	cleanURL, err := source.SanitizeGitURL(req.SourceRef, s.guards)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	token := req.Token
	req.Token = "" // drop our struct copy immediately
	s.enqueueJob(w, r, store.SourceGit, cleanURL, scan.Secret{Token: token})
}

// createZipScan handles the multipart path: save the uploaded archive under the
// job's working dir, then enqueue with its local path (extraction happens in the
// worker, with zip-slip + size guards).
func (s *Server) createZipScan(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "upload too large or malformed")
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }()

	file, hdr, err := r.FormFile("archive")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing file field \"archive\"")
		return
	}
	defer file.Close()

	id, err := newID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "id generation failed")
		return
	}

	// Persist the upload where the worker can read it: <jobsDir>/<id>/upload.bin.
	jobDir := filepath.Join(s.mgr.JobsDir(), id)
	if err := os.MkdirAll(jobDir, 0o750); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not stage upload")
		return
	}
	uploadPath := filepath.Join(jobDir, "upload.bin")
	if err := saveUpload(uploadPath, file); err != nil {
		_ = os.RemoveAll(jobDir)
		writeErr(w, http.StatusInternalServerError, "could not save upload")
		return
	}

	// source_ref is the (sanitized) original filename — display only.
	ref := filepath.Base(filepath.Clean("/" + hdr.Filename))
	if ref == "" || ref == "." || ref == string(os.PathSeparator) {
		ref = "upload"
	}
	s.enqueueJobWithID(w, r, id, store.SourceZip, ref, scan.Secret{UploadPath: uploadPath})
}

// enqueueJob generates an id then delegates to enqueueJobWithID.
func (s *Server) enqueueJob(w http.ResponseWriter, r *http.Request, sourceType, ref string, sec scan.Secret) {
	id, err := newID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "id generation failed")
		return
	}
	s.enqueueJobWithID(w, r, id, sourceType, ref, sec)
}

// enqueueJobWithID creates the job row and enqueues it with its in-memory secret.
func (s *Server) enqueueJobWithID(w http.ResponseWriter, r *http.Request, id, sourceType, ref string, sec scan.Secret) {
	job, err := s.store.CreateJob(r.Context(), id, sourceType, ref)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not create job")
		return
	}
	if err := s.mgr.Enqueue(id, sec); err != nil {
		if errors.Is(err, scan.ErrQueueFull) {
			_ = s.store.Fail(r.Context(), id, "queue full, try again later")
			writeErr(w, http.StatusServiceUnavailable, "scan queue is full, try again later")
			return
		}
		writeErr(w, http.StatusInternalServerError, "enqueue failed")
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

// saveUpload streams an uploaded file to path.
func saveUpload(path string, r io.Reader) error {
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, r)
	return err
}

// handleListScans returns recent jobs, newest first.
func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.store.ListJobs(r.Context(), 100)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list jobs")
		return
	}
	if jobs == nil {
		jobs = []*store.Job{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": jobs})
}

// handleGetScan returns one job (the endpoint the UI polls for progress).
func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, job)
}

// handleListFindings returns a job's findings with optional filters.
func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetJob(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not load job")
		return
	}

	q := r.URL.Query()
	filter := store.FindingFilter{
		Severity: q.Get("severity"),
		Category: q.Get("category"),
		File:     q.Get("file"),
	}
	findings, err := s.store.ListFindings(r.Context(), id, filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not list findings")
		return
	}
	if findings == nil {
		findings = []store.Finding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}

// handleCancelScan cancels a queued/running job.
func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	changed, err := s.store.Cancel(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not cancel job")
		return
	}
	if !changed {
		writeErr(w, http.StatusConflict, "job already finished")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": store.StatusCanceled})
}

// handleDeleteScan deletes a finished scan (its findings, DB row, and on-disk
// working dir). Refuses to delete a queued/running scan — cancel it first.
func (s *Server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.store.DeleteJob(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "scan not found")
		return
	case errors.Is(err, store.ErrInProgress):
		writeErr(w, http.StatusConflict, "scan is still running — cancel it first")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "could not delete scan")
		return
	}
	// Best-effort: remove the job's working dir so uploads/clones don't linger.
	// The DB row is already gone, so a leftover dir is harmless if this fails.
	_ = os.RemoveAll(filepath.Join(s.mgr.JobsDir(), id))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// newID returns a random RFC-4122 v4 UUID string, without pulling in an external
// dependency.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
