package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Job statuses. queued→fetching→scanning→done, or →failed/canceled.
const (
	StatusQueued   = "queued"
	StatusFetching = "fetching"
	StatusScanning = "scanning"
	StatusDone     = "done"
	StatusFailed   = "failed"
	StatusCanceled = "canceled"
)

// Source types.
const (
	SourceGit   = "git"
	SourceZip   = "zip"
	SourceImage = "image"
)

// ErrNotFound is returned when a job id does not exist.
var ErrNotFound = errors.New("not found")

// Summary is the per-severity finding count stored on a job (JSON column).
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Job is a scan task row.
type Job struct {
	ID         string   `json:"id"`
	SourceType string   `json:"source_type"`
	SourceRef  string   `json:"source_ref"` // token-stripped; never contains secrets
	Status     string   `json:"status"`
	Progress   string   `json:"progress,omitempty"`
	Error      string   `json:"error,omitempty"`
	Summary    *Summary `json:"summary,omitempty"`
	CreatedAt  int64    `json:"created_at"`
	StartedAt  int64    `json:"started_at,omitempty"`
	FinishedAt int64    `json:"finished_at,omitempty"`
}

// Finding is a normalized result row.
type Finding struct {
	ID           int64  `json:"id"`
	JobID        string `json:"job_id"`
	Tool         string `json:"tool"`
	Category     string `json:"category"`
	Severity     string `json:"severity"`
	RuleID       string `json:"rule_id,omitempty"`
	Title        string `json:"title,omitempty"`
	Message      string `json:"message,omitempty"`
	FilePath     string `json:"file_path,omitempty"`
	Line         int    `json:"line,omitempty"`
	PkgName      string `json:"pkg_name,omitempty"`
	PkgVer       string `json:"pkg_ver,omitempty"`
	FixedVer     string `json:"fixed_ver,omitempty"`
	CVE          string `json:"cve,omitempty"`
	Relationship string `json:"relationship,omitempty"` // SCA: direct | indirect
	Raw          string `json:"raw,omitempty"`
}

func now() int64 { return time.Now().Unix() }

// CreateJob inserts a new queued job. sourceRef must already be token-stripped.
func (s *Store) CreateJob(ctx context.Context, id, sourceType, sourceRef string) (*Job, error) {
	j := &Job{
		ID:         id,
		SourceType: sourceType,
		SourceRef:  sourceRef,
		Status:     StatusQueued,
		CreatedAt:  now(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO jobs (id, source_type, source_ref, status, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		j.ID, j.SourceType, j.SourceRef, j.Status, j.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert job: %w", err)
	}
	return j, nil
}

// GetJob returns one job or ErrNotFound.
func (s *Store) GetJob(ctx context.Context, id string) (*Job, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, source_type, source_ref, status, progress, error, summary,
		        created_at, started_at, finished_at
		 FROM jobs WHERE id = ?`, id)
	j, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return j, err
}

// ListJobs returns jobs newest-first, capped at limit (0 → 100).
func (s *Store) ListJobs(ctx context.Context, limit int) ([]*Job, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, source_type, source_ref, status, progress, error, summary,
		        created_at, started_at, finished_at
		 FROM jobs ORDER BY created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	defer rows.Close()

	var out []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanJob(row rowScanner) (*Job, error) {
	var (
		j                             Job
		progress, errMsg, summaryJSON sql.NullString
		startedAt, finishedAt         sql.NullInt64
	)
	if err := row.Scan(&j.ID, &j.SourceType, &j.SourceRef, &j.Status,
		&progress, &errMsg, &summaryJSON, &j.CreatedAt, &startedAt, &finishedAt); err != nil {
		return nil, err
	}
	j.Progress = progress.String
	j.Error = errMsg.String
	j.StartedAt = startedAt.Int64
	j.FinishedAt = finishedAt.Int64
	if summaryJSON.Valid && summaryJSON.String != "" {
		var sum Summary
		if err := json.Unmarshal([]byte(summaryJSON.String), &sum); err == nil {
			j.Summary = &sum
		}
	}
	return &j, nil
}

// SetStatus updates status + progress. When moving into a running state it
// stamps started_at (once); terminal states stamp finished_at.
func (s *Store) SetStatus(ctx context.Context, id, status, progress string) error {
	var startClause string
	switch status {
	case StatusFetching:
		// started_at set on first transition out of queued.
		startClause = ", started_at = COALESCE(started_at, ?)"
	}
	args := []any{status, progress}
	query := `UPDATE jobs SET status = ?, progress = ?`
	if startClause != "" {
		query += startClause
		args = append(args, now())
	}
	if isTerminal(status) {
		query += ", finished_at = ?"
		args = append(args, now())
	}
	// Never move a job out of a terminal state: a cancel (or failure) that
	// landed mid-run must not be clobbered by the runner's next progress update.
	query += ` WHERE id = ? AND status NOT IN (?, ?, ?)`
	args = append(args, id, StatusDone, StatusFailed, StatusCanceled)

	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("set status: %w", err)
	}
	return mustAffect(res)
}

// Fail marks a job failed with a reason (terminal).
func (s *Store) Fail(ctx context.Context, id, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET status = ?, error = ?, finished_at = ? WHERE id = ?`,
		StatusFailed, reason, now(), id)
	if err != nil {
		return fmt.Errorf("fail job: %w", err)
	}
	return mustAffect(res)
}

// SetError records a message in the error column WITHOUT changing status. Used
// for a partial-success warning (e.g. one scanner failed but others produced
// results, so the job is still done).
func (s *Store) SetError(ctx context.Context, id, msg string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE jobs SET error = ? WHERE id = ?`, msg, id)
	if err != nil {
		return fmt.Errorf("set error: %w", err)
	}
	return mustAffect(res)
}

// SetSummary writes the per-severity counts (JSON column).
func (s *Store) SetSummary(ctx context.Context, id string, sum Summary) error {
	b, err := json.Marshal(sum)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET summary = ? WHERE id = ?`, string(b), id)
	if err != nil {
		return fmt.Errorf("set summary: %w", err)
	}
	return mustAffect(res)
}

// Cancel marks a queued/running job canceled. Terminal jobs are left as-is and
// the returned bool reports whether a transition happened.
func (s *Store) Cancel(ctx context.Context, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET status = ?, finished_at = ?
		 WHERE id = ? AND status IN (?, ?, ?)`,
		StatusCanceled, now(), id, StatusQueued, StatusFetching, StatusScanning)
	if err != nil {
		return false, fmt.Errorf("cancel job: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Distinguish "not found" from "already terminal".
		if _, err := s.GetJob(ctx, id); err != nil {
			return false, err
		}
	}
	return n > 0, nil
}

// IsCanceled reports whether the job's persisted status is canceled. The worker
// polls this so an API cancel can stop an in-flight scan.
func (s *Store) IsCanceled(ctx context.Context, id string) (bool, error) {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM jobs WHERE id = ?`, id).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, err
	}
	return status == StatusCanceled, nil
}

// RecoverOrphans marks any job still in a non-terminal state (from a previous
// process) as failed. Called once at startup before serving traffic.
func (s *Store) RecoverOrphans(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE jobs SET status = ?, error = ?, finished_at = ?
		 WHERE status IN (?, ?, ?)`,
		StatusFailed, "interrupted by restart", now(),
		StatusQueued, StatusFetching, StatusScanning)
	if err != nil {
		return 0, fmt.Errorf("recover orphans: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// InsertFindings bulk-inserts findings in one transaction.
func (s *Store) InsertFindings(ctx context.Context, fs []Finding) error {
	if len(fs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO findings (job_id, tool, category, severity, rule_id, title,
		    message, file_path, line, pkg_name, pkg_ver, fixed_ver, cve, relationship, raw)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for i := range fs {
		f := &fs[i]
		if _, err := stmt.ExecContext(ctx, f.JobID, f.Tool, f.Category, f.Severity,
			f.RuleID, f.Title, f.Message, f.FilePath, f.Line, f.PkgName, f.PkgVer,
			f.FixedVer, f.CVE, f.Relationship, f.Raw); err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
	}
	return tx.Commit()
}

// FindingFilter narrows a findings query. Empty fields are ignored.
type FindingFilter struct {
	Severity string
	Category string
	File     string
}

// ListFindings returns a job's findings, optionally filtered, ordered by a
// fixed severity rank then file/line.
func (s *Store) ListFindings(ctx context.Context, jobID string, f FindingFilter) ([]Finding, error) {
	var conds []string
	args := []any{jobID}
	conds = append(conds, "job_id = ?")
	if f.Severity != "" {
		conds = append(conds, "severity = ?")
		args = append(args, f.Severity)
	}
	if f.Category != "" {
		conds = append(conds, "category = ?")
		args = append(args, f.Category)
	}
	if f.File != "" {
		conds = append(conds, "file_path LIKE ?")
		args = append(args, "%"+f.File+"%")
	}

	query := `SELECT id, job_id, tool, category, severity, rule_id, title, message,
	                 file_path, line, pkg_name, pkg_ver, fixed_ver, cve, relationship, raw
	          FROM findings WHERE ` + strings.Join(conds, " AND ") +
		` ORDER BY CASE severity
		     WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
		     WHEN 'low' THEN 3 ELSE 4 END,
		   CASE WHEN relationship = 'direct' THEN 0 ELSE 1 END,
		   file_path, line, id`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var (
			f                                                   Finding
			ruleID, title, msg, file, pkgName, pkgVer, fixedVer sql.NullString
			cve, relationship, raw                              sql.NullString
			line                                                sql.NullInt64
		)
		if err := rows.Scan(&f.ID, &f.JobID, &f.Tool, &f.Category, &f.Severity,
			&ruleID, &title, &msg, &file, &line, &pkgName, &pkgVer, &fixedVer,
			&cve, &relationship, &raw); err != nil {
			return nil, err
		}
		f.RuleID, f.Title, f.Message, f.FilePath = ruleID.String, title.String, msg.String, file.String
		f.Line = int(line.Int64)
		f.PkgName, f.PkgVer, f.FixedVer = pkgName.String, pkgVer.String, fixedVer.String
		f.CVE, f.Relationship, f.Raw = cve.String, relationship.String, raw.String
		out = append(out, f)
	}
	return out, rows.Err()
}

func isTerminal(status string) bool {
	switch status {
	case StatusDone, StatusFailed, StatusCanceled:
		return true
	}
	return false
}

func mustAffect(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
