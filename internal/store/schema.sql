-- codescan SQLite schema (v1). Applied idempotently on every startup.
-- Timestamps are Unix seconds. See docs/codescan-v1-plan.md §4.

CREATE TABLE IF NOT EXISTS jobs (
  id          TEXT PRIMARY KEY,          -- uuid
  source_type TEXT NOT NULL,             -- git | zip | image
  source_ref  TEXT NOT NULL,             -- repo url / filename / image tag (token-stripped)
  status      TEXT NOT NULL,             -- queued|fetching|scanning|done|failed|canceled
  progress    TEXT,                      -- human-readable current stage
  error       TEXT,                      -- failure reason
  summary     TEXT,                      -- JSON: {critical,high,medium,low,info}
  created_at  INTEGER NOT NULL,
  started_at  INTEGER,
  finished_at INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id    TEXT NOT NULL REFERENCES jobs(id),
  tool      TEXT NOT NULL,               -- semgrep | trivy
  category  TEXT NOT NULL,               -- sast | sca | secret | iac | license | image
  severity  TEXT NOT NULL,               -- critical|high|medium|low|info
  rule_id   TEXT,                        -- semgrep rule / trivy CVE / check id
  title     TEXT,
  message   TEXT,
  file_path TEXT,
  line      INTEGER,
  pkg_name  TEXT,                        -- SCA/image: affected package
  pkg_ver   TEXT,
  fixed_ver TEXT,                        -- version that fixes the issue
  cve       TEXT,
  relationship TEXT,                     -- SCA: direct | indirect (dependency kind)
  usage     TEXT,                        -- SCA(direct/npm): used | unused_suspected
  raw       TEXT                         -- original JSON fragment, for export/trace
);

CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id);
