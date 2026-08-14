# Vendored Semgrep rules

v1 ships Semgrep rulesets **inside the image** so scans work offline and never
depend on the Semgrep registry (the 4YI pod has restricted egress). See
docs/codescan-v1-plan.md §2.

**How it's populated:** the `Dockerfile` clones `github.com/semgrep/semgrep-rules`
into `rules/registry/` at build time (pinned via the `SEMGREP_RULES_REF` build
arg) and strips `.git` + non-rule dirs. The scanner reads `CODESCAN_RULES_DIR`
(`/app/rules`), finds the vendored `.yaml`/`.yml` rules, and runs
`semgrep --config /app/rules` — no network needed.

This directory itself only holds this README in git; the rules land under
`rules/registry/` in the built image (git-ignored locally so the large ruleset
isn't committed to the app repo).

**Local dev without the vendored rules:** when `rules/` has no rule files the
engine falls back to the `p/default` registry pack, which requires network. That
path is for a developer laptop only; production always uses the vendored copy.
