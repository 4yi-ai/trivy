# syntax=docker/dockerfile:1

# ---------- build stage: compile the Go binary (static, no cgo) ----------
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 keeps the binary static (modernc.org/sqlite is pure Go), so it
# runs on the slim runtime image without libc surprises.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/codescan ./cmd/codescan

# ---------- runtime stage: Go binary + Semgrep + Trivy CLIs ----------
FROM python:3.12-slim-bookworm AS runtime

# Pin Trivy to a REAL released version (github.com/aquasecurity/trivy/releases).
# NOTE: 0.58.1 never existed and 404'd the download, failing the whole build.
# Semgrep tracks latest for now (pin in v2). See plan §8.
ARG TRIVY_VERSION=0.73.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*

# Semgrep (Python package).
RUN pip install --no-cache-dir semgrep

# Trivy (single release binary).
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) tarch="Linux-64bit" ;; \
      arm64) tarch="Linux-ARM64" ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${tarch}.tar.gz" -o /tmp/trivy.tgz; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tgz; \
    trivy --version

# Non-root user aligned with 4yi-app.json storage.fsGroup (10001) so the
# process can write the persistent volume.
RUN groupadd -g 10001 codescan \
    && useradd -u 10001 -g 10001 -m -s /usr/sbin/nologin codescan

COPY --from=build /out/codescan /usr/local/bin/codescan
COPY rules /app/rules

# Vendor Semgrep's community rules INTO the image so scans run fully offline —
# the 4YI pod has restricted egress and must not depend on the Semgrep registry
# (plan §2). The engine points CODESCAN_RULES_DIR here and loads them locally.
# Pin by ref for reproducibility; bump deliberately. .git is stripped to save space.
ARG SEMGREP_RULES_REF=develop
RUN set -eux; \
    git clone --depth 1 --branch "${SEMGREP_RULES_REF}" \
        https://github.com/semgrep/semgrep-rules.git /app/rules/registry; \
    rm -rf /app/rules/registry/.git; \
    # Prune dirs that hold no OSS-usable rules (Apex needs Semgrep Pro) or non-rule
    # material, to keep the image lean and cut scan noise.
    find /app/rules/registry -type d \( -name '.github' -o -name 'stats' -o -name 'template' -o -name 'apex' \) -prune -exec rm -rf {} +; \
    # CRITICAL: remove repo-level config files (e.g. .pre-commit-config.yaml, mkdocs.yml).
    # `semgrep --config <dir>` loads every *.yaml as a rule; ONE non-rule config
    # makes semgrep exit 7 ("invalid configuration file found") and fail the whole
    # scan — even with 2000+ valid rules present. Verified locally.
    find /app/rules/registry -type f \( -name '.*.yaml' -o -name '.*.yml' -o -name 'mkdocs.yml' \) -delete; \
    # Drop test fixtures (never rules) to slim the image.
    find /app/rules/registry -type f \( -name '*.test.yaml' -o -name '*.test.yml' -o -name '*.fixed.*' \) -delete; \
    echo "vendored semgrep rules: $(find /app/rules/registry -name '*.yaml' -o -name '*.yml' | wc -l) files"

ENV HOST=0.0.0.0 \
    PORT=8080 \
    DATA_DIR=/app/data \
    TRIVY_CACHE_DIR=/app/data/trivy-cache \
    CODESCAN_RULES_DIR=/app/rules

RUN mkdir -p /app/data && chown -R 10001:10001 /app
USER 10001:10001
WORKDIR /app
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:8080/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/codescan"]
