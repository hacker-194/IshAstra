# syntax=docker/dockerfile:1
# Strix ScopeGate - production image.
#
#   docker build -t strix:3.5.0 .
#   docker run -p 8000:8000 -e STRIX_ENV=production \
#     -e STRIX_API_KEY=... -e STRIX_AUDIT_HMAC_KEY=... \
#     -e STRIX_ENCRYPTION_KEY=... strix:3.5.0
#
# Installs from constraints.txt (the same set CI uses) instead of a package
# manager the project does not use; the runtime stage copies only the venv.

# =============================================================================
# Build stage
# =============================================================================
FROM python:3.12-slim AS builder

# libxmlsec1/libxml2 build against these; python3-saml and WeasyPrint need them.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    pkg-config \
    libxml2-dev \
    libxslt1-dev \
    libxmlsec1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# README.md is required by pyproject (readme = "README.md"); LICENSE ships in the wheel.
COPY pyproject.toml constraints.txt README.md LICENSE ./
COPY src ./src

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -c constraints.txt ".[k8s-jobs,postgres]"

# =============================================================================
# Runtime stage
# =============================================================================
FROM python:3.12-slim AS runtime

# Shared libraries (XML/SAML, WeasyPrint) plus the external scanners the
# adapters require: without these every assessment reports "no usable coverage".
ARG NUCLEI_VERSION=3.11.1
ARG TARGETARCH=amd64
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    nmap \
    nikto \
    sqlmap \
    libxml2 \
    libxslt1.1 \
    libxmlsec1 \
    libxmlsec1-openssl \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Nuclei releases ship as a zip; pin the version CI uses.
RUN curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
    && python -c "from zipfile import ZipFile; ZipFile('/tmp/nuclei.zip').extract('nuclei', '/usr/local/bin')" \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

RUN groupadd -r -g 10001 strix \
    && useradd -r -u 10001 -g strix -d /app -s /usr/sbin/nologin strix \
    && mkdir -p /app /var/lib/strix /tmp/strix \
    && chown -R strix:strix /app /var/lib/strix /tmp/strix

# The nuclei adapter reads ${HOME}/nuclei-templates; bake the official set in so
# a scan does not depend on egress at run time.
RUN HOME=/var/lib/strix nuclei -update-templates -disable-update-check \
    && chown -R strix:strix /var/lib/strix/nuclei-templates

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # SQLite lives on the writable volume; /app stays read-only.
    STRIX_DB=/var/lib/strix/strix.db \
    HOME=/var/lib/strix

WORKDIR /app
USER strix

EXPOSE 8000

# /api/health is the unauthenticated liveness route (the old /health is a 404).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

ENTRYPOINT ["strix"]
# The CLI has no `api` group: the server command is `serve`.
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
