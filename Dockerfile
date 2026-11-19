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
ARG NUCLEI_TEMPLATES_VERSION=10.5.2
ARG NIKTO_VERSION=2.5.0
ARG TARGETARCH=amd64
# nikto is not packaged in Debian bookworm; install the pinned upstream release
# and its Perl dependencies instead of letting apt fail the whole build.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    nmap \
    sqlmap \
    perl \
    libwww-perl \
    libnet-ssleay-perl \
    libjson-perl \
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

RUN curl -fsSL -o /tmp/nikto.tar.gz \
      "https://github.com/sullo/nikto/archive/refs/tags/${NIKTO_VERSION}.tar.gz" \
    && mkdir -p /opt/nikto \
    && tar -xzf /tmp/nikto.tar.gz -C /opt/nikto --strip-components=1 \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && rm -f /tmp/nikto.tar.gz

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
# Bake the pinned official template set; `nuclei -update-templates` exits 0
# without writing anything when it cannot reach the release API, which made the
# build fail later at chown. Downloading the tagged archive is deterministic.
RUN curl -fsSL -o /tmp/nuclei-templates.tar.gz \
      "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz" \
    && mkdir -p /var/lib/strix/nuclei-templates \
    && tar -xzf /tmp/nuclei-templates.tar.gz -C /var/lib/strix/nuclei-templates --strip-components=1 \
    && rm -f /tmp/nuclei-templates.tar.gz \
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
