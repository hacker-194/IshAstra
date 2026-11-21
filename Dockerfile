# syntax=docker/dockerfile:1













FROM python:3.12-slim AS builder


RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    pkg-config \
    libxml2-dev \
    libxslt1-dev \
    libxmlsec1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY pyproject.toml constraints.txt README.md LICENSE ./
COPY src ./src

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -c constraints.txt ".[k8s-jobs,postgres]"




FROM python:3.12-slim AS runtime



ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_TEMPLATES_VERSION=10.5.2
ARG NIKTO_VERSION=2.5.0
ARG TARGETARCH=amd64


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


RUN curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
    && python -c "from zipfile import ZipFile; ZipFile('/tmp/nuclei.zip').extract('nuclei', '/usr/local/bin')" \
    && chmod +x /usr/local/bin/nuclei \
    && rm -f /tmp/nuclei.zip

RUN groupadd -r -g 10001 ishastra \
    && useradd -r -u 10001 -g ishastra -d /app -s /usr/sbin/nologin ishastra \
    && mkdir -p /app /var/lib/ishastra /tmp/ishastra \
    && chown -R ishastra:ishastra /app /var/lib/ishastra /tmp/ishastra

RUN curl -fsSL -o /tmp/nuclei-templates.tar.gz \
      "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz" \
    && mkdir -p /var/lib/ishastra/nuclei-templates \
    && tar -xzf /tmp/nuclei-templates.tar.gz -C /var/lib/ishastra/nuclei-templates --strip-components=1 \
    && rm -f /tmp/nuclei-templates.tar.gz \
    && chown -R ishastra:ishastra /var/lib/ishastra/nuclei-templates

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ISHASTRA_DB=/var/lib/ishastra/ishastra.db \
    HOME=/var/lib/ishastra

WORKDIR /app
USER ishastra

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

ENTRYPOINT ["ishastra"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
