FROM python:3.12-slim-bookworm

# nmap powers the "network"/"ports" profiles (the native TCP detector and the
# git-exposure detector need no external binary); omit it to ship a smaller
# image — the job will report nmap as unavailable, never as clean.
RUN apt-get update && apt-get install -y --no-install-recommends nmap sqlite3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /home/strix strix \
    && mkdir -p /var/lib/strix /etc/strix && chown strix /var/lib/strix

WORKDIR /app
# constraints.txt pins the exact direct dependency versions used for the release;
# src/ last so an application change does not invalidate the dependency layer.
COPY pyproject.toml constraints.txt README.md ./
COPY src ./src
# Fail the build if installation fails: an earlier `|| true` silently shipped an
# image with no `strix` entrypoint after a malformed requirement.
RUN pip install --no-cache-dir -c constraints.txt .
RUN pip uninstall -y pip setuptools || true

USER strix
ENV STRIX_DB=/var/lib/strix/strix.db \
    STRIX_SCOPE_FILE=/etc/strix/scope.json \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
EXPOSE 8000
VOLUME ["/var/lib/strix"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"
# One worker process owns the database (enforced by the worker lease); the
# server binds all interfaces here because the container network is the
# boundary — pass --host 127.0.0.1 behind a reverse proxy on the host instead.
CMD ["strix", "--host", "0.0.0.0", "--port", "8000"]
