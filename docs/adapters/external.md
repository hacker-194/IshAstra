# External Tool Adapters

# External Tool Adapters

Ishastra wraps industry-standard security tools with Scope Gate enforcement.

## Overview

| Adapter | Tool | Version | Purpose | Scope Gate |
|---------|------|---------|---------|------------|
| Nmap | nmap | 7.94+ | Port/service discovery | ✅ |
| Nuclei | nuclei | 3.2+ | Template-based vuln scanning | ✅ |
| SQLMap | sqlmap | 1.8+ | SQL injection detection | ✅ |
| Nikto | nikto | 2.5+ | Web server issues | ✅ |

All external adapters:
- **Resolve target via Scope Gate** before execution
- **Connect ONLY to pinned IP** from Layer 3
- **Set Host header** for virtual hosting/SNI
- **Enforce timeouts** and resource limits
- **Parse output** to normalized Findings

---

## Nmap Adapter

**Class**: `NmapAdapter`  
**Name**: `nmap`  
**Targets**: `tcp` (host:port)

### Purpose

Network discovery and port scanning with service version detection.

### Capabilities

| Scan Type | Flag | Description |
|-----------|------|-------------|
| SYN Scan | `-sS` | Default, stealthy |
| Connect Scan | `-sT` | Full TCP connect |
| UDP Scan | `-sU` | UDP services |
| Version Detection | `-sV` | Service versions |
| OS Detection | `-O` | OS fingerprinting |
| Script Scan | `--script` | NSE scripts (vuln, auth, etc.) |

### Configuration

```json
{
  "adapters": {
    "nmap": {
      "scan_type": "syn",
      "version_detection": true,
      "os_detection": false,
      "scripts": ["vuln", "auth", "default"],
      "top_ports": 1000,
      "timeout": 300,
      "max_rate": 1000,
      "min_rate": 50,
      "host_timeout": 60
    }
  }
}
```

### Scope Gate Integration

```python
class NmapAdapter(BaseAdapter):
    name = "nmap"
    
    async def run(self) -> AsyncIterator[Finding]:
        # 1. Scope Gate validation - get pinned destination
        dest = await self._authorize_connection(self.config.target)
        
        # 2. Build nmap command with PINNED IP
        cmd = ["nmap"]
        
        # Scan type
        if self.config.options.get("scan_type") == "syn":
            cmd.append("-sS")
        elif self.config.options.get("scan_type") == "connect":
            cmd.append("-sT")
        
        # Options
        if self.config.options.get("version_detection"):
            cmd.append("-sV")
        if self.config.options.get("os_detection"):
            cmd.append("-O")
        
        # Scripts
        scripts = self.config.options.get("scripts", ["vuln"])
        cmd.extend(["--script", ",".join(scripts)])
        
        # Output
        cmd.extend(["-oX", "-"])  # XML to stdout
        
        # Target: PINNED IP only
        cmd.append(dest.ip)
        
        # 3. Execute with timeout
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, "HOST_HEADER": dest.host}  # For scripts
        )
        
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=self.config.options.get("timeout", 300)
        )
        
        # 4. Parse XML output to Findings
        yield from self._parse_nmap_xml(stdout)
```

### Example Findings

```json
{
  "id": "NMAP-OPEN-PORT-22",
  "title": "Open SSH Port",
  "description": "Port 22/tcp open with OpenSSH 9.2p1",
  "severity": "INFO",
  "category": "network",
  "location": "10.0.0.50:22",
  "evidence": {
    "port": 22,
    "protocol": "tcp",
    "service": "ssh",
    "version": "OpenSSH 9.2p1",
    "state": "open",
    "scripts": {
      "ssh-hostkey": "RSA 2048...",
      "ssh2-enum-algos": "..."
    }
  },
  "references": [
    "https://nmap.org/nsedoc/scripts/ssh-hostkey.html"
  ],
  "metadata": {
    "adapter": "nmap",
    "adapter_version": "7.94",
    "scan_type": "syn"
  }
}
```

---

## Nuclei Adapter

**Class**: `NucleiAdapter`  
**Name**: `nuclei`  
**Targets**: `http`, `https`

### Purpose

Template-based vulnerability scanning using Nuclei templates.

### Capabilities

| Feature | Description |
|---------|-------------|
| Template Categories | cves, vulnerabilities, misconfiguration, exposures, tokens |
| Severity Filter | critical, high, medium, low, info |
| Rate Limiting | Configurable requests/second |
| Custom Templates | Local or remote template paths |
| Headless Mode | JavaScript rendering (optional) |

### Configuration

```json
{
  "adapters": {
    "nuclei": {
      "templates": [
        "cves/",
        "vulnerabilities/",
        "misconfiguration/",
        "exposures/",
        "tokens/"
      ],
      "severity": ["critical", "high", "medium"],
      "rate_limit": 100,
      "timeout": 10,
      "retries": 1,
      "headless": false,
      "tags": [],
      "exclude_tags": ["dos", "fuzz"]
    }
  }
}
```

### Scope Gate Integration

```python
class NucleiAdapter(BaseAdapter):
    name = "nuclei"
    
    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)
        
        cmd = [
            "nuclei",
            "-target", dest.ip,           # PINNED IP
            "-H", f"Host: {dest.host}",   # Host header for virtual hosting
            "-silent",
            "-json",
            "-severity", ",".join(self.config.options.get("severity", ["critical", "high", "medium"])),
            "-rate-limit", str(self.config.options.get("rate_limit", 150)),
            "-timeout", str(self.config.options.get("timeout", 10)),
            "-retries", str(self.config.options.get("retries", 1)),
        ]
        
        # Templates
        templates = self.config.options.get("templates")
        if templates:
            cmd.extend(["-t", ",".join(templates)])
        
        # Tags
        tags = self.config.options.get("tags")
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        exclude_tags = self.config.options.get("exclude_tags")
        if exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
        
        # Headless
        if self.config.options.get("headless"):
            cmd.append("-headless")
        
        yield from self._run_and_parse(cmd, self._parse_nuclei_json)
```

### Example Findings

```json
{
  "id": "NUCLEI-CVE-2024-1234",
  "title": "CVE-2024-1234: Example App RCE",
  "description": "Remote code execution in Example App version < 2.5.0",
  "severity": "CRITICAL",
  "category": "rce",
  "location": "https://app.example.com/vulnerable-endpoint",
  "evidence": {
    "template_id": "cve-2024-1234",
    "template_name": "Example App RCE",
    "matched_at": "https://app.example.com/vulnerable-endpoint?param=payload",
    "request": "GET /vulnerable-endpoint?param=payload HTTP/1.1",
    "response": "HTTP/1.1 200 OK\n...",
    "extracted_results": ["command_output"]
  },
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    "https://github.com/projectdiscovery/nuclei-templates"
  ],
  "metadata": {
    "adapter": "nuclei",
    "adapter_version": "3.2.0",
    "template": "cves/2024/cve-2024-1234.yaml"
  }
}
```

---

## SQLMap Adapter

**Class**: `SQLMapAdapter`  
**Name**: `sqlmap`  
**Targets**: `http`, `https`

### Purpose

Automated SQL injection detection and exploitation.

### Capabilities

| Feature | Description |
|---------|-------------|
| Detection | Boolean, time-based, error-based, UNION, stacked queries |
| Database Fingerprinting | MySQL, PostgreSQL, MSSQL, Oracle, SQLite |
| Data Extraction | Tables, columns, data dump |
| WAF Evasion | Tamper scripts |
| Risk Levels | 1-3 (conservative to aggressive) |

### Configuration

```json
{
  "adapters": {
    "sqlmap": {
      "level": 1,
      "risk": 1,
      "technique": "BEUSTQ",
      "timeout": 600,
      "batch": true,
      "fresh_queries": true,
      "flush_session": true,
      "tamper": [],
      "dbms": "",
      "prefix": "",
      "suffix": ""
    }
  }
}
```

### Scope Gate Integration

```python
class SQLMapAdapter(BaseAdapter):
    name = "sqlmap"
    
    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)
        
        parsed = parse_url(self.config.target)
        path = self.config.options.get("path", parsed.path or "/")
        query = parsed.query or ""
        
        # Build target URL with pinned IP
        target_url = f"{parsed.scheme}://{dest.ip}{path}"
        if query:
            target_url += f"?{query}"
        
        cmd = [
            "sqlmap",
            "-u", target_url,
            "--host", dest.host,           # Host header
            "--batch",                     # Non-interactive
            "--output-dir", "/tmp/sqlmap",
            "--flush-session",
            "--fresh-queries",
            "--level", str(self.config.options.get("level", 1)),
            "--risk", str(self.config.options.get("risk", 1)),
            "--technique", self.config.options.get("technique", "BEUSTQ"),
        ]
        
        # DBMS hint
        if dbms := self.config.options.get("dbms"):
            cmd.extend(["--dbms", dbms])
        
        # Tamper scripts
        if tamper := self.config.options.get("tamper"):
            cmd.extend(["--tamper", ",".join(tamper)])
        
        # Prefix/suffix for injection
        if prefix := self.config.options.get("prefix"):
            cmd.extend(["--prefix", prefix])
        if suffix := self.config.options.get("suffix"):
            cmd.extend(["--suffix", suffix])
        
        yield from self._run_and_parse(cmd, self._parse_sqlmap_output)
```

### Example Findings

```json
{
  "id": "SQLMAP-SQLI-/search",
  "title": "SQL Injection in Search Parameter",
  "description": "Boolean-based blind SQL injection in 'q' parameter",
  "severity": "CRITICAL",
  "category": "sqli",
  "location": "https://app.example.com/search?q=test",
  "evidence": {
    "parameter": "q",
    "type": "boolean-based blind",
    "title": "MySQL >= 5.0 AND boolean-based blind - WHERE/HAVING",
    "payload": "test' AND 1234=1234 AND 'abcd'='abcd",
    "dbms": "MySQL 5.7",
    "technique": "boolean-based blind"
  },
  "references": [
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://github.com/sqlmapproject/sqlmap"
  ],
  "metadata": {
    "adapter": "sqlmap",
    "adapter_version": "1.8",
    "technique": "boolean-blind"
  }
}
```

---

## Nikto Adapter

**Class**: `NiktoAdapter`  
**Name**: `nikto`  
**Targets**: `http`, `https`

### Purpose

Web server vulnerability scanner for misconfigurations, outdated software, and dangerous files.

### Capabilities

| Check Category | Examples |
|----------------|----------|
| Server Config | Directory indexing, server tokens, TRACE method |
| Outdated Software | Apache, nginx, IIS version checks |
| Dangerous Files | /phpinfo.php, /server-status, /.git/, backup files |
| Headers | Missing security headers, X-Powered-By |
| Authentication | Default credentials, basic auth exposure |

### Configuration

```json
{
  "adapters": {
    "nikto": {
      "timeout": 30,
      "plugins": "ALL",
      "exclude_plugins": [],
      "ssl": true,
      "port": "auto",
      "maxtime": 120
    }
  }
}
```

### Scope Gate Integration

```python
class NiktoAdapter(BaseAdapter):
    name = "nikto"
    
    async def run(self) -> AsyncIterator[Finding]:
        dest = await self._authorize_connection(self.config.target)
        
        parsed = parse_url(self.config.target)
        
        cmd = [
            "nikto",
            "-h", dest.ip,                    # PINNED IP
            "-host", dest.host,               # Host header
            "-port", str(dest.port),
            "-Format", "json",
            "-output", "/tmp/nikto.json",
            "-timeout", str(self.config.options.get("timeout", 30)),
            "-maxtime", str(self.config.options.get("maxtime", 120)),
        ]
        
        # SSL
        if dest.scheme == "https" or self.config.options.get("ssl"):
            cmd.append("-ssl")
        
        # Plugins
        if plugins := self.config.options.get("plugins"):
            cmd.extend(["-Plugins", plugins])
        if exclude := self.config.options.get("exclude_plugins"):
            cmd.extend(["-exclude", ",".join(exclude)])
        
        yield from self._run_and_parse(cmd, self._parse_nikto_json)
```

### Example Findings

```json
{
  "id": "NIKTO-OUTDATED-NGINX",
  "title": "Outdated nginx Version",
  "description": "nginx version 1.18.0 is outdated (current: 1.24.0)",
  "severity": "MEDIUM",
  "category": "outdated",
  "location": "https://app.example.com/",
  "evidence": {
    "osvdb": "12345",
    "method": "GET",
    "uri": "/",
    "message": "Server header reveals nginx/1.18.0"
  },
  "references": [
    "https://nginx.org/en/security_advisories.html"
  ],
  "metadata": {
    "adapter": "nikto",
    "adapter_version": "2.5.0",
    "plugin": "outdated"
  }
}
```

---

## Running External Adapters

### Via API

```bash
curl -X POST https://api.ishastra.dev/api/v1/assessments \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_id": "scope-123",
    "targets": ["https://app.example.com"],
    "adapters": ["nmap", "nuclei", "sqlmap", "nikto"]
  }'
```

### Via CLI

```bash
# Run single external adapter
ishastra adapter run nuclei --target https://example.com --scope scope.json

# Run all external
ishastra adapter run-external --target https://example.com --scope scope.json
```

---

## Tool Installation

### Docker (Recommended)

```dockerfile
# All tools pre-installed in Ishastra worker image
FROM ghcr.io/ishastra/worker:3.5.0
# Includes: nmap, nuclei, sqlmap, nikto, and dependencies
```

### Manual Installation

```bash
# nmap
apt-get install nmap

# nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# sqlmap
git clone https://github.com/sqlmapproject/sqlmap.git

# nikto
git clone https://github.com/sullo/nikto.git
```

### Nuclei Templates

```bash
# Update templates
nuclei -update-templates

# Custom templates directory
mkdir -p /opt/nuclei-templates/custom
# Add .yaml templates
```

---

## Safety & Resource Limits

### Per-Adapter Limits

| Adapter | Timeout | Max Memory | Max CPU |
|---------|---------|------------|---------|
| nmap | 300s | 1GB | 1 core |
| nuclei | 600s | 2GB | 2 cores |
| sqlmap | 600s | 1GB | 1 core |
| nikto | 120s | 512MB | 1 core |

### Container Security

```yaml
# Kubernetes security context for worker pods
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  readOnlyRootFilesystem: true
  seccompProfile:
    type: RuntimeDefault
```

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| Tool not found | Not in PATH | Install tool, check Docker image |
| Permission denied | Needs root (nmap -sS) | Use `-sT` connect scan, or NET_RAW capability |
| Timeout | Target slow/unresponsive | Increase timeout, check network |
| No output | Tool crashed | Check stderr, verify tool version |
| Parse errors | Output format changed | Update parser, pin tool version |
| Scope Gate DENY | Target IP not authorized | Add CIDR to scope |

---

## Related

- [Built-in Adapters](../adapters/built-in.md)
- [Custom Adapters](../adapters/custom.md)
- [Adapter SDK](../adapters/sdk.md)
- [Architecture: Adapters](../architecture/adapters.md)
- [Scope Gate](../scope-gate/concepts.md)