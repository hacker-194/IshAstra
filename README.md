<div align="center">

<img src="./assets/banner.svg" alt="IshAstra — Authorization-First Security Assessment Platform" width="100%">

<br>

### 🛡️ Authorization is enforced before every outbound connection IshAstra makes.

<br>

[![License](https://img.shields.io/github/license/hacker-194/IshAstra?style=for-the-badge&color=2563eb)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/hacker-194/IshAstra/ci.yml?style=for-the-badge&label=CI&logo=githubactions&logoColor=white)](https://github.com/hacker-194/IshAstra/actions)
[![Python](https://img.shields.io/badge/python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.25%2B-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)](https://kubernetes.io)

[![TLA+](https://img.shields.io/badge/TLA%2B-model--checked-8b5cf6?style=flat-square)](docs/scope-gate/tla-verification.md)
[![Ed25519](https://img.shields.io/badge/evidence-Ed25519--signed-0ea5e9?style=flat-square)](#signed-evidence-bundles)
[![SARIF](https://img.shields.io/badge/reports-SARIF-22c55e?style=flat-square)](#why-ishastra)
[![Status](https://img.shields.io/badge/status-pilot-ready-22c55e?style=flat-square)](docs/quickstart/production.md)
[![Stars](https://img.shields.io/github/stars/hacker-194/IshAstra?style=flat-square&logo=github&color=eab308)](https://github.com/hacker-194/IshAstra/stargazers)

<p>
  <a href="#try-it-in-one-command"><b>Quick start</b></a> &nbsp;·&nbsp;
  <a href="#why-ishastra"><b>Why IshAstra</b></a> &nbsp;·&nbsp;
  <a href="#architecture"><b>Architecture</b></a> &nbsp;·&nbsp;
  <a href="#deployment"><b>Deployment</b></a> &nbsp;·&nbsp;
  <a href="#documentation"><b>Docs</b></a> &nbsp;·&nbsp;
  <a href="#security"><b>Security</b></a> &nbsp;·&nbsp;
  <a href="#contributing"><b>Contributing</b></a>
</p>

<img src="./assets/divider.svg" alt="" width="100%">

<table>
  <tr>
    <td align="center" width="25%"><h2>6</h2><sub>TLA+ invariants</sub></td>
    <td align="center" width="25%"><h2>21.4M</h2><sub>states model-checked</sub></td>
    <td align="center" width="25%"><h2>3</h2><sub>default-deny gate layers</sub></td>
    <td align="center" width="25%"><h2>$0</h2><sub>free-tier deployable</sub></td>
  </tr>
</table>

</div>

> [!NOTE]
> **Project status: pilot-ready** (IshAstra 4.0). The authorization core is TLA+-model-checked and CI-enforced; Phase 2 adds capability tokens, egress gateway (CONNECT proxy), hardened worker containers, and signed evidence bundles. Read [Production deployment](docs/quickstart/production.md) before promising uptime, and [SECURITY.md](SECURITY.md) for the honest security posture.

## Why IshAstra

Most scanners ask *"what can I find?"* IshAstra asks **"am I allowed to touch this?"** first, and proves the answer afterwards.

<table>
  <tr>
    <td width="33%" valign="top">
      <h3>🛡️ Default-deny</h3>
      A three-layer Scope Gate validates URL/host, DNS/IP and the pinned destination before any connection is made. If it isn't explicitly authorized, it doesn't happen.
    </td>
    <td width="33%" valign="top">
      <h3>🔐 Tenant isolation</h3>
      API-key tenant isolation, with per-task scope binding through <code>ContextVar</code>s, keeps tenants apart.
    </td>
    <td width="33%" valign="top">
      <h3>⛓️ Audit chain</h3>
      Every gate decision is receipted in a cryptographic chain that is tamper-evident, verifiable offline and compliance-ready.
    </td>
  </tr>
  <tr>
    <td width="33%" valign="top">
      <h3>📜 Policy-as-code</h3>
      Express scope as code with CIDR, ASN and geo rules in a signed scope file. The gate refuses anything else.
    </td>
    <td width="33%" valign="top">
      <h3>🌐 DNS-rebinding proof</h3>
      Hostnames are resolved, every IP is validated, and the connection is pinned to the single approved destination.
    </td>
    <td width="33%" valign="top">
      <h3>🧰 Real tools</h3>
      Runs Nuclei, nmap, SQLMap and Nikto through adapters that re-check the gate and emit normalized findings.
    </td>
  </tr>
</table>

<details>
<summary><b>📊 How IshAstra compares</b></summary>

<br>

| Feature                           | **IshAstra** | Nuclei | Trivy | OWASP ZAP | OpenVAS |
| --------------------------------- | :----------: | :----: | :---: | :-------: | :-----: |
| **Default-deny authorization**    |      ✅      |   ❌   |  ❌   |    ❌     |   ❌    |
| **API-key tenant isolation**      |      ✅      |   ❌   |  ❌   |    ❌     |   ❌    |
| **Cryptographic audit chain**     |      ✅      |   ❌   |  ❌   |    ❌     |   ❌    |
| **SARIF + compliance reports**    |      ✅      |   ✅   |  ✅   |    ✅     |   ✅    |
| **Runs Nuclei / nmap / SQLMap**   |      ✅      |   ✅   |  ❌   |    ❌     |   ❌    |
| **Policy-as-code (CIDR+ASN+Geo)** |      ✅      |   ❌   |  ❌   |    ❌     |   ❌    |
| **DNS rebinding protection**      |      ✅      |   ❌   |  ❌   |    ❌     |   ❌    |
| **Free-tier deployable**          |      ✅      |   ✅   |  ✅   |    ❌     |   ❌    |
| **TLA+ model-checked**            |      ✅      |   ❌   |  ❌   |    ❌     |   ❌    |

</details>

## Try it in one command

> [!NOTE]
> The package is not yet published to PyPI, so install from the repository.

```bash
git clone https://github.com/hacker-194/IshAstra.git
cd IshAstra
python3 -m venv .venv && . .venv/bin/activate
pip install -c constraints.txt -e .
ishastra demo
```

The demo writes its own **Ed25519-signed scope** (localhost only), generates an admin key, uses SQLite, and prints the URL plus the key you paste into the top bar. Nothing outside `.ishastra-demo/` is touched.

### Drop it into CI

The bundled GitHub Action runs a scoped assessment and uploads SARIF:

```yaml
- uses: hacker-194/IshAstra@main  # pin to a commit SHA in production
  with:
    target: https://staging.example.com
    scope-file: scope.json          # signed; the gate refuses anything else
    profile: web-deep
    fail-on-findings: "true"
```

## Architecture

```mermaid
flowchart TB
    API["🌐 REST API<br/>FastAPI"] --> Q["📬 Job queue<br/>in-process · Redis Streams · k8s-jobs"]
    Q --> W["⚙️ Assessment worker<br/>threaded pool"]

    subgraph GATE["🛡️ Scope Gate: default-deny authorization"]
        direction LR
        L1["Layer 1<br/>URL / Host"] --> L2["Layer 2<br/>DNS / IP policy"] --> L3["Layer 3<br/>Pinned destination"]
        L3 -.-> OBS["👁️ Observer<br/>IshAstra Proof"]
    end

    W --> GATE

    subgraph AD["🧰 Adapter framework"]
        direction LR
        HTTP["HTTP probe"]
        CRAWL["Crawler"]
        DYN["Dynamic validation"]
        EXT["External<br/>nmap · Nuclei · SQLMap · Nikto"]
    end

    GATE --> AD
    AD --> F["📊 Findings engine<br/>Normalize → Dedupe → Redact → Persist (SQLite) → Export"]
```

> Every adapter **re-checks the Scope Gate internally**, so a misbehaving adapter can't bypass authorization.

## Phase 2: Security spine (pilot-ready)

| Component | What it does | Key property |
| :-------- | :----------- | :----------- |
| **Capability tokens** | Ed25519-signed JWTs (TTL ≤ 900 s) carrying tenant, engagement, targets, pinned IPs, allowed ports/protocols/tools, budget | Unforgeable; verifiable offline; revocable by token/engagement/tenant |
| **Egress gateway** | CONNECT proxy that enforces capability tokens on every outbound TCP connection | Default-deny; allow/deny receipts in audit chain; Nmap/Nuclei routed through proxy |
| **Worker manager** | Disposable containers with `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, non-root user | No host access; per-task capability injection; automatic cleanup |
| **Evidence signing** | Canonical JSON + Ed25519 manifest; SHA-256 pinned members | Tamper-evident; offline verification; compliance-ready |

```mermaid
flowchart LR
    CAP["🔐 Capability<br/>Token (Ed25519 JWT)"] --> EG["🌐 Egress<br/>Gateway"]
    CAP --> WM["⚙️ Worker<br/>Manager"]
    EG -->|CONNECT proxy| TOOLS["Nuclei · nmap · HTTP"]
    WM -->|disposable container| TOOLS
    TOOLS --> ES["✍️ Evidence<br/>Signing"]
    ES --> BUNDLE["📦 Signed<br/>evidence.zip"]
```

## Core innovations

### 1. Scope Gate: default-deny authorization

<sub><code>src/ishastra/core/scope.py</code></sub>

```mermaid
flowchart LR
    R(["Outbound<br/>request"]) --> L1{"Layer 1<br/>URL · host · port<br/>in scope?"}
    L1 -- "no" --> D1["⛔ DENY"]
    L1 -- "yes" --> L2{"Layer 2<br/>every resolved IP<br/>authorized?"}
    L2 -- "no" --> D2["⛔ DENY"]
    L2 -- "yes" --> L3["Layer 3<br/>pin destination<br/>scheme · host · port · IP"]
    L3 --> OK(["✅ ALLOW<br/>connect to pinned IP only"])
    D1 -.-> PR["⛓️ Receipt in audit chain"]
    D2 -.-> PR
    OK -.-> PR

    classDef deny fill:#3b0d0d,stroke:#f87171,color:#fecaca
    classDef allow fill:#052e1c,stroke:#34d399,color:#a7f3d0
    class D1,D2 deny
    class OK allow
```

| Layer | What it checks | Resolves DNS? |
| :---- | :------------- | :-----------: |
| **1 · URL / Host** | Structure, host against include/exclude, port against `allowed_ports` | No |
| **2 · DNS / IP** | Resolves the hostname and validates **every** IP against `authorized_networks`. Special-use addresses (loopback, link-local, private, multicast) are denied unless explicitly authorized | Yes |
| **3 · Pinned destination** | Returns a single `Destination` (scheme, host, port, IP), which prevents DNS rebinding | n/a |

- **`ContextVar` isolation:** per-task scope binding for multi-tenant safety
- **TLA+ verified:** 6 invariants, 21.4M states model-checked

### 2. Break-glass dual approval

<sub><code>src/ishastra/core/scope_breakglass.py</code></sub>

Emergency authorization with a dual-approval workflow. Time-bounded, audited and metrics-instrumented.

### 3. IshAstra Proof: cryptographic audit chain

```mermaid
flowchart LR
    G["🔑 Grant<br/>authorized scope"] --> GT["🛡️ Gate<br/>allow / deny"] --> P["⛓️ Proof<br/>receipt in chain"] --> V["✅ Verify<br/>offline"]
```

Every gate decision is receipted. The chain is **tamper-evident**, **verifiable offline** and **compliance-ready**.

### 4. Adapter framework: real tools, normalized output

- **Built-in:** HTTP Probe, Crawler, Dynamic Validation
- **External:** nmap, Nuclei, SQLMap, Nikto
- All adapters re-check the Scope Gate internally
- **Enforcement modes:** `proxy` (routed through CONNECT gateway, e.g., Nuclei), `firewall` (host nftables), `none` (direct execution with in-process gate re-check)

| Adapter | Enforcement | Notes |
| :------ | :---------- | :---- |
| HTTP Probe | `proxy` | All requests through gateway |
| Nuclei | `proxy` | Runs via `--proxy` flag |
| nmap | `none` | Direct execution; gateway logic tested but path not proxied |
| SQLMap | `none` | Direct execution; in-process gate re-check |
| Nikto | `none` | Direct execution; in-process gate re-check |

## Signed evidence bundles

`ishastra bundle` packages everything an auditor needs into one zip. The manifest is **Ed25519-signed** and every member is **SHA-256 pinned**. Verification is offline, and any member that was edited, added or removed after signing is rejected.

```mermaid
flowchart LR
    A["Job result"] --> M
    B["Findings<br/>SARIF"] --> M
    C["HTML report"] --> M
    D["Audit-chain<br/>entries"] --> M
    E["Exact scope<br/>document"] --> M
    M["✍️ Signed manifest<br/>Ed25519 · SHA-256 pinned"] --> Z["📦 evidence.zip"]
    Z --> VF["✅ Offline verify<br/>tampering rejected"]
```

```bash
# Create
ishastra bundle --job <job-id> --scope scope.json --key scope-signing-key.pem --kid <kid> -o evidence.zip

# Verify (offline)
ishastra bundle --verify evidence.zip --jwks jwks.json
```

## Deployment

| Environment                | Command                                                        |   Cost   |
| :------------------------- | :------------------------------------------------------------- | :------: |
| **Free tier (Oracle)**     | `./scripts/bootstrap-free.sh`                                  | $0/month |
| **Single-host production** | systemd or Compose, one writer                                 |   Low    |
| **Local dev**              | `docker compose up -d` (after setting the required passwords)  |   Free   |
| **Kubernetes (Helm)**      | `helm install ishastra ./deploy/helm/ishastra -n ishastra --create-namespace` | Varies |

<details>
<summary><b>☁️ Free tier: $0/month on Oracle Cloud Always Free</b></summary>

<br>

```bash
# One-shot bootstrap on Oracle Cloud Always Free
git clone https://github.com/hacker-194/IshAstra.git
cd IshAstra
chmod +x scripts/bootstrap-free.sh
./scripts/bootstrap-free.sh
```

**What you get:**

| | Component | Details |
| :-: | :-------- | :------ |
| ☸️ | **k0s cluster** | Oracle Always Free Arm (2 OCPU / 12 GB total, halved by Oracle in June 2026). Add a third controller for quorum |
| 🐘 | **Neon PostgreSQL** | Serverless, 0.5 GB free |
| ⚡ | **Upstash Redis** | Serverless, 256 MB free |
| 🌩️ | **Cloudflare Tunnel** | Ingress with zero public IP and DDoS protection |
| 🔒 | **SealedSecrets** | Git-safe secret management |
| 📈 | **Prometheus + Grafana** | Monitoring out of the box |
| 🚪 | **IshAstra ScopeGate API** | Served at `https://api.yourdomain.com` |

</details>

<details>
<summary><b>🐳 Local development with Docker Compose</b></summary>

<br>

```bash
cp .env.example .env
# Set POSTGRES_PASSWORD and GRAFANA_PASSWORD in .env
docker compose up -d
# API     → http://localhost:8000
# Grafana → http://localhost:3000  (log in with GRAFANA_PASSWORD)
```

</details>

### Data backend and queue modes

| Component | Default | Alternative | Notes |
| :-------- | :------ | :---------- | :---- |
| **Database** | **SQLite**, the supported single-host pilot backend | **PostgreSQL** via `ISHASTRA_DB=postgresql://...` and the `postgres` extra | *Experimental.* Schema, RLS and a single-host worker path are tested, but there is no HA or multi-node failover |
| **Queue** | **`in-process`**, held in memory (a restart loses queued jobs) | **`redis-streams`** via `ISHASTRA_QUEUE_MODE=redis-streams` and `ISHASTRA_REDIS_URL`, for durable work shared by workers | `k8s-jobs` is experimental. See [ARCHITECTURE.md](ARCHITECTURE.md#deployment-constraints) |

## Extend and integrate

<details>
<summary><b>🔌 Third-party adapters (plugins)</b></summary>

<br>

Adapters plug in without forking the project. Publish one under the `ishastra.adapters` entry-point group and it becomes available to profiles:

```toml
[project.entry-points."ishastra.adapters"]
my-probe = "my_package.adapters:MyProbe"
```

A plugin can add an adapter id but **cannot replace a built-in one**.

> [!CAUTION]
> Third-party adapters are opt-in. Set `ISHASTRA_ALLOW_PLUGINS=1` only for packages you trust: plugins run in-process and can open network connections **without the Scope Gate**.

</details>

<details>
<summary><b>🔔 Job notifications (webhooks &amp; Slack)</b></summary>

<br>

Set `ISHASTRA_NOTIFY_WEBHOOK_URL` to POST a JSON summary (job, target, state, verdict, severity counts) whenever a job finishes. The same body carries Slack `text` and `blocks`, so a Slack incoming webhook renders it as a formatted card while other receivers read the structured fields.

- Destinations must be **public https URLs**
- Set `ISHASTRA_WEBHOOK_SECRET` to add an `X-Ishastra-Signature: sha256=…` HMAC header so the receiver can verify the payload

</details>

## Documentation

| | Guide | |
| :-: | :---- | :-- |
| 🚀 | [Quick Start](docs/quickstart/overview.md) | Install and run your first assessment |
| 🏗️ | [Architecture](ARCHITECTURE.md) | System design and deployment constraints |
| 🛡️ | [Scope Gate Deep Dive](docs/scope-gate/concepts.md) | How authorization decisions are made |
| 🔌 | [Adapter Development](docs/adapters/custom.md) | Build your own adapter |
| 📦 | [Deployment Guide](DEPLOYMENT.md) | Deploy beyond the demo |
| 🏭 | [Production Deployment & Readiness](docs/quickstart/production.md) | What to know before promising uptime |
| 💸 | [Free-Tier Deployment](docs/deployment/free-tier.md) | The $0/month path |
| 🔑 | [API Reference](docs/api/authentication.md) | Authentication and endpoints |
| 📋 | [Compliance Mapping](docs/compliance/overview.md) | Compliance overview |

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- 🧑‍💻 Development setup
- 🎨 Code style (`ruff`, `mypy`)
- 🧪 Testing requirements
- 🔀 PR process

<a href="https://github.com/hacker-194/IshAstra/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=hacker-194/IshAstra" alt="Contributors">
</a>

## Security

- 🔒 [Security Policy](SECURITY.md): vulnerability disclosure
- 🔍 [Security Review](docs/security-review.md)
- 📐 [TLA+ Verification](docs/scope-gate/tla-verification.md)

> [!IMPORTANT]
> IshAstra is built for authorized testing. Only assess systems you own or have explicit permission to test.

## License

Released under the **Apache-2.0** license. See [LICENSE](LICENSE).

## Community

- 💬 **Questions and ideas:** [GitHub Discussions](https://github.com/hacker-194/IshAstra/discussions)
- 🐛 **Bugs and requests:** [GitHub Issues](https://github.com/hacker-194/IshAstra/issues)

<br>

<div align="center">

<img src="./assets/divider.svg" alt="" width="100%">

*Authorization-first. Audit-ready. Free forever.*

<br>

[⭐ Star this repo](https://github.com/hacker-194/IshAstra) &nbsp;·&nbsp; [🐛 Report a bug](https://github.com/hacker-194/IshAstra/issues) &nbsp;·&nbsp; [💬 Join the discussion](https://github.com/hacker-194/IshAstra/discussions)

</div>
