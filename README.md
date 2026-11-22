<div align="center">

<img src="./assets/banner.svg" alt="IshAstra — Authorization-First Security Assessment Platform" width="100%">

<br>

<span style="display:block; margin:2rem 0; padding:1rem; background:linear-gradient(135deg, #667eea 0%, #764ba2 100%); color:white; border-radius:8; text-align:center;">
⚡ <strong>IshAstra</strong> ⚡<br>
<span style="font-size:0.9rem; opacity:0.9">Authorization-First Security Assessment Platform</span>
</span>

<br>

### 🛡️ Authorization is enforced before every outbound connection IshAstra makes.

<br>

<div style="display:flex; justify-content:center; gap:2rem; margin:1rem 0; flex-wrap:wrap;">
  <div style="background:rgba(255,255,255,0.9); padding:1rem; border-radius:8; backdrop-filter:blur(10px); min-width:150px;">
    <div style="font-size:2rem; margin-bottom:0.5rem;">🛡️</div>
    <strong>Default-Deny</strong><br>
    Every connection validated against scope
  </div>
  <div style="background:rgba(255,255,255,0.9); padding:1rem; border-radius:8; backdrop-filter:blur(10px); min-width:150px;">
    <div style="font-size:2rem; margin-bottom:0.5rem;">🔐</div>
    <strong>Tenant Isolation</strong><br>
    API-key per-task binding
  </div>
  <div style="background:rgba(255,255,255,0.9); padding:1rem; border-radius:8; backdrop-filter:blur(10px); min-width:150px;">
    <div style="font-size:2rem; margin-bottom:0.5rem;">✅</div>
    <strong>Cryptographic Chain</strong><br>
    Ed25519 signed evidence
  </div>
</div>

<br>

<div style="background:linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); padding:1rem; border-radius:8; margin:1rem 0;">

<details style="padding:1rem; background:white; border-radius:6;">
  <summary style="cursor:pointer; font-weight:600; color:#333;">📊 IshAstra vs Other Tools</summary>
  <p style="margin:0.5rem 0; color:#666; font-size:0.9rem;">
  Default-deny authorization • API-key tenant isolation • Cryptographic audit chain • SARIF + compliance reports • Runs Nuclei / nmap / SQLMap • Policy-as-code (CIDR+ASN+Geo) • DNS rebinding protection • Free-tier deployable • TLA+ model-checked (6 invariants, 21.4M states)
  </p>
</details>

</div>

<br>

<div style="display:flex; justify-content:center; gap:1rem; flex-wrap:wrap; margin:1rem 0;">

  [![License](https://img.shields.io/github/license/hacker-194/IshAstra?style=for-the-badge&color=2563eb&labelColor=1e293b)](LICENSE)
  [![CI](https://img.shields.io/github/actions/workflow/status/hacker-194/IshAstra/ci.yml?style=for-the-badge&label=%F0%9F%94%99%20CI&logoColor=white&labelColor=1e293b)](https://github.com/hacker-194/IshAstra/actions)
  [![Python](https://img.shields.io/badge/python-3.12%2B-3776AB?style=for-the-badge&logo=python&logoColor=white&labelColor=1e293b)](https://python.org)
  [![Kubernetes](https://img.shields.io/badge/kubernetes-1.28%2B-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white&labelColor=1e293b)](https://kubernetes.io)
  [![TLA+](https://img.shields.io/badge/TLA%2B-model%20checked-8b5cf6?style=flat-square&labelColor=1e293b)](docs/tla)
  [![Ed25519](https://img.shields.io/badge/evidence-Ed25519%20signed-0ea5e9?style=flat-square&labelColor=1e293b)](#signed-evidence-bundles)
  [![SARIF](https://img.shields.io/badge/reports-SARIF-22c55e?style=flat-square&labelColor=1e293b)](#why-ishastra)
  [![Status](https://img.shields.io/badge/status-pilot--grade-f59e0b?style=flat-square&labelColor=1e293b)](docs/quickstart/production.md)
  [![Stars](https://img.shields.io/github/stars/hacker-194/IshAstra?style=flat-square&color=eab308&labelColor=1e293b)](https://github.com/hacker-194/IshAstra/stargazers)

</div>

<br>

Why IshAstra  •  Architecture  •  Deployment  •  Docs  •  Security  •  Contributing

6 TLA+ invariants 21.4M states model-checked 3 default-deny gate layers $0 free-tier deployable

Authorization core: TLA+-model-checked, CI-enforced. Production-ready with single-tenant deployment.

Why IshAstra

🛡️ Default-deny authorization

A three-layer Scope Gate validates URL/host, DNS/IP and the pinned destination before any connection is made. If it isn't explicitly authorized, it doesn't happen. No scope, no connection.

🔐 Tenant isolation

API-key tenant isolation, with per-task scope binding through ContextVars, keeps tenants strictly apart. No cross-tenant leakage.

⛓️ Cryptographic audit chain

Every gate decision is receipted in a tamper-evident chain that is verifiable offline and compliance-ready. Your evidence, cryptographically signed.

📜 Policy-as-code

Express scope as code with CIDR, ASN and geo rules in a signed scope file. The gate refuses anything else. Code is law.

🌐 DNS-rebinding proof

Hostnames are resolved, every IP is validated, and the connection is pinned to the single approved destination. No DNS rebinding accepted.

🧰 Real tools

Runs Nuclei, nmap, SQLMap and Nikto through adapters that re-check the gate and emit normalized findings. Real tools, normalized output.

📊 How IshAstra compares

| Feature | IshAstra | Nuclei | Trivy | OWASP ZAP | OpenVAS |
|---|---|---|---|---|---|
| Default-deny authorization | ✅ | ❌ | ❌ | ❌ | ❌ |
| API-key tenant isolation | ✅ | ❌ | ❌ | ❌ | ❌ |
| Cryptographic audit chain | ✅ | ❌ | ❌ | ❌ | ❌ |
| SARIF + compliance reports | ✅ | ✅ | ✅ | ✅ | ✅ |
| Runs Nuclei / nmap / SQLMap | ✅ | ✅ | ❌ | ❌ | ❌ |
| Policy-as-code (CIDR+ASN+Geo) | ✅ | ❌ | ❌ | ❌ | ❌ |
| DNS rebinding protection | ✅ | ❌ | ❌ | ❌ | ❌ |
| Free-tier deployable | ✅ | ✅ | ✅ | ❌ | ❌ |
| TLA+ model-checked | ✅ | ❌ | ❌ | ❌ | ❌ |

Try it in one command

Note

The package is not yet published to PyPI, so install from the repository.

git clone https://github.com/hacker-194/IshAstra
cd IshAstra
python3 -m venv .venv && . .venv/bin/activate
pip install -c constraints.txt -e .

ishastra demo

The demo writes its own Ed25519-signed scope (localhost only), generates an admin key, uses SQLite, and prints the URL plus the key you paste into the top bar. Nothing outside .ishastra-demo/ is touched.

Drop it into CI

The bundled GitHub Action runs a scoped assessment and uploads SARIF:

- uses: hacker-194/IshAstra@master  # pin to a commit SHA in production
  with:
    target: https://staging.example.com
    scope-file: scope.json          # signed; the gate refuses anything else
    profile: web-deep
    fail-on-findings: "true"

Architecture

Every adapter re-checks the Scope Gate internally, so a misbehaving adapter can't bypass authorization.

Core innovations

1. Scope Gate: default-deny authorization

src/ishastra/core/scope.py

Layer | What it checks | Resolves DNS?
--- | --- | ---
1 · URL / Host | Structure, host against include/exclude, port against allowed_ports | No
2 · DNS / IP | Resolves the hostname and validates every IP against authorized_networks. Special-use addresses (loopback, link-local, private, multicast) are denied unless explicitly authorized | Yes
3 · Pinned destination | Returns a single Destination (scheme, host, port, IP), which prevents DNS rebinding | n/a

ContextVar isolation: per-task scope binding for multi-tenant safety

TLA+ verified: 6 invariants, 21.4M states model-checked

2. Break-glass dual approval

src/ishastra/core/scope_breakglass.py

Emergency authorization with a dual-approval workflow. Time-bounded, audited and metrics-instrumented.

3. IshAstra Proof: cryptographic audit chain

Every gate decision is receipted. The chain is tamper-evident, verifiable offline and compliance-ready.

4. Adapter framework: real tools, normalized output

Built-in: HTTP Probe, Crawler, Dynamic Validation

External: nmap, Nuclei, SQLMap, Nikto

All adapters re-check the Scope Gate internally

Signed evidence bundles

ishastra bundle packages everything an auditor needs into one zip. The manifest is Ed25519-signed and every member is SHA-256 pinned. Verification is offline, and any member that was edited, added or removed after signing is rejected.

# Create

ishastra bundle --job <job-id> --scope scope.json --key scope-signing-key.pem --kid <kid> -o evidence.zip

# Verify (offline)

ishastra bundle --verify evidence.zip --jwks jwks.json

Deployment

Environment | Command | Cost
--- | --- | ---
Free tier (Oracle) | ./scripts/bootstrap-free.sh | $0/month
Single-host production | systemd or Compose, one writer | Low
Local dev | docker compose up -d | Free
Kind / Minikube | ./scripts/bootstrap-kind.sh | Free

☁️ Free tier: $0/month on Oracle Cloud Always Free

🐳 Local development with Docker Compose

Data backend and queue modes

Component | Default | Alternative | Notes
--- | --- | --- | ---
Database | SQLite, the supported single-host pilot backend | PostgreSQL via `ISHASTRA_DB=postgresql://...` and the `postgres` extra | Experimental. Schema, RLS and a single-host worker path are tested, but there is no HA or multi-node failover.
Queue | in-process, held in memory (a restart loses queued jobs) | redis-streams via `ISHASTRA_QUEUE_MODE=redis-streams` and `ISHASTRA_REDIS_URL`, for durable work shared by workers | `k8s-jobs` is experimental. See ARCHITECTURE.md.

Extend and integrate

🔌 Third-party adapters (plugins)

🔔 Job notifications (webhooks & Slack)

Documentation

Guide

🚀 Quick Start | Install and run your first assessment
🏗️ Architecture | System design and deployment constraints
🛡️ Scope Gate Deep Dive | How authorization decisions are made
🔌 Adapter Development | Build your own adapter
📦 Deployment Guide | Deploy beyond the demo
🏭 Production Deployment & Readiness | What to know before promising uptime
💸 Free-Tier Deployment | The $0/month path
🔑 API Reference | Authentication and endpoints
📋 Compliance Mapping | Compliance overview

Contributions are welcome! See CONTRIBUTING.md for:

🧑‍💻 Development setup
🎨 Code style (ruff, mypy)
🧪 Testing requirements
🔀 PR process

Contributors

Security

🔒 Security Policy: vulnerability disclosure
🔍 Security Review
📐 TLA+ Verification

Important

IshAstra is built for authorized testing. Only assess systems you own or have explicit permission to test.

License

Released under the Apache-2.0 license. See LICENSE.

Community

💬 Questions and ideas: GitHub Discussions
🐛 Bugs and requests: GitHub Issues

Built with ❤️ for the open source security community.

Authorization-first. Audit-ready. Free forever.

⭐ Star this repo  ·  🐛 Report a bug  ·  💬 Join the discussion

About

No description, website, or topics provided.

Resources

Readme
Apache-2.0 license
Code of conduct
Code of conduct
Contributing
Contributing
Security policy
Security policy

Activity

Stars 0 stars
Watchers 0 watching
Forks 0 forks
Releases 1 (1)

Ishastra v3.5.0 Latest

8 (8)

github-pages 1 hour ago pypi 1 hour ago

Packages

1 (1)

ishastra

Contributors

1 (1)

@hacker-194 hacker-194

Languages

Python89.8% JavaScript2.6% CSS2.5% HTML2.4% Go Template1.4% Shell1.1% Other0.2%
About
No description, website, or topics provided.

Resources

Readme
Apache-2.0 license
Code of conduct
Code of conduct
Contributing
Contributing
Security policy
Securitypolicy