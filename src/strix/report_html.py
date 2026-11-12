"""Self-contained HTML assessment report.

Everything is inline (one file, no external assets, no JavaScript) so the
report can be attached to an email or archived. All finding text is HTML-
escaped: evidence routinely contains attacker-controlled strings, and a
report that executes its own evidence would be an own-goal XSS.
"""

from __future__ import annotations

import html
from typing import Any

_SEVERITY_CLASS = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "info": "sev-info",
}
_STATE_CLASS = {
    "completed": "state-ok",
    "partial": "state-warn",
    "failed": "state-bad",
    "cancelled": "state-warn",
}


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_html_report(report: dict[str, Any]) -> str:
    """Render the /report evidence bundle (or an equivalent dict) as HTML."""
    findings = report.get("findings") or []
    coverage = report.get("coverage") or {}
    adapters = coverage.get("adapters") or []
    severity_counts = report.get("severity_counts") or {}
    integrity = report.get("integrity") or {}
    order = ("critical", "high", "medium", "low", "info")

    severity_chips = " ".join(
        f'<span class="chip {_SEVERITY_CLASS.get(sev, "sev-info")}">{_esc(sev)}'
        f"<b>{int(severity_counts.get(sev, 0))}</b></span>"
        for sev in order
        if severity_counts.get(sev)
    )

    adapter_rows = "".join(
        f"<tr><td>{_esc(run.get('adapter'))}</td>"
        f"<td><span class=\"chip {_STATE_CLASS.get(run.get('state'), '')}\">"
        f"{_esc(run.get('state'))}</span></td>"
        f"<td>{int(run.get('findings') or 0)}</td>"
        f"<td>{_esc(run.get('elapsed_ms'))}</td>"
        f"<td class=\"detail\">{_esc(run.get('detail'))}</td></tr>"
        for run in adapters
    )

    finding_cards: list[str] = []
    for index, finding in enumerate(findings, 1):
        severity = str(finding.get("severity", "info"))
        finding_cards.append(f"""
  <article class="finding {_SEVERITY_CLASS.get(severity, 'sev-info')}">
    <header>
      <span class="chip {_SEVERITY_CLASS.get(severity, 'sev-info')}">{_esc(severity)}</span>
      <span class="chip">{_esc(finding.get('verification'))}</span>
      <span class="chip">{_esc(finding.get('confidence'))} confidence</span>
      <h3>{index}. {_esc(finding.get('title'))}</h3>
    </header>
    <p class="meta"><b>{_esc(finding.get('category'))}</b>
       &middot; {_esc(finding.get('cwe') or 'no CWE')}
       &middot; detector {_esc(finding.get('detector'))}
       {_esc(finding.get('detector_version'))}</p>
    <p class="meta">Asset: <code>{_esc(finding.get('asset'))}</code>
       &middot; Location: <code>{_esc(finding.get('location'))}</code></p>
    <pre class="evidence">{_esc(finding.get('evidence'))}</pre>
    <p class="fix"><b>Remediation:</b> {_esc(finding.get('remediation'))}</p>
    <p class="meta">Lifecycle: <b>{_esc(finding.get('status') or 'new')}</b>
       &middot; remediation {_esc(finding.get('remediation_status') or 'pending')}
       &middot; risk {_esc(finding.get('risk_rating') or 'low')}</p>
    <p class="desc">{_esc(finding.get('description'))}</p>
  </article>""")

    state = str(report.get("state", "unknown"))
    chain_valid = bool(integrity.get("chain_valid"))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Strix report — {_esc(report.get('target'))}</title>
<style>
:root {{ --ink:#1a2233; --muted:#5b6579; --line:#dde3ee; --bg:#f6f8fc; --card:#ffffff;
        --critical:#8f1d1d; --high:#b3372a; --medium:#a06a12; --low:#4a6d8c; --info:#5b6579; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; padding:2rem; background:var(--bg); color:var(--ink);
       font:15px/1.55 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }}
main {{ max-width: 60rem; margin: 0 auto; }}
header.report {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
                 padding:1.4rem 1.6rem; margin-bottom:1.2rem; }}
h1 {{ margin:0 0 .2rem; font-size:1.45rem; }}
.sub {{ color:var(--muted); margin:.1rem 0; }}
.kv {{ display:grid; grid-template-columns:max-content 1fr; gap:.15rem 1rem; margin-top:.9rem;
       font-size:.92rem; }}
.kv dt {{ color:var(--muted); }}
.kv dd {{ margin:0; font-family:ui-monospace, "SF Mono", Menlo, Consolas, monospace; }}
.chip {{ display:inline-block; padding:.1rem .55rem; border-radius:999px; background:#eef1f7;
         border:1px solid var(--line); font-size:.78rem; margin-right:.35rem;
         text-transform:uppercase; letter-spacing:.03em; }}
.chip b {{ margin-left:.35rem; }}
.sev-critical {{ background:#fbe9e9; border-color:#e6b3b3; color:var(--critical); }}
.sev-high {{ background:#fdeeea; border-color:#eec0b3; color:var(--high); }}
.sev-medium {{ background:#fdf4e3; border-color:#ecd4a4; color:var(--medium); }}
.sev-low {{ background:#eaf2f8; border-color:#bcd3e4; color:var(--low); }}
.sev-info {{ background:#eef1f7; border-color:var(--line); color:var(--info); }}
.state-ok {{ background:#e7f4ec; border-color:#b3d9c2; color:#1e6b40; }}
.state-warn {{ background:#fdf4e3; border-color:#ecd4a4; color:var(--medium); }}
.state-bad {{ background:#fbe9e9; border-color:#e6b3b3; color:var(--critical); }}
section {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
           padding:1.2rem 1.6rem; margin-bottom:1.2rem; }}
h2 {{ font-size:1.05rem; margin:.2rem 0 .8rem; }}
table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
th, td {{ text-align:left; padding:.45rem .6rem; border-bottom:1px solid var(--line);
          vertical-align:top; }}
th {{ color:var(--muted); font-weight:600; }}
td.detail {{ color:var(--muted); font-size:.85rem; }}
article.finding {{ border:1px solid var(--line); border-left-width:5px; border-radius:10px;
                   padding:1rem 1.2rem; margin:0 0 1rem; background:var(--card); }}
article.finding.sev-critical {{ border-left-color:var(--critical); }}
article.finding.sev-high {{ border-left-color:var(--high); }}
article.finding.sev-medium {{ border-left-color:var(--medium); }}
article.finding.sev-low {{ border-left-color:var(--low); }}
article.finding h3 {{ margin:.3rem 0 .4rem; font-size:1rem; }}
article.finding .meta {{ color:var(--muted); font-size:.85rem; margin:.25rem 0; }}
pre.evidence {{ background:#f2f4fa; border:1px solid var(--line); border-radius:8px;
                padding:.7rem .9rem; font-size:.82rem; white-space:pre-wrap;
                word-break:break-word; margin:.6rem 0; }}
p.fix {{ font-size:.9rem; margin:.4rem 0; }}
p.desc {{ color:var(--muted); font-size:.86rem; margin:.3rem 0 0; }}
footer {{ color:var(--muted); font-size:.82rem; margin-top:1.4rem; text-align:center; }}
.code {{ font-family:ui-monospace, Menlo, Consolas, monospace; }}
</style>
</head>
<body>
<main>
<header class="report">
  <h1>Strix assessment report</h1>
  <p class="sub">Target <code class="code">{_esc(report.get('target'))}</code>
     &middot; job <code class="code">{_esc(report.get('job_id'))}</code></p>
  <p class="sub"><span class="chip {_STATE_CLASS.get(state, '')}">{_esc(state)}</span>
     {_esc(report.get('verdict'))}</p>
  <dl class="kv">
    <dt>Program</dt><dd>{_esc(report.get('program'))}</dd>
    <dt>Authorized by</dt><dd>{_esc(report.get('authorized_by'))}</dd>
    <dt>Authorization ref</dt><dd>{_esc(report.get('authorization_ref'))}</dd>
    <dt>Scope</dt><dd>{_esc(', '.join(report.get('scope_include') or []))}</dd>
    <dt>Generated at</dt><dd>{_esc(report.get('generated_at'))}</dd>
  </dl>
  <p style="margin:.9rem 0 0">{severity_chips or '<span class="chip sev-info">no findings</span>'}</p>
</header>

<section>
  <h2>Coverage</h2>
  <table>
    <thead><tr><th>Adapter</th><th>State</th><th>Findings</th><th>ms</th><th>Detail</th></tr></thead>
    <tbody>{adapter_rows or '<tr><td colspan="5">no adapter runs recorded</td></tr>'}</tbody>
  </table>
</section>

<section>
  <h2>Findings ({len(findings)})</h2>
  {''.join(finding_cards) if findings else
   '<p>No findings were recorded for this assessment.</p>'}
</section>

<footer>
  Evidence redacted for credential-shaped values. Audit chain:
  <span class="code">{'valid' if chain_valid else 'UNVERIFIED'}</span>
  &middot; chain hash <span class="code">{_esc(integrity.get('chain_hash'))}</span><br>
  Generated by strix — findings are evidence-backed observations; severities are
  advisory until validated by the program owner.
</footer>
</main>
</body>
</html>"""
