"""Self-contained HTML assessment report.

Everything is inline (one file, no external assets, no JavaScript) so the
report can be attached to an email or archived. All finding text is HTML-
escaped: evidence routinely contains attacker-controlled strings, and a
report that executes its own evidence would be an own-goal XSS.

Includes print-optimized CSS for professional PDF output via WeasyPrint
and Devanagari font support for Nepali language.
"""

from __future__ import annotations

from typing import Any

from strix.locale import (
    LOCALES,
    LocaleCode,
    TemplateContext,
    esc,
    get_confidence_label,
    get_html_dir,
    get_html_lang,
    get_report_sections,
    get_report_title,
    get_severity_label,
    get_status_label,
    get_verification_label,
)

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


def render_html_report(
    report: dict[str, Any],
    locale_code: LocaleCode = "en_US",
    context: TemplateContext | None = None,
) -> str:
    """Render the /report evidence bundle (or an equivalent dict) as HTML.

    Args:
        report: Report data dictionary
        locale_code: Locale to render in (default: en_US)
        context: Optional template context with localized names
    """
    locale = LOCALES[locale_code]
    sections = get_report_sections(locale_code)
    html_dir = get_html_dir(locale_code)
    html_lang = get_html_lang(locale_code)
    report_title = get_report_title(locale_code)

    findings = report.get("findings") or []
    coverage = report.get("coverage") or {}
    adapters = coverage.get("adapters") or []
    severity_counts = report.get("severity_counts") or {}
    integrity = report.get("integrity") or {}
    order = ("critical", "high", "medium", "low", "info")

    # Build localized severity chips
    severity_chips = " ".join(
        f'<span class="chip {_SEVERITY_CLASS.get(sev, "sev-info")}">'
        f"{esc(get_severity_label(sev, locale_code), locale_code)}"
        f"<b>{int(severity_counts.get(sev, 0))}</b></span>"
        for sev in order
        if severity_counts.get(sev)
    )

    adapter_rows = "".join(
        f"<tr><td>{esc(run.get('adapter'), locale_code)}</td>"
        f'<td><span class="chip {_STATE_CLASS.get(run.get("state"), "")}">'
        f"{esc(run.get('state'), locale_code)}</span></td>"
        f"<td>{int(run.get('findings') or 0)}</td>"
        f"<td>{esc(run.get('elapsed_ms'), locale_code)}</td>"
        f'<td class="detail">{esc(run.get("detail"), locale_code)}</td></tr>'
        for run in adapters
    )

    finding_cards: list[str] = []
    for index, finding in enumerate(findings, 1):
        severity = str(finding.get("severity", "info"))
        verification = str(finding.get("verification", "unverified"))
        confidence = str(finding.get("confidence", "low"))
        status = str(finding.get("status", "new"))
        remediation_status = str(finding.get("remediation_status", "pending"))
        risk_rating = str(finding.get("risk_rating", "low"))

        finding_cards.append(f"""
  <article class="finding {_SEVERITY_CLASS.get(severity, "sev-info")}">
    <header>
      <span class="chip {_SEVERITY_CLASS.get(severity, "sev-info")}">
        {esc(get_severity_label(severity, locale_code), locale_code)}</span>
      <span class="chip">
        {esc(get_verification_label(verification, locale_code), locale_code)}</span>
      <span class="chip">
        {esc(get_confidence_label(confidence, locale_code), locale_code)}
        {esc(sections.get("confidence", "Confidence"), locale_code)}</span>
      <h3>{index}. {esc(finding.get("title"), locale_code)}</h3>
    </header>
    <p class="meta"><b>
      {esc(get_severity_label(finding.get("category"), locale_code), locale_code)}</b>
       &middot; {esc(finding.get("cwe") or "no CWE", locale_code)}
       &middot; {esc(sections.get("detector", "Detector"), locale_code)}
       {esc(finding.get("detector"), locale_code)}
       {esc(finding.get("detector_version"), locale_code)}</p>
    <p class="meta">{esc(sections.get("asset", "Asset"), locale_code)}: <code>
      {esc(finding.get("asset"), locale_code)}</code>
       &middot; {esc(sections.get("location", "Location"), locale_code)}: <code>
      {esc(finding.get("location"), locale_code)}</code></p>
    <pre class="evidence">{esc(finding.get("evidence"), locale_code)}</pre>
    <p class="fix"><b>
      {esc(sections.get("remediation", "Remediation"), locale_code)}:</b>
      {esc(finding.get("remediation"), locale_code)}</p>
    <p class="meta">{esc(sections.get("lifecycle", "Lifecycle"), locale_code)}: <b>
      {esc(get_status_label(status, locale_code), locale_code)}</b>
       &middot; {esc(sections.get("remediation", "Remediation"), locale_code)}
       {esc(get_status_label(remediation_status, locale_code), locale_code)}
       &middot; {esc(sections.get("risk_rating", "Risk Rating"), locale_code)}
       {esc(get_severity_label(risk_rating, locale_code), locale_code)}</p>
    <p class="desc">{esc(finding.get("description"), locale_code)}</p>
  </article>""")

    state = str(report.get("state", "unknown"))
    chain_valid = bool(integrity.get("chain_valid"))

    # Context values
    if context is None:
        context = TemplateContext(
            locale_code=locale_code,
            client_name=report.get("program", ""),
            organization_name="Strix Security",
            program_name=report.get("program", ""),
            authorized_by=report.get("authorized_by", ""),
            authorization_ref=report.get("authorization_ref", ""),
            target=report.get("target", ""),
        )

    target = context.target or report.get("target", "")
    job_id = report.get("job_id", "unknown")
    program = context.get_program_name()
    authorized_by = context.get_authorized_by()
    auth_ref = context.authorization_ref
    scope_include = ", ".join(report.get("scope_include") or [])

    # Use locale-aware date formatting if generated_at is provided
    generated_at_raw = report.get("generated_at")
    if generated_at_raw and context.generated_at is None:
        # Try to parse the datetime string
        import datetime

        try:
            dt = datetime.datetime.fromisoformat(generated_at_raw.replace("Z", "+00:00"))
            # TemplateContext is frozen, create a new instance with the generated_at
            context = TemplateContext(
                locale_code=context.locale_code,
                client_name=context.client_name,
                client_name_nepali=context.client_name_nepali,
                organization_name=context.organization_name,
                organization_name_nepali=context.organization_name_nepali,
                program_name=context.program_name,
                program_name_nepali=context.program_name_nepali,
                authorized_by=context.authorized_by,
                authorized_by_nepali=context.authorized_by_nepali,
                authorization_ref=context.authorization_ref,
                target=context.target,
                generated_at=dt,
            )
        except Exception:
            pass
    is_nepali = locale_code == "ne_NP"
    generated_at = context.get_generated_datetime(include_bs=is_nepali, use_nepali_digits=is_nepali)
    verdict = esc(report.get("verdict", "unknown"), locale_code)

    # Font configuration
    font_family = (
        f"'{locale.font_family}', 'Noto Sans Devanagari', -apple-system, "
        f'"Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
    )
    font_mono = (
        f"'{locale.font_family_mono}', 'Noto Sans Mono', ui-monospace, "
        f'"SF Mono", Menlo, Consolas, monospace'
    )
    font_devanagari = f"'{locale.devanagari_font_family}', 'Noto Sans Devanagari', sans-serif"

    # Text alignment based on direction
    text_align = "right" if html_dir == "rtl" else "left"

    return f"""<!DOCTYPE html>
<html lang="{html_lang}" dir="{html_dir}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{report_title} — {esc(target, locale_code)}</title>
<style>
:root {{
  --ink:#1a2233; --muted:#5b6579; --line:#dde3ee; --bg:#f6f8fc; --card:#ffffff;
  --critical:#8f1d1d; --high:#b3372a; --medium:#a06a12; --low:#4a6d8c; --info:#5b6579;
  --font-family: {font_family};
  --font-mono: {font_mono};
  --font-devanagari: {font_devanagari};
}}
* {{ box-sizing: border-box; }}
body {{
  margin:0; padding:2rem; background:var(--bg); color:var(--ink);
  font:15px/1.55 var(--font-family);
  direction: {html_dir};
}}
main {{ max-width: 60rem; margin: 0 auto; }}
header.report {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
                 padding:1.4rem 1.6rem; margin-bottom:1.2rem; }}
h1 {{ margin:0 0 .2rem; font-size:1.45rem; }}
.sub {{ color:var(--muted); margin:.1rem 0; }}
.kv {{ display:grid; grid-template-columns:max-content 1fr; gap:.15rem 1rem; margin-top:.9rem;
       font-size:.92rem; direction: {html_dir}; }}
.kv dt {{ color:var(--muted); }}
.kv dd {{ margin:0; font-family:var(--font-mono); }}
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
table {{ width:100%; border-collapse:collapse; font-size:.9rem; direction: {html_dir}; }}
th, td {{ text-align:{text_align}; padding:.45rem .6rem; border-bottom:1px solid var(--line);
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
                word-break:break-word; margin:.6rem 0; font-family:var(--font-mono); direction: ltr; }}
p.fix {{ font-size:.9rem; margin:.4rem 0; }}
p.desc {{ color:var(--muted); font-size:.86rem; margin:.3rem 0 0; }}
footer {{ color:var(--muted); font-size:.82rem; margin-top:1.4rem; text-align:center; }}
.code {{ font-family:var(--font-mono); }}

/* Devanagari font support for Nepali content */
.lang-ne, .nepali, [lang="ne"] {{
    font-family: var(--font-devanagari) !important;
}}
.lang-ne * {{
    font-feature-settings: "liga" 1, "clig" 1, "calt" 1;
}}

/* Mixed script handling */
[dir="rtl"] .kv,
[dir="rtl"] table,
[dir="rtl"] .chip {{ direction: rtl; }}

/* ─── Print / PDF Optimizations ─── */
@page {{
    size: A4;
    margin: 2cm 1.5cm 2cm 1.5cm;
    @top-center {{
        content: "{report_title}";
        font-size: 9pt;
        color: #666;
        font-family: var(--font-family);
    }}
    @bottom-center {{
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9pt;
        color: #666;
        font-family: var(--font-family);
    }}
    @bottom-left {{
        content: "Confidential — Authorized Use Only";
        font-size: 8pt;
        color: #999;
    }}
    @bottom-right {{
        content: "Generated by Strix";
        font-size: 8pt;
        color: #999;
    }}
}}

@media print {{
    body {{
        margin: 0;
        padding: 0;
        background: white;
        font-size: 11pt;
        line-height: 1.5;
    }}
    main {{
        max-width: none;
        margin: 0;
    }}
    header.report {{
        break-after: avoid-page;
        box-shadow: none;
        border: 1px solid #ddd;
    }}
    section {{
        break-inside: avoid;
        box-shadow: none;
        border: 1px solid #ddd;
    }}
    article.finding {{
        break-inside: avoid-page;
        box-shadow: none;
        border: 1px solid #ddd;
    }}
    .no-print {{
        display: none !important;
    }}
    .chip {{
        border: 1px solid #ccc !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    .sev-critical, .sev-high, .sev-medium, .sev-low, .sev-info {{
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    article.finding.sev-critical,
    article.finding.sev-high,
    article.finding.sev-medium,
    article.finding.sev-low {{
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    pre.evidence {{
        white-space: pre-wrap;
        word-break: break-word;
        font-size: 8pt;
        background: #f5f5f5 !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }}
    table {{
        font-size: 9pt;
    }}
    th, td {{
        padding: 4pt 6pt;
    }}
    footer {{
        display: none;
    }}
}}

/* Font embedding hints for PDF generators */
@font-face {{
  font-family: 'Noto Sans Devanagari';
  src: local('Noto Sans Devanagari');
  font-display: swap;
}}
@font-face {{
  font-family: 'Noto Sans';
  src: local('Noto Sans');
  font-display: swap;
}}
@font-face {{
  font-family: 'Noto Sans Mono';
  src: local('Noto Sans Mono');
  font-display: swap;
}}
</style>
</head>
<body>
<main>
<header class="report">
  <h1>{report_title}</h1>
  <p class="sub">
    {esc(sections.get("target", "Target"), locale_code)}
    <code class="code">{esc(target, locale_code)}</code>
    &middot; {esc(sections.get("job_id", "Job ID"), locale_code)}
    <code class="code">{esc(job_id, locale_code)}</code>
  </p>
  <p class="sub"><span class="chip {_STATE_CLASS.get(state, "")}">{esc(state, locale_code)}</span>
     {verdict}</p>
  <dl class="kv">
    <dt>{esc("Program", locale_code)}</dt><dd>{esc(program, locale_code)}</dd>
    <dt>{esc("Authorized by", locale_code)}</dt><dd>{esc(authorized_by, locale_code)}</dd>
    <dt>{esc("Authorization ref", locale_code)}</dt><dd>{esc(auth_ref, locale_code)}</dd>
    <dt>{esc("Scope", locale_code)}</dt><dd>{esc(scope_include, locale_code)}</dd>
    <dt>{esc("Generated at", locale_code)}</dt><dd>{esc(generated_at, locale_code)}</dd>
  </dl>
  <p style="margin:.9rem 0 0">
    {severity_chips or f'<span class="chip sev-info">{esc("No findings were recorded.", locale_code)}</span>'}
  </p>
</header>

<section>
  <h2>{esc(sections.get("coverage", "Coverage"), locale_code)}</h2>
  <table>
    <thead>
      <tr>
        <th>{esc("Adapter", locale_code)}</th>
        <th>{esc("State", locale_code)}</th>
        <th>{esc("Findings", locale_code)}</th>
        <th>{esc("ms", locale_code)}</th>
        <th>{esc("Detail", locale_code)}</th>
      </tr>
    </thead>
    <tbody>
      {adapter_rows or f'<tr><td colspan="5">{esc("no adapter runs recorded", locale_code)}</td></tr>'}
    </tbody>
  </table>
</section>

<section>
  <h2>{esc("Findings", locale_code)} ({len(findings)})</h2>
  {
        "".join(finding_cards)
        if findings
        else f"<p>{esc('No findings were recorded for this assessment.', locale_code)}</p>"
    }
</section>

<footer>
  {esc("Evidence", locale_code)} redacted for credential-shaped values.
  {esc("Audit chain", locale_code)}:
  <span class="code">{"valid" if chain_valid else "UNVERIFIED"}</span>
  &middot; chain hash <span class="code">{esc(integrity.get("chain_hash"), locale_code)}</span><br>
  Generated by strix — findings are evidence-backed observations; severities are
  advisory until validated by the program owner.
</footer>
</main>
</body>
</html>"""
