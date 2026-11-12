/**
 * Strix Cyber Command Center — Interactive Client Controller
 * Talks to the Strix HTTP API; no framework, no build step.
 */

// State Management
const state = {
  apiKey: null,
  auditLogs: [],
};

// -----------------------------------------------------------------------------
// Auth Helpers
// -----------------------------------------------------------------------------
function getAuthHeaders() {
  return state.apiKey ? { 'Authorization': `Bearer ${state.apiKey}` } : {};
}

// DOM Content Loaded Initializer
document.addEventListener('DOMContentLoaded', () => {
  initAuth();
  initNavigation();
  initOverview();
  initScanner();
  initAudit();
  initEvidence();
  initAssessment();
});

// -----------------------------------------------------------------------------
// AUTH UI
// -----------------------------------------------------------------------------
function initAuth() {
  const input = document.getElementById('api-key-input');
  const saveBtn = document.getElementById('btn-save-api-key');
  const clearBtn = document.getElementById('btn-clear-api-key');

  if (!input || !saveBtn) return;

  // Restore the key saved for this browser session
  const savedKey = sessionStorage.getItem('strix_api_key');
  if (savedKey) {
    state.apiKey = savedKey;
    input.value = savedKey;
    showToast('API key restored from session', 'info');
  }

  saveBtn.addEventListener('click', () => {
    const key = input.value.trim();
    if (!key) {
      showToast('Please enter an API key', 'warning');
      return;
    }
    state.apiKey = key;
    sessionStorage.setItem('strix_api_key', key);
    showToast('API key saved', 'success');
  });

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      state.apiKey = null;
      input.value = '';
      sessionStorage.removeItem('strix_api_key');
      showToast('API key cleared', 'info');
    });
  }
}

// Toast Notification Helper
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(8px)';
    setTimeout(() => toast.remove(), 250);
  }, 4000);
}

// -----------------------------------------------------------------------------
// NAVIGATION TABS
// -----------------------------------------------------------------------------
function initNavigation() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetTab = tab.dataset.tab;
      switchTab(targetTab);
    });
  });
}

function switchTab(tabId) {
  document.querySelectorAll('.nav-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === tabId);
  });
  document.querySelectorAll('.view-panel').forEach(p => {
    p.classList.toggle('active', p.id === `tab-${tabId}`);
  });

  // Lazy refresh based on active tab
  if (tabId === 'overview') loadOverview();
  if (tabId === 'audit') loadAudit();
  if (tabId === 'evidence') {
    loadScope();
    loadAssessmentProfiles();
    loadJobHistory();
  }
}

// -----------------------------------------------------------------------------
// OVERVIEW & MITRE CATALOG
// -----------------------------------------------------------------------------
function initOverview() {
  const refreshBtn = document.getElementById('btn-refresh-overview');
  if (refreshBtn) refreshBtn.addEventListener('click', loadOverview);

  document.getElementById('btn-quick-scan')?.addEventListener('click', () => {
    switchTab('evidence');
    document.getElementById('assess-target-input')?.focus();
  });

  loadOverview();
}

async function loadOverview() {
  try {
    const res = await fetch('/api/overview', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load overview data');
    const data = await res.json();

    document.getElementById('kpi-assessments').textContent = data.total_jobs;
    document.getElementById('kpi-findings').textContent = data.total_findings;
    document.getElementById('kpi-targets').textContent = data.total_targets;

    document.getElementById('hdr-targets-count').textContent = data.total_targets;
    document.getElementById('hdr-audit-count').textContent = data.audit_events;
    document.getElementById('hdr-findings-count').textContent = data.total_findings;
  } catch (err) {
    console.warn('Overview load error:', err);
  }
}

// -----------------------------------------------------------------------------
// SCANNER & PROBE ENGINE
// -----------------------------------------------------------------------------
function initScanner() {
  const probeBtn = document.getElementById('btn-run-probe');

  if (probeBtn) probeBtn.addEventListener('click', executeProbe);
}

async function executeProbe() {
  const input = document.getElementById('scan-url-input');
  const url = input?.value.trim();
  if (!url) {
    showToast('Please specify an endpoint URL.', 'warning');
    return;
  }

  const container = document.getElementById('probe-results-container');
  const urlDisplay = document.getElementById('probe-url-display');
  const gradeBadge = document.getElementById('probe-grade-badge');
  const probeBtn = document.getElementById('btn-run-probe');

  probeBtn.disabled = true;
  probeBtn.innerHTML = '<span class="btn-icon">⏳</span> Probing...';
  urlDisplay.textContent = `Probing ${url}...`;
  container.innerHTML = '<div class="loading-shimmer" style="padding: 24px; text-align: center;">Measuring HTTP latency & inspecting security directives...</div>';

  try {
    const res = await fetch('/api/probe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({ url }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Probe failed');

    urlDisplay.textContent = `${data.url} — HTTP ${data.status_code || 'N/A'}`;

    // Grade badge
    gradeBadge.textContent = data.security_grade;
    gradeBadge.className = `grade-badge grade-${data.security_grade}`;

    const headers = data.security_headers || {};
    container.innerHTML = `
      <div class="probe-metrics-bar">
        <div class="metric-box">
          <span class="label">RESPONSE LATENCY</span>
          <span class="value">${data.latency_ms} ms</span>
        </div>
        <div class="metric-box">
          <span class="label">HTTP STATUS</span>
          <span class="value">${data.status_code || 'Offline'}</span>
        </div>
        <div class="metric-box">
          <span class="label">SECURITY SCORE</span>
          <span class="value">${data.security_score} / 100</span>
        </div>
      </div>

      <div class="header-checks-list">
        <div class="header-check-item">
          <span>Content-Security-Policy (CSP)</span>
          <span class="check-status ${headers.csp ? 'pass' : 'fail'}">${headers.csp ? 'ENFORCED' : 'MISSING'}</span>
        </div>
        <div class="header-check-item">
          <span>Strict-Transport-Security (HSTS)</span>
          <span class="check-status ${headers.hsts ? 'pass' : 'fail'}">${headers.hsts ? 'ENFORCED' : 'MISSING'}</span>
        </div>
        <div class="header-check-item">
          <span>X-Frame-Options (Clickjacking)</span>
          <span class="check-status ${headers.frame ? 'pass' : 'fail'}">${headers.frame ? 'ENFORCED' : 'MISSING'}</span>
        </div>
        <div class="header-check-item">
          <span>Cookie Secure Flag</span>
          <span class="check-status ${headers.cookie_secure ? 'pass' : 'fail'}">${headers.cookie_secure ? 'SECURE' : 'UNSECURED'}</span>
        </div>
      </div>

      ${data.deductions && data.deductions.length > 0 ? `
        <div class="defense-badge-row" style="background: rgba(244, 63, 94, 0.08);">
          <strong style="color: var(--crimson);">Directives Requiring Remediation:</strong>
          <ul style="margin-left: 16px; margin-top: 4px;">
            ${data.deductions.map(d => `<li>${escapeHtml(d)}</li>`).join('')}
          </ul>
        </div>
      ` : ''}
    `;

    showToast(`Probe complete: Grade ${data.security_grade} (${data.security_score}/100)`, 'success');
  } catch (err) {
    container.innerHTML = `<div class="empty-desc" style="color: var(--crimson);">Probe error: ${escapeHtml(err.message)}</div>`;
    showToast(err.message, 'error');
  } finally {
    probeBtn.disabled = false;
    probeBtn.innerHTML = '<span class="btn-icon">🔍</span> Live Header Probe';
  }
}

// -----------------------------------------------------------------------------
// SIEM INGEST & LOGS
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// GATED REMEDIATION & PLAYBOOKS
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// PIPELINE ORCHESTRATOR
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// AUDIT & COMPLIANCE
// -----------------------------------------------------------------------------
function initAudit() {
  const refreshBtn = document.getElementById('btn-refresh-audit');
  const exportBtn = document.getElementById('btn-export-audit');
  const filterInput = document.getElementById('audit-filter-input');

  if (refreshBtn) refreshBtn.addEventListener('click', loadAudit);
  if (exportBtn) exportBtn.addEventListener('click', exportAuditJSON);
  if (filterInput) {
    filterInput.addEventListener('input', (e) => {
      renderAuditTable(e.target.value.toLowerCase());
    });
  }

  loadAudit();
}

async function loadAudit() {
  const tbody = document.getElementById('audit-table-body');
  const countBadge = document.getElementById('audit-count-badge');
  if (!tbody) return;

  try {
    const res = await fetch('/api/audit?limit=100', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load audit records');
    const data = await res.json();
    state.auditLogs = data.audit_logs || [];

    if (countBadge) countBadge.textContent = `${data.total_records} RECORDS`;
    renderAuditTable('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="table-empty" style="color: var(--crimson);">Audit load error: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function renderAuditTable(query = '') {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;

  const filtered = state.auditLogs.filter(entry => {
    if (!query) return true;
    const jsonStr = JSON.stringify(entry).toLowerCase();
    return jsonStr.includes(query);
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="table-empty">No audit logs matching query.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map((item, idx) => {
    const event = item.event || 'action';
    const target = item.target || 'N/A';
    const details = Object.entries(item)
      .filter(([k]) => k !== 'event' && k !== 'target')
      .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
      .join('; ');

    const hasRedacted = JSON.stringify(item).includes('[REDACTED]');

    return `
      <tr>
        <td style="color: var(--text-dim);">#${state.auditLogs.length - idx}</td>
        <td><span class="badge ${event.includes('denied') || event.includes('rejected') ? 'warning' : 'info'}">${event.toUpperCase()}</span></td>
        <td><code>${escapeHtml(target)}</code></td>
        <td style="max-width: 480px; word-break: break-all;">${escapeHtml(details)}</td>
        <td>${hasRedacted ? '<span class="redact-pill">SEC-REDACTED</span>' : '<span style="color: var(--text-dim); font-size: 10px;">VERIFIED CLEAN</span>'}</td>
      </tr>
    `;
  }).join('');
}

function exportAuditJSON() {
  const blob = new Blob([JSON.stringify(state.auditLogs, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `strix-audit-ledger-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Audit JSON ledger exported', 'success');
}

// -----------------------------------------------------------------------------
// ASSESSMENT JOBS
// -----------------------------------------------------------------------------
const JOB_BADGE = {
  completed: 'success', partial: 'medium', failed: 'high', cancelled: 'neutral', running: 'info', queued: 'info',
};
const LIVE_STATES = ['queued', 'running'];

function initAssessment() {
  document.getElementById('btn-run-assess')?.addEventListener('click', runAssessment);
  document.getElementById('btn-refresh-jobs')?.addEventListener('click', loadJobHistory);
  const select = document.getElementById('assess-profile-select');
  if (select) {
    select.addEventListener('change', updateProfileHint);
    select.value = (() => {
      const opts = Array.from(select.options).map(o => o.value);
      if (opts.includes('hybrid')) return 'hybrid';
      if (opts.includes('agent')) return 'agent';
      if (opts.includes('web-deep')) return 'web-deep';
      return 'web';
    })();
  }
}

async function loadAssessmentProfiles() {
  const select = document.getElementById('assess-profile-select');
  if (!select) return;
  try {
    const res = await fetch('/api/adapters', { headers: getAuthHeaders() });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Adapters unavailable');

    select.innerHTML = Object.keys(data.profiles).map(profile =>
      `<option value="${escapeHtml(profile)}">${escapeHtml(profile)}</option>`
    ).join('');
    select.dataset.adapters = JSON.stringify(
      Object.fromEntries(data.adapters.map(a => [a.id, a]))
    );
    updateProfileHint();
  } catch (err) {
    // Leave the static options in place; the run will surface the real error.
    console.warn('Profile load failed:', err.message);
  }
}

function updateProfileHint() {
  const select = document.getElementById('assess-profile-select');
  const hint = document.getElementById('assess-profile-hint');
  if (!select || !hint) return;

  let adapters = {};
  try { adapters = JSON.parse(select.dataset.adapters || '{}'); } catch (e) { /* ignore */ }
  const profileAdapters = { web: ['strix-http'], 'web-deep': ['strix-http', 'strix-dynamic-validation', 'nuclei'], api: ['strix-http', 'strix-openapi'], 'api-deep': ['strix-http', 'strix-openapi', 'strix-dynamic-validation', 'nuclei'], network: ['strix-http', 'nmap'], agent: ['strix-agent'], hybrid: ['strix-http', 'strix-git-exposure', 'strix-agent'] };
  // A job deadline per profile, sent with the submission. The autonomous
  // engine takes minutes per run, so the default 120s would cut it short.
  const profileTimeouts = { agent: 900, hybrid: 900 };
  const names = profileAdapters[select.value] || [];
  const missing = names.filter(name => adapters[name] && adapters[name].available === false);
  hint.textContent = missing.length
    ? `Unavailable in this deployment: ${missing.join(', ')} — the job will report it as unavailable, never clean.`
    : names.map(name => adapters[name] ? `${name} (${adapters[name].detail})` : name).join(' · ');
}

async function runAssessment() {
  const target = document.getElementById('assess-target-input')?.value.trim();
  const profile = document.getElementById('assess-profile-select')?.value || 'web';
  const container = document.getElementById('assess-output-container');
  const badge = document.getElementById('assess-status-badge');
  const button = document.getElementById('btn-run-assess');

  if (!target) {
    showToast('Enter an authorized target first.', 'warning');
    return;
  }

  button.disabled = true;
  button.innerHTML = '<span class="btn-icon">⏳</span> Running...';
  badge.textContent = 'QUEUED';
  badge.className = 'badge info';
  container.innerHTML = '<div class="loading-shimmer" style="padding: 24px; text-align: center;">Queued — waiting for a worker to claim the job...</div>';

  try {
    const res = await fetch('/api/assess', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({
        target, profile,
        ...(profileTimeouts[profile] ? { timeout: profileTimeouts[profile] } : {}),
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Assessment failed');

    // 202 means accepted, not successful: follow the job until it settles.
    showToast(`Job ${data.id} queued`, 'info');
    await pollJob(data);
    loadJobHistory();
  } catch (err) {
    badge.textContent = 'FAILED';
    badge.className = 'badge high';
    container.innerHTML = `<div class="empty-desc" style="color: var(--crimson);">${escapeHtml(err.message)}</div>`;
    showToast(err.message, 'error');
  } finally {
    button.disabled = false;
    button.innerHTML = '<span class="btn-icon">▶</span> Start Assessment';
  }
}

async function pollJob(job) {
  const container = document.getElementById('assess-output-container');
  const badge = document.getElementById('assess-status-badge');
  const deadline = Date.now() + (((job.policy && job.policy.timeout_seconds) || 120) + 30) * 1000;
  let current = job;

  while (LIVE_STATES.includes(current.state)) {
    renderAssessment(current);
    badge.textContent = current.state.toUpperCase();
    badge.className = `badge ${JOB_BADGE[current.state] || 'info'}`;
    if (Date.now() > deadline) {
      showToast('Job still running past its deadline — check history shortly.', 'warning');
      return current;
    }
    await sleep(600);
    try {
      const res = await fetch(`/api/assess/${encodeURIComponent(job.id)}`, { headers: getAuthHeaders() });
      const payload = await res.json();
      if (!res.ok) throw new Error(payload.detail || 'Job status unavailable');
      current = payload;
    } catch (err) {
      showToast(err.message, 'error');
      return current;
    }
  }

  renderAssessment(current);
  badge.textContent = current.state.toUpperCase();
  badge.className = `badge ${JOB_BADGE[current.state] || 'neutral'}`;
  // Accepted is not successful: report what the job actually achieved.
  showToast(`Job ${current.state}: ${current.verdict}`,
            current.state === 'completed' ? 'success' : 'warning');
  return current;
}

async function cancelJob(jobId) {
  try {
    const res = await fetch(`/api/assess/${encodeURIComponent(jobId)}/cancel`, {
      method: 'POST', headers: getAuthHeaders(),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || 'Cancel failed');
    showToast('Cancellation signalled — waiting for the worker...', 'info');
    await pollJob({ id: jobId, state: 'running' });
    loadJobHistory();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function renderAssessment(job) {
  const container = document.getElementById('assess-output-container');
  const runs = (job.coverage.adapters || []).map(run => `
    <div class="header-check-item">
      <span>${escapeHtml(run.adapter)} <code>${escapeHtml(String(run.elapsed_ms))}ms</code></span>
      <span class="check-status ${run.state === 'ok' ? 'pass' : (run.state === 'unavailable' ? 'warn' : 'fail')}">${escapeHtml(run.state.toUpperCase())}</span>
    </div>
  `).join('');

  const findings = (job.findings || []).length
    ? job.findings.map(f => `
        <div class="finding-card ${f.severity === 'critical' || f.severity === 'high' ? 'severity-high' : (f.severity === 'medium' ? 'severity-med' : 'severity-low')}">
          <div class="finding-hdr">
            <span class="finding-id">${escapeHtml(f.severity.toUpperCase())} · ${escapeHtml(f.category)}</span>
            <span class="finding-weight">${escapeHtml(f.verification)} / ${escapeHtml(f.confidence)}</span>
          </div>
          <div class="finding-details">
            <div><strong>${escapeHtml(f.title)}</strong></div>
            <div class="finding-meta-row">
              <span><strong>Location:</strong> ${escapeHtml(f.location || f.asset)}</span>
              ${f.cwe ? `<span><strong>${escapeHtml(f.cwe)}</strong></span>` : ''}
            </div>
            <div class="evidence-block"><strong>Evidence:</strong> ${escapeHtml(f.evidence)}</div>
            <div class="defense-badge-row"><strong>Remediation:</strong> ${escapeHtml(f.remediation || 'Review the evidence.')}</div>
            <div class="finding-status-row">
              <span class="badge ${f.status === 'closed' ? 'low' : 'neutral'}">${escapeHtml((f.status || 'new').toUpperCase().replace(/_/g, ' '))}</span>
              ${(f.allowed_transitions || []).length ? `
                <select class="finding-status-select" data-finding-select="${escapeHtml(f.fingerprint)}">
                  ${f.allowed_transitions.map(s => `<option value="${escapeHtml(s)}">${escapeHtml(s.replace(/_/g, ' '))}</option>`).join('')}
                </select>
                <button class="strix-btn secondary action-btn" data-finding-update="${escapeHtml(f.fingerprint)}">Update</button>
              ` : '<span class="assess-history-meta">No further transitions</span>'}
            </div>
          </div>
        </div>
      `).join('')
    : `<div class="empty-state">
        <div class="empty-icon">${job.clean ? '✓' : '!'}</div>
        <div class="empty-title">${job.clean ? 'No Findings (Complete Coverage)' : 'No Findings — Inconclusive'}</div>
        <div class="empty-desc">${escapeHtml(job.verdict)}</div>
      </div>`;

  container.innerHTML = `
    <div class="probe-metrics-bar">
      <div class="metric-box"><span class="label">JOB</span><span class="value">${escapeHtml(job.id)}</span></div>
      <div class="metric-box"><span class="label">STATE</span><span class="value">${escapeHtml(job.state.toUpperCase())}</span></div>
      <div class="metric-box"><span class="label">COVERAGE</span><span class="value">${(job.coverage && job.coverage.ok) || 0}/${(job.coverage && job.coverage.total) || 0}</span></div>
      <div class="metric-box"><span class="label">FINDINGS</span><span class="value">${(job.findings || []).length}</span></div>
    </div>

    <div class="defense-badge-row"><strong>Verdict:</strong> ${escapeHtml(job.verdict)}</div>
    ${job.error ? `<div class="empty-desc" style="color: var(--crimson);">${escapeHtml(job.error)}</div>` : ''}

    ${LIVE_STATES.includes(job.state) ? `
      <div class="input-row" style="margin: 12px 0;">
        <button class="strix-btn secondary action-btn" id="btn-cancel-job">Cancel Job</button>
        <span class="assess-history-meta">${job.state === 'queued' ? 'Waiting for a worker to claim this job…' : 'Adapters running…'}</span>
      </div>` : ''}

    <div class="header-checks-list">${runs}</div>

    <div class="input-row" style="margin: 12px 0;">
      <button class="strix-btn secondary action-btn" data-sarif="${escapeHtml(job.id)}">Download SARIF</button>
    </div>

    ${findings}
  `;

  container.querySelector('[data-sarif]')?.addEventListener('click', () => downloadSarif(job.id));
  container.querySelector('#btn-cancel-job')?.addEventListener('click', () => cancelJob(job.id));
  container.querySelectorAll('[data-finding-update]').forEach(button => {
    button.addEventListener('click', () => updateFindingStatus(job.id, button.dataset.findingUpdate, container));
  });
}

async function updateFindingStatus(jobId, fingerprint, container) {
  const select = container.querySelector(`[data-finding-select="${fingerprint}"]`);
  const status = select?.value;
  if (!status) return;
  try {
    const res = await fetch(`/api/assess/${encodeURIComponent(jobId)}/findings/${encodeURIComponent(fingerprint)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({ status }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Finding update failed');
    showToast(`Finding moved to ${data.status.replace(/_/g, ' ')}`, 'success');
    await openJob(jobId);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function downloadSarif(jobId) {
  try {
    // Authenticated fetch: a bare link would arrive without the bearer token.
    const res = await fetch(`/api/assess/${encodeURIComponent(jobId)}/sarif`, { headers: getAuthHeaders() });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.detail || 'SARIF download failed');
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `strix-${jobId}.sarif.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('SARIF report downloaded', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function loadJobHistory() {
  const container = document.getElementById('assess-history');
  if (!container) return;
  try {
    const res = await fetch('/api/assess?limit=10', { headers: getAuthHeaders() });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Job history unavailable');
    if (!data.jobs.length) {
      container.innerHTML = '<div class="empty-desc">No jobs recorded for this tenant yet.</div>';
      return;
    }
    container.innerHTML = data.jobs.map(job => `
      <button class="assess-history-item" data-job="${escapeHtml(job.id)}">
        <span class="badge ${JOB_BADGE[job.state] || 'neutral'}">${escapeHtml(job.state.toUpperCase())}</span>
        <code>${escapeHtml(job.target)}</code>
        <span class="assess-history-meta">${escapeHtml(job.profile)} · ${job.findings.length} findings</span>
      </button>
    `).join('');
    container.querySelectorAll('[data-job]').forEach(button => {
      button.addEventListener('click', () => openJob(button.dataset.job));
    });
  } catch (err) {
    container.innerHTML = `<div class="empty-desc" style="color: var(--crimson);">${escapeHtml(err.message)}</div>`;
  }
}

async function openJob(jobId) {
  const container = document.getElementById('assess-output-container');
  const badge = document.getElementById('assess-status-badge');
  try {
    const res = await fetch(`/api/assess/${encodeURIComponent(jobId)}`, { headers: getAuthHeaders() });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Job unavailable');
    renderAssessment(data);
    badge.textContent = data.state.toUpperCase();
    badge.className = `badge ${JOB_BADGE[data.state] || 'neutral'}`;
    document.getElementById('assess-target-input').value = data.target;
    // A live job opened from history resumes its progress/cancel loop.
    if (LIVE_STATES.includes(data.state)) pollJob(data);
  } catch (err) {
    container.innerHTML = `<div class="empty-desc" style="color: var(--crimson);">${escapeHtml(err.message)}</div>`;
    showToast(err.message, 'error');
  }
}

// -----------------------------------------------------------------------------
// AUTHORIZATION SCOPE & EVIDENCE BUNDLES
// -----------------------------------------------------------------------------
let lastReport = null;

function initEvidence() {
  document.getElementById('btn-refresh-scope')?.addEventListener('click', loadScope);
  document.getElementById('btn-generate-report')?.addEventListener('click', generateReport);
  document.getElementById('btn-copy-report')?.addEventListener('click', copyReportJSON);
  document.getElementById('btn-download-report')?.addEventListener('click', downloadReportJSON);

}

async function loadScope() {
  const panel = document.getElementById('scope-panel');
  const badge = document.getElementById('scope-status-badge');
  const source = document.getElementById('scope-source');
  if (!panel) return;

  try {
    const res = await fetch('/api/scope', { headers: getAuthHeaders() });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Scope unavailable');

    source.textContent = `source: ${data.source}`;

    if (!data.configured) {
      badge.textContent = 'NOT CONFIGURED';
      badge.className = 'badge high';
      panel.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon" style="color: var(--crimson);">⛔</div>
          <div class="empty-title">No Authorized Scope</div>
          <div class="empty-desc">Every scan and probe is refused until an authorization record exists. Create <code>scope.json</code> (see <code>scope.example.json</code>) or point <code>STRIX_SCOPE_FILE</code> at one, then restart the server.</div>
        </div>
      `;
      return;
    }

    badge.textContent = 'AUTHORIZED';
    badge.className = 'badge low';
    const chips = (hosts) => hosts.length
      ? hosts.map(host => `<span class="tech-chip">${escapeHtml(host)}</span>`).join('')
      : '<span class="scope-empty">none</span>';

    panel.innerHTML = `
      <div class="scope-grid">
        <div class="scope-field"><span class="field-tag">PROGRAM</span><span>${escapeHtml(data.program)}</span></div>
        <div class="scope-field"><span class="field-tag">AUTHORIZED BY</span><span>${escapeHtml(data.authorized_by)}</span></div>
        <div class="scope-field"><span class="field-tag">AUTHORIZATION REF</span><code>${escapeHtml(data.authorization_ref)}</code></div>
      </div>
      <div class="scope-lists">
        <div><span class="field-tag">IN SCOPE</span><div class="scope-chips">${chips(data.include)}</div></div>
        <div><span class="field-tag">EXCLUDED</span><div class="scope-chips">${chips(data.exclude)}</div></div>
      </div>
    `;
  } catch (err) {
    badge.textContent = 'UNAVAILABLE';
    badge.className = 'badge neutral';
    panel.innerHTML = `<div class="empty-desc" style="color: var(--crimson);">${escapeHtml(err.message)} — save a valid API key above and refresh.</div>`;
  }
}

async function generateReport() {
  const field = document.getElementById('report-target-input');
  const target = field?.value.trim();
  const container = document.getElementById('report-output-container');
  const badge = document.getElementById('report-status-badge');
  const button = document.getElementById('btn-generate-report');
  if (!container) return;

  if (!target) {
    showToast('Enter a target you have already assessed.', 'warning');
    return;
  }

  button.disabled = true;
  button.innerHTML = '<span class="btn-icon">⏳</span> Building...';
  badge.textContent = 'BUILDING';
  badge.className = 'badge neutral';

  try {
    const res = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({ target }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Report generation failed');

    lastReport = data;
    badge.textContent = `${data.findings.length} FINDINGS`;
    badge.className = `badge ${data.severity_counts.critical || data.severity_counts.high ? 'high' : (data.findings.length ? 'medium' : 'low')}`;
    document.getElementById('btn-copy-report').disabled = false;
    document.getElementById('btn-download-report').disabled = false;
    container.innerHTML = renderReport(data);
    showToast('Evidence bundle generated', 'success');
  } catch (err) {
    lastReport = null;
    document.getElementById('btn-copy-report').disabled = true;
    document.getElementById('btn-download-report').disabled = true;
    badge.textContent = 'FAILED';
    badge.className = 'badge high';
    container.innerHTML = `<div class="empty-desc" style="color: var(--crimson);">Report error: ${escapeHtml(err.message)}</div>`;
    showToast(err.message, 'error');
  } finally {
    button.disabled = false;
    button.innerHTML = '<span class="btn-icon">▶</span> Generate Report';
  }
}

const SEVERITY_CLASS = { critical: 'severity-high', high: 'severity-high', medium: 'severity-med' };

function renderReport(report) {
  const findings = report.findings.length
    ? report.findings.map(f => `
      <div class="finding-card ${SEVERITY_CLASS[f.severity] || 'severity-low'}">
        <div class="finding-hdr">
          <span class="finding-id">${escapeHtml(f.title)}</span>
          <span class="finding-weight">${escapeHtml(f.severity.toUpperCase())} // ${escapeHtml(f.confidence)} confidence</span>
        </div>
        <div class="finding-details">
          <div class="finding-meta-row">
            <span><strong>Category:</strong> ${escapeHtml(f.category)}</span>
            <span><strong>Verification:</strong> ${escapeHtml(f.verification)}</span>
            ${f.cwe ? `<span><strong>CWE:</strong> ${escapeHtml(f.cwe)}</span>` : ''}
          </div>
          <div class="evidence-block"><strong>Evidence:</strong> ${escapeHtml(f.evidence)}</div>
          ${f.remediation ? `<div class="defense-badge-row"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>` : ''}
        </div>
      </div>
    `).join('')
    : `<div class="empty-state">
        <div class="empty-title">No Findings Recorded</div>
        <div class="empty-desc">Read the verdict above: only a completed run with full coverage counts as a clean result.</div>
      </div>`;

  return `
    <div class="probe-metrics-bar">
      <div class="metric-box"><span class="label">STATE</span><span class="value">${escapeHtml(report.state.toUpperCase())}</span></div>
      <div class="metric-box"><span class="label">FINDINGS</span><span class="value">${report.findings.length}</span></div>
      <div class="metric-box"><span class="label">AUDIT CHAIN</span><span class="value">${report.integrity.chain_valid ? 'VALID' : 'BROKEN'}</span></div>
    </div>

    <div class="defense-badge-row"><strong>Verdict:</strong> ${escapeHtml(report.verdict)}</div>
    <div class="defense-badge-row">
      <strong>Authorization:</strong> ${escapeHtml(report.program)} — ${escapeHtml(report.authorization_ref)} (authorized by ${escapeHtml(report.authorized_by)})
    </div>

    <div class="evidence-meta">
      <span><strong>Target:</strong> <code>${escapeHtml(report.target)}</code></span>
      <span><strong>Job:</strong> <code>${escapeHtml(report.job_id)}</code></span>
      <span><strong>Generated:</strong> ${escapeHtml(report.generated_at)}</span>
      <span><strong>Bundle hash:</strong> <code>${escapeHtml(report.integrity.chain_hash.slice(0, 16))}…</code></span>
    </div>

    ${findings}
  `;
}

async function copyReportJSON() {
  if (!lastReport) return;
  const json = JSON.stringify(lastReport, null, 2);
  try {
    await navigator.clipboard.writeText(json);
    showToast('Evidence bundle copied to clipboard', 'success');
  } catch (err) {
    showToast('Clipboard unavailable — use Download instead', 'warning');
  }
}

function downloadReportJSON() {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `strix-evidence-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Evidence bundle downloaded', 'success');
}

// -----------------------------------------------------------------------------
// UTILITIES
// -----------------------------------------------------------------------------
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
