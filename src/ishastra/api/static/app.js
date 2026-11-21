/**
 * Ishastra Security Assessment Platform -- Premium SPA Controller
 * Minimalism & Swiss Style Design System
 * Talks to the Ishastra HTTP API; no framework, no build step.
 */

// ============================================================================
// STATE MANAGEMENT
// ============================================================================
const state = {
  apiKey: null,
  csrfToken: null,
  user: null,
  oidcConfigured: false,
  currentView: 'dashboard',
  currentTenant: null,
  tenants: [],
  theme: 'light',
  reducedMotion: false,
  sidebarOpen: false,
  activeModal: null,
  bulkSelection: new Set(),
  sortConfig: { key: null, direction: 'asc' },
  filters: {},
};

// ============================================================================
// CSRF & AUTH HELPERS
// ============================================================================
function getCsrfToken() {
  const cookies = document.cookie.split(';');
  for (const cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'ishastra_csrf') {
      state.csrfToken = value;
      return value;
    }
  }
  return state.csrfToken;
}

function setCsrfToken(token) {
  state.csrfToken = token;
}

function getAuthHeaders() {
  const headers = state.apiKey ? { 'Authorization': `Bearer ${state.apiKey}` } : {};
  const csrfToken = getCsrfToken();
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  return headers;
}

// ============================================================================
// UTILITIES
// ============================================================================
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/'/g, '&apos;');
}

function formatDate(epoch) {
  if (!epoch) return '--';
  const date = new Date(Number(epoch) * 1000);
  return Number.isNaN(date.valueOf()) ? '--' : date.toLocaleString();
}

function formatRelativeTime(epoch) {
  if (!epoch) return '--';
  const diff = Date.now() - Number(epoch) * 1000;
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (seconds < 60) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return formatDate(epoch);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function debounce(fn, delay) {
  let timeoutId;
  return (...args) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn.apply(this, args), delay);
  };
}

// ============================================================================
// THEME MANAGEMENT
// ============================================================================
function initTheme() {
  const savedTheme = localStorage.getItem('ishastra_theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  state.theme = savedTheme || (prefersDark ? 'dark' : 'light');
  state.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  applyTheme();

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    if (!localStorage.getItem('ishastra_theme')) {
      state.theme = e.matches ? 'dark' : 'light';
      applyTheme();
    }
  });

  window.matchMedia('(prefers-reduced-motion: reduce)').addEventListener('change', (e) => {
    state.reducedMotion = e.matches;
  });
}

function applyTheme() {
  document.documentElement.setAttribute('data-theme', state.theme);
  localStorage.setItem('ishastra_theme', state.theme);
  updateThemeButton();
}

function toggleTheme() {
  state.theme = state.theme === 'light' ? 'dark' : 'light';
  applyTheme();
  showToast(`Switched to ${state.theme} mode`, 'info');
}

function updateThemeButton() {
  const btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.setAttribute('aria-label', state.theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode');
  }
}

// ============================================================================
// TOAST NOTIFICATIONS
// ============================================================================
function showToast(message, type = 'info', title = null) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'polite');

  const icon = getToastIcon(type);

  toast.innerHTML = `
    <svg class="toast-icon" aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      ${icon}
    </svg>
    <div class="toast-content">
      ${title ? `<div class="toast-title">${escapeHtml(title)}</div>` : ''}
      <div class="toast-message">${escapeHtml(message)}</div>
    </div>
    <button class="toast-close" aria-label="Dismiss notification">
      <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M18 6L6 18M6 6l12 12"/>
      </svg>
    </button>
  `;

  toast.querySelector('.toast-close').addEventListener('click', () => dismissToast(toast));
  container.appendChild(toast);

  setTimeout(() => dismissToast(toast), 5000);

  return toast;
}

function dismissToast(toast) {
  toast.style.animation = 'slideIn 0.2s ease-out reverse';
  setTimeout(() => toast.remove(), 200);
}

function getToastIcon(type) {
  const icons = {
    success: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    warning: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    error: '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
  };
  return icons[type] || icons.info;
}

// ============================================================================
// MODAL MANAGEMENT
// ============================================================================
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (!modal) return;

  state.activeModal = modalId;
  modal.showModal();
  document.body.style.overflow = 'hidden';

  const focusable = modal.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  if (focusable) focusable.focus();

  modal.addEventListener('keydown', trapFocus);
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId) || document.querySelector(`dialog[data-modal="${modalId}"]`);
  if (!modal) return;

  modal.close();
  document.body.style.overflow = '';
  state.activeModal = null;
  modal.removeEventListener('keydown', trapFocus);
}

function closeActiveModal() {
  if (state.activeModal) {
    closeModal(state.activeModal);
  }
}

function trapFocus(e) {
  if (e.key !== 'Tab') return;

  const modal = document.getElementById(state.activeModal);
  if (!modal) return;

  const focusable = modal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  const first = focusable[0];
  const last = focusable[focusable.length - 1];

  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

document.addEventListener('click', (e) => {
  if (e.target.tagName === 'DIALOG' && e.target.open) {
    const rect = e.target.getBoundingClientRect();
    if (e.clientX < rect.left || e.clientX > rect.right || e.clientY < rect.top || e.clientY > rect.bottom) {
      closeActiveModal();
    }
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && state.activeModal) {
    closeActiveModal();
  }
});

// ============================================================================
// SIDEBAR NAVIGATION
// ============================================================================
function initSidebar() {
  const navItems = document.querySelectorAll('.nav-item');
  const mobileToggle = document.getElementById('mobile-menu-toggle');
  const sidebarOverlay = document.getElementById('sidebar-overlay');
  const sidebar = document.querySelector('.sidebar');

  navItems.forEach(item => {
    item.addEventListener('click', () => switchView(item.dataset.view));
  });

  if (mobileToggle) {
    mobileToggle.addEventListener('click', toggleSidebar);
  }

  if (sidebarOverlay) {
    sidebarOverlay.addEventListener('click', closeSidebar);
  }

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      if (window.innerWidth < 768) closeSidebar();
    });
  });
}

function toggleSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  state.sidebarOpen = !state.sidebarOpen;
  sidebar.classList.toggle('open', state.sidebarOpen);
  overlay.classList.toggle('visible', state.sidebarOpen);
}

function closeSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  state.sidebarOpen = false;
  sidebar.classList.remove('open');
  overlay.classList.remove('visible');
}

function switchView(viewId) {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.toggle('active', item.dataset.view === viewId);
  });

  document.querySelectorAll('.view-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === `view-${viewId}`);
  });

  state.currentView = viewId;
  closeSidebar();

  loadViewData(viewId);
  updatePageHeader(viewId);
}

function updatePageHeader(viewId) {
  const titles = {
    dashboard: { title: 'Dashboard', desc: 'Overview of your security posture and recent activity' },
    assessments: { title: 'Assessments', desc: 'Manage and monitor security assessment jobs' },
    targets: { title: 'Targets', desc: 'Authorized scan targets and asset inventory' },
    findings: { title: 'Findings', desc: 'Vulnerability findings across all assessments' },
    policies: { title: 'Policies', desc: 'Assessment policies and compliance rules' },
    scopes: { title: 'Scopes', desc: 'Authorization scopes and evidence bundles' },
    tenants: { title: 'Tenants', desc: 'Multi-tenant management and isolation' },
    audit: { title: 'Audit Log', desc: 'Immutable audit trail of all platform actions' },
    compliance: { title: 'Compliance', desc: 'Compliance dashboards and framework mappings' },
    evidence: { title: 'Evidence', desc: 'Evidence bundles and report generation' },
    settings: { title: 'Settings', desc: 'Platform configuration and integrations' },
  };

  const config = titles[viewId] || { title: 'Dashboard', desc: '' };
  document.getElementById('page-title').textContent = config.title;
  document.getElementById('page-desc').textContent = config.desc;
}

// ============================================================================
// VIEW DATA LOADING
// ============================================================================
async function loadViewData(viewId) {
  try {
    switch (viewId) {
      case 'dashboard': await loadDashboard(); break;
      case 'assessments': await loadAssessments(); break;
      case 'targets': await loadTargets(); break;
      case 'findings': await loadFindings(); break;
      case 'policies': await loadPolicies(); break;
      case 'scopes': await loadScopes(); break;
      case 'tenants': await loadTenants(); break;
      case 'audit': await loadAudit(); break;
      case 'compliance': await loadCompliance(); break;
      case 'evidence': await loadEvidence(); break;
      case 'settings': await loadSettings(); break;
    }
  } catch (err) {
    console.error(`Failed to load ${viewId}:`, err);
    showToast(`Failed to load ${viewId}`, 'error');
  }
}

// ============================================================================
// DASHBOARD
// ============================================================================
async function loadDashboard() {
  await Promise.all([
    loadDashboardKPIs(),
    loadRecentActivity(),
    loadQuickActions(),
    loadTrendsChart(),
  ]);
}

async function loadDashboardKPIs() {
  try {
    const res = await fetch('/api/overview', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load overview');
    const data = await res.json();

    setElementText('kpi-assessments', data.total_jobs || 0);
    setElementText('kpi-findings', data.total_findings || 0);
    setElementText('kpi-targets', data.total_targets || 0);
    setElementText('kpi-tenants', data.total_tenants || 1);
  } catch (err) {
    console.warn('Dashboard KPIs load error:', err);
  }
}

async function loadRecentActivity() {
  const container = document.getElementById('recent-activity-list');
  if (!container) return;

  try {
    const res = await fetch('/api/audit?limit=10', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load activity');
    const data = await res.json();

    if (!data.audit_logs?.length) {
      container.innerHTML = '<div class="empty-state"><p>No recent activity</p></div>';
      return;
    }

    container.innerHTML = data.audit_logs.map(item => `
      <div class="activity-item">
        <div class="activity-icon">
          <svg class="icon icon-md" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            ${getActivityIcon(item.event)}
          </svg>
        </div>
        <div class="activity-content">
          <div class="activity-title">${escapeHtml(formatEventName(item.event))}</div>
          <div class="activity-meta">
            <span>${escapeHtml(item.target || 'N/A')}</span>
            <span>${formatRelativeTime(item.timestamp)}</span>
          </div>
        </div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p>Failed to load activity</p></div>`;
  }
}

function getActivityIcon(event) {
  const icons = {
    assessment_started: '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/><path d="M5 17V7h0a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v10"/>',
    assessment_completed: '<circle cx="12" cy="12" r="10"/><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    finding_created: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    policy_created: '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>',
    scope_updated: '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>',
    user_login: '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/>',
  };
  return icons[event] || '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>';
}

function formatEventName(event) {
  return event.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

function loadQuickActions() {
}

async function loadTrendsChart() {
  const container = document.getElementById('trends-chart');
  if (!container) return;

  try {
    const res = await fetch('/api/findings/trends?bucket=day&days=30', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Trends unavailable');
    const data = await res.json();

    if (!data.buckets?.length) {
      container.innerHTML = '<div class="empty-state"><p>No trend data available</p></div>';
      return;
    }

    renderTrendsChart(container, data.buckets);
  } catch (err) {
    container.innerHTML = '<div class="empty-state"><p>Failed to load trends</p></div>';
  }
}

function renderTrendsChart(container, buckets) {
  const max = Math.max(1, ...buckets.map(b => b.observations));
  const width = container.clientWidth || 600;
  const height = 300;
  const padding = { top: 20, right: 20, bottom: 40, left: 50 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const xScale = i => padding.left + (i / (buckets.length - 1)) * chartWidth;
  const yScale = value => padding.top + chartHeight - (value / max) * chartHeight;

  const points = buckets.map((b, i) => `${xScale(i)},${yScale(b.observations)}`).join(' ');

  container.innerHTML = `
    <svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" aria-label="Findings trend over 30 days" role="img">
      <defs>
        <linearGradient id="trend-gradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--color-purple)" stop-opacity="0.3"/>
          <stop offset="100%" stop-color="var(--color-purple)" stop-opacity="0"/>
        </linearGradient>
      </defs>
      ${[0, 0.25, 0.5, 0.75, 1].map(ratio => `
        <line x1="${padding.left}" y1="${padding.top + chartHeight * ratio}" x2="${width - padding.right}" y2="${padding.top + chartHeight * ratio}" stroke="var(--border-subtle)" stroke-width="1"/>
      `).join('')}
      <polyline points="${padding.left},${height - padding.bottom} ${points} ${width - padding.right},${height - padding.bottom}" fill="url(#trend-gradient)"/>
      <polyline points="${points}" fill="none" stroke="var(--color-purple)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      ${buckets.map((b, i) => `
        <circle cx="${xScale(i)}" cy="${yScale(b.observations)}" r="4" fill="var(--bg-surface)" stroke="var(--color-purple)" stroke-width="2"
          data-tooltip="${escapeHtml(b.bucket)}: ${b.observations} observations"/>
      `).join('')}
      ${[0, 0.5, 1].map(ratio => `
        <text x="${padding.left - 10}" y="${padding.top + chartHeight * (1 - ratio) + 4}" text-anchor="end" font-size="11" fill="var(--text-tertiary)" font-family="var(--font-mono)">
          ${Math.round(max * ratio)}
        </text>
      `).join('')}
      ${buckets.filter((_, i) => i % Math.ceil(buckets.length / 6) === 0).map((b, i) => `
        <text x="${xScale(i * Math.ceil(buckets.length / 6))}" y="${height - padding.bottom + 20}" text-anchor="middle" font-size="11" fill="var(--text-tertiary)" font-family="var(--font-mono)">
          ${escapeHtml(b.bucket.split('-').slice(1).join('-'))}
        </text>
      `).join('')}
    </svg>
    <div class="chart-legend">
      <div class="legend-item">
        <span class="legend-color" style="background: var(--color-purple)"></span>
        <span>Observations</span>
      </div>
    </div>
  `;
}

// ============================================================================
// ASSESSMENTS
// ============================================================================
async function loadAssessments() {
  await renderAssessmentsTable();
  setupAssessmentsToolbar();
}

async function renderAssessmentsTable(filters = {}) {
  const tbody = document.getElementById('assessments-tbody');
  const emptyState = document.getElementById('assessments-empty');
  const countBadge = document.getElementById('assessments-count');
  if (!tbody) return;

  try {
    const params = new URLSearchParams({ page_size: 50, ...filters });
    const res = await fetch(`/api/assess?${params}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load assessments');
    const data = await res.json();

    if (countBadge) countBadge.textContent = `${data.total} assessment${data.total !== 1 ? 's' : ''}`;

    if (!data.jobs?.length) {
      tbody.innerHTML = '';
      if (emptyState) emptyState.hidden = false;
      return;
    }
    if (emptyState) emptyState.hidden = true;

    tbody.innerHTML = data.jobs.map(job => `
      <tr data-job-id="${escapeHtml(job.id)}">
        <td>
          <input type="checkbox" class="row-checkbox" value="${escapeHtml(job.id)}" aria-label="Select assessment ${escapeHtml(job.id)}">
        </td>
        <td><code>${escapeHtml(job.id)}</code></td>
        <td>${escapeHtml(job.target)}</td>
        <td><span class="tag tag-${getTagClass(job.profile)}">${escapeHtml(job.profile)}</span></td>
        <td><span class="badge status-${job.state}">${escapeHtml(job.state.replace(/_/g, ' '))}</span></td>
        <td>${escapeHtml(job.findings?.length || 0)}</td>
        <td>${formatRelativeTime(job.created_at)}</td>
        <td>
          <div class="action-menu">
            <button class="icon-btn" aria-label="Actions for ${escapeHtml(job.id)}">
              <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>
              </svg>
            </button>
          </div>
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('tr[data-job-id]').forEach(row => {
      row.addEventListener('click', (e) => {
        if (e.target.type === 'checkbox' || e.target.closest('.icon-btn')) return;
        openAssessmentDetail(row.dataset.jobId);
      });
    });

    tbody.querySelectorAll('.row-checkbox').forEach(cb => {
      cb.addEventListener('change', updateBulkActions);
    });

    const selectAll = document.getElementById('select-all-assessments');
    if (selectAll) {
      selectAll.onchange = () => {
        tbody.querySelectorAll('.row-checkbox').forEach(cb => {
          cb.checked = selectAll.checked;
        });
        updateBulkActions();
      };
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="table-empty-row"><div class="table-empty"><p>Failed to load assessments</p></div></td></tr>`;
  }
}

function getTagClass(profile) {
  const classes = { web: 'neutral', 'web-deep': 'purple', api: 'info', 'api-deep': 'purple', network: 'gold', agent: 'success', hybrid: 'warning' };
  return classes[profile] || 'neutral';
}

function setupAssessmentsToolbar() {
  const filterSelect = document.getElementById('assessments-status-filter');
  const searchInput = document.getElementById('assessments-search');

  if (filterSelect) {
    filterSelect.addEventListener('change', debounce(() => renderAssessmentsTable(getAssessmentsFilters()), 300));
  }
  if (searchInput) {
    searchInput.addEventListener('input', debounce(() => renderAssessmentsTable(getAssessmentsFilters()), 300));
  }
}

function getAssessmentsFilters() {
  const filters = {};
  const statusFilter = document.getElementById('assessments-status-filter');
  const searchInput = document.getElementById('assessments-search');
  if (statusFilter?.value) filters.state = statusFilter.value;
  if (searchInput?.value) filters.q = searchInput.value;
  return filters;
}

function updateBulkActions() {
  const checkboxes = document.querySelectorAll('.row-checkbox:checked');
  const bulkBar = document.getElementById('assessments-bulk-bar');
  const bulkCount = document.getElementById('bulk-count');

  state.bulkSelection = new Set(Array.from(checkboxes).map(cb => cb.value));

  if (bulkBar) {
    bulkBar.hidden = state.bulkSelection.size === 0;
  }
  if (bulkCount) {
    bulkCount.textContent = `${state.bulkSelection.size} selected`;
  }
}

async function openAssessmentDetail(jobId) {
  const modal = document.getElementById('assessment-detail-modal');
  const container = document.getElementById('assessment-detail-content');
  if (!modal || !container) return;

  container.innerHTML = '<div class="loading-shimmer" style="height: 200px;"></div>';
  openModal('assessment-detail-modal');

  try {
    const res = await fetch(`/api/assess/${encodeURIComponent(jobId)}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load assessment');
    const job = await res.json();

    renderAssessmentDetail(container, job);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p>Failed to load assessment: ${escapeHtml(err.message)}</p></div>`;
  }
}

function renderAssessmentDetail(container, job) {
  const runs = (job.coverage?.adapters || []).map(run => `
    <div class="header-check-item">
      <span>${escapeHtml(run.adapter)} <code>${escapeHtml(String(run.elapsed_ms))}ms</code></span>
      <span class="check-status ${run.state === 'ok' ? 'pass' : (run.state === 'unavailable' ? 'warn' : 'fail')}">${escapeHtml(run.state.toUpperCase())}</span>
    </div>
  `).join('');

  const findings = (job.findings || []).length
    ? job.findings.map(f => `
      <div class="finding-card severity-${f.severity}">
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
        </div>
      </div>
    `).join('')
    : `<div class="empty-state"><div class="empty-icon">${job.clean ? '✓' : '!'}</div><div class="empty-title">${job.clean ? 'No Findings (Complete Coverage)' : 'No Findings -- Inconclusive'}</div><div class="empty-desc">${escapeHtml(job.verdict)}</div></div>`;

  container.innerHTML = `
    <div class="probe-metrics-bar">
      <div class="metric-box"><span class="label">JOB ID</span><span class="value mono">${escapeHtml(job.id)}</span></div>
      <div class="metric-box"><span class="label">STATE</span><span class="value"><span class="badge status-${job.state}">${escapeHtml(job.state.toUpperCase())}</span></span></div>
      <div class="metric-box"><span class="label">COVERAGE</span><span class="value">${(job.coverage && job.coverage.ok) || 0}/${(job.coverage && job.coverage.total) || 0}</span></div>
      <div class="metric-box"><span class="label">FINDINGS</span><span class="value">${(job.findings || []).length}</span></div>
    </div>

    <div class="defense-badge-row"><strong>Verdict:</strong> ${escapeHtml(job.verdict)}</div>
    ${job.error ? `<div class="alert alert-error"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg><div><h3>Error</h3><p>${escapeHtml(job.error)}</p></div></div>` : ''}

    <div class="card-header" style="margin-top: var(--space-6); padding-bottom: var(--space-3);">
      <h3 class="card-title">Adapter Runs</h3>
    </div>
    <div class="header-checks-list">${runs}</div>

    <div class="card-header" style="margin-top: var(--space-6); padding-bottom: var(--space-3);">
      <h3 class="card-title">Findings</h3>
    </div>
    ${findings}

    <div class="card-footer">
      <button class="btn btn-secondary" data-sarif="${escapeHtml(job.id)}">Download SARIF</button>
      ${['queued', 'running'].includes(job.state) ? `<button class="btn btn-danger" data-cancel="${escapeHtml(job.id)}">Cancel Job</button>` : ''}
    </div>
  `;

  container.querySelector('[data-sarif]')?.addEventListener('click', () => downloadSarif(job.id));
  container.querySelector('[data-cancel]')?.addEventListener('click', () => cancelAssessment(job.id));
}

async function cancelAssessment(jobId) {
  try {
    const res = await fetch(`/api/assess/${encodeURIComponent(jobId)}/cancel`, {
      method: 'POST', headers: getAuthHeaders(),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || 'Cancel failed');
    showToast('Cancellation signalled', 'info');
    closeActiveModal();
    await loadAssessments();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function downloadSarif(jobId) {
  try {
    const res = await fetch(`/api/assess/${encodeURIComponent(jobId)}/sarif`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('SARIF download failed');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ishastra-${jobId}.sarif.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('SARIF report downloaded', 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// TARGETS / ASSETS
// ============================================================================
async function loadTargets() {
  await Promise.all([
    renderAssetsTable(),
    loadAssetStats(),
  ]);
  setupTargetsToolbar();
}

async function loadAssetStats() {
  try {
    const res = await fetch('/api/assets/stats', { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    setElementText('targets-total', data.total || 0);
    setElementText('targets-critical', data.critical || 0);
    setElementText('targets-high', data.high || 0);
    setElementText('targets-open-findings', data.open_findings || 0);
  } catch (err) {
    console.warn('Asset stats load error:', err);
  }
}

async function renderAssetsTable(filters = {}) {
  const tbody = document.getElementById('targets-tbody');
  const emptyState = document.getElementById('targets-empty');
  const countBadge = document.getElementById('targets-count');
  if (!tbody) return;

  try {
    const params = new URLSearchParams({ page_size: 100, ...filters });
    const res = await fetch(`/api/assets?${params}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load assets');
    const data = await res.json();

    if (countBadge) countBadge.textContent = `${data.total} asset${data.total !== 1 ? 's' : ''}`;

    if (!data.items?.length) {
      tbody.innerHTML = '';
      if (emptyState) emptyState.hidden = false;
      return;
    }
    if (emptyState) emptyState.hidden = true;

    tbody.innerHTML = data.items.map(asset => `
      <tr data-asset-key="${escapeHtml(asset.asset_key)}">
        <td>
          <input type="checkbox" class="row-checkbox" value="${escapeHtml(asset.asset_key)}" aria-label="Select asset ${escapeHtml(asset.asset)}">
        </td>
        <td><button class="btn btn-ghost btn-sm" data-asset-detail="${escapeHtml(asset.asset_key)}">${escapeHtml(asset.asset)}</button></td>
        <td><span class="tag tag-neutral">${escapeHtml(asset.asset_type)}</span></td>
        <td>${escapeHtml(asset.owner || '--')}</td>
        <td><span class="tag tag-${asset.criticality?.toLowerCase() || 'neutral'}">${escapeHtml(asset.criticality || '--')}</span></td>
        <td>${asset.open_finding_count} / ${asset.finding_count}</td>
        <td>${formatRelativeTime(asset.last_seen)}</td>
        <td>
          <div class="action-menu">
            <button class="icon-btn" aria-label="Actions for ${escapeHtml(asset.asset)}">
              <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>
              </svg>
            </button>
          </div>
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('[data-asset-detail]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        openAssetDetail(btn.dataset.assetDetail);
      });
    });

    tbody.querySelectorAll('.row-checkbox').forEach(cb => {
      cb.addEventListener('change', updateTargetsBulkActions);
    });

    const selectAll = document.getElementById('select-all-targets');
    if (selectAll) {
      selectAll.onchange = () => {
        tbody.querySelectorAll('.row-checkbox').forEach(cb => cb.checked = selectAll.checked);
        updateTargetsBulkActions();
      };
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="table-empty-row"><div class="table-empty"><p>Failed to load assets</p></div></td></tr>`;
  }
}

function setupTargetsToolbar() {
  const typeFilter = document.getElementById('targets-type-filter');
  const criticalityFilter = document.getElementById('targets-criticality-filter');
  const searchInput = document.getElementById('targets-search');

  [typeFilter, criticalityFilter, searchInput].forEach(el => {
    if (el) el.addEventListener('input', debounce(() => renderAssetsTable(getTargetsFilters()), 300));
    if (el) el.addEventListener('change', debounce(() => renderAssetsTable(getTargetsFilters()), 300));
  });
}

function getTargetsFilters() {
  const filters = {};
  const typeFilter = document.getElementById('targets-type-filter');
  const criticalityFilter = document.getElementById('targets-criticality-filter');
  const searchInput = document.getElementById('targets-search');
  if (typeFilter?.value) filters.asset_type = typeFilter.value;
  if (criticalityFilter?.value) filters.criticality = criticalityFilter.value;
  if (searchInput?.value) filters.q = searchInput.value;
  return filters;
}

function updateTargetsBulkActions() {
  const checkboxes = document.querySelectorAll('#targets-tbody .row-checkbox:checked');
  const bulkBar = document.getElementById('targets-bulk-bar');
  const bulkCount = document.getElementById('targets-bulk-count');
  const selected = Array.from(checkboxes).map(cb => cb.value);

  if (bulkBar) bulkBar.hidden = selected.length === 0;
  if (bulkCount) bulkCount.textContent = `${selected.length} selected`;
}

async function openAssetDetail(assetKey) {
  const modal = document.getElementById('asset-detail-modal');
  const container = document.getElementById('asset-detail-content');
  if (!modal || !container) return;

  container.innerHTML = '<div class="loading-shimmer" style="height: 200px;"></div>';
  openModal('asset-detail-modal');

  try {
    const res = await fetch(`/api/assets/${encodeURIComponent(assetKey)}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Asset unavailable');
    const asset = await res.json();
    renderAssetDetail(container, asset);
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p>Failed to load asset: ${escapeHtml(err.message)}</p></div>`;
  }
}

function renderAssetDetail(container, asset) {
  const findingsHtml = asset.findings?.length
    ? asset.findings.map(f => `
      <div class="finding-card severity-${f.severity}">
        <div class="finding-hdr">
          <span class="finding-id">${escapeHtml(f.severity.toUpperCase())} · ${escapeHtml(f.category)}</span>
          <span class="finding-weight">${escapeHtml(f.status)} · job ${escapeHtml(f.job_state)}</span>
        </div>
        <div class="finding-details">
          <div><strong>${escapeHtml(f.title)}</strong></div>
          <div class="evidence-block">${escapeHtml(f.evidence)}</div>
        </div>
      </div>
    `).join('')
    : '<div class="empty-state"><p>No findings for this asset</p></div>';

  container.innerHTML = `
    <div class="card-header">
      <div>
        <h3 class="card-title">${escapeHtml(asset.asset)}</h3>
        <div class="card-subtitle">${escapeHtml(asset.asset_type)} · ${escapeHtml(asset.criticality)} · Owner: ${escapeHtml(asset.owner || 'unassigned')}</div>
      </div>
    </div>
    <div class="card-body">
      <div class="probe-metrics-bar">
        <div class="metric-box"><span class="label">ASSET KEY</span><span class="value mono">${escapeHtml(asset.asset_key)}</span></div>
        <div class="metric-box"><span class="label">FIRST SEEN</span><span class="value">${formatDate(asset.first_seen)}</span></div>
        <div class="metric-box"><span class="label">LAST SEEN</span><span class="value">${formatRelativeTime(asset.last_seen)}</span></div>
        <div class="metric-box"><span class="label">TOTAL FINDINGS</span><span class="value">${asset.finding_count}</span></div>
      </div>
      <div class="card-header" style="margin-top: var(--space-6); padding-bottom: var(--space-3);">
        <h3 class="card-title">Findings</h3>
      </div>
      ${findingsHtml}
    </div>
  `;
}

// ============================================================================
// FINDINGS
// ============================================================================
async function loadFindings() {
  await renderFindingsTable();
  setupFindingsToolbar();
}

async function renderFindingsTable(filters = {}) {
  const tbody = document.getElementById('findings-tbody');
  const emptyState = document.getElementById('findings-empty');
  const countBadge = document.getElementById('findings-count');
  if (!tbody) return;

  try {
    const params = new URLSearchParams({ page_size: 100, ...filters });
    const res = await fetch(`/api/findings?${params}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load findings');
    const data = await res.json();

    if (countBadge) countBadge.textContent = `${data.total} finding${data.total !== 1 ? 's' : ''}`;

    if (!data.items?.length) {
      tbody.innerHTML = '';
      if (emptyState) emptyState.hidden = false;
      return;
    }
    if (emptyState) emptyState.hidden = true;

    tbody.innerHTML = data.items.map(finding => `
      <tr data-finding-id="${escapeHtml(finding.fingerprint)}">
        <td>
          <input type="checkbox" class="row-checkbox" value="${escapeHtml(finding.fingerprint)}" aria-label="Select finding">
        </td>
        <td>
          <div><strong>${escapeHtml(finding.title)}</strong></div>
          <div class="card-subtitle">${escapeHtml(finding.asset)}</div>
        </td>
        <td><span class="badge severity-${finding.severity}">${escapeHtml(finding.severity.toUpperCase())}</span></td>
        <td><span class="badge status-${finding.status}">${escapeHtml(finding.status.replace(/_/g, ' '))}</span></td>
        <td>${finding.occurrence_count}</td>
        <td>${formatRelativeTime(finding.first_seen)} / ${formatRelativeTime(finding.last_seen)}</td>
        <td>${escapeHtml(finding.resolution?.state || 'open')}</td>
        <td>
          <div class="action-menu">
            <button class="icon-btn" aria-label="Actions for finding">
              <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>
              </svg>
            </button>
          </div>
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('.row-checkbox').forEach(cb => {
      cb.addEventListener('change', updateFindingsBulkActions);
    });

    const selectAll = document.getElementById('select-all-findings');
    if (selectAll) {
      selectAll.onchange = () => {
        tbody.querySelectorAll('.row-checkbox').forEach(cb => cb.checked = selectAll.checked);
        updateFindingsBulkActions();
      };
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="table-empty-row"><div class="table-empty"><p>Failed to load findings</p></div></td></tr>`;
  }
}

function setupFindingsToolbar() {
  const severityFilter = document.getElementById('findings-severity-filter');
  const statusFilter = document.getElementById('findings-status-filter');
  const searchInput = document.getElementById('findings-search');

  [severityFilter, statusFilter, searchInput].forEach(el => {
    if (el) el.addEventListener('input', debounce(() => renderFindingsTable(getFindingsFilters()), 300));
    if (el) el.addEventListener('change', debounce(() => renderFindingsTable(getFindingsFilters()), 300));
  });
}

function getFindingsFilters() {
  const filters = {};
  const severityFilter = document.getElementById('findings-severity-filter');
  const statusFilter = document.getElementById('findings-status-filter');
  const searchInput = document.getElementById('findings-search');
  if (severityFilter?.value) filters.severity = severityFilter.value;
  if (statusFilter?.value) filters.status = statusFilter.value;
  if (searchInput?.value) filters.q = searchInput.value;
  return filters;
}

function updateFindingsBulkActions() {
  const checkboxes = document.querySelectorAll('#findings-tbody .row-checkbox:checked');
  const bulkBar = document.getElementById('findings-bulk-bar');
  const bulkCount = document.getElementById('findings-bulk-count');
  const selected = Array.from(checkboxes).map(cb => cb.value);

  if (bulkBar) bulkBar.hidden = selected.length === 0;
  if (bulkCount) bulkCount.textContent = `${selected.length} selected`;
}

// ============================================================================
// POLICIES
// ============================================================================
async function loadPolicies() {
  await renderPoliciesTable();
}

async function renderPoliciesTable() {
  const tbody = document.getElementById('policies-tbody');
  const emptyState = document.getElementById('policies-empty');
  if (!tbody) return;

  try {
    const res = await fetch('/api/policies', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load policies');
    const data = await res.json();

    if (!data.items?.length) {
      tbody.innerHTML = '';
      if (emptyState) emptyState.hidden = false;
      return;
    }
    if (emptyState) emptyState.hidden = true;

    tbody.innerHTML = data.items.map(policy => `
      <tr>
        <td><code>${escapeHtml(policy.policy_id)}</code></td>
        <td>${escapeHtml(policy.name)}</td>
        <td><span class="tag tag-${policy.tier || 'neutral'}">${escapeHtml(policy.tier || 'standard')}</span></td>
        <td>${escapeHtml(policy.description || '--')}</td>
        <td>v${policy.version}</td>
        <td>${policy.created_at ? formatDate(policy.created_at) : '--'}</td>
        <td>
          <div class="action-menu">
            <button class="icon-btn" aria-label="Edit policy" data-edit-policy="${escapeHtml(policy.policy_id)}">
              <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            </button>
            <button class="icon-btn destructive" aria-label="Delete policy" data-delete-policy="${escapeHtml(policy.policy_id)}">
              <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
            </button>
          </div>
        </td>
      </tr>
    `).join('');

    tbody.querySelectorAll('[data-edit-policy]').forEach(btn => {
      btn.addEventListener('click', () => openPolicyModal(btn.dataset.editPolicy));
    });
    tbody.querySelectorAll('[data-delete-policy]').forEach(btn => {
      btn.addEventListener('click', () => deletePolicy(btn.dataset.deletePolicy));
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="table-empty-row"><div class="table-empty"><p>Failed to load policies</p></div></td></tr>`;
  }
}

function openPolicyModal(policyId = null) {
  const modal = document.getElementById('policy-modal');
  const form = document.getElementById('policy-form');
  const title = document.getElementById('policy-modal-title');
  if (!modal || !form) return;

  form.reset();
  form.dataset.policyId = policyId || '';
  title.textContent = policyId ? 'Edit Policy' : 'Create Policy';

  if (policyId) {
    loadPolicyForEdit(policyId);
  }

  openModal('policy-modal');
}

async function loadPolicyForEdit(policyId) {
  try {
    const res = await fetch(`/api/policies/${encodeURIComponent(policyId)}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Policy not found');
    const policy = await res.json();

    document.getElementById('policy-id').value = policy.policy_id;
    document.getElementById('policy-name').value = policy.name;
    document.getElementById('policy-tier').value = policy.tier;
    document.getElementById('policy-description').value = policy.description || '';
    document.getElementById('policy-config').value = JSON.stringify(policy.config || {}, null, 2);
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function savePolicy(e) {
  e.preventDefault();
  const form = e.target;
  const policyId = form.dataset.policyId;
  const isNew = !policyId;

  const payload = {
    policy_id: document.getElementById('policy-id').value || undefined,
    name: document.getElementById('policy-name').value,
    tier: document.getElementById('policy-tier').value,
    description: document.getElementById('policy-description').value,
    config: JSON.parse(document.getElementById('policy-config').value || '{}'),
  };

  try {
    const url = isNew ? '/api/policies' : `/api/policies/${encodeURIComponent(policyId)}`;
    const method = isNew ? 'POST' : 'PATCH';
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error((await res.json()).detail || 'Failed to save policy');
    showToast(`Policy ${isNew ? 'created' : 'updated'}`, 'success');
    closeActiveModal();
    await loadPolicies();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deletePolicy(policyId) {
  if (!confirm(`Delete policy "${policyId}"? This cannot be undone.`)) return;
  try {
    const res = await fetch(`/api/policies/${encodeURIComponent(policyId)}`, {
      method: 'DELETE', headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to delete policy');
    showToast('Policy deleted', 'success');
    await loadPolicies();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// SCOPES
// ============================================================================
async function loadScopes() {
  const panel = document.getElementById('scope-panel');
  const badge = document.getElementById('scope-status-badge');
  const source = document.getElementById('scope-source');
  if (!panel) return;

  try {
    const res = await fetch('/api/scope', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Scope unavailable');
    const data = await res.json();

    source.textContent = `source: ${data.source}`;

    if (!data.configured) {
      badge.textContent = 'NOT CONFIGURED';
      badge.className = 'badge severity-critical';
      panel.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon" style="color: var(--color-danger);">⛔</div>
          <div class="empty-title">No Authorized Scope</div>
          <div class="empty-desc">Every scan and probe is refused until an authorization record exists. Create <code>scope.json</code> (see <code>scope.example.json</code>) or point <code>ISHASTRA_SCOPE_FILE</code> at one, then restart the server.</div>
        </div>
      `;
      return;
    }

    badge.textContent = 'AUTHORIZED';
    badge.className = 'badge severity-low';
    const chips = (hosts) => hosts.length
      ? hosts.map(host => `<span class="scope-chip">${escapeHtml(host)}</span>`).join('')
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
    badge.className = 'badge tag-neutral';
    panel.innerHTML = `<div class="empty-state"><p>Failed to load scope: ${escapeHtml(err.message)}</p></div>`;
  }
}

// ============================================================================
// TENANTS
// ============================================================================
async function loadTenants() {
  await renderTenantsTable();
  await loadTenantSelector();
}

async function loadTenantSelector() {
  const select = document.getElementById('tenant-select');
  if (!select) return;

  try {
    const res = await fetch('/api/tenants', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load tenants');
    const data = await res.json();

    state.tenants = data.items || [];
    select.innerHTML = state.tenants.map(t => `
      <option value="${escapeHtml(t.tenant_id)}" ${t.tenant_id === state.currentTenant ? 'selected' : ''}>
        ${escapeHtml(t.name)} (${escapeHtml(t.tenant_id)})
      </option>
    `).join('');

    select.addEventListener('change', (e) => switchTenant(e.target.value));
  } catch (err) {
    console.warn('Tenant selector load error:', err);
  }
}

function switchTenant(tenantId) {
  state.currentTenant = tenantId;
  showToast(`Switched to tenant: ${tenantId}`, 'info');
  loadViewData(state.currentView);
}

async function renderTenantsTable() {
  const tbody = document.getElementById('tenants-tbody');
  const emptyState = document.getElementById('tenants-empty');
  if (!tbody) return;

  try {
    const res = await fetch('/api/tenants', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load tenants');
    const data = await res.json();

    if (!data.items?.length) {
      tbody.innerHTML = '';
      if (emptyState) emptyState.hidden = false;
      return;
    }
    if (emptyState) emptyState.hidden = true;

    tbody.innerHTML = data.items.map(tenant => `
      <tr>
        <td><code>${escapeHtml(tenant.tenant_id)}</code></td>
        <td>${escapeHtml(tenant.name)}</td>
        <td><span class="badge status-${tenant.status}">${escapeHtml(tenant.status)}</span></td>
        <td>${tenant.assessment_count || 0}</td>
        <td>${tenant.asset_count || 0}</td>
        <td>${tenant.user_count || 0}</td>
        <td>${tenant.created_at ? formatDate(tenant.created_at) : '--'}</td>
        <td>
          <div class="action-menu">
            <button class="icon-btn" aria-label="Edit tenant" data-edit-tenant="${escapeHtml(tenant.tenant_id)}">
              <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            </button>
          </div>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" class="table-empty-row"><div class="table-empty"><p>Failed to load tenants</p></div></td></tr>`;
  }
}

// ============================================================================
// AUDIT LOG
// ============================================================================
async function loadAudit() {
  await renderAuditTable();
  setupAuditToolbar();
}

async function renderAuditTable(filters = {}) {
  const tbody = document.getElementById('audit-tbody');
  const emptyState = document.getElementById('audit-empty');
  const countBadge = document.getElementById('audit-count');
  if (!tbody) return;

  try {
    const params = new URLSearchParams({ limit: 100, ...filters });
    const res = await fetch(`/api/audit?${params}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load audit logs');
    const data = await res.json();

    if (countBadge) countBadge.textContent = `${data.total_records} record${data.total_records !== 1 ? 's' : ''}`;

    if (!data.audit_logs?.length) {
      tbody.innerHTML = '';
      if (emptyState) emptyState.hidden = false;
      return;
    }
    if (emptyState) emptyState.hidden = true;

    tbody.innerHTML = data.audit_logs.map((item, idx) => {
      const event = item.event || 'action';
      const target = item.target || 'N/A';
      const details = Object.entries(item)
        .filter(([k]) => k !== 'event' && k !== 'target' && k !== 'timestamp')
        .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
        .join('; ');
      const hasRedacted = JSON.stringify(item).includes('[REDACTED]');

      return `
        <tr>
          <td style="color: var(--text-tertiary); font-family: var(--font-mono); font-size: var(--text-xs);">#${data.total_records - idx}</td>
          <td><span class="badge ${event.includes('denied') || event.includes('rejected') ? 'severity-high' : 'tag-info'}">${escapeHtml(event.toUpperCase().replace(/_/g, ' '))}</span></td>
          <td><code>${escapeHtml(target)}</code></td>
          <td style="max-width: 480px; word-break: break-all; font-family: var(--font-mono); font-size: var(--text-xs);">${escapeHtml(details)}</td>
          <td>${hasRedacted ? '<span class="badge severity-low">SEC-REDACTED</span>' : '<span style="color: var(--text-tertiary); font-size: var(--text-xs);">VERIFIED CLEAN</span>'}</td>
          <td>${formatRelativeTime(item.timestamp)}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="table-empty-row"><div class="table-empty"><p>Failed to load audit log</p></div></td></tr>`;
  }
}

function setupAuditToolbar() {
  const searchInput = document.getElementById('audit-search');
  const exportBtn = document.getElementById('btn-export-audit');

  if (searchInput) {
    searchInput.addEventListener('input', debounce(() => renderAuditTable({ q: searchInput.value }), 300));
  }
  if (exportBtn) {
    exportBtn.addEventListener('click', exportAuditJSON);
  }
}

function exportAuditJSON() {
  showToast('Export functionality requires backend support', 'info');
}

// ============================================================================
// COMPLIANCE
// ============================================================================
async function loadCompliance() {
  const container = document.getElementById('compliance-content');
  if (!container) return;

  try {
    const res = await fetch('/api/compliance/overview', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Compliance unavailable');
    const data = await res.json();

    container.innerHTML = `
      <div class="kpi-row">
        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Frameworks</span>
            <span class="kpi-tag tag-info">${data.frameworks_count || 0}</span>
          </div>
          <div class="kpi-value">${data.frameworks_count || 0}</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Controls</span>
            <span class="kpi-tag tag-purple">${data.controls_count || 0}</span>
          </div>
          <div class="kpi-value">${data.controls_count || 0}</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Passing</span>
            <span class="kpi-tag tag-success">${data.passing_count || 0}</span>
          </div>
          <div class="kpi-value">${data.passing_count || 0}</div>
        </div>
        <div class="kpi-card">
          <div class="kpi-header">
            <span class="kpi-label">Failing</span>
            <span class="kpi-tag tag-danger">${data.failing_count || 0}</span>
          </div>
          <div class="kpi-value">${data.failing_count || 0}</div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><h3 class="card-title">Framework Coverage</h3></div>
        <div class="card-body">
          <div class="table-wrapper">
            <table class="data-table">
              <thead>
                <tr><th>Framework</th><th>Version</th><th>Controls</th><th>Passing</th><th>Failing</th><th>Coverage</th></tr>
              </thead>
              <tbody>
                ${(data.frameworks || []).map(f => `
                  <tr>
                    <td><strong>${escapeHtml(f.name)}</strong></td>
                    <td>${escapeHtml(f.version)}</td>
                    <td>${f.controls}</td>
                    <td><span class="badge severity-low">${f.passing}</span></td>
                    <td><span class="badge severity-high">${f.failing}</span></td>
                    <td>${f.coverage}%</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p>Failed to load compliance: ${escapeHtml(err.message)}</p></div>`;
  }
}

// ============================================================================
// EVIDENCE
// ============================================================================
async function loadEvidence() {
  await loadAssessmentProfiles();
}

let lastReport = null;

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
    console.warn('Profile load failed:', err.message);
  }
}

function updateProfileHint() {
  const select = document.getElementById('assess-profile-select');
  const hint = document.getElementById('assess-profile-hint');
  if (!select || !hint) return;

  let adapters = {};
  try { adapters = JSON.parse(select.dataset.adapters || '{}'); } catch (e) {}
  const profileAdapters = { web: ['strix-http'], 'web-deep': ['strix-http', 'strix-dynamic-validation', 'nuclei'], api: ['strix-http', 'strix-openapi'], 'api-deep': ['strix-http', 'strix-openapi', 'strix-dynamic-validation', 'nuclei'], network: ['strix-http', 'nmap'], agent: ['strix-agent'], hybrid: ['strix-http', 'strix-git-exposure', 'strix-agent'] };
  const profileTimeouts = { agent: 900, hybrid: 900 };
  const names = profileAdapters[select.value] || [];
  const missing = names.filter(name => adapters[name] && adapters[name].available === false);
  hint.textContent = missing.length
    ? `Unavailable in this deployment: ${missing.join(', ')} -- the job will report it as unavailable, never clean.`
    : names.map(name => adapters[name] ? `${name} (${adapters[name].detail})` : name).join(' · ');
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
  badge.className = 'badge tag-neutral';

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
    badge.className = `badge ${data.severity_counts.critical || data.severity_counts.high ? 'severity-high' : (data.findings.length ? 'severity-medium' : 'severity-low')}`;
    document.getElementById('btn-copy-report').disabled = false;
    document.getElementById('btn-download-report').disabled = false;
    container.innerHTML = renderReport(data);
    showToast('Evidence bundle generated', 'success');
  } catch (err) {
    lastReport = null;
    document.getElementById('btn-copy-report').disabled = true;
    document.getElementById('btn-download-report').disabled = true;
    badge.textContent = 'FAILED';
    badge.className = 'badge severity-high';
    container.innerHTML = `<div class="empty-state"><p>Report error: ${escapeHtml(err.message)}</p></div>`;
    showToast(err.message, 'error');
  } finally {
    button.disabled = false;
    button.innerHTML = '<span class="btn-icon">▶</span> Generate Report';
  }
}

const SEVERITY_CLASS = { critical: 'severity-high', high: 'severity-high', medium: 'severity-medium' };

function renderReport(report) {
  const findings = report.findings.length
    ? report.findings.map(f => `
      <div class="finding-card severity-${f.severity}">
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
    : `<div class="empty-state"><div class="empty-title">No Findings Recorded</div><div class="empty-desc">Read the verdict above: only a completed run with full coverage counts as a clean result.</div></div>`;

  return `
    <div class="probe-metrics-bar">
      <div class="metric-box"><span class="label">STATE</span><span class="value">${escapeHtml(report.state.toUpperCase())}</span></div>
      <div class="metric-box"><span class="label">FINDINGS</span><span class="value">${report.findings.length}</span></div>
      <div class="metric-box"><span class="label">AUDIT CHAIN</span><span class="value">${report.integrity.chain_valid ? 'VALID' : 'BROKEN'}</span></div>
    </div>
    <div class="defense-badge-row"><strong>Verdict:</strong> ${escapeHtml(report.verdict)}</div>
    <div class="defense-badge-row"><strong>Authorization:</strong> ${escapeHtml(report.program)} -- ${escapeHtml(report.authorization_ref)} (authorized by ${escapeHtml(report.authorized_by)})</div>
    <div class="evidence-meta">
      <span><strong>Target:</strong> <code>${escapeHtml(report.target)}</code></span>
      <span><strong>Job:</strong> <code>${escapeHtml(report.job_id)}</code></span>
      <span><strong>Generated:</strong> ${escapeHtml(report.generated_at)}</span>
      <span><strong>Bundle hash:</strong> <code>${escapeHtml(report.integrity.chain_hash.slice(0, 16))}...</code></span>
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
    showToast('Clipboard unavailable -- use Download instead', 'warning');
  }
}

function downloadReportJSON() {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ishastra-evidence-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Evidence bundle downloaded', 'success');
}

// ============================================================================
// SETTINGS
// ============================================================================
async function loadSettings() {
  setupSettingsNav();
  await loadProfileSettings();
  await loadApiKeysSettings();
  await loadIntegrationsSettings();
  await loadAppearanceSettings();
  await loadDangerZoneSettings();
}

function setupSettingsNav() {
  const navItems = document.querySelectorAll('.settings-nav-item');
  const panels = document.querySelectorAll('.settings-panel');

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const panelId = item.dataset.panel;

      navItems.forEach(n => n.classList.toggle('active', n === item));
      panels.forEach(p => p.classList.toggle('active', p.id === `settings-${panelId}`));
    });
  });
}

async function loadProfileSettings() {
  try {
    const res = await fetch('/api/auth/profile', { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('profile-tenant').textContent = data.tenant_id || '--';
    document.getElementById('profile-role').textContent = data.role || '--';
    document.getElementById('profile-email').textContent = data.email || '--';
  } catch (err) {
    console.warn('Profile settings load error:', err);
  }
}

async function loadApiKeysSettings() {
  const container = document.getElementById('api-keys-list');
  if (!container) return;

  try {
    const res = await fetch('/api/auth/api-keys', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to load API keys');
    const data = await res.json();

    if (!data.keys?.length) {
      container.innerHTML = '<div class="empty-state"><p>No API keys created yet</p></div>';
      return;
    }

    container.innerHTML = data.keys.map(key => `
      <div class="card" style="margin-bottom: var(--space-4);">
        <div class="card-body">
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: var(--space-4);">
            <div>
              <div style="display: flex; align-items: center; gap: var(--space-3);">
                <code class="mono" style="background: var(--bg-hover); padding: var(--space-1) var(--space-2); border-radius: var(--radius-sm);">${escapeHtml(key.prefix)}••••••••</code>
                <span class="badge ${key.active ? 'severity-low' : 'tag-neutral'}">${key.active ? 'Active' : 'Revoked'}</span>
              </div>
              <div class="card-subtitle">Created: ${formatDate(key.created_at)} • Last used: ${formatRelativeTime(key.last_used)}</div>
            </div>
            <button class="btn btn-danger btn-sm" data-revoke-key="${escapeHtml(key.id)}">Revoke</button>
          </div>
        </div>
      </div>
    `).join('');

    container.querySelectorAll('[data-revoke-key]').forEach(btn => {
      btn.addEventListener('click', () => revokeApiKey(btn.dataset.revokeKey));
    });
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><p>Failed to load API keys: ${escapeHtml(err.message)}</p></div>`;
  }
}

async function createApiKey() {
  const name = document.getElementById('new-api-key-name').value.trim();
  if (!name) {
    showToast('Enter a name for the API key', 'warning');
    return;
  }

  try {
    const res = await fetch('/api/auth/api-keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) throw new Error((await res.json()).detail || 'Failed to create API key');
    const data = await res.json();

    showToast(`API key created: ${data.key}`, 'success', 'Copy this key now -- it won\'t be shown again');
    document.getElementById('new-api-key-name').value = '';
    await loadApiKeysSettings();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function revokeApiKey(keyId) {
  if (!confirm('Revoke this API key? This cannot be undone.')) return;
  try {
    const res = await fetch(`/api/auth/api-keys/${encodeURIComponent(keyId)}`, {
      method: 'DELETE', headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to revoke API key');
    showToast('API key revoked', 'success');
    await loadApiKeysSettings();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function loadIntegrationsSettings() {
}

async function loadAppearanceSettings() {
  const themeSelect = document.getElementById('theme-preference');
  if (themeSelect) {
    themeSelect.value = state.theme;
    themeSelect.addEventListener('change', (e) => {
      state.theme = e.target.value;
      applyTheme();
    });
  }
}

async function loadDangerZoneSettings() {
}

// ============================================================================
// USER MENU & AUTH
// ============================================================================
function initUserMenu() {
  const trigger = document.getElementById('user-menu-trigger');
  const dropdown = document.getElementById('user-dropdown');

  if (trigger && dropdown) {
    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdown.classList.toggle('visible');
    });

    document.addEventListener('click', (e) => {
      if (!trigger.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.classList.remove('visible');
      }
    });
  }

  document.getElementById('btn-oidc-login')?.addEventListener('click', () => {
    window.location.href = '/auth/login';
  });

  document.getElementById('btn-oidc-logout')?.addEventListener('click', async () => {
    try {
      await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    } catch (e) { console.warn('Logout failed:', e); }
    state.user = null;
    state.apiKey = null;
    sessionStorage.removeItem('ishastra_api_key');
    updateAuthUI();
    showToast('Logged out', 'info');
    window.location.href = '/';
  });
}

async function checkAuthStatus() {
  try {
    const res = await fetch('/auth/status', { credentials: 'include' });
    const data = await res.json();
    state.oidcConfigured = data.oidc_configured !== false;
    if (data.authenticated) {
      state.user = data;
      state.apiKey = null;
      sessionStorage.removeItem('ishastra_api_key');
    }
    updateAuthUI();
  } catch (err) {
    console.warn('Auth status check failed:', err);
  }
}

function updateAuthUI() {
  const loginBtn = document.getElementById('btn-oidc-login');
  const logoutBtn = document.getElementById('btn-oidc-logout');
  const userInfo = document.getElementById('oidc-user-info');
  const apiKeyInput = document.getElementById('api-key-input');
  const apiKeyLabel = document.querySelector('.auth-label');

  if (state.user) {
    loginBtn?.style.setProperty('display', 'none');
    logoutBtn?.style.setProperty('display', 'inline-flex');
    if (userInfo) {
      userInfo.textContent = `${state.user.tenant_id} (${state.user.role})`;
      userInfo.style.display = 'inline';
    }
    apiKeyInput?.style.setProperty('display', 'none');
    apiKeyLabel?.style.setProperty('display', 'none');
    document.getElementById('btn-save-api-key')?.style.setProperty('display', 'none');
    document.getElementById('btn-clear-api-key')?.style.setProperty('display', 'none');
  } else {
    loginBtn?.style.setProperty('display', state.oidcConfigured ? 'inline-flex' : 'none');
    logoutBtn?.style.setProperty('display', 'none');
    userInfo?.style.setProperty('display', 'none');
    apiKeyInput?.style.setProperty('display', 'inline-block');
    apiKeyLabel?.style.setProperty('display', 'inline');
    document.getElementById('btn-save-api-key')?.style.setProperty('display', 'inline-flex');
    document.getElementById('btn-clear-api-key')?.style.setProperty('display', 'inline-flex');
  }
}

function initApiKeyInput() {
  const input = document.getElementById('api-key-input');
  const saveBtn = document.getElementById('btn-save-api-key');
  const clearBtn = document.getElementById('btn-clear-api-key');

  if (!input || !saveBtn) return;

  const savedKey = sessionStorage.getItem('ishastra_api_key');
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
    sessionStorage.setItem('ishastra_api_key', key);
    showToast('API key saved', 'success');
  });

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      state.apiKey = null;
      input.value = '';
      sessionStorage.removeItem('ishastra_api_key');
      showToast('API key cleared', 'info');
    });
  }
}

// ============================================================================
// API STATUS INDICATOR
// ============================================================================
async function updateApiStatus() {
  const indicator = document.getElementById('api-status-indicator');
  const text = document.getElementById('api-status-text');
  if (!indicator || !text) return;

  try {
    const res = await fetch('/health', { method: 'HEAD' });
    if (res.ok) {
      indicator.dataset.status = 'connected';
      text.textContent = 'API Connected';
    } else {
      indicator.dataset.status = 'error';
      text.textContent = 'API Error';
    }
  } catch (err) {
    indicator.dataset.status = 'error';
    text.textContent = 'API Unreachable';
  }
}

function startApiStatusPolling() {
  updateApiStatus();
  setInterval(updateApiStatus, 30000);
}

// ============================================================================
// SYSTEM STATUS (SIDEBAR FOOTER)
// ============================================================================
async function updateSystemStatus() {
  const dot = document.querySelector('.status-dot[data-status]');
  const version = document.querySelector('.version-info');

  try {
    const res = await fetch('/health', { method: 'HEAD' });
    if (dot) {
      dot.dataset.status = res.ok ? 'healthy' : 'degraded';
    }
  } catch (err) {
    if (dot) dot.dataset.status = 'down';
  }

  if (version) {
    const buildVersion = document.querySelector('meta[name="build-version"]')?.content || 'v3.5.0';
    version.textContent = buildVersion;
  }
}

function startSystemStatusPolling() {
  updateSystemStatus();
  setInterval(updateSystemStatus, 60000);
}

// ============================================================================
// KEYBOARD SHORTCUTS
// ============================================================================
function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;

    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      showToast('Command palette coming soon', 'info');
    }

    if ((e.metaKey || e.ctrlKey) && e.key === '/') {
      e.preventDefault();
      showToast('Keyboard shortcuts: Ctrl+K (command palette), Ctrl+/ (help), Esc (close modal)', 'info');
    }

    if (e.altKey && e.key >= '1' && e.key <= '9') {
      e.preventDefault();
      const views = ['dashboard', 'assessments', 'targets', 'findings', 'policies', 'scopes', 'tenants', 'audit', 'compliance'];
      const index = parseInt(e.key) - 1;
      if (views[index]) switchView(views[index]);
    }
  });
}

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', async () => {
  initTheme();
  initSidebar();
  initUserMenu();
  initApiKeyInput();
  initKeyboardShortcuts();

  await checkAuthStatus();

  startApiStatusPolling();
  startSystemStatusPolling();

  switchView('dashboard');

  document.getElementById('policy-form')?.addEventListener('submit', savePolicy);
  document.getElementById('btn-create-api-key')?.addEventListener('click', createApiKey);
  document.getElementById('btn-generate-report')?.addEventListener('click', generateReport);
  document.getElementById('btn-copy-report')?.addEventListener('click', copyReportJSON);
  document.getElementById('btn-download-report')?.addEventListener('click', downloadReportJSON);

  document.getElementById('theme-toggle')?.addEventListener('click', toggleTheme);

  document.getElementById('btn-new-assessment')?.addEventListener('click', () => switchView('assessments'));
  document.getElementById('btn-new-target')?.addEventListener('click', () => switchView('targets'));
  document.getElementById('btn-new-policy')?.addEventListener('click', () => openPolicyModal());
  document.getElementById('btn-new-tenant')?.addEventListener('click', () => showToast('Tenant creation via API', 'info'));

  document.querySelectorAll('[data-modal-close]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.modalClose));
  });

  if (state.apiKey && sessionStorage.getItem('ishastra_api_key')) {
    showToast('Session restored', 'info');
  }
});

function setElementText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

window.openAssessmentDetail = openAssessmentDetail;
window.openAssetDetail = openAssetDetail;
window.openPolicyModal = openPolicyModal;
window.switchView = switchView;
window.switchTenant = switchTenant;
window.toggleTheme = toggleTheme;
window.showToast = showToast;