/* my_seims — Frontend SPA */
'use strict';

// ── Constants ────────────────────────────────────────────────────────────────
const SEV_CLASS = { critical:'sev-critical', high:'sev-high', medium:'sev-medium', low:'sev-low', info:'sev-info' };
const SEV_ICON  = { critical:'fa-circle-exclamation', high:'fa-triangle-exclamation', medium:'fa-circle-dot', low:'fa-circle-info', info:'fa-circle' };
const CAT_LABELS = { authentication:'Authentication', privilege_escalation:'Privilege Escalation',
  network:'Network Activity', system:'System Activity', security:'Security',
  malware:'Malware / Suspicious', persistence:'Persistence' };
const SRC_LABELS = { unified_log:'macOS Unified Log', login_history:'Login History',
  network:'Network Monitor', process_scan:'Process Scanner',
  install_log:'Software Install Log', system_log:'System Log' };

// ── State ────────────────────────────────────────────────────────────────────
const S = {
  page: 'dashboard',
  charts: {},
  refreshTimer: null,
  autoRefresh: true,
  evtFilter: { page:1, per_page:50, severity:'', category:'', search:'', hours:24 },
  altFilter: { page:1, per_page:50, status:'new', severity:'' },
  altTab: 'new',
  selectedAlerts: new Set(),
};

// ── API ──────────────────────────────────────────────────────────────────────
const api = {
  async get(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  },
  async post(url, data={}) {
    const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  },
  async del(url) {
    const r = await fetch(url, { method:'DELETE' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  },
  async put(url, data={}) {
    const r = await fetch(url, { method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  },
};

// ── Toast ────────────────────────────────────────────────────────────────────
function toast(msg, type='info') {
  const icons = { success:'fa-circle-check', error:'fa-circle-xmark', info:'fa-circle-info' };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<i class="fa-solid ${icons[type]||icons.info}"></i><span>${msg}</span>`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ── Modal ─────────────────────────────────────────────────────────────────────
function openModal(title, bodyHtml, footerHtml='') {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = bodyHtml;
  document.getElementById('modal-footer').innerHTML = footerHtml;
  document.getElementById('modal-backdrop').classList.remove('hidden');
}
function closeModal() {
  document.getElementById('modal-backdrop').classList.add('hidden');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function sevBadge(s) { return `<span class="sev ${SEV_CLASS[s]||'sev-info'}">${(s||'').toUpperCase()}</span>`; }
function statusBadge(s) { return `<span class="status-badge status-${s||'new'}">${(s||'new').toUpperCase()}</span>`; }
function fmtBytes(b) {
  if (b >= 1e9) return (b/1e9).toFixed(1)+' GB';
  if (b >= 1e6) return (b/1e6).toFixed(1)+' MB';
  if (b >= 1e3) return (b/1e3).toFixed(1)+' KB';
  return b + ' B';
}
function fmtTime(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts.replace(' ', 'T'));
    return d.toLocaleString('en-US', { month:'short', day:'numeric', hour:'numeric', minute:'2-digit', hour12:true });
  } catch { return ts.slice(0,16); }
}
function fmtTimeAgo(ts) {
  if (!ts) return 'never';
  try {
    const d = new Date(ts.replace(' ','T'));
    const s = Math.floor((Date.now()-d)/1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s/60)}m ago`;
    if (s < 86400) return `${Math.floor(s/3600)}h ago`;
    return `${Math.floor(s/86400)}d ago`;
  } catch { return ts.slice(0,16); }
}
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function pagination(page, pages, onPage) {
  if (pages <= 1) return '';
  let html = `<div class="pagination"><span>Page ${page} of ${pages}</span>`;
  html += `<button class="page-btn" ${page<=1?'disabled':''} onclick="(${onPage})(${page-1})">‹</button>`;
  const lo = Math.max(1, page-2), hi = Math.min(pages, page+2);
  for (let i=lo; i<=hi; i++) html += `<button class="page-btn ${i===page?'active':''}" onclick="(${onPage})(${i})">${i}</button>`;
  html += `<button class="page-btn" ${page>=pages?'disabled':''} onclick="(${onPage})(${page+1})">›</button></div>`;
  return html;
}

// ── Router ────────────────────────────────────────────────────────────────────
function navigate(page) {
  S.page = page;
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });
  const titles = {
    dashboard:'Dashboard', events:'Events', alerts:'Alerts',
    monitor:'Live Monitor', rules:'Detection Rules', reports:'Reports', settings:'Settings'
  };
  document.getElementById('page-title').textContent = titles[page] || page;
  document.getElementById('page-subtitle').textContent = '';
  clearInterval(S.refreshTimer);
  destroyCharts();
  renderPage(page);
  if (S.autoRefresh) {
    S.refreshTimer = setInterval(() => renderPage(S.page), 30000);
  }
}

function destroyCharts() {
  Object.values(S.charts).forEach(c => { try { c.destroy(); } catch {} });
  S.charts = {};
}

async function renderPage(page) {
  const body = document.getElementById('page-body');
  const loading = document.getElementById('page-loading');
  loading.classList.remove('hidden');
  try {
    switch(page) {
      case 'dashboard': await renderDashboard(); break;
      case 'events':    await renderEvents(); break;
      case 'alerts':    await renderAlerts(); break;
      case 'monitor':   await renderMonitor(); break;
      case 'rules':     await renderRules(); break;
      case 'reports':   await renderReports(); break;
      case 'settings':  await renderSettings(); break;
    }
  } catch(e) {
    body.innerHTML = `<div class="empty-state"><i class="fa-solid fa-triangle-exclamation"></i><p>Error loading page: ${esc(e.message)}</p></div>`;
  } finally {
    loading.classList.add('hidden');
  }
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function renderDashboard() {
  const d = await api.get('/api/dashboard');
  const { stats, severity_distribution: sd, hourly_events: hourly,
          recent_alerts, top_categories, system_health: sh, last_scan } = d;

  document.getElementById('last-scan-time').textContent = fmtTimeAgo(last_scan);
  const ba = stats.critical_alerts || stats.active_alerts;
  const badge = document.getElementById('badge-alerts');
  if (badge && ba > 0) { badge.textContent = ba; badge.className = `nav-badge ${stats.critical_alerts>0?'critical':''}`; }

  const body = document.getElementById('page-body');
  body.innerHTML = `
  <!-- Stat cards -->
  <div class="stat-grid">
    <div class="stat-card info">
      <div class="stat-label"><i class="fa-solid fa-calendar-day"></i> Events Today</div>
      <div class="stat-value">${stats.total_today}</div>
      <div class="stat-sub">${stats.events_1h} in last hour</div>
    </div>
    <div class="stat-card ${stats.active_alerts>0?'high':'low'}">
      <div class="stat-label"><i class="fa-solid fa-bell"></i> Active Alerts</div>
      <div class="stat-value">${stats.active_alerts}</div>
      <div class="stat-sub">unacknowledged</div>
    </div>
    <div class="stat-card ${stats.critical_alerts>0?'critical':'low'}">
      <div class="stat-label"><i class="fa-solid fa-circle-exclamation"></i> Critical</div>
      <div class="stat-value" style="color:var(--sev-critical)">${stats.critical_alerts}</div>
      <div class="stat-sub">need immediate review</div>
    </div>
    <div class="stat-card ${stats.high_alerts>0?'high':'low'}">
      <div class="stat-label"><i class="fa-solid fa-triangle-exclamation"></i> High</div>
      <div class="stat-value" style="color:var(--sev-high)">${stats.high_alerts}</div>
      <div class="stat-sub">review promptly</div>
    </div>
    <div class="stat-card">
      <div class="stat-label"><i class="fa-solid fa-microchip"></i> System</div>
      <div class="stat-value" style="color:var(--blue)">${Math.round(sh.cpu)}%</div>
      <div class="stat-sub">CPU usage</div>
    </div>
  </div>

  <!-- Charts row -->
  <div class="grid-3-1 mb-12">
    <div class="card">
      <div class="card-title"><i class="fa-solid fa-chart-line"></i>Events — Last 24 Hours</div>
      <div class="chart-wrap"><canvas id="chart-events"></canvas></div>
    </div>
    <div class="card">
      <div class="card-title"><i class="fa-solid fa-chart-pie"></i>Severity Distribution</div>
      <div class="chart-wrap"><canvas id="chart-sev"></canvas></div>
    </div>
  </div>

  <!-- System health + Top categories -->
  <div class="grid-2 mb-12">
    <div class="card">
      <div class="card-title"><i class="fa-solid fa-server"></i>System Health</div>
      ${gaugeHtml('CPU Usage', sh.cpu, 'cpu')}
      ${gaugeHtml('Memory', sh.memory, 'mem')}
      ${gaugeHtml('Disk', sh.disk, 'disk')}
    </div>
    <div class="card">
      <div class="card-title"><i class="fa-solid fa-tag"></i>Top Alert Categories (24h)</div>
      ${top_categories.length === 0
        ? '<div class="empty-state"><i class="fa-solid fa-check-circle"></i><p>No alerts in last 24 hours</p></div>'
        : top_categories.map(c => `
          <div class="gauge-item">
            <div class="gauge-label"><span>${CAT_LABELS[c.category]||c.category}</span><span class="gauge-pct">${c.cnt}</span></div>
          </div>`).join('')}
    </div>
  </div>

  <!-- Recent alerts -->
  <div class="card">
    <div class="section-header">
      <div class="card-title" style="margin:0"><i class="fa-solid fa-triangle-exclamation"></i>Recent Alerts</div>
      <button class="btn btn-secondary btn-sm" onclick="navigate('alerts')">View All</button>
    </div>
    ${recentAlertsTable(recent_alerts)}
  </div>`;

  // Charts
  const evtCtx = document.getElementById('chart-events');
  if (evtCtx) {
    S.charts.events = new Chart(evtCtx, {
      type: 'line',
      data: {
        labels: hourly.map(h => h.hour),
        datasets: [{ label:'Events', data: hourly.map(h => h.count),
          borderColor:'#58a6ff', backgroundColor:'rgba(88,166,255,0.08)',
          tension:0.3, fill:true, pointRadius:2 }]
      },
      options: chartOpts('Events per hour')
    });
  }
  const sevCtx = document.getElementById('chart-sev');
  if (sevCtx) {
    const sevLabels = ['critical','high','medium','low','info'];
    const sevColors = ['#f85149','#e3623b','#e3b341','#3fb950','#58a6ff'];
    const sevData = sevLabels.map(s => sd[s]||0);
    if (sevData.some(v => v>0)) {
      S.charts.sev = new Chart(sevCtx, {
        type: 'doughnut',
        data: { labels: sevLabels.map(s=>s.toUpperCase()), datasets:[{ data:sevData, backgroundColor:sevColors, borderWidth:1, borderColor:'#161b22' }] },
        options: { responsive:true, maintainAspectRatio:false,
          plugins:{ legend:{ position:'right', labels:{ color:'#8b949e', font:{size:10}, boxWidth:10 } } } }
      });
    } else {
      sevCtx.parentElement.innerHTML = '<div class="empty-state"><i class="fa-solid fa-check-circle"></i><p>No events yet</p></div>';
    }
  }
}

function gaugeHtml(label, pct, cls) {
  pct = Math.round(pct)||0;
  const fill = pct>85?'crit':pct>70?'high':cls;
  return `<div class="gauge-item">
    <div class="gauge-label"><span>${label}</span><span class="gauge-pct">${pct}%</span></div>
    <div class="gauge-bar"><div class="gauge-fill ${fill}" style="width:${pct}%"></div></div>
  </div>`;
}

function chartOpts(yLabel) {
  return {
    responsive:true, maintainAspectRatio:false,
    plugins:{ legend:{ display:false } },
    scales:{
      x:{ ticks:{ color:'#6e7681', font:{size:9}, maxTicksLimit:8 }, grid:{ color:'rgba(48,54,61,0.5)' } },
      y:{ ticks:{ color:'#6e7681', font:{size:9} }, grid:{ color:'rgba(48,54,61,0.5)' }, beginAtZero:true }
    }
  };
}

function recentAlertsTable(alerts) {
  if (!alerts.length) return '<div class="empty-state"><i class="fa-solid fa-shield-check"></i><p>No alerts — system clean</p></div>';
  return `<div class="table-wrap"><table>
    <thead><tr><th>Severity</th><th>Alert</th><th>Category</th><th>Status</th><th>When</th></tr></thead>
    <tbody>${alerts.map(a => `
    <tr class="clickable" onclick="showAlertModal(${a.id})">
      <td>${sevBadge(a.severity)}</td>
      <td class="fw-600">${esc(a.title)}</td>
      <td class="text-muted">${CAT_LABELS[a.category]||a.category}</td>
      <td>${statusBadge(a.status)}</td>
      <td class="text-muted">${fmtTimeAgo(a.created_at)}</td>
    </tr>`).join('')}
    </tbody></table></div>`;
}

// ── Events ────────────────────────────────────────────────────────────────────
async function renderEvents() {
  const f = S.evtFilter;
  const qs = new URLSearchParams(f).toString();
  const d  = await api.get(`/api/events?${qs}`);
  const body = document.getElementById('page-body');
  document.getElementById('page-subtitle').textContent = `${d.total} total`;

  body.innerHTML = `
  <div class="filters-bar">
    <input type="text" class="filter-search" placeholder="Search messages…" id="evt-search" value="${esc(f.search)}">
    <select id="evt-sev">
      <option value="">All Severities</option>
      ${['critical','high','medium','low','info'].map(s=>`<option value="${s}" ${f.severity===s?'selected':''}>${s.toUpperCase()}</option>`).join('')}
    </select>
    <select id="evt-cat">
      <option value="">All Categories</option>
      ${Object.entries(CAT_LABELS).map(([v,l])=>`<option value="${v}" ${f.category===v?'selected':''}>${l}</option>`).join('')}
    </select>
    <select id="evt-src">
      <option value="">All Sources</option>
      ${Object.entries(SRC_LABELS).map(([v,l])=>`<option value="${v}" ${f.source===v?'selected':''}>${l}</option>`).join('')}
    </select>
    <select id="evt-hours">
      ${[1,6,12,24,48,168].map(h=>`<option value="${h}" ${f.hours==h?'selected':''}>${h}h</option>`).join('')}
    </select>
  </div>

  <div class="card">
    <div class="table-wrap">
    <table>
      <thead><tr>
        <th>Time</th><th>Severity</th><th>Category</th><th>Source</th><th>Process</th><th>What Happened</th>
      </tr></thead>
      <tbody>
      ${d.events.length === 0 ? `<tr><td colspan="6"><div class="empty-state"><i class="fa-solid fa-check-circle"></i><p>No events matching filters</p></div></td></tr>` :
        d.events.map(ev => `
        <tr class="clickable" onclick="showEventModal(${ev.id})">
          <td class="td-mono">${fmtTime(ev.created_at)}</td>
          <td>${sevBadge(ev.severity)}</td>
          <td class="text-muted">${CAT_LABELS[ev.category]||ev.category}</td>
          <td class="text-muted">${SRC_LABELS[ev.source]||ev.source}</td>
          <td class="td-mono">${esc((ev.process||'').slice(0,18))}</td>
          <td class="td-msg">${esc(ev.message)}</td>
        </tr>`).join('')}
      </tbody>
    </table>
    </div>
    ${pagination(d.page, d.pages, p => { S.evtFilter.page=p; renderEvents(); })}
  </div>`;

  // Filter handlers
  let debounce;
  document.getElementById('evt-search').addEventListener('input', e => {
    clearTimeout(debounce);
    debounce = setTimeout(() => { S.evtFilter.search = e.target.value; S.evtFilter.page=1; renderEvents(); }, 400);
  });
  ['evt-sev','evt-cat','evt-src','evt-hours'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', () => {
      if (id==='evt-sev') S.evtFilter.severity = el.value;
      else if (id==='evt-cat') S.evtFilter.category = el.value;
      else if (id==='evt-src') S.evtFilter.source = el.value;
      else if (id==='evt-hours') S.evtFilter.hours = +el.value;
      S.evtFilter.page = 1; renderEvents();
    });
  });
}

async function showEventModal(id) {
  const ev = await api.get(`/api/events/${id}`);
  openModal(`Event #${id} — ${ev.source_label||ev.source}`,
    `<div class="human-block"><i class="fa-solid fa-lightbulb" style="color:var(--blue);margin-right:6px"></i>${esc(ev.human_message||ev.message)}</div>
    <div class="event-detail-grid">
      <span class="edg-label">Time</span><span class="edg-val">${esc(ev.timestamp_human||fmtTime(ev.created_at))}</span>
      <span class="edg-label">Severity</span><span class="edg-val">${sevBadge(ev.severity)}</span>
      <span class="edg-label">Category</span><span class="edg-val">${esc(ev.category_label||ev.category)}</span>
      <span class="edg-label">Source</span><span class="edg-val">${esc(ev.source_label||ev.source)}</span>
      <span class="edg-label">Process</span><span class="edg-val td-mono">${esc(ev.process||'—')}</span>
      <span class="edg-label">Rule ID</span><span class="edg-val">${ev.rule_id||'None'}</span>
    </div>
    <div class="form-label">Raw Log Entry</div>
    <div class="raw-block">${esc(ev.raw||ev.message)}</div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">Close</button>`
  );
}

// ── Alerts ────────────────────────────────────────────────────────────────────
async function renderAlerts() {
  const f   = S.altFilter;
  const qs  = new URLSearchParams(f).toString();
  const d   = await api.get(`/api/alerts?${qs}`);
  const counts = await Promise.all(['new','acknowledged','resolved'].map(s =>
    api.get(`/api/alerts?status=${s}&per_page=1`).then(r => r.total).catch(() => 0)
  ));
  S.selectedAlerts.clear();
  const body = document.getElementById('page-body');

  body.innerHTML = `
  <div class="tabs">
    ${[['new',counts[0],'color-red'],['acknowledged',counts[1],'color-yellow'],['resolved',counts[2],'color-green'],['','d.total','']].map(([s,c,cl],i) => {
      const label = ['New','Acknowledged','Resolved','All'][i];
      const cnt   = [counts[0],counts[1],counts[2],d.total][i];
      return `<div class="tab ${S.altTab===s?'active':''}" onclick="setAltTab('${s}')">${label}<span class="tab-count ${cl}">${cnt}</span></div>`;
    }).join('')}
  </div>

  <div class="filters-bar">
    <select id="alt-sev">
      <option value="">All Severities</option>
      ${['critical','high','medium','low'].map(s=>`<option value="${s}" ${f.severity===s?'selected':''}>${s.toUpperCase()}</option>`).join('')}
    </select>
    <button class="btn btn-secondary btn-sm" id="btn-bulk-ack"><i class="fa-solid fa-check"></i> Ack Selected</button>
    <button class="btn btn-secondary btn-sm" id="btn-bulk-res"><i class="fa-solid fa-check-double"></i> Resolve Selected</button>
    <button class="btn btn-secondary btn-sm ml-auto" id="btn-select-all"><i class="fa-solid fa-square-check"></i> Select All</button>
  </div>

  <div class="card">
    <div class="table-wrap">
    <table>
      <thead><tr>
        <th><input type="checkbox" id="chk-all"></th>
        <th>Severity</th><th>Alert Title</th><th>Category</th><th>Status</th><th>Count</th><th>Detected</th><th>Actions</th>
      </tr></thead>
      <tbody>
      ${d.alerts.length === 0 ? `<tr><td colspan="8"><div class="empty-state"><i class="fa-solid fa-shield-check"></i><p>No alerts in this view</p></div></td></tr>` :
        d.alerts.map(a => `
        <tr class="clickable" onclick="showAlertModal(${a.id})">
          <td onclick="event.stopPropagation()"><input type="checkbox" class="alt-chk" data-id="${a.id}"></td>
          <td>${sevBadge(a.severity)}</td>
          <td class="fw-600">${esc(a.title)}</td>
          <td class="text-muted">${CAT_LABELS[a.category]||a.category}</td>
          <td>${statusBadge(a.status)}</td>
          <td class="text-muted">${a.event_count||1}</td>
          <td class="td-mono">${fmtTime(a.created_at)}</td>
          <td onclick="event.stopPropagation()">
            ${a.status==='new'?`<button class="btn btn-secondary btn-sm" onclick="ackAlert(${a.id})"><i class="fa-solid fa-check"></i></button>`:''}
            ${a.status!=='resolved'?`<button class="btn btn-success btn-sm" onclick="resolveAlert(${a.id})"><i class="fa-solid fa-check-double"></i></button>`:''}
          </td>
        </tr>`).join('')}
      </tbody>
    </table>
    </div>
    ${pagination(d.page, d.pages, p => { S.altFilter.page=p; renderAlerts(); })}
  </div>`;

  // Wire filters
  document.getElementById('alt-sev').addEventListener('change', e => { S.altFilter.severity=e.target.value; S.altFilter.page=1; renderAlerts(); });
  document.getElementById('chk-all').addEventListener('change', e => {
    document.querySelectorAll('.alt-chk').forEach(c => { c.checked=e.target.checked; if(e.target.checked) S.selectedAlerts.add(+c.dataset.id); else S.selectedAlerts.delete(+c.dataset.id); });
  });
  document.querySelectorAll('.alt-chk').forEach(c => c.addEventListener('change', e => {
    if(e.target.checked) S.selectedAlerts.add(+e.target.dataset.id); else S.selectedAlerts.delete(+e.target.dataset.id);
  }));
  document.getElementById('btn-bulk-ack').onclick = () => bulkAction('acknowledge');
  document.getElementById('btn-bulk-res').onclick = () => bulkAction('resolve');
  document.getElementById('btn-select-all').onclick = () => {
    document.querySelectorAll('.alt-chk').forEach(c => { c.checked=true; S.selectedAlerts.add(+c.dataset.id); });
  };
}

function setAltTab(status) {
  S.altTab = status; S.altFilter.status = status; S.altFilter.page = 1; renderAlerts();
}

async function showAlertModal(id) {
  const d = await api.get(`/api/alerts?per_page=200`);
  const a = d.alerts.find(x => x.id===id);
  if (!a) return;
  openModal(`${a.title}`,
    `<div class="human-block"><i class="fa-solid fa-lightbulb" style="color:var(--blue);margin-right:6px"></i>${esc((a.description||'').split('\n\n')[0])}</div>
    <div class="event-detail-grid">
      <span class="edg-label">Severity</span><span class="edg-val">${sevBadge(a.severity)}</span>
      <span class="edg-label">Category</span><span class="edg-val">${CAT_LABELS[a.category]||a.category}</span>
      <span class="edg-label">Status</span><span class="edg-val">${statusBadge(a.status)}</span>
      <span class="edg-label">Detected</span><span class="edg-val">${fmtTime(a.created_at)}</span>
      <span class="edg-label">Events</span><span class="edg-val">${a.event_count||1}</span>
      ${a.acknowledged_at?`<span class="edg-label">Acked</span><span class="edg-val">${fmtTime(a.acknowledged_at)}</span>`:''}
      ${a.resolved_at?`<span class="edg-label">Resolved</span><span class="edg-val">${fmtTime(a.resolved_at)}</span>`:''}
    </div>
    ${a.description&&a.description.includes('\n\n')?`<div class="form-label">Raw Event</div><div class="raw-block">${esc(a.description.split('\n\n')[1]||'')}</div>`:''}`,
    `${a.status==='new'?`<button class="btn btn-secondary" onclick="ackAlert(${id});closeModal()"><i class="fa-solid fa-check"></i> Acknowledge</button>`:''}
     ${a.status!=='resolved'?`<button class="btn btn-success" onclick="resolveAlert(${id});closeModal()"><i class="fa-solid fa-check-double"></i> Resolve</button>`:''}
     <button class="btn btn-secondary" onclick="closeModal()">Close</button>`
  );
}

async function ackAlert(id) {
  await api.post(`/api/alerts/${id}/acknowledge`);
  toast('Alert acknowledged', 'success'); renderAlerts();
}
async function resolveAlert(id) {
  await api.post(`/api/alerts/${id}/resolve`);
  toast('Alert resolved', 'success'); renderAlerts();
}
async function bulkAction(action) {
  const ids = [...S.selectedAlerts];
  if (!ids.length) { toast('No alerts selected', 'info'); return; }
  await api.post('/api/alerts/bulk', { action, ids });
  toast(`${ids.length} alert(s) ${action}d`, 'success');
  S.selectedAlerts.clear(); renderAlerts();
}

// ── Live Monitor ───────────────────────────────────────────────────────────────
async function renderMonitor() {
  const d = await api.get('/api/system/health');
  const body = document.getElementById('page-body');

  body.innerHTML = `
  <div class="grid-3 mb-12">
    <div class="card">
      <div class="card-title"><i class="fa-solid fa-microchip"></i>CPU</div>
      ${gaugeHtml('Usage', d.cpu, 'cpu')}
      <div class="text-muted text-sm mt-12">${d.cpu.toFixed(1)}% utilization</div>
    </div>
    <div class="card">
      <div class="card-title"><i class="fa-solid fa-memory"></i>Memory</div>
      ${gaugeHtml('Usage', d.memory.percent, 'mem')}
      <div class="text-muted text-sm mt-12">${fmtBytes(d.memory.used)} / ${fmtBytes(d.memory.total)}</div>
    </div>
    <div class="card">
      <div class="card-title"><i class="fa-solid fa-hard-drive"></i>Disk</div>
      ${gaugeHtml('Usage', d.disk.percent, 'disk')}
      <div class="text-muted text-sm mt-12">${fmtBytes(d.disk.used)} / ${fmtBytes(d.disk.total)}</div>
    </div>
  </div>
  <div class="grid-2">
    <div class="card">
      <div class="card-title"><i class="fa-solid fa-list-check"></i>Top Processes by CPU</div>
      <div class="table-wrap"><table>
        <thead><tr><th>PID</th><th>Process</th><th>CPU %</th><th>Memory %</th></tr></thead>
        <tbody>${(d.top_processes||[]).map(p=>`
        <tr><td class="proc-pid">${p.pid}</td><td class="proc-name">${esc(p.name)}</td>
            <td>${gaugeHtml('',p.cpu,'cpu')}</td><td>${p.mem.toFixed(1)}%</td></tr>`).join('')}
        </tbody></table></div>
    </div>
    <div class="card">
      <div class="card-title"><i class="fa-solid fa-network-wired"></i>Active Connections</div>
      ${!d.connections||d.connections.length===0
        ? '<div class="empty-state"><i class="fa-solid fa-plug-circle-check"></i><p>No established connections</p></div>'
        : `<div class="table-wrap"><table>
          <thead><tr><th>Local</th><th>Remote</th><th>PID</th></tr></thead>
          <tbody>${d.connections.map(c=>`
          <tr><td class="net-local">${esc(c.local)}</td><td class="net-remote">${esc(c.remote)}</td>
              <td class="proc-pid">${c.pid||'—'}</td></tr>`).join('')}
          </tbody></table></div>`}
    </div>
  </div>`;
}

// ── Detection Rules ───────────────────────────────────────────────────────────
async function renderRules() {
  const d = await api.get('/api/rules');
  const body = document.getElementById('page-body');
  document.getElementById('page-subtitle').textContent = `${d.rules.length} rules`;

  body.innerHTML = `
  <div class="section-header mb-12">
    <h2>Detection Rules</h2>
    <button class="btn btn-primary" onclick="showRuleModal()"><i class="fa-solid fa-plus"></i> New Rule</button>
  </div>
  <div class="card">
    <div class="table-wrap"><table>
      <thead><tr><th>Enabled</th><th>Name</th><th>Severity</th><th>Category</th><th>Threshold</th><th>Pattern</th><th>Actions</th></tr></thead>
      <tbody>${d.rules.map(r=>`
      <tr>
        <td><span class="rule-toggle ${r.enabled?'on':''}" onclick="toggleRule(${r.id},this)"></span></td>
        <td class="fw-600">${esc(r.name)}</td>
        <td>${sevBadge(r.severity)}</td>
        <td class="text-muted">${CAT_LABELS[r.category]||r.category}</td>
        <td class="text-muted">${r.threshold} / ${r.time_window}s</td>
        <td class="td-mono td-msg">${esc(r.pattern||r.process_name||'—')}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="showRuleModal(${JSON.stringify(r).replace(/"/g,'&quot;')})"><i class="fa-solid fa-pen"></i></button>
          <button class="btn btn-danger btn-sm" onclick="deleteRule(${r.id})"><i class="fa-solid fa-trash"></i></button>
        </td>
      </tr>`).join('')}
      </tbody></table></div>
  </div>`;
}

async function toggleRule(id, el) {
  await api.post(`/api/rules/${id}/toggle`);
  el.classList.toggle('on');
}
async function deleteRule(id) {
  if (!confirm('Delete this rule?')) return;
  await api.del(`/api/rules/${id}`);
  toast('Rule deleted', 'success'); renderRules();
}
function showRuleModal(r={}) {
  const isEdit = !!r.id;
  openModal(isEdit?'Edit Rule':'New Detection Rule', `
  <div class="form-row">
    <div class="form-group"><label class="form-label">Rule Name *</label>
      <input class="form-control" id="r-name" value="${esc(r.name||'')}"></div>
    <div class="form-group"><label class="form-label">Severity</label>
      <select class="form-control" id="r-sev">
        ${['critical','high','medium','low','info'].map(s=>`<option value="${s}" ${(r.severity||'medium')===s?'selected':''}>${s.toUpperCase()}</option>`).join('')}
      </select></div>
  </div>
  <div class="form-group"><label class="form-label">Description</label>
    <input class="form-control" id="r-desc" value="${esc(r.description||'')}"></div>
  <div class="form-row">
    <div class="form-group"><label class="form-label">Category</label>
      <select class="form-control" id="r-cat">
        ${Object.entries(CAT_LABELS).map(([v,l])=>`<option value="${v}" ${(r.category||'system')===v?'selected':''}>${l}</option>`).join('')}
      </select></div>
    <div class="form-group"><label class="form-label">Log Source</label>
      <select class="form-control" id="r-src">
        ${['unified','install','system','network','login'].map(s=>`<option value="${s}" ${(r.log_source||'unified')===s?'selected':''}>${s}</option>`).join('')}
      </select></div>
  </div>
  <div class="form-group"><label class="form-label">Pattern (regex)</label>
    <input class="form-control td-mono" id="r-pattern" value="${esc(r.pattern||'')}"></div>
  <div class="form-group"><label class="form-label">Process Name</label>
    <input class="form-control td-mono" id="r-proc" value="${esc(r.process_name||'')}"></div>
  <div class="form-row">
    <div class="form-group"><label class="form-label">Threshold (# matches)</label>
      <input class="form-control" type="number" id="r-thresh" value="${r.threshold||1}" min="1"></div>
    <div class="form-group"><label class="form-label">Time Window (seconds)</label>
      <input class="form-control" type="number" id="r-window" value="${r.time_window||300}" min="60"></div>
  </div>`,
  `<button class="btn btn-primary" onclick="saveRule(${r.id||0})">${isEdit?'Save Changes':'Create Rule'}</button>
   <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>`
  );
}
async function saveRule(id) {
  const data = {
    name: document.getElementById('r-name').value.trim(),
    description: document.getElementById('r-desc').value.trim(),
    severity: document.getElementById('r-sev').value,
    category: document.getElementById('r-cat').value,
    log_source: document.getElementById('r-src').value,
    pattern: document.getElementById('r-pattern').value.trim(),
    process_name: document.getElementById('r-proc').value.trim(),
    threshold: +document.getElementById('r-thresh').value,
    time_window: +document.getElementById('r-window').value,
    enabled: 1,
  };
  if (!data.name) { toast('Rule name is required', 'error'); return; }
  if (id) { await api.put(`/api/rules/${id}`, data); toast('Rule updated', 'success'); }
  else { await api.post('/api/rules', data); toast('Rule created', 'success'); }
  closeModal(); renderRules();
}

// ── Reports ────────────────────────────────────────────────────────────────────
async function renderReports() {
  const d = await api.get('/api/reports');
  const body = document.getElementById('page-body');

  body.innerHTML = `
  <div class="section-header mb-12">
    <h2>PDF Security Reports</h2>
    <button class="btn btn-primary" onclick="showGenReportModal()"><i class="fa-solid fa-file-pdf"></i> Generate Report</button>
  </div>
  <div class="card">
    ${d.reports.length===0
      ? '<div class="empty-state"><i class="fa-solid fa-file-pdf"></i><p>No reports generated yet. Click "Generate Report" to create your first one.</p></div>'
      : `<div class="table-wrap"><table>
        <thead><tr><th>Title</th><th>Events</th><th>Alerts</th><th>Size</th><th>Generated</th><th>Actions</th></tr></thead>
        <tbody>${d.reports.map(r=>`
        <tr>
          <td class="fw-600">${esc(r.title||r.filename)}</td>
          <td>${r.event_count}</td>
          <td>${r.alert_count}</td>
          <td class="text-muted">${fmtBytes(r.size)}</td>
          <td class="td-mono">${fmtTime(r.generated_at)}</td>
          <td>
            <a class="btn btn-primary btn-sm" href="/api/reports/${r.filename}/download"><i class="fa-solid fa-download"></i> Download</a>
            <button class="btn btn-danger btn-sm" onclick="deleteReport(${r.id})"><i class="fa-solid fa-trash"></i></button>
          </td>
        </tr>`).join('')}
        </tbody></table></div>`}
  </div>`;
}

function showGenReportModal() {
  openModal('Generate PDF Report', `
  <div class="form-group"><label class="form-label">Report Title</label>
    <input class="form-control" id="rep-title" placeholder="e.g. Weekly Security Report" value="Security Report — ${new Date().toLocaleDateString('en-US',{month:'long',day:'numeric',year:'numeric'})}"></div>
  <div class="form-group"><label class="form-label">Time Range</label>
    <select class="form-control" id="rep-hours">
      <option value="6">Last 6 hours</option>
      <option value="12">Last 12 hours</option>
      <option value="24" selected>Last 24 hours</option>
      <option value="48">Last 48 hours</option>
      <option value="168">Last 7 days</option>
      <option value="720">Last 30 days</option>
    </select></div>
  <p class="text-muted text-sm mt-12">The report will include an executive summary, human-readable alert details, a full event log with plain-English descriptions, and actionable recommendations. The PDF will be saved to the <code>reports/</code> folder.</p>`,
  `<button class="btn btn-primary" id="btn-gen-rep"><i class="fa-solid fa-file-pdf"></i> Generate</button>
   <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>`
  );
  document.getElementById('btn-gen-rep').onclick = generateReport;
}

async function generateReport() {
  const title = document.getElementById('rep-title').value.trim();
  const hours  = +document.getElementById('rep-hours').value;
  const btn = document.getElementById('btn-gen-rep');
  btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Generating…';
  try {
    const r = await api.post('/api/reports/generate', { title, hours });
    if (r.status === 'ok') {
      toast('Report generated — downloading…', 'success');
      window.location.href = `/api/reports/${r.filename}/download`;
      closeModal(); renderReports();
    } else {
      toast('Error: ' + (r.message||'Unknown error'), 'error');
    }
  } catch(e) {
    toast('Failed to generate report', 'error');
  } finally {
    btn.disabled = false;
  }
}

async function deleteReport(id) {
  if (!confirm('Delete this report?')) return;
  await api.del(`/api/reports/${id}`);
  toast('Report deleted', 'success'); renderReports();
}

// ── Settings ───────────────────────────────────────────────────────────────────
async function renderSettings() {
  const d = await api.get('/api/settings');
  const body = document.getElementById('page-body');

  body.innerHTML = `
  <div class="grid-2">
    <div>
      <div class="card mb-12">
        <div class="card-title"><i class="fa-solid fa-clock"></i>Scan Configuration</div>
        <div class="form-group"><label class="form-label">Scan Interval</label>
          <select class="form-control" id="s-interval">
            ${[5,10,15,30,60].map(m=>`<option value="${m}" ${d.scan_interval==m?'selected':''}>${m} minutes</option>`).join('')}
          </select></div>
        <div class="form-group"><label class="form-label">Scan Lookback Window</label>
          <select class="form-control" id="s-lookback">
            ${['5m','10m','15m','30m','1h'].map(v=>`<option value="${v}" ${d.scan_lookback===v?'selected':''}>${v}</option>`).join('')}
          </select></div>
        <div class="form-group"><label class="form-label">Event Retention (days)</label>
          <select class="form-control" id="s-retention">
            ${[7,14,30,60,90].map(n=>`<option value="${n}" ${d.retention_days==n?'selected':''}>${n} days</option>`).join('')}
          </select></div>
      </div>

      <div class="card mb-12">
        <div class="card-title"><i class="fa-solid fa-file-pdf"></i>Report Settings</div>
        <div class="checkbox-wrap">
          <input type="checkbox" id="s-autoreport" ${d.auto_report==='true'?'checked':''}>
          <label for="s-autoreport">Auto-generate daily report</label>
        </div>
      </div>

      <button class="btn btn-primary" onclick="saveSettings()"><i class="fa-solid fa-floppy-disk"></i> Save Settings</button>
    </div>

    <div>
      <div class="card mb-12">
        <div class="card-title"><i class="fa-solid fa-info-circle"></i>System Information</div>
        <div class="event-detail-grid">
          <span class="edg-label">Last Scan</span><span class="edg-val">${fmtTimeAgo(d.last_scan)}</span>
          <span class="edg-label">Scan Interval</span><span class="edg-val">Every ${d.scan_interval} minutes</span>
          <span class="edg-label">Retention</span><span class="edg-val">${d.retention_days} days</span>
          <span class="edg-label">Auto-Report</span><span class="edg-val">${d.auto_report==='true'?'Enabled':'Disabled'}</span>
          <span class="edg-label">App URL</span><span class="edg-val"><a href="http://localhost:5001">localhost:5001</a></span>
        </div>
      </div>
      <div class="card mb-12">
        <div class="card-title"><i class="fa-solid fa-database"></i>Scan History</div>
        <div id="scan-hist-widget"></div>
      </div>
    </div>
  </div>`;

  // Load scan history
  api.get('/api/scan/history').then(h => {
    const el = document.getElementById('scan-hist-widget');
    if (!el) return;
    el.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Started</th><th>Duration</th><th>Events</th><th>Alerts</th><th>Status</th></tr></thead>
      <tbody>${(h.history||[]).slice(0,8).map(s=>{
        const dur = s.completed_at&&s.started_at?
          Math.round((new Date(s.completed_at)-new Date(s.started_at.replace(' ','T')))/1000)+'s':'—';
        return `<tr>
          <td class="td-mono">${fmtTime(s.started_at)}</td>
          <td>${dur}</td>
          <td>${s.events_found}</td>
          <td>${s.alerts_generated}</td>
          <td><span class="status-badge ${s.status==='completed'?'status-resolved':s.status==='failed'?'status-new':'status-acknowledged'}">${s.status}</span></td>
        </tr>`;
      }).join('')}</tbody></table></div>`;
  });
}

async function saveSettings() {
  const data = {
    scan_interval:  document.getElementById('s-interval').value,
    scan_lookback:  document.getElementById('s-lookback').value,
    retention_days: document.getElementById('s-retention').value,
    auto_report:    document.getElementById('s-autoreport').checked ? 'true' : 'false',
  };
  await api.post('/api/settings', data);
  toast('Settings saved', 'success');
}

// ── Scan now ──────────────────────────────────────────────────────────────────
async function triggerScan() {
  const dot  = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  const btn  = document.getElementById('btn-scan-now');
  dot.className  = 'status-dot running';
  text.textContent = 'Scanning…';
  btn.disabled = true;
  try {
    const r = await api.post('/api/scan');
    dot.className  = 'status-dot ok';
    text.textContent = `Done — ${r.events||0}ev ${r.alerts||0}al`;
    document.getElementById('last-scan-time').textContent = 'just now';
    toast(`Scan complete: ${r.events||0} events, ${r.alerts||0} alerts`, 'success');
    if (S.page === 'dashboard') renderDashboard();
    else if (S.page === 'alerts') renderAlerts();
    else if (S.page === 'events') renderEvents();
  } catch(e) {
    dot.className  = 'status-dot error';
    text.textContent = 'Scan failed';
    toast('Scan failed', 'error');
  } finally {
    btn.disabled = false;
    setTimeout(() => { dot.className='status-dot idle'; text.textContent='Ready'; }, 5000);
  }
}

// ── Stop / Restart ────────────────────────────────────────────────────────────
async function stopServer() {
  openModal('Stop Server',
    `<p style="font-size:13px;line-height:1.7">This will <strong>stop the my_seims server</strong>. The dashboard will become unreachable until you restart it from the terminal.</p>
     <p class="text-muted text-sm mt-12">To start again:<br>
     <code style="font-size:11px;background:var(--bg3);padding:4px 8px;border-radius:4px;display:inline-block;margin-top:6px">
     bash ~/Desktop/my_seims/run.sh</code></p>`,
    `<button class="btn btn-danger" id="btn-confirm-stop"><i class="fa-solid fa-power-off"></i> Stop Server</button>
     <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>`
  );
  document.getElementById('btn-confirm-stop').onclick = async () => {
    closeModal();
    try {
      await api.post('/api/shutdown');
    } catch {}
    // Show stopped state
    document.getElementById('status-dot').className = 'status-dot error';
    document.getElementById('status-text').textContent = 'Stopped';
    document.getElementById('btn-stop').disabled    = true;
    document.getElementById('btn-restart').disabled = true;
    document.getElementById('btn-scan-now').disabled = true;
    toast('Server stopped. Refresh this tab once you restart.', 'info');
  };
}

async function restartServer() {
  const overlay  = document.getElementById('restart-overlay');
  const roTitle  = document.getElementById('ro-title');
  const roSub    = document.getElementById('ro-sub');
  const roBar    = document.getElementById('ro-bar');

  // Show overlay
  overlay.classList.remove('hidden');
  roTitle.textContent = 'Restarting server…';
  roSub.textContent   = 'Sending restart signal';
  roBar.style.width   = '0%';

  try { await api.post('/api/restart'); } catch {}

  // Poll until server is back (max 20s)
  const MAX = 20, STEP = 500;
  let elapsed = 0;
  roSub.textContent = 'Waiting for server to come back online…';

  const poll = setInterval(async () => {
    elapsed += STEP;
    roBar.style.width = Math.min((elapsed / (MAX * 1000)) * 100, 95) + '%';
    roSub.textContent = `${Math.ceil((MAX * 1000 - elapsed) / 1000)}s remaining…`;

    try {
      const r = await fetch('/api/status', { cache: 'no-store' });
      if (r.ok) {
        clearInterval(poll);
        roBar.style.width   = '100%';
        roTitle.textContent = 'Server restarted!';
        roSub.textContent   = 'Reloading dashboard…';
        setTimeout(() => { overlay.classList.add('hidden'); navigate('dashboard'); }, 800);
      }
    } catch {}

    if (elapsed >= MAX * 1000) {
      clearInterval(poll);
      roTitle.textContent = 'Server not responding';
      roSub.textContent   = 'Try: bash ~/Desktop/my_seims/run.sh';
      roBar.style.background = 'var(--red)';
      setTimeout(() => overlay.classList.add('hidden'), 4000);
    }
  }, STEP);
}

// ── Init ──────────────────────────────────────────────────────────────────────
function init() {
  // Nav
  document.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', e => { e.preventDefault(); navigate(el.dataset.page); });
  });

  // Scan now
  document.getElementById('btn-scan-now').addEventListener('click', triggerScan);

  // Stop / Restart
  document.getElementById('btn-stop').addEventListener('click', stopServer);
  document.getElementById('btn-restart').addEventListener('click', restartServer);

  // Modal close
  document.getElementById('modal-close').addEventListener('click', closeModal);
  document.getElementById('modal-backdrop').addEventListener('click', e => {
    if (e.target === document.getElementById('modal-backdrop')) closeModal();
  });

  // Auto-refresh toggle
  document.getElementById('auto-refresh-toggle').addEventListener('change', e => {
    S.autoRefresh = e.target.checked;
    clearInterval(S.refreshTimer);
    if (S.autoRefresh) S.refreshTimer = setInterval(() => renderPage(S.page), 30000);
  });

  // Start on dashboard
  navigate('dashboard');
}

document.addEventListener('DOMContentLoaded', init);
