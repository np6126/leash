// ── Theme ─────────────────────────────────────────────────────────────────────

const MOON_PATH = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>';
const SUN_PATHS = '<circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="5"/><line x1="12" y1="19" x2="12" y2="22"/><line x1="4.22" y1="4.22" x2="6.34" y2="6.34"/><line x1="17.66" y1="17.66" x2="19.78" y2="19.78"/><line x1="2" y1="12" x2="5" y2="12"/><line x1="19" y1="12" x2="22" y2="12"/><line x1="4.22" y1="19.78" x2="6.34" y2="17.66"/><line x1="17.66" y1="6.34" x2="19.78" y2="4.22"/>';

const COPY_SVG  = '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="10" height="11" rx="1"/><path d="M3 12H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h8a1 1 0 0 1 1 1v1"/></svg>';
const CHECK_SVG = '<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="2,8 6,12 14,4"/></svg>';

const EYE_OPEN = '<circle cx="12" cy="12" r="3"/><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>';
const EYE_OFF  = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>';
const SENSITIVE_HEADERS = new Set(['authorization', 'x-api-key', 'cookie', 'set-cookie', 'proxy-authorization', 'x-auth-token']);

function _applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  document.getElementById('theme-icon').innerHTML = theme === 'light' ? MOON_PATH : SUN_PATHS;
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  _applyTheme(next);
  localStorage.setItem('leash-theme', next);
}

_applyTheme(localStorage.getItem('leash-theme') || 'dark');

let redactHeaders = localStorage.getItem('leash-redact') !== '0';

function _applyRedact(active) {
  document.getElementById('redact-icon').innerHTML = active ? EYE_OFF : EYE_OPEN;
  document.getElementById('redact-btn').classList.toggle('btn-active', active);
}

function toggleRedact() {
  redactHeaders = !redactHeaders;
  localStorage.setItem('leash-redact', redactHeaders ? '1' : '0');
  _applyRedact(redactHeaders);
  if (expandedId !== null) {
    const td = document.querySelector(`#detail-${expandedId} td`);
    if (td) td.innerHTML = buildDetailPanel(expandedId);
  }
}

_applyRedact(redactHeaders);

// ── Utilities ─────────────────────────────────────────────────────────────────

const pad = n => String(n).padStart(2, '0');

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const date = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  return `<span class="time-sec">${time}</span><span class="time-date">${date}</span>`;
}

function fmtStatus(s) {
  if (!s) return '<span class="badge b-none">—</span>';
  const cls = s < 300 ? 'b-2xx' : s < 400 ? 'b-3xx' : s < 500 ? 'b-4xx' : 'b-5xx';
  return `<span class="badge ${cls}">${s}</span>`;
}

function fmtMethod(m) {
  if (!m) return '<span class="badge b-none">—</span>';
  const map = { GET:'m-GET', POST:'m-POST', PUT:'m-PUT', PATCH:'m-PATCH', DELETE:'m-DELETE' };
  const cls = map[m.toUpperCase()] || 'm-other';
  return `<span class="method ${cls}">${m}</span>`;
}

function _fmtBytesValue(b) {
  if (!b) return '';
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1048576).toFixed(1)} MB`;
}

function fmtEvent(ev) {
  const ch = '<svg class="ev-chev" width="7" height="7" viewBox="0 0 8 8" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="2,1 6,4 2,7"/></svg>';
  if (ev === 'allowed') return `<span class="event-dot ev-allowed">${ch}allowed</span>`;
  if (ev === 'blocked') return `<span class="event-dot ev-blocked">${ch}blocked</span>`;
  if (ev === 'error')   return `<span class="event-dot ev-error">${ch}error</span>`;
  return `<span class="event-dot">${ch}${ev}</span>`;
}

function rowClass(ev) {
  if (ev === 'blocked') return 'row-blocked';
  if (ev === 'error') return 'row-error';
  return '';
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Filters ──────────────────────────────────────────────────────────────────

let internetOnly = false;

function toggleInternetOnly() {
  internetOnly = !internetOnly;
  document.getElementById('internet-toggle').classList.toggle('active', internetOnly);
  fetchLogs(true);
}

// ── Row state ─────────────────────────────────────────────────────────────────
// Each row gets a stable integer id (nextId++) that never changes, even when
// new rows are prepended. This lets expandedId survive incremental updates.

let nextId        = 0;    // monotonically increasing row counter
let rowById       = {};   // id → row data
let currentIds    = [];   // ordered display ids (newest first)
let expandedId    = null; // currently expanded row id (integer), or null
let topTs         = null; // ts of the first (newest) displayed row
let bodyLimitKb   = 1024; // updated from /api/meta on load; matches BODY_LIMIT_KB server default
let _fetchFails   = 0;    // consecutive fetchLogs failures; triggers disconnect indicator at 3

// ── Sort state ────────────────────────────────────────────────────────────────

let sortKey = null;
let sortDir = -1;

function _displayIds() {
  if (!sortKey) return currentIds;
  return [...currentIds].sort((a, b) => {
    const va = rowById[a][sortKey];
    const vb = rowById[b][sortKey];
    if (va == null && vb == null) return 0;
    if (va == null) return 1;
    if (vb == null) return -1;
    if (typeof va === 'string' || typeof vb === 'string') {
      return sortDir * String(va).localeCompare(String(vb));
    }
    return sortDir * (va < vb ? -1 : va > vb ? 1 : 0);
  });
}

function _updateSortHeaders() {
  document.querySelectorAll('thead th[data-sort]').forEach(th => {
    th.classList.remove('th-sorted-asc', 'th-sorted-desc');
    if (th.dataset.sort === sortKey) {
      th.classList.add(sortDir === 1 ? 'th-sorted-asc' : 'th-sorted-desc');
    }
  });
}

function _collapseRow(id) {
  const detail = document.getElementById('detail-' + id);
  const row = document.querySelector(`tr.data-row[data-rid="${id}"]`);
  if (detail) detail.style.display = 'none';
  if (row) row.classList.remove('row-expanded');
}

function _expandRow(id, scroll = false) {
  if (expandedId !== null && expandedId !== id) _collapseRow(expandedId);
  const detail = document.getElementById('detail-' + id);
  const row = document.querySelector(`tr.data-row[data-rid="${id}"]`);
  if (!detail || !row) return;
  detail.style.display = '';
  row.classList.add('row-expanded');
  if (scroll) row.scrollIntoView({ block: 'nearest' });
  expandedId = id;
}

function _rebuildTbody() {
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = _displayIds().map(id => buildRowHtml(id)).join('');
  if (expandedId !== null) _expandRow(expandedId);
  _updateSortHeaders();
}

function sortBy(key) {
  sortDir = (sortKey === key) ? -sortDir : (key === 'ts' ? -1 : 1);
  sortKey = key;
  _rebuildTbody();
}

function _resetRows() {
  nextId = 0; rowById = {}; currentIds = []; expandedId = null; topTs = null;
}

// ── Render (full re-render) ───────────────────────────────────────────────────

function render(rows) {
  const tbody   = document.getElementById('tbody');
  const empty   = document.getElementById('empty');
  const countEl = document.getElementById('filter-count');

  const prevTs = expandedId !== null && rowById[expandedId]
    ? rowById[expandedId].ts : null;

  const prevScrolls = [];
  if (expandedId !== null) {
    document.querySelectorAll(`#detail-${expandedId} .detail-body-pre`)
      .forEach(el => prevScrolls.push(el.scrollTop));
  }

  _resetRows();

  if (!rows.length) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    countEl.textContent = '0 entries';
    return;
  }
  empty.style.display = 'none';
  countEl.textContent = rows.length + (rows.length >= 500 ? '+' : '') + ' entries';
  topTs = rows[0].ts;

  for (const r of rows) {
    const id = nextId++;
    rowById[id] = r;
    currentIds.push(id);
  }

  tbody.innerHTML = _displayIds().map(id => buildRowHtml(id)).join('');
  _updateSortHeaders();

  if (prevTs !== null) {
    const newId = currentIds.find(id => rowById[id].ts === prevTs);
    if (newId !== undefined) {
      document.getElementById('detail-' + newId).style.display = '';
      document.querySelector(`tr.data-row[data-rid="${newId}"]`).classList.add('row-expanded');
      expandedId = newId;
      if (prevScrolls.length) {
        document.querySelectorAll(`#detail-${newId} .detail-body-pre`)
          .forEach((el, i) => { if (i < prevScrolls.length) el.scrollTop = prevScrolls[i]; });
      }
    }
  }
}

// ── Incremental prepend (auto-refresh path) ───────────────────────────────────

function prependRows(newRows) {
  const tbody   = document.getElementById('tbody');
  const countEl = document.getElementById('filter-count');

  const newIds = newRows.map(r => {
    const id = nextId++;
    rowById[id] = r;
    return id;
  });
  currentIds = [...newIds, ...currentIds];
  topTs = rowById[newIds[0]].ts;

  document.getElementById('empty').style.display = 'none';
  if (sortKey) {
    _rebuildTbody();
  } else {
    tbody.insertAdjacentHTML('afterbegin', newIds.map(id => buildRowHtml(id)).join(''));
  }
  countEl.textContent = currentIds.length + (currentIds.length >= 500 ? '+' : '') + ' entries';
}

// ── Row HTML ──────────────────────────────────────────────────────────────────

function buildRowHtml(id) {
  const r   = rowById[id];
  const displayText = r.url || r.host || '—';
  const titleText = (!r.url && r.host && r.port) ? `${r.host}:${r.port}` : displayText;
  const methodBadge = r.method ? fmtMethod(r.method) : '';
  const portBadge = r.port
    ? `<span class="${(r.port === 443 || r.port === 80) ? 'port-std' : 'port-nonstandard'}" style="flex-shrink:0">:${r.port}</span>`
    : '';
  const urlHtml = `${methodBadge}<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0">${esc(displayText)}</span>${portBadge}`;
  const bytesInline = r.bytes ? `<span class="col-bytes-inline">${_fmtBytesValue(r.bytes)}</span>` : '';
  return `<tr class="data-row ${rowClass(r.event)}" data-rid="${id}">
    <td>${fmtTime(r.ts)}<span class="mobile-client"> · ${esc(r.client || '')}</span></td>
    <td class="mono" style="color:var(--muted2)">${esc(r.client || '—')}</td>
    <td class="mono" title="${esc(titleText)}" style="display:flex;align-items:center">${urlHtml}</td>
    <td>${fmtStatus(r.status)}${bytesInline}</td>
    <td>${fmtEvent(r.event)}</td>
  </tr>
  <tr class="detail-row" id="detail-${id}" style="display:none">
    <td colspan="5">${buildDetailPanel(id)}</td>
  </tr>`;
}

function buildHeadersBlock(headers, highlightKey) {
  if (!headers || !headers.length) return '<div class="detail-empty">No headers captured</div>';
  let html = '<div class="detail-headers">';
  for (const [k, v] of headers) {
    const isHL       = highlightKey && k.toLowerCase() === highlightKey;
    const isSensitive = redactHeaders && SENSITIVE_HEADERS.has(k.toLowerCase());
    const displayVal  = isSensitive ? '••••••••' : v;
    html += `<span class="detail-hdr-name">${esc(k)}</span><span class="detail-hdr-val${isHL ? ' detail-hdr-highlight' : ''}${isSensitive ? ' detail-hdr-redacted' : ''}">${esc(displayVal)}</span>`;
  }
  html += '</div>';
  return html;
}

const _unescape = s => s.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\r/g, '');

function _sanitizeJsonStrings(text) {
  // Escape unescaped control characters inside JSON string values.
  // Needed because Python's json.dumps encodes \n as \\n, but the browser's
  // JSON.parse of the API response decodes it back to a real newline —
  // making a subsequent JSON.parse of the body text fail (bare newlines in
  // JSON strings are invalid).
  const out = [];
  let inStr = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (escaped)              { out.push(c); escaped = false; continue; }
    if (c === '\\' && inStr)  { out.push(c); escaped = true;  continue; }
    if (c === '"')            { inStr = !inStr; out.push(c); continue; }
    if (inStr && (c === '\n' || c === '\r' || c === '\t'))
      out.push(c === '\n' ? '\\n' : c === '\r' ? '\\r' : '\\t');
    else
      out.push(c);
  }
  return out.join('');
}

function _dumbIndent(text) {
  // Best-effort indenter for truncated or otherwise un-parseable JSON.
  const IND = '  ';
  const out = [];
  let depth = 0, inStr = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (escaped)              { out.push(c); escaped = false; continue; }
    if (c === '\\' && inStr)  { out.push(c); escaped = true;  continue; }
    if (c === '"')            { inStr = !inStr; out.push(c); continue; }
    if (inStr)                { out.push(c); continue; }
    switch (c) {
      case ' ': case '\t': case '\n': case '\r': break;
      case '{': case '[': out.push(c, '\n', IND.repeat(++depth)); break;
      case '}': case ']': out.push('\n', IND.repeat(depth > 0 ? --depth : 0), c); break;
      case ',':            out.push(c, '\n', IND.repeat(depth)); break;
      case ':':            out.push(': '); break;
      default:             out.push(c);
    }
  }
  return out.join('');
}

function prettyBody(text) {
  // 1. Valid complete JSON
  try { return _unescape(JSON.stringify(JSON.parse(text), null, 2)); } catch (_) {}
  // 2. Valid JSON whose string values contain bare newlines (Python json.dumps
  //    encodes them as \n, but browser JSON.parse decodes them back to real
  //    newlines — making a second JSON.parse fail on the body text)
  try { return _unescape(JSON.stringify(JSON.parse(_sanitizeJsonStrings(text)), null, 2)); } catch (_) {}
  // 3. Truncated / invalid JSON that at least starts like a JSON object or array
  const t = text.trimStart();
  if (t[0] === '{' || t[0] === '[') return _unescape(_dumbIndent(text));
  // 4. SSE: format each data: line individually
  if (/^data: /m.test(text)) {
    return text.split('\n').map(line => {
      if (!line.startsWith('data: ') || line === 'data: [DONE]') return line;
      try { return 'data: ' + JSON.stringify(JSON.parse(line.slice(6)), null, 2); } catch (_) { return line; }
    }).join('\n');
  }
  return text;
}

function _copyFallback(text, done) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try { document.execCommand('copy'); done(); } catch (_) {}
  document.body.removeChild(ta);
}

function copyBody(btn) {
  const text = btn.nextElementSibling.textContent;
  const done = () => {
    btn.innerHTML = CHECK_SVG;
    btn.classList.add('copied');
    setTimeout(() => { btn.innerHTML = COPY_SVG; btn.classList.remove('copied'); }, 2000);
  };
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(() => _copyFallback(text, done));
  } else {
    _copyFallback(text, done);
  }
}

function buildBodyBlock(body, truncated) {
  if (body == null) return '<div class="detail-empty">No body</div>';
  return `<div class="body-wrap">
    <button class="copy-btn" onclick="copyBody(this)" title="Copy to clipboard">${COPY_SVG}</button>
    <pre class="detail-body-pre">${esc(prettyBody(body))}</pre>
  </div>${truncated ? `<div class="detail-truncated">↳ body truncated at ${bodyLimitKb} KB</div>` : ''}`;
}

function buildDetailPanel(id) {
  const r = rowById[id];
  const manageBtn = `<button class="btn-manage-access" onclick="event.stopPropagation();showAllowlistDialog(rowById[${id}])">Manage Access</button>`;
  const footer = `<div class="detail-footer">${manageBtn}</div>`;

  if (r.event === 'connect_allowed') {
    return `<div class="detail-panel single-col"><div class="detail-tunnel-msg">CONNECT tunnel established — no HTTP headers or body available for this event.</div>${footer}</div>`;
  }

  if (r.event === 'error') {
    const errMsg = r.reason || 'unknown error';
    return `<div class="detail-panel single-col">
      <div class="detail-section">
        <div class="detail-section-title">CONNECTION ERROR</div>
        ${r.method && r.url ? `<div class="detail-req-line">${esc(r.method)} ${esc(r.url)}</div>` : ''}
        <div class="detail-redirect-banner" style="border-color:rgba(240,150,66,.3);background:rgba(240,150,66,.06);color:var(--orange)">⚠ ${esc(errMsg)}</div>
        ${buildHeadersBlock(r.req_headers, null)}
        ${buildBodyBlock(r.req_body, r.req_truncated)}
      </div>
      ${footer}
    </div>`;
  }

  const isBlocked  = r.event === 'blocked';
  const isRedirect = !isBlocked && r.status >= 300 && r.status < 400;

  let locationVal = null;
  if (isRedirect && r.res_headers) {
    const lp = r.res_headers.find(([k]) => k.toLowerCase() === 'location');
    if (lp) locationVal = lp[1];
  }

  let html = `<div class="detail-panel${isBlocked ? ' single-col' : ''}">`;

  html += `<div class="detail-section">`;
  html += `<div class="detail-section-title">REQUEST${isBlocked ? ' — blocked, no response' : ''}</div>`;
  if (r.method && r.url) html += `<div class="detail-req-line">${esc(r.method)} ${esc(r.url)}</div>`;
  html += buildHeadersBlock(r.req_headers, null);
  html += buildBodyBlock(r.req_body, r.req_truncated);
  html += '</div>';

  if (!isBlocked) {
    html += '<div class="detail-section">';
    html += '<div class="detail-section-title">RESPONSE</div>';
    if (isRedirect && locationVal) {
      html += `<div class="detail-redirect-banner">↪ Redirect → <strong style="margin-left:4px">${esc(locationVal)}</strong></div>`;
    }
    html += buildHeadersBlock(r.res_headers, isRedirect ? 'location' : null);
    html += buildBodyBlock(r.res_body, r.res_truncated);
    html += '</div>';
  }

  html += footer + '</div>';
  return html;
}

async function fetchMeta() {
  try {
    const res = await fetch('/api/meta');
    const m = await res.json();
    document.getElementById('log-size').textContent = m.size_mb.toFixed(2) + ' MB';
    document.getElementById('total-count').textContent = m.total_lines.toLocaleString();
    bodyLimitKb = m.body_limit_kb ?? 1024;
  } catch(e) {}
}

async function clearLogs() {
  if (!confirm('Clear all log entries?\nThis cannot be undone.')) return;
  await fetch('/api/logs/clear', { method: 'POST' });
  await Promise.all([fetchLogs(true), fetchMeta()]);
}

let debounceTimer;
function onFilter() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => fetchLogs(true), 120);
}

// ── Fetch ─────────────────────────────────────────────────────────────────────
// full=true  → always re-render the entire table (filter change, first load, clear)
// full=false → only prepend rows newer than topTs; touch nothing else

async function fetchLogs(full = false) {
  const q       = document.getElementById('q').value;
  const client  = document.getElementById('client').value;
  const spinner = document.getElementById('filter-spinner');
  const errEl   = document.getElementById('fetch-error');
  const params  = new URLSearchParams({ q, client, limit: 500 });
  if (internetOnly) params.set('internet_only', '1');
  if (full && spinner) spinner.style.opacity = '1';
  try {
    const res  = await fetch('/api/logs?' + params);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const rows = await res.json();
    _fetchFails = 0;
    if (errEl) errEl.style.display = 'none';

    if (full || topTs === null || currentIds.length === 0 || rows.length === 0) {
      render(rows);
      return;
    }

    const newRows = rows.filter(r => r.ts > topTs);
    if (newRows.length > 0) prependRows(newRows);
  } catch(e) {
    _fetchFails++;
    if (_fetchFails >= 3 && errEl) errEl.style.display = '';
  } finally {
    if (spinner) spinner.style.opacity = '0';
  }
}

// ── Allowlist state ───────────────────────────────────────────────────────────

let allowlist    = { allowed_destinations: [] };
let dialogRecord = null;

async function loadAllowlist() {
  try {
    const res = await fetch('/api/allowlist');
    if (res.ok) allowlist = await res.json();
  } catch(e) {}
}

function _findAllowlistEntry(host) {
  const dests = allowlist.allowed_destinations || [];
  const direct = dests.find(e => e.host === host);
  if (direct) return direct;
  const labels = host.split('.');
  for (let i = 1; i < labels.length - 1; i++) {
    const parent = labels.slice(i).join('.');
    const entry = dests.find(e => e.host === parent);
    if (entry) return entry;
  }
  return null;
}

function checkAllowlistStatus(host, port, method, path) {
  const entry = _findAllowlistEntry(host);
  if (!entry) return { status: 'not_in_list' };
  const ports = (entry.ports || [443]).map(Number);
  if (!ports.includes(Number(port))) return { status: 'not_in_list' };
  const paths = entry.paths;
  if (!paths || !paths.length) return { status: 'host_allowed', entry };
  if (!method && !path) return { status: 'host_allowed', entry };
  const matched = paths.some(rule => {
    const mOk = !rule.method || rule.method === (method || '').toUpperCase();
    const pOk = path && path.startsWith(rule.prefix);
    return mOk && pOk;
  });
  return matched ? { status: 'path_allowed', entry } : { status: 'path_blocked', entry };
}

function extractPath(url) {
  if (!url) return '';
  try { return new URL(url).pathname; } catch(_) { return url; }
}

// ── Dialog ────────────────────────────────────────────────────────────────────

async function showAllowlistDialog(record) {
  await loadAllowlist();
  dialogRecord = record;
  const host   = record.host   || '';
  const port   = record.port   || 443;
  const method = record.method || '';
  const path   = record.url ? extractPath(record.url) : '';
  const { status } = checkAllowlistStatus(host, port, method, path);

  const statusMap = {
    not_in_list:  ['status-blocked', '✗', 'blocked · not in allowlist'],
    host_allowed: ['status-allowed', '✓', 'allowed · all paths permitted'],
    path_blocked: ['status-warn',    '⚠', 'path blocked · host is in allowlist'],
    path_allowed: ['status-allowed', '✓', 'allowed · matched path rule'],
  };
  const [cls, icon, label] = statusMap[status];

  let html = `<div class="dialog-status ${cls}"><span>${icon}</span>${label}</div>`;
  html += `<div class="dialog-info">`;
  html += `<div class="info-row"><span class="info-label">HOST</span><span class="info-value">${esc(host)}</span></div>`;
  html += `<div class="info-row"><span class="info-label">PORT</span><span class="info-value">${esc(String(port))}</span></div>`;
  if (method) html += `<div class="info-row"><span class="info-label">METHOD</span><span class="info-value">${esc(method)}</span></div>`;
  if (path)   html += `<div class="info-row"><span class="info-label">PATH</span><span class="info-value">${esc(path)}</span></div>`;
  html += `</div>`;

  if (status === 'not_in_list' || status === 'path_blocked') {
    const hostTitle = status === 'path_blocked' ? 'Remove path restrictions' : 'Allow entire host';
    const hostSub   = status === 'path_blocked'
      ? `All paths on ${esc(host)} will be permitted`
      : 'All methods · all paths permitted';
    html += `<div class="dialog-sep"></div><div class="scope-cards" id="scope-cards">`;
    html += mkCard('host', true,  hostTitle, `${esc(host)}:${port}`, hostSub);
    if (method && path) {
      const pathTitle = status === 'path_blocked' ? 'Add this path rule' : 'Allow this path only';
      html += mkCard('path', false, pathTitle, `${esc(method)} ${esc(path)}`, `on ${esc(host)}`);
    }
    html += `</div>`;
    html += `<div class="dialog-actions">
      <button class="btn-dialog btn-cancel" onclick="closeDialog()">Cancel</button>
      <button class="btn-dialog btn-add" onclick="confirmAdd()">${status === 'path_blocked' ? 'Allow' : 'Add to list'}</button>
    </div>`;

  } else if (status === 'host_allowed') {
    html += `<div class="dialog-actions">
      <button class="btn-dialog btn-cancel" onclick="closeDialog()">Cancel</button>
      <button class="btn-dialog btn-remove" onclick="confirmRemove('host')">Remove from list</button>
    </div>`;

  } else {
    html += `<div class="dialog-sep"></div><div class="scope-cards" id="scope-cards">`;
    const pathFirst = !!(method && path);
    if (pathFirst) {
      html += mkCard('path', true,  'Remove this path rule', `${esc(method)} ${esc(path)}`, `Other rules on ${esc(host)} remain`);
    }
    html += mkCard('host', !pathFirst, 'Remove entire host', `${esc(host)}:${port}`, 'Removes all rules for this host');
    html += `</div>`;
    html += `<div class="dialog-actions">
      <button class="btn-dialog btn-cancel" onclick="closeDialog()">Cancel</button>
      <button class="btn-dialog btn-remove" onclick="confirmRemove(getScope())">Remove</button>
    </div>`;
  }

  document.getElementById('dialog-body').innerHTML = html;
  document.getElementById('dialog-overlay').style.display = 'flex';
}

function mkCard(scope, selected, title, detail, sub) {
  const cls = selected ? ' selected' : '';
  const dot = selected ? '●' : '○';
  return `<div class="scope-card${cls}" data-scope="${scope}" onclick="selectScope(this)">
    <div class="scope-radio">${dot}</div>
    <div class="scope-content">
      <div class="scope-title">${title}</div>
      <div class="scope-detail">${detail}</div>
      <div class="scope-sub">${sub}</div>
    </div>
  </div>`;
}

function selectScope(card) {
  document.querySelectorAll('#scope-cards .scope-card').forEach(c => {
    c.classList.remove('selected');
    c.querySelector('.scope-radio').textContent = '○';
  });
  card.classList.add('selected');
  card.querySelector('.scope-radio').textContent = '●';
}

function getScope() {
  const sel = document.querySelector('#scope-cards .scope-card.selected');
  return sel ? sel.dataset.scope : 'host';
}

function closeDialog() {
  document.getElementById('dialog-overlay').style.display = 'none';
  dialogRecord = null;
}

function closeDialogIfBg(e) {
  if (e.target.id === 'dialog-overlay') closeDialog();
}

async function confirmAdd() {
  if (!dialogRecord) return;
  const scope  = getScope();
  const host   = dialogRecord.host || '';
  const port   = dialogRecord.port || 443;
  const method = (dialogRecord.method || '').toUpperCase();
  const prefix = dialogRecord.url ? extractPath(dialogRecord.url) : '/';
  try {
    const res = await fetch('/api/allowlist/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, port, scope, method, prefix }),
    });
    const data = await res.json();
    if (data.ok) {
      allowlist = data.allowlist;
      closeDialog();
      showToast('Added: ' + (scope === 'host' ? host : `${method} ${prefix}`), 'added');
    } else {
      showToast(data.error || 'Error saving allowlist', 'err');
    }
  } catch(_) { showToast('Request failed', 'err'); }
}

async function confirmRemove(scope) {
  if (!dialogRecord) return;
  const host   = dialogRecord.host || '';
  const port   = dialogRecord.port || 443;
  const method = (dialogRecord.method || '').toUpperCase();
  const prefix = dialogRecord.url ? extractPath(dialogRecord.url) : '/';
  try {
    const res = await fetch('/api/allowlist/remove', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, port, scope, method, prefix }),
    });
    const data = await res.json();
    if (data.ok) {
      allowlist = data.allowlist;
      closeDialog();
      showToast('Removed: ' + host, 'removed');
    } else {
      showToast(data.error || 'Error saving allowlist', 'err');
    }
  } catch(_) { showToast('Request failed', 'err'); }
}

function showToast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast toast-${type} show`;
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3000);
}

// ── Row click (event delegation) ─────────────────────────────────────────────

document.getElementById('tbody').addEventListener('click', e => {
  if (e.target.closest('.detail-row')) return;
  const tr = e.target.closest('tr.data-row[data-rid]');
  if (!tr) return;
  const id = +tr.dataset.rid;
  if (expandedId === id) {
    _collapseRow(id);
    expandedId = null;
  } else {
    _expandRow(id);
  }
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeDialog(); return; }
  if (e.target.closest('input, button, textarea')) return;
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
  e.preventDefault();
  const ids  = _displayIds();
  const idx  = expandedId !== null ? ids.indexOf(expandedId) : -1;
  const next = e.key === 'ArrowDown'
    ? ids[Math.min(ids.length - 1, idx + 1)]
    : ids[Math.max(0, idx < 0 ? 0 : idx - 1)];
  if (next === undefined || next === expandedId) return;
  _expandRow(next, true);
});

// ── Init ─────────────────────────────────────────────────────────────────────

fetchLogs(true);
fetchMeta();
loadAllowlist();
setInterval(() => { fetchLogs(false); fetchMeta(); }, 5000);
