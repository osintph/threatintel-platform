// Script of the Quick Scan page (templates/quick_scan.html). The page is served
// with "script-src 'self'": no inline script, no inline event handler, no eval.
let currentSession = null;
let pollTimer = null;
let pollUnanswered = 0;

// ── CSRF, session and error handling for every API call ────────────────────
// Same-origin requests other than GET and HEAD carry the session's token.
// 401 from the API means the session has ended: go to the sign-in page.
// Any other answer from the API that is not a success is shown as a toast
// (unless the call passes quiet: true and shows it itself) and handed on as
// JSON with ok: false and "error" set to the text to show, see apiErrorText().
(function () {
  const meta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = meta ? meta.content : '';
  const nativeFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const req = (typeof Request !== 'undefined' && input instanceof Request) ? input : null;
    let url;
    try { url = new URL(req ? req.url : String(input), window.location.href); } catch (e) { return nativeFetch(input, init); }
    const sameOrigin = url.origin === window.location.origin;
    const method = String((init && init.method) || (req && req.method) || 'GET').toUpperCase();
    if (sameOrigin && method !== 'GET' && method !== 'HEAD') {
      const headers = new Headers((init && init.headers) || (req && req.headers) || {});
      headers.set('X-CSRF-Token', csrfToken);
      init = Object.assign({}, init, { headers });
    }
    const res = await nativeFetch(input, init);
    if (!sameOrigin || !url.pathname.startsWith('/api/')) return res;
    if (res.status === 401) {
      window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname);
      return res;
    }
    if (res.status === 403) {
      let error = '';
      try { error = (await res.clone().json()).error || ''; } catch (e) {}
      if (error === 'password_change_required' || error === 'mfa_setup_required') {
        window.location.href = '/';
      } else if (error === 'admin required') {
        if (typeof toast === 'function') toast('Admin only', 'error');
        return new Response(JSON.stringify({ ok: false, error: 'Admin only' }),
          { status: 403, headers: { 'Content-Type': 'application/json' } });
      }
    }
    if (res.ok) return res;
    let data = null;
    try { data = await res.clone().json(); } catch (e) {}
    if (!data || typeof data !== 'object' || Array.isArray(data)) data = {};
    const error = apiErrorText(data, res.status);
    if (!(init && init.quiet)) toast(error, 'error');
    // A status that allows no body (304 and the like) is handed on as it came.
    try {
      return new Response(JSON.stringify(Object.assign({}, data, { ok: false, error })),
        { status: res.status, statusText: res.statusText, headers: { 'Content-Type': 'application/json' } });
    } catch (e) { return res; }
  };
})();

// The text to show for an API answer that is not a success: the server's
// "error" text, followed by its error id when it sent one.
function apiErrorText(data, status) {
  let text = typeof data.error === 'string' && data.error ? data.error
    : typeof data.message === 'string' && data.message ? data.message
    : status === 429 ? 'Too many requests. Try again in a moment.'
    : 'The server answered with an error (' + status + ')';
  if (typeof data.detail === 'string' && data.detail) text += ': ' + data.detail;
  if (data.error_id) text += ' (error id ' + data.error_id + ')';
  return text;
}
// The text for a call that got no usable answer.
function failText(e) {
  if (e instanceof TypeError && /fetch|network|load failed/i.test(e.message)) return 'Network error: no answer from the server';
  if (e instanceof SyntaxError) return 'The server sent an answer that could not be read';
  return (e && e.message) ? e.message : String(e);
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
// http(s) links only; anything else (javascript:, data:, …) becomes '#'.
function safeUrl(u) {
  const s = String(u == null ? '' : u).trim();
  if (!s) return '#';
  try {
    const proto = new URL(s, window.location.origin).protocol;
    return (proto === 'http:' || proto === 'https:') ? s : '#';
  } catch (e) { return '#'; }
}
let toastTimer = null;
function toast(msg, kind) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (kind === 'error' ? ' error' : '');
  // An error stays longer: it may carry an error id to note down.
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = 'toast'; }, kind === 'error' ? 8000 : 3200);
}
// The line below the activity counters.
function showWarn(text) {
  const w = document.getElementById('qs-warn');
  w.style.display = text ? '' : 'none';
  w.textContent = text ? '⚠ ' + text : '';
}
function isOnion(url) { return /\.onion(\/|$|:)/i.test(url || ''); }
function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso + 'Z');
  return isNaN(d) ? String(iso) : d.toLocaleString();
}

// There are no on* attributes in the page. A control names the function to
// call in data-act (on click) or data-act-change (on change); one delegated
// listener per event calls the function registered under that name in ACTIONS
// (filled in at the end of this script).
const ACTIONS = {};
function delegate(type, attr) {
  document.addEventListener(type, ev => {
    const el = ev.target instanceof Element ? ev.target.closest('[' + attr + ']') : null;
    if (!el || el.disabled) return;
    const name = el.getAttribute(attr);
    if (Object.prototype.hasOwnProperty.call(ACTIONS, name)) ACTIONS[name].call(el);
  });
}
delegate('click', 'data-act');
delegate('change', 'data-act-change');

async function startScan() {
  const target = document.getElementById('qs-target').value.trim();
  if (!target) { toast('Enter a target first', 'error'); return; }
  const typeSel = document.getElementById('qs-type').value;
  const sources = Array.from(
    document.querySelectorAll('#qs-sources input[type=checkbox]:checked')
  ).map(cb => cb.value);
  if (!sources.length) { toast('Select at least one source', 'error'); return; }

  const btn = document.getElementById('qs-start');
  btn.disabled = true;
  try {
    // 409 (a scan is already running), 400 and 429 come with the text to show.
    const resp = await fetch('/api/quick-scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: target,
        target_type: typeSel === 'auto' ? null : typeSel,
        sources: sources,
      }),
    });
    const data = await resp.json();
    if (!resp.ok) { toast(data.error || 'Failed to start', 'error'); btn.disabled = false; return; }
    currentSession = data.session_id;
    document.getElementById('qs-activity-panel').style.display = '';
    document.getElementById('qs-findings-panel').style.display = '';
    document.getElementById('qs-target-label').textContent = target;
    showWarn('');
    toast('Scan started (#' + currentSession + ')');
    startPolling();
  } catch (e) {
    toast(failText(e), 'error');
    btn.disabled = false;
  }
}

function startPolling() {
  stopPolling();
  pollUnanswered = 0;
  pollStatus();
  pollTimer = setInterval(pollStatus, 2000);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

// Runs every 2 seconds while a scan runs. It stops when the scan has ended, on
// any answer that is not a success and after five requests in a row without
// an answer; the line below the counters says why.
async function pollStatus() {
  if (!currentSession) return;
  let resp, s;
  try {
    resp = await fetch('/api/quick-scan/status/' + encodeURIComponent(currentSession), { quiet: true });
    s = await resp.json();
  } catch (e) {
    // While polling, a request without an answer is tried again a few times.
    if (pollTimer && ++pollUnanswered < 5) return;
    const what = pollTimer ? 'Status updates stopped: ' : 'Status not loaded: ';
    stopPolling();
    document.getElementById('qs-start').disabled = false;
    showWarn(what + failText(e));
    return;
  }
  pollUnanswered = 0;
  if (!resp.ok) {
    const what = pollTimer ? 'Status updates stopped: ' : 'Status not loaded: ';
    stopPolling();
    document.getElementById('qs-start').disabled = false;
    showWarn(what + s.error);
    return;
  }
  document.getElementById('qs-status').textContent = s.status;
  document.getElementById('qs-dot').className = 'dot ' + s.status;
  document.getElementById('qs-urls').textContent = s.urls_visited;
  document.getElementById('qs-findings').textContent = s.findings_count;
  document.getElementById('qs-cancel').style.display =
    (s.status === 'running' || s.status === 'pending') ? '' : 'none';
  showWarn(s.error_message || '');
  if (s.status === 'completed' || s.status === 'failed' || s.status === 'cancelled') {
    stopPolling();
    document.getElementById('qs-start').disabled = false;
    reloadFindings();
    loadSessions();
  } else {
    reloadFindings();
  }
}

async function cancelScan() {
  if (!currentSession) return;
  const btn = document.getElementById('qs-cancel');
  btn.disabled = true;
  try {
    const resp = await fetch('/api/quick-scan/cancel/' + encodeURIComponent(currentSession), { method: 'POST' });
    const data = await resp.json();
    if (!resp.ok) { toast(data.error || 'Failed to cancel', 'error'); return; }
    toast('Scan cancelled');
    pollStatus();
    loadSessions();
  } catch (e) {
    toast(failText(e), 'error');
  } finally {
    btn.disabled = false;
  }
}

async function reloadFindings() {
  if (!currentSession) return;
  const hiOnly = document.getElementById('qs-hi-only').checked ? '?high_signal_only=1' : '';
  try {
    const resp = await fetch('/api/quick-scan/findings/' + encodeURIComponent(currentSession) + hiOnly, { quiet: true });
    const rows = await resp.json();
    if (!resp.ok) { showWarn('Findings not loaded: ' + rows.error); return; }
    renderFindings(rows);
  } catch (e) {
    showWarn('Findings not loaded: ' + failText(e));
  }
}

function renderFindings(rows) {
  const body = document.getElementById('qs-findings-body');
  const empty = document.getElementById('qs-findings-empty');
  body.innerHTML = '';
  if (!rows.length) { empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  for (const f of rows) {
    const ctx = String(f.context || '');
    const short = ctx.length > 100 ? ctx.slice(0, 100) + '…' : ctx;
    const urlCell = isOnion(f.url)
      ? '<span class="onion">' + esc(f.url) + '</span>'
      : '<a href="' + esc(safeUrl(f.url)) + '" target="_blank" rel="noopener noreferrer">' + esc(f.url) + '</a>';
    const badge = f.high_signal
      ? '<span class="badge badge-hi">HIGH</span>'
      : '<span class="badge badge-lo">—</span>';
    const tr = document.createElement('tr');
    tr.innerHTML =
      '<td>' + esc(f.source_name) + '</td>' +
      '<td class="url">' + urlCell + '</td>' +
      '<td>' + esc(f.matched_variant) + '</td>' +
      '<td class="ctx" title="' + esc(ctx) + '">' + esc(short) + '</td>' +
      '<td>' + badge + '</td>' +
      '<td>' + esc(fmtTime(f.found_at)) + '</td>';
    body.appendChild(tr);
  }
}

async function loadSessions() {
  const body = document.getElementById('qs-sessions-body');
  const empty = document.getElementById('qs-sessions-empty');
  try {
    const resp = await fetch('/api/quick-scan/sessions', { quiet: true });
    const rows = await resp.json();
    body.innerHTML = '';
    if (!resp.ok) { empty.textContent = rows.error; empty.style.display = 'block'; return; }
    empty.textContent = 'No previous sessions.';
    if (!rows.length) { empty.style.display = 'block'; return; }
    empty.style.display = 'none';
    for (const s of rows) {
      const tr = document.createElement('tr');
      tr.className = 'sess-row';
      tr.addEventListener('click', () => openSession(s.id, s.target_value));
      tr.innerHTML =
        '<td>' + esc(s.target_value) + '</td>' +
        '<td>' + esc(s.target_type) + '</td>' +
        '<td><span class="dot ' + esc(s.status) + '"></span>' + esc(s.status) + '</td>' +
        '<td>' + esc(s.urls_visited) + '</td>' +
        '<td>' + esc(s.findings_count) + '</td>' +
        '<td>' + esc(fmtTime(s.started_at)) + '</td>';
      body.appendChild(tr);
    }
  } catch (e) {
    empty.textContent = failText(e);
    empty.style.display = 'block';
  }
}

function openSession(id, target) {
  currentSession = id;
  stopPolling();
  pollUnanswered = 0;
  document.getElementById('qs-activity-panel').style.display = '';
  document.getElementById('qs-findings-panel').style.display = '';
  document.getElementById('qs-target-label').textContent = target;
  pollStatus();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Every function the page's markup may name in a data-act attribute.
Object.assign(ACTIONS, {
  cancelScan,
  loadSessions,
  reloadFindings,
  startScan,
});

loadSessions();
