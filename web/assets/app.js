'use strict';

const state = { procs: [], hosts: [], socket: null, query: '' };
const $ = (id) => document.getElementById(id);

const TAB_ON = 'tab-btn w-full text-left px-3 py-2 rounded-lg text-xs font-medium bg-cyan-950/60 text-cyan-300 border border-cyan-800/50';
const TAB_OFF = 'tab-btn w-full text-left px-3 py-2 rounded-lg text-xs font-medium text-slate-400 hover:bg-slate-800/60 hover:text-slate-200 transition';
const LOG_COLORS = { red: 'text-red-400 font-bold', yellow: 'text-yellow-400', emerald: 'text-emerald-400', cyan: 'text-cyan-400' };
const BTN = 'px-2.5 py-1 rounded text-[11px] font-semibold transition border ';

function log(message, color = 'emerald') {
  const box = $('log');
  const line = document.createElement('div');
  line.className = LOG_COLORS[color] || LOG_COLORS.emerald;
  line.textContent = `[${new Date().toTimeString().slice(0, 8)}] ${message}`;
  box.appendChild(line);
  while (box.childElementCount > 300) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}

function setLabel(ids, text, cls) {
  for (const id of ids) {
    const el = $(id);
    if (!el) continue;
    el.textContent = text;
    el.classList.remove('text-emerald-400', 'text-red-400', 'text-amber-400');
    el.classList.add(cls);
  }
}

function setDashboardLink(kind) {
  const map = { up: ['CONNECTED', 'text-emerald-400'], connecting: ['CONNECTING', 'text-amber-400'], down: ['DISCONNECTED', 'text-red-400'] };
  setLabel(['topConnectionStatus', 'sidebarDashboardStatus'], ...map[kind]);
}

function setHosts(hosts) {
  state.hosts = hosts;
  const n = hosts.length;
  setLabel(['topDaemonStatus'], n ? `${n} ONLINE` : 'OFFLINE', n ? 'text-emerald-400' : 'text-red-400');
  $('sidebarHostCount').textContent = `${n} connected`;
  $('statHosts').textContent = String(n);
}

function updateStats() {
  const flagged = state.procs.filter((p) => p.status === 'rogue').length;
  $('statTotal').textContent = String(state.procs.length);
  $('statFlagged').textContent = String(flagged);
  $('statFlagged').className = `text-2xl font-extrabold font-mono mt-1 ${flagged ? 'text-red-400' : 'text-emerald-400'}`;
  $('statFrozen').textContent = String(state.procs.filter((p) => p.status === 'suspended').length);
}

function badge(status) {
  const span = document.createElement('span');
  const styles = {
    rogue: ['FLAGGED', 'bg-red-950 text-red-300 border-red-800 pulse-danger'],
    suspended: ['FROZEN', 'bg-yellow-950 text-yellow-300 border-yellow-800'],
    normal: ['OK', 'bg-emerald-950 text-emerald-300 border-emerald-800'],
  };
  const [label, cls] = styles[status] || styles.normal;
  span.className = `px-2 py-0.5 rounded text-[10px] border font-bold ${cls}`;
  span.textContent = label;
  if (status === 'rogue') span.title = 'Sustained high CPU or very high memory (thresholds are set on the daemon)';
  return span;
}

function cell(className, child) {
  const td = document.createElement('td');
  td.className = className;
  if (typeof child === 'string') td.textContent = child;
  else if (child) td.appendChild(child);
  return td;
}

function controlButton(action, label, cls, proc) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = BTN + cls;
  b.textContent = label;
  b.dataset.action = action;
  b.dataset.pid = String(proc.pid);
  b.dataset.host = proc.host;
  return b;
}

function render() {
  const q = state.query.toLowerCase();
  const rows = state.procs.filter((p) => !q || `${p.pid} ${p.name} ${p.host} ${p.cmd}`.toLowerCase().includes(q));
  const body = $('processBody');
  body.replaceChildren();
  for (const p of rows) {
    const tr = document.createElement('tr');
    tr.className = 'hover:bg-slate-900/50 transition';
    const name = document.createElement('div');
    name.className = 'font-bold text-slate-200';
    name.textContent = p.name;
    const host = document.createElement('div');
    host.className = 'text-[10px] text-slate-500';
    host.textContent = p.host;
    const nameCell = cell('py-3 px-4');
    nameCell.append(name, host);

    const controls = cell('py-3 px-4 text-right space-x-1');
    if (p.protected) {
      const note = document.createElement('span');
      note.className = 'text-slate-500 text-[10px]';
      note.textContent = 'PROTECTED';
      controls.appendChild(note);
    } else {
      if (p.status === 'suspended') {
        controls.appendChild(controlButton('RESUME', 'Resume', 'bg-emerald-950/60 hover:bg-emerald-900 border-emerald-700/60 text-emerald-300', p));
      } else {
        controls.appendChild(controlButton('SUSPEND', 'Freeze', 'bg-yellow-950/60 hover:bg-yellow-900 border-yellow-700/60 text-yellow-300', p));
      }
      controls.appendChild(controlButton('KILL', 'Kill', 'bg-red-950/80 hover:bg-red-900 border-red-700 text-red-300', p));
    }

    const cmd = cell('py-3 px-4 text-slate-400 text-[11px] max-w-xs truncate', p.cmd || '—');
    cmd.title = p.cmd || '';
    tr.append(
      cell('py-3 px-4 font-bold text-slate-300', String(p.pid)),
      nameCell,
      cell('py-3 px-4', badge(p.status)),
      cell('py-3 px-4 text-slate-300', `${p.cpu.toFixed(1)}% / ${Math.round(p.rss_mb)} MB`),
      cmd,
      controls,
    );
    body.appendChild(tr);
  }
  $('emptyState').classList.toggle('hidden', state.procs.length > 0);
  updateStats();
}

function ingestTelemetry(payload) {
  const host = String(payload.host || 'unknown');
  const incoming = (Array.isArray(payload.processes) ? payload.processes : []).map((p) => ({
    pid: Number(p.pid),
    name: String(p.name || 'unknown'),
    host,
    status: ['rogue', 'suspended'].includes(p.status) ? p.status : 'normal',
    cpu: Number(p.cpu) || 0,
    rss_mb: Number(p.rss_mb) || 0,
    create_time: typeof p.create_time === 'number' ? p.create_time : undefined,
    cmd: String(p.cmd || ''),
    protected: Boolean(p.protected),
  })).filter((p) => Number.isInteger(p.pid) && p.pid > 0);
  state.procs = state.procs.filter((p) => p.host !== host).concat(incoming);
  $('lastTelemetryStatus').textContent = new Date().toLocaleTimeString();
  render();
}

function send(action, pid, host) {
  const proc = state.procs.find((p) => p.pid === Number(pid) && p.host === host);
  if (!proc || !state.socket || state.socket.readyState !== WebSocket.OPEN) {
    log('Cannot send command: the dashboard link or the target process is unavailable.', 'red');
    return;
  }
  if (proc.protected) {
    log(`Refused: PID ${pid} is a protected AEGIS process.`, 'red');
    return;
  }
  state.socket.send(JSON.stringify({ action, pid: proc.pid, host: proc.host, create_time: proc.create_time }));
  log(`${action} sent for PID ${pid} on ${host}; waiting for the daemon to confirm.`, 'yellow');
}

function connect() {
  setDashboardLink('connecting');
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${scheme}//${window.location.host}/ws/dashboard`);
  state.socket = socket;
  socket.onopen = () => { setDashboardLink('up'); log('Connected to the AEGIS control plane.', 'emerald'); };
  socket.onmessage = (event) => {
    let msg;
    try { msg = JSON.parse(event.data); } catch (_) { return; }
    if (msg.type === 'telemetry') ingestTelemetry(msg);
    else if (msg.type === 'status') {
      const before = state.hosts.join(',');
      const hosts = Array.isArray(msg.hosts) ? msg.hosts.map(String) : [];
      setHosts(hosts);
      if (hosts.join(',') !== before) log(`Hosts online: ${hosts.length ? hosts.join(', ') : 'none'}.`, hosts.length ? 'emerald' : 'yellow');
    } else if (msg.type === 'host_offline') {
      state.procs = state.procs.filter((p) => p.host !== msg.host);
      render();
    } else if (msg.type === 'command_result') {
      log(String(msg.detail || 'Command response received.'), msg.ok ? 'cyan' : 'red');
    } else if (msg.type === 'ack') {
      log(`${msg.host || 'host'}: ${msg.action} PID ${msg.pid}: ${msg.detail || (msg.ok ? 'confirmed' : 'rejected')}`, msg.ok ? 'emerald' : 'red');
    }
  };
  socket.onclose = () => {
    setDashboardLink('down');
    setHosts([]);
    state.procs = [];
    render();
    log('Disconnected from the control plane. Retrying in 3 s…', 'red');
    setTimeout(async () => {
      // If the session expired, reloading sends us to the login page instead of looping.
      try {
        const info = await (await fetch('/api/session', { cache: 'no-store' })).json();
        if (info.auth_required && !info.authenticated) { window.location.reload(); return; }
      } catch (_) { /* server down: keep retrying */ }
      connect();
    }, 3000);
  };
}

function switchTab(name) {
  for (const section of ['processes', 'connect']) $(`tab-${section}`).classList.toggle('hidden', section !== name);
  document.querySelectorAll('aside .tab-btn').forEach((b) => { b.className = b.dataset.tab === name ? TAB_ON : TAB_OFF; });
}

function buildConnectCommand() {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `python daemon_security.py --gateway ${scheme}//${window.location.host}/ws/security-stream --host-id my-server`;
}

document.addEventListener('click', (event) => {
  const tab = event.target.closest('[data-tab]');
  if (tab) { switchTab(tab.dataset.tab); return; }
  const btn = event.target.closest('button[data-action]');
  if (!btn) return;
  const { action, pid, host } = btn.dataset;
  if (action === 'KILL' && !window.confirm(`Terminate PID ${pid} on ${host} and all of its child processes?`)) return;
  send(action, pid, host);
});

$('searchInput').addEventListener('input', (e) => { state.query = e.target.value; render(); });
$('clearLogBtn').addEventListener('click', () => $('log').replaceChildren());
$('copyCmdBtn').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(buildConnectCommand()); log('Command copied.', 'cyan'); }
  catch (_) { log('Could not copy automatically; select the command and copy it.', 'yellow'); }
});
$('freezeAllBtn').addEventListener('click', () => {
  const targets = state.procs.filter((p) => !p.protected && p.status !== 'suspended');
  if (!targets.length) { log('Nothing to freeze.', 'yellow'); return; }
  if (!window.confirm(`Freeze ${targets.length} monitored process(es) across ${new Set(targets.map((t) => t.host)).size} host(s)?`)) return;
  targets.forEach((p) => send('SUSPEND', p.pid, p.host));
});

(async function init() {
  $('connectCmd').textContent = buildConnectCommand();
  switchTab('processes');
  try {
    const info = await (await fetch('/api/session', { cache: 'no-store' })).json();
    $('logoutForm').classList.toggle('hidden', !info.auth_required);
    $('localBanner').classList.toggle('hidden', info.auth_required);
  } catch (_) { /* ignore: websocket status will show the problem */ }
  render();
  connect();
})();
