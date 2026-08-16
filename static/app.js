async function apiFetch(url, options) {
  const res = await fetch(url, options);
  if (res.status === 401) {
    window.location.href = '/login.html';
    throw new Error('unauthenticated');
  }
  return res;
}

// ---------- 主题切换（深色/浅色，偏好存在浏览器本地，只影响这个浏览器） ----------
(function initTheme() {
  const saved = window.localStorage.getItem('ollama-scanner-theme');
  if (saved === 'light') document.documentElement.setAttribute('data-theme', 'light');
})();

document.getElementById('themeToggle')?.addEventListener('click', () => {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  if (isLight) {
    document.documentElement.removeAttribute('data-theme');
    window.localStorage.setItem('ollama-scanner-theme', 'dark');
  } else {
    document.documentElement.setAttribute('data-theme', 'light');
    window.localStorage.setItem('ollama-scanner-theme', 'light');
  }
});

// ---------- 通用可收纳面板：点击标题旁边的按钮折叠/展开内容，状态记住在本地 ----------
function setupCollapsible(btnId, bodyId, storageKey) {
  const btn = document.getElementById(btnId);
  const body = document.getElementById(bodyId);
  if (!btn || !body) return;
  let collapsed = false;
  try { collapsed = localStorage.getItem(storageKey) === '1'; } catch (e) {}
  const apply = () => {
    body.hidden = collapsed;
    btn.textContent = collapsed ? '▸ 展开' : '▾ 收起';
  };
  apply();
  btn.addEventListener('click', () => {
    collapsed = !collapsed;
    apply();
    try { localStorage.setItem(storageKey, collapsed ? '1' : '0'); } catch (e) {}
  });
}
setupCollapsible('resultsCollapseBtn', 'resultsBody', 'ollama-scanner-collapse-results');
setupCollapsible('modelsAllCollapseBtn', 'modelsAllBody', 'ollama-scanner-collapse-modelsall');

const hostForm = document.getElementById('hostForm');
const hostInput = document.getElementById('hostInput');
const hostList = document.getElementById('hostList');
const hostEmpty = document.getElementById('hostEmpty');

const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const statusPill = document.getElementById('statusPill');
const logEl = document.getElementById('log');
const resultsBody = document.getElementById('resultsBody');
const radar = document.getElementById('radar');

const concurrencyRange = document.getElementById('concurrencyRange');
const concurrencyNumber = document.getElementById('concurrencyNumber');
const concurrencyValue = document.getElementById('concurrencyValue');
const modelConcurrencyRange = document.getElementById('modelConcurrencyRange');
const modelConcurrencyNumber = document.getElementById('modelConcurrencyNumber');
const modelConcurrencyValue = document.getElementById('modelConcurrencyValue');

const logoutBtn = document.getElementById('logoutBtn');
const leaderboardToggle = document.getElementById('leaderboardToggle');
const leaderboardPanel = document.getElementById('leaderboardPanel');
const leaderboardRefresh = document.getElementById('leaderboardRefresh');
const lbHostList = document.getElementById('lbHostList');
const lbHostEmpty = document.getElementById('lbHostEmpty');
const lbModelPanel = document.getElementById('lbModelPanel');
const lbModelHostLabel = document.getElementById('lbModelHostLabel');
const lbModelList = document.getElementById('lbModelList');
const lbModelEmpty = document.getElementById('lbModelEmpty');
const lbRanked = document.getElementById('lbRanked');
const lbFailed = document.getElementById('lbFailed');

let pollTimer = null;
let lastSeq = 0;
let wasRunning = false;
let lbActiveHost = null;

// ---------- Logout ----------

logoutBtn.addEventListener('click', async () => {
  await apiFetch('/api/logout', { method: 'POST' });
  window.location.href = '/login.html';
});

// ---------- Leaderboard panel toggle ----------

leaderboardToggle.addEventListener('click', () => {
  const isHidden = leaderboardPanel.hasAttribute('hidden');
  if (isHidden) {
    leaderboardPanel.removeAttribute('hidden');
    leaderboardToggle.classList.add('is-lit');
    refreshLeaderboardSidebar();
    refreshLeaderboardTable();
  } else {
    leaderboardPanel.setAttribute('hidden', '');
  }
});

leaderboardRefresh.addEventListener('click', () => {
  refreshLeaderboardSidebar();
  refreshLeaderboardTable();
});

const lbExportCsv = document.getElementById('lbExportCsv');
const lbExportMd = document.getElementById('lbExportMd');

function downloadLeaderboard(fmt) {
  // 直接跳转即可触发浏览器下载（后端用 Content-Disposition: attachment），
  // 走的是当前登录会话的 cookie，不需要额外处理。
  window.location.href = `/api/leaderboard/export?fmt=${fmt}`;
}
lbExportCsv.addEventListener('click', () => downloadLeaderboard('csv'));
lbExportMd.addEventListener('click', () => downloadLeaderboard('md'));

// ---------- Audit log panel ----------

const auditToggle = document.getElementById('auditToggle');
const auditPanel = document.getElementById('auditPanel');
const auditRefresh = document.getElementById('auditRefresh');
const auditList = document.getElementById('auditList');
const auditEmpty = document.getElementById('auditEmpty');

const AUDIT_ACTION_LABELS = {
  add_host: '新增主机',
  patch_host: '修改主机',
  delete_host: '删除主机',
  login_success: '登录成功',
  login_failed: '登录失败',
  update_settings: '更新设置',
  notify_test: '测试通知',
  notify_failed: '通知发送失败',
};

auditToggle.addEventListener('click', () => {
  const isHidden = auditPanel.hasAttribute('hidden');
  if (isHidden) {
    auditPanel.removeAttribute('hidden');
    auditToggle.classList.add('is-lit');
    refreshAuditLog();
  } else {
    auditPanel.setAttribute('hidden', '');
    auditToggle.classList.remove('is-lit');
  }
});
auditRefresh.addEventListener('click', refreshAuditLog);

async function refreshAuditLog() {
  try {
    const res = await apiFetch('/api/audit-log');
    const logs = await res.json();
    renderAuditLog(logs);
  } catch (e) {
    // ignore, apiFetch already handles auth redirect
  }
}

function renderAuditLog(logs) {
  auditEmpty.style.display = logs.length ? 'none' : 'block';
  auditList.innerHTML = logs.map((l) => `
    <div class="audit-row">
      <span class="audit-row__ts">${escapeHtml(l.ts)}</span>
      <span class="audit-row__action">${escapeHtml(AUDIT_ACTION_LABELS[l.action] || l.action)}</span>
      <span class="audit-row__ip">${escapeHtml(l.ip)}</span>
      <span class="audit-row__detail">${escapeHtml(l.detail || '')}</span>
    </div>
  `).join('');
}

// ---------- Concurrency control ----------

function clampConcurrency(v) {
  v = parseInt(v, 10);
  if (isNaN(v)) v = 3;
  return Math.min(100, Math.max(1, v));
}

function setConcurrency(v) {
  v = clampConcurrency(v);
  concurrencyRange.value = v;
  concurrencyNumber.value = v;
  concurrencyValue.textContent = v;
  try { localStorage.setItem('ollama-scanner-concurrency', String(v)); } catch (e) {}
}

concurrencyRange.addEventListener('input', () => setConcurrency(concurrencyRange.value));
concurrencyNumber.addEventListener('input', () => setConcurrency(concurrencyNumber.value));

(function initConcurrency() {
  let saved = 3;
  try {
    const stored = localStorage.getItem('ollama-scanner-concurrency');
    if (stored) saved = clampConcurrency(stored);
  } catch (e) {}
  setConcurrency(saved);
})();

// ---------- Model concurrency control (每个主机内并发测试几个模型) ----------

function clampModelConcurrency(v) {
  v = parseInt(v, 10);
  if (isNaN(v)) v = 4;
  return Math.min(20, Math.max(1, v));
}

function setModelConcurrency(v) {
  v = clampModelConcurrency(v);
  modelConcurrencyRange.value = v;
  modelConcurrencyNumber.value = v;
  modelConcurrencyValue.textContent = v;
  try { localStorage.setItem('ollama-scanner-model-concurrency', String(v)); } catch (e) {}
}

modelConcurrencyRange.addEventListener('input', () => setModelConcurrency(modelConcurrencyRange.value));
modelConcurrencyNumber.addEventListener('input', () => setModelConcurrency(modelConcurrencyNumber.value));

(function initModelConcurrency() {
  let saved = 4;
  try {
    const stored = localStorage.getItem('ollama-scanner-model-concurrency');
    if (stored) saved = clampModelConcurrency(stored);
  } catch (e) {}
  setModelConcurrency(saved);
})();

// ---------- Hosts ----------

let allHostsCache = [];
let hostTagFilter = '';

async function fetchHosts() {
  const res = await apiFetch('/api/hosts');
  const hosts = await res.json();
  allHostsCache = hosts;
  renderHosts(filterHostsByTag(hosts));
}

function filterHostsByTag(hosts) {
  const q = hostTagFilter.trim().toLowerCase();
  if (!q) return hosts;
  return hosts.filter(
    (h) => (h.tags || []).some((t) => t.toLowerCase().includes(q)) || (h.group || '').toLowerCase().includes(q)
  );
}

const hostTagFilterInput = document.getElementById('hostTagFilter');
hostTagFilterInput.addEventListener('input', () => {
  hostTagFilter = hostTagFilterInput.value;
  renderHosts(filterHostsByTag(allHostsCache));
});

const hostFailedZone = document.getElementById('hostFailedZone');
const hostFailedList = document.getElementById('hostFailedList');

function isHostFailed(host) {
  return host.last_scan_status === 'unreachable' || host.last_scan_status === 'all_down';
}

function renderHosts(hosts) {
  const normalHosts = hosts.filter((h) => !isHostFailed(h));
  const failedHosts = hosts.filter((h) => isHostFailed(h));

  hostList.innerHTML = '';
  hostEmpty.style.display = normalHosts.length ? 'none' : 'block';
  normalHosts.forEach((host) => hostList.appendChild(buildHostItem(host)));

  hostFailedZone.hidden = failedHosts.length === 0;
  hostFailedList.innerHTML = '';
  failedHosts.forEach((host) => hostFailedList.appendChild(buildHostItem(host)));
}

function buildHostItem(host) {
  const { url, enabled, favorite, tags, group, last_scan_status } = host;
  const tagList = tags || [];
  const failed = isHostFailed(host);
  const li = document.createElement('li');
  li.className = `host-item${enabled ? '' : ' host-item--disabled'}${failed ? ' host-item--failed' : ''}`;
  const statusLabel = last_scan_status === 'unreachable'
    ? '⛔ 上次扫描整链接不可达'
    : last_scan_status === 'all_down'
      ? '⛔ 上次扫描全部模型不通'
      : '';
  li.innerHTML = `
    <button class="host-item__star${favorite ? ' is-lit' : ''}" title="${favorite ? '取消收藏' : '收藏此地址'}" aria-pressed="${favorite}">★</button>
    <span class="host-item__main">
      <span class="host-item__url">${escapeHtml(url)}</span>
      ${statusLabel ? `<span class="host-tag host-tag--fail">${statusLabel}</span>` : ''}
      ${group ? `<span class="host-tag host-tag--group">📁 ${escapeHtml(group)}</span>` : ''}
      ${tagList.length ? `<span class="host-item__tags">${tagList.map((t) => `<span class="host-tag">${escapeHtml(t)}</span>`).join('')}</span>` : ''}
    </span>
    <button class="host-item__tagbtn" title="编辑分组">📁</button>
    <button class="host-item__tagbtn" title="编辑标签">🏷</button>
    <label class="host-item__toggle" title="${enabled ? '启用中，参与扫描' : '已禁用，不参与扫描'}">
      <input type="checkbox" ${enabled ? 'checked' : ''} aria-label="启用 ${escapeHtml(url)}" />
      <span class="host-item__toggle-track"><span class="host-item__toggle-thumb"></span></span>
    </label>
    <button class="host-item__remove" title="移除" aria-label="移除 ${escapeHtml(url)}">×</button>
  `;
  const [groupBtn, tagBtn] = li.querySelectorAll('.host-item__tagbtn');
  li.querySelector('.host-item__star').addEventListener('click', () => patchHost(url, { favorite: !favorite }));
  groupBtn.addEventListener('click', () => editHostGroup(url, group));
  tagBtn.addEventListener('click', () => editHostTags(url, tagList));
  li.querySelector('.host-item__toggle input').addEventListener('change', (e) => patchHost(url, { enabled: e.target.checked }));
  li.querySelector('.host-item__remove').addEventListener('click', () => removeHost(url));
  return li;
}

async function bulkToggleHosts(enabled, scope) {
  try {
    const res = await apiFetch('/api/hosts/bulk-toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, scope }),
    });
    const data = await res.json();
    allHostsCache = data.hosts;
    renderHosts(filterHostsByTag(allHostsCache));
  } catch (e) {
    // ignore
  }
}

document.getElementById('hostEnableAllBtn').addEventListener('click', () => bulkToggleHosts(true, 'normal'));
document.getElementById('hostDisableAllBtn').addEventListener('click', () => bulkToggleHosts(false, 'normal'));
document.getElementById('hostFailedEnableAllBtn').addEventListener('click', () => bulkToggleHosts(true, 'failed'));
document.getElementById('hostFailedDisableAllBtn').addEventListener('click', () => bulkToggleHosts(false, 'failed'));

document.getElementById('hostFailedDeleteAllBtn').addEventListener('click', async () => {
  if (!confirm('确定要一键删除"失败区"里的全部链接吗？此操作不可撤销。')) return;
  try {
    const res = await apiFetch('/api/hosts/failed', { method: 'DELETE' });
    const data = await res.json();
    allHostsCache = data.hosts;
    renderHosts(filterHostsByTag(allHostsCache));
  } catch (e) {
    // ignore
  }
});

document.getElementById('hostDeleteAllBtn').addEventListener('click', async () => {
  const count = allHostsCache.length;
  if (!count) {
    alert('主机列表本来就是空的。');
    return;
  }
  if (!confirm(`确定要清空整个主机列表吗？会删掉全部 ${count} 条记录（正常的 + 失败区的），此操作不可撤销。`)) return;
  const typed = prompt(`真的要删吗？这一步没法反悔。输入「删除」两个字确认（不含引号）：`);
  if (typed !== '删除') {
    if (typed !== null) alert('输入不匹配，已取消，主机列表没有变化。');
    return;
  }
  try {
    const res = await apiFetch('/api/hosts/all', { method: 'DELETE' });
    const data = await res.json();
    allHostsCache = data.hosts;
    renderHosts(filterHostsByTag(allHostsCache));
  } catch (e) {
    // ignore
  }
});

function editHostGroup(url, currentGroup) {
  const input = window.prompt('给这台主机设置一个分组名（比如：机房A / 项目X），留空清除分组', currentGroup || '');
  if (input === null) return; // 取消
  patchHost(url, { group: input.trim() });
}

function editHostTags(url, currentTags) {
  const input = window.prompt('用逗号分隔多个标签，例如：机房A,GPU', (currentTags || []).join(','));
  if (input === null) return; // 取消
  const tags = input.split(',').map((t) => t.trim()).filter(Boolean);
  patchHost(url, { tags });
}

async function patchHost(url, changes) {
  const res = await apiFetch('/api/hosts', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, ...changes }),
  });
  if (res.ok) {
    const hosts = await res.json();
    allHostsCache = hosts;
    renderHosts(filterHostsByTag(hosts));
  }
}

async function addHost(url, force) {
  const res = await apiFetch('/api/hosts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, force: !!force }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const detail = err.detail;
    // 探活失败 / 该地址在某个归档里出现过：后端返回 {code, message}，弹二次确认后带 force 重新提交
    if (detail && typeof detail === 'object' && (detail.code === 'unreachable' || detail.code === 'already_archived')) {
      if (window.confirm(`${detail.message}\n\n仍然要添加这个地址吗？`)) {
        return addHost(url, true);
      }
      return;
    }
    alert((typeof detail === 'string' ? detail : detail?.message) || '添加失败');
    return;
  }
  const hosts = await res.json();
  allHostsCache = hosts;
  renderHosts(filterHostsByTag(hosts));
}

async function removeHost(url) {
  const res = await apiFetch('/api/hosts', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (res.ok) {
    const hosts = await res.json();
    allHostsCache = hosts;
    renderHosts(filterHostsByTag(hosts));
  }
}

hostForm.addEventListener('submit', (e) => {
  e.preventDefault();
  const val = hostInput.value.trim();
  if (!val) return;
  addHost(val);
  hostInput.value = '';
});

// ---------- Batch paste parsing ----------

const batchToggle = document.getElementById('batchToggle');
const batchPanel = document.getElementById('batchPanel');
const batchInput = document.getElementById('batchInput');
const batchParseBtn = document.getElementById('batchParseBtn');
const batchCancelBtn = document.getElementById('batchCancelBtn');
const batchPreview = document.getElementById('batchPreview');

batchToggle.addEventListener('click', () => {
  const showing = !batchPanel.hidden;
  batchPanel.hidden = showing;
  if (!showing) batchInput.focus();
});
batchCancelBtn.addEventListener('click', () => {
  batchPanel.hidden = true;
  batchInput.value = '';
  batchPreview.innerHTML = '';
});

// Matches ip[:port], with or without a leading http(s)://
const IP_PORT_RE = /(?:https?:\/\/)?(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?/g;
const DEFAULT_PORT = '11434';

function isPrivateIp(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local
  return false;
}

function parseAddresses(text) {
  const seen = new Set();
  const results = [];
  let match;
  IP_PORT_RE.lastIndex = 0;
  while ((match = IP_PORT_RE.exec(text)) !== null) {
    const ip = match[1];
    const port = match[2] || DEFAULT_PORT;
    const url = `http://${ip}:${port}`;
    if (seen.has(url)) continue;
    seen.add(url);
    results.push({ url, ip, private: isPrivateIp(ip) });
  }
  return results;
}

batchParseBtn.addEventListener('click', async () => {
  const parsed = parseAddresses(batchInput.value);
  if (!parsed.length) {
    batchPreview.innerHTML = '<li>没有识别到任何 ip:port 地址。</li>';
    return;
  }

  const privateOnes = parsed.filter((p) => p.private);
  const publicOnes = parsed.filter((p) => !p.private);

  if (publicOnes.length) {
    const list = publicOnes.map((p) => `  • ${p.url}`).join('\n');
    const confirmed = confirm(
      `以下 ${publicOnes.length} 个地址不属于内网网段（10.x / 172.16-31.x / 192.168.x）：\n\n${list}\n\n` +
      `请确认这些都是你自己拥有或已获得明确授权测试的主机，再继续添加。\n点击"确定"添加全部，"取消"仅添加内网地址。`
    );
    if (!confirmed) {
      publicOnes.length = 0; // drop them, keep only private
    }
  }

  const toAdd = [...privateOnes, ...(publicOnes.length ? publicOnes : [])];
  batchPreview.innerHTML = toAdd
    .map((p) => `<li><span class="${p.private ? 'tag-private' : 'tag-public'}">${p.private ? '内网' : '公网'}</span> ${escapeHtml(p.url)}</li>`)
    .join('');

  for (const p of toAdd) {
    await addHost(p.url);
  }

  if (toAdd.length) {
    batchInput.value = '';
  }
});

// ---------- Scan control ----------

// 与"🛰 指挥中心视图"共用同一份 localStorage key，两个界面切换测试选择保持一致。
const SCAN_TOGGLE_STORAGE_KEY = 'ollama-scanner-hud-scan-toggles';

function loadScanToggleState() {
  try {
    const raw = localStorage.getItem(SCAN_TOGGLE_STORAGE_KEY);
    if (!raw) return { core: false, control: false, language: false, headless: false };
    const parsed = JSON.parse(raw);
    return {
      core: !!parsed.core,
      control: !!parsed.control,
      language: !!parsed.language,
      headless: !!parsed.headless,
    };
  } catch (e) {
    return { core: false, control: false, language: false, headless: false };
  }
}

function saveScanToggleState() {
  try {
    localStorage.setItem(SCAN_TOGGLE_STORAGE_KEY, JSON.stringify(scanToggleState));
  } catch (e) {
    // 存储不可用（隐私模式等）就算了，不影响本次会话内正常使用
  }
}

const scanToggleState = loadScanToggleState();

document.querySelectorAll('.scan-toggle[data-toggle]').forEach((btn) => {
  const key = btn.dataset.toggle;
  if (key === 'core' || key === 'control' || key === 'language' || key === 'headless') {
    btn.dataset.on = String(scanToggleState[key]);
  }
});

function syncMasterScanToggle() {
  const allOn = scanToggleState.core && scanToggleState.control && scanToggleState.language && scanToggleState.headless;
  document.querySelector('.scan-toggle[data-toggle="all"]').dataset.on = String(allOn);
}

document.querySelectorAll('.scan-toggle[data-toggle]').forEach((btn) => {
  const key = btn.dataset.toggle;
  if (key === 'quick') {
    // 快速在线测试是扫描流水线的第一步（先探测模型可用性，后面的测试都依赖这一步的
    // 结果），不能单独关闭，点击时解释一下，而不是让它看起来像个卡死的按钮。
    btn.addEventListener('click', () => {
      alert('"快速在线测试"是扫描流程的第一步：先探测每个模型是否可用，后面第 3/4/5/6 项测试都要依赖这一步的结果来决定测哪些模型。\n\n所以它不能单独关闭；如果这次扫描只想测在线状态、不想跑更深的测试，把下面 3/4/5/6 全部关掉（红色）再开始扫描就行。');
    });
    return;
  }
  btn.addEventListener('click', () => {
    if (key === 'all') {
      const turnOn = btn.dataset.on !== 'true';
      ['core', 'control', 'language', 'headless'].forEach((k) => {
        scanToggleState[k] = turnOn;
        document.querySelector(`.scan-toggle[data-toggle="${k}"]`).dataset.on = String(turnOn);
      });
      btn.dataset.on = String(turnOn);
      saveScanToggleState();
      return;
    }
    scanToggleState[key] = !scanToggleState[key];
    btn.dataset.on = String(scanToggleState[key]);
    syncMasterScanToggle();
    saveScanToggleState();
  });
});
syncMasterScanToggle();

async function startScan() {
  const anyDeepTestOn = scanToggleState.core || scanToggleState.control || scanToggleState.language || scanToggleState.headless;
  if (!anyDeepTestOn) {
    const ok = confirm('当前 3/4/5/6 测试开关都是关闭(红)状态，本次只会跑"快速在线测试"。\n\n确定要这样开始吗？');
    if (!ok) return;
  }
  const concurrency = clampConcurrency(concurrencyNumber.value);
  const model_concurrency = clampModelConcurrency(modelConcurrencyNumber.value);
  const res = await apiFetch('/api/scan/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      concurrency, model_concurrency,
      enable_core: scanToggleState.core,
      enable_control: scanToggleState.control,
      enable_language: scanToggleState.language,
      enable_headless: scanToggleState.headless,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || '无法开始扫描');
    return;
  }
  logEl.innerHTML = '';
  lastSeq = 0;
  setRunningUI(true);
  // 不再手动 poll()：扫描线程一开始写日志，WS 广播就会自动把它们推过来。
}

async function stopScan() {
  await apiFetch('/api/scan/stop', { method: 'POST' });
  setStatusPill('stopping', '停止中…');
  stopBtn.disabled = true;
}

startBtn.addEventListener('click', startScan);
stopBtn.addEventListener('click', stopScan);

function setRunningUI(running) {
  startBtn.disabled = running;
  stopBtn.disabled = !running;
  concurrencyRange.disabled = running;
  concurrencyNumber.disabled = running;
  modelConcurrencyRange.disabled = running;
  modelConcurrencyNumber.disabled = running;
  radar.classList.toggle('is-active', running);
  if (running) setStatusPill('running', '扫描中…');
}

function setStatusPill(kind, text) {
  statusPill.className = `status-pill status-pill--${kind}`;
  statusPill.textContent = text;
}

// ---------- 实时异常 toast（不依赖任何外部通知渠道配置，控制台开着就能看到） ----------

function showAlertToast(title, message) {
  let container = document.getElementById('alertToastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'alertToastContainer';
    container.className = 'alert-toast-container';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  toast.className = 'alert-toast';
  const titleEl = document.createElement('div');
  titleEl.className = 'alert-toast__title';
  titleEl.textContent = title;
  const bodyEl = document.createElement('div');
  bodyEl.className = 'alert-toast__body';
  bodyEl.textContent = message; // textContent，不是 innerHTML：消息里可能包含主机地址等用户输入过的内容，不能当 HTML 解析
  const closeBtn = document.createElement('button');
  closeBtn.className = 'alert-toast__close';
  closeBtn.textContent = '✕';
  closeBtn.addEventListener('click', () => toast.remove());
  toast.append(titleEl, bodyEl, closeBtn);
  container.appendChild(toast);
  // 15 秒后自动消失，避免开着页面几天不关、toast 堆成一整屏
  setTimeout(() => toast.remove(), 15000);
}

// ---------- WebSocket 日志/状态流（取代原来 1.2 秒一次的轮询） ----------
// 设计：单一长连接持续推日志；连接断开时指数退避重连；重连成功后依赖后端
// 主动下发的 log_backfill 补齐断线期间错过的日志，不需要客户端自己算 since。
// 如果 WS 连接一直起不来（比如反代不支持 ws 升级），退化为一次性 HTTP 兜底，
// 保证至少能看到当前状态，而不是整个日志面板死掉。

let ws = null;
let wsReconnectDelay = 1000;
const WS_RECONNECT_MAX_DELAY = 10000;

function wsConnect() {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${proto}//${window.location.host}/ws/logs`);

  ws.addEventListener('open', () => {
    wsReconnectDelay = 1000; // 连上了就重置退避时间
  });

  ws.addEventListener('message', (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch (e) {
      return;
    }
    if (msg.type === 'log') {
      appendLogs([msg.entry]);
    } else if (msg.type === 'log_backfill') {
      appendLogs(msg.entries);
    } else if (msg.type === 'status') {
      setRunningUI(msg.running);
      if (!msg.running) {
        if (msg.has_results) {
          // 结果本体没有随每条状态消息广播（避免大 JSON 刷屏），
          // 扫描结束这一刻单独拉一次就够了，不是轮询。
          fetchFinalResults();
        } else if (wasRunning) {
          setStatusPill('idle', '待机');
        }
      }
      wasRunning = msg.running;
    } else if (msg.type === 'alert') {
      showAlertToast(msg.title || '⚠️ 异常', msg.message || '');
    }
  });

  ws.addEventListener('close', () => {
    if (document.getElementById('logoutBtn') == null) return; // 页面已经跳转走了（比如登出），不用重连
    setTimeout(wsConnect, wsReconnectDelay);
    wsReconnectDelay = Math.min(wsReconnectDelay * 2, WS_RECONNECT_MAX_DELAY);
  });

  ws.addEventListener('error', () => {
    ws.close();
  });
}

async function fetchFinalResults() {
  try {
    const res = await apiFetch('/api/scan/status?since=0');
    const data = await res.json();
    if (data.results) {
      setStatusPill('done', '已完成');
      renderResults(data.results);
    }
  } catch (e) {
    // ignore，下次状态变化或手动刷新会再拉一次
  }
}

const MAX_LOG_LINES = 3000; // 超长扫描（几十台主机跑几小时）避免日志把DOM撑爆导致页面变卡

function appendLogs(logs) {
  if (!logs || !logs.length) return;
  const atBottom = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 40;
  const frag = document.createDocumentFragment();
  logs.forEach((l) => {
    lastSeq = Math.max(lastSeq, l.seq);
    const div = document.createElement('div');
    div.className = 'log__line';
    div.innerHTML = `<span class="log__ts">${l.ts}</span>${escapeHtml(l.text)}`;
    frag.appendChild(div);
  });
  logEl.appendChild(frag);
  while (logEl.children.length > MAX_LOG_LINES) {
    logEl.removeChild(logEl.firstChild);
  }
  if (atBottom) logEl.scrollTop = logEl.scrollHeight;
}

// ---------- Results ----------

function renderResults(results) {
  if (!results || !results.advanced || Object.keys(results.advanced).length === 0) {
    resultsBody.innerHTML = '<p class="results-empty">本次扫描没有可用模型进入高级测试阶段。</p>';
    return;
  }

  resultsBody.innerHTML = '';
  Object.entries(results.advanced).forEach(([key, tests]) => {
    const [host, model] = key.split('|');
    const passCount = tests.filter((t) => t.status === 'PASS').length;
    const allPass = tests.length > 0 && passCount === tests.length;

    const card = document.createElement('div');
    card.className = 'result-card';
    card.innerHTML = `
      <div class="result-card__head">
        <span>${escapeHtml(model)} <span style="color:var(--dim)">@ ${escapeHtml(host)}</span></span>
        <span class="result-card__badge ${allPass ? 'result-card__badge--pass' : 'result-card__badge--fail'}">
          ${passCount}/${tests.length} 通过
        </span>
      </div>
      <div class="result-card__tests">
        ${tests.map((t) => `
          <div class="result-test">
            <span>${escapeHtml(t.test)}</span>
            <span class="result-test__status--${t.status}">${t.status} (${t.elapsed.toFixed(1)}s)</span>
          </div>
        `).join('')}
      </div>
    `;
    resultsBody.appendChild(card);
  });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---------- Leaderboard sidebar: hosts -> models connectivity ----------

async function refreshLeaderboardSidebar() {
  try {
    const res = await apiFetch('/api/hosts/status');
    const hosts = await res.json();
    renderLbHostList(hosts);
  } catch (e) {
    // ignore, apiFetch already handles auth redirect
  }
}

function renderLbHostList(hosts) {
  lbHostList.innerHTML = '';
  lbHostEmpty.style.display = hosts.length ? 'none' : 'block';

  hosts.forEach((host) => {
    const failed = host.last_scan_status === 'unreachable' || host.last_scan_status === 'all_down';
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `lb-host-item${host.url === lbActiveHost ? ' is-active' : ''}${failed ? ' lb-host-item--failed' : ''}`;
    btn.textContent = host.url + (host.enabled ? '' : ' (已禁用)') + (failed ? ' ⛔' : '');
    btn.addEventListener('click', () => {
      lbActiveHost = host.url;
      renderLbHostList(hosts);
      renderLbModelPanel(host);
    });
    li.appendChild(btn);
    lbHostList.appendChild(li);
  });

  if (lbActiveHost) {
    const active = hosts.find((h) => h.url === lbActiveHost);
    if (active) renderLbModelPanel(active);
  }
}

function renderLbModelPanel(host) {
  lbModelPanel.hidden = false;
  lbModelHostLabel.textContent = host.url;
  lbModelList.innerHTML = '';
  lbModelEmpty.style.display = host.models.length ? 'none' : 'block';

  host.models.forEach((m) => {
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'lb-model-item';
    const dotClass = m.ok === true ? 'status-dot--ok' : m.ok === false ? 'status-dot--fail' : 'status-dot--unknown';
    const uptimeHtml = m.uptime_pct != null ? `<span class="lb-model-item__uptime">在线率 ${m.uptime_pct}%</span>` : '';
    btn.innerHTML = `
      <span class="status-dot ${dotClass}" data-role="dot"></span>
      <span class="lb-model-item__name">${escapeHtml(m.model)}</span>
      ${uptimeHtml}
    `;
    btn.title = '点击发送「你好」测试连通性';
    btn.addEventListener('click', () => pingModel(host.url, m.model, btn));
    li.appendChild(btn);
    lbModelList.appendChild(li);
  });
}

async function pingModel(hostUrl, model, btnEl) {
  const dot = btnEl.querySelector('[data-role="dot"]');
  dot.className = 'status-dot status-dot--checking';
  btnEl.disabled = true;
  try {
    const res = await apiFetch('/api/ping', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: hostUrl, model }),
    });
    const data = await res.json();
    dot.className = `status-dot ${data.ok ? 'status-dot--ok' : 'status-dot--fail'}`;
    btnEl.title = data.ok
      ? `正常 (${data.elapsed}s)`
      : `失败: ${(data.error || '无响应').slice(0, 80)}`;
  } catch (e) {
    dot.className = 'status-dot status-dot--fail';
  } finally {
    btnEl.disabled = false;
  }
}

// ---------- Leaderboard table（精简版：只做"模型是否可用"的快速测试排行） ----------

let lbQuickData = null;
const lbRankedTitle = document.getElementById('lbRankedTitle');

async function refreshLeaderboardTable() {
  try {
    const res = await apiFetch('/api/leaderboard/quick');
    lbQuickData = await res.json();
    renderActiveCategory();
  } catch (e) {
    // ignore, apiFetch already handles auth redirect
  }
}

function renderActiveCategory() {
  if (!lbQuickData) return;
  lbRankedTitle.textContent = `排行榜（可用 · 按响应耗时排序）`;
  renderQuickTable(lbRanked, lbQuickData.ranked, true);
  renderQuickTable(lbFailed, lbQuickData.failed, false);
}

function renderQuickTable(container, entries, ranked) {
  if (!entries || !entries.length) {
    container.innerHTML = `<p class="results-empty">${ranked ? '暂无可用模型。' : '暂无不可用记录。'}</p>`;
    return;
  }
  container.innerHTML = '';
  entries.forEach((entry) => {
    const row = document.createElement('div');
    row.className = `lb-row${ranked ? '' : ' lb-row--fail'}`;
    const statsHtml = ranked ? `<strong>${entry.elapsed ?? '?'}s</strong> 响应耗时` : '不可用';
    const familyHint = entry.family_hint
      ? `<div class="lb-row__family">参考系列: ${escapeHtml(entry.family_hint)}</div>`
      : '';
    row.innerHTML = `
      <span class="lb-row__rank">${ranked ? '#' + entry.rank : '✘'}</span>
      <span class="lb-row__info">
        <div class="lb-row__model">${escapeHtml(entry.model)}</div>
        <div class="lb-row__host">@ ${escapeHtml(entry.host)}</div>
        ${familyHint}
      </span>
      <span class="lb-row__stats">${statsHtml}</span>
    `;
    container.appendChild(row);
  });
}

function renderLbTable(container, entries, ranked) {
  if (!entries || !entries.length) {
    container.innerHTML = `<p class="results-empty">${ranked ? '暂无排名数据。' : '暂无失败记录。'}</p>`;
    return;
  }
  container.innerHTML = '';
  entries.forEach((entry) => {
    const row = document.createElement('div');
    row.className = `lb-row${ranked ? '' : ' lb-row--fail'}`;
    const statsHtml = ranked
      ? `<strong>${entry.elapsed_total}s</strong> 总耗时 · ${entry.passed}/${entry.total} 通过`
      : `${entry.passed || 0}/${entry.total || 0} 通过${entry.error ? ' · ' + escapeHtml(entry.error) : ''}`;
    const familyHint = entry.family_hint
      ? `<div class="lb-row__family">参考系列: ${escapeHtml(entry.family_hint)}</div>`
      : '';
    row.innerHTML = `
      <span class="lb-row__rank">${ranked ? '#' + entry.rank : '✘'}</span>
      <span class="lb-row__info">
        <div class="lb-row__model">${escapeHtml(entry.model)}</div>
        <div class="lb-row__host">@ ${escapeHtml(entry.host)}</div>
        ${familyHint}
      </span>
      <span class="lb-row__stats">${statsHtml}</span>
      <button type="button" class="lb-row__retest">↻ 重新测试</button>
    `;
    row.querySelector('.lb-row__retest').addEventListener('click', (e) => retestLeaderboardEntry(entry, e.target));
    container.appendChild(row);
  });
}

async function retestLeaderboardEntry(entry, btnEl) {
  btnEl.disabled = true;
  const originalText = btnEl.textContent;
  btnEl.textContent = '测试中…';
  try {
    await apiFetch('/api/leaderboard/retest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: entry.host, model: entry.model }),
    });
    await refreshLeaderboardTable();
  } catch (e) {
    btnEl.disabled = false;
    btnEl.textContent = originalText;
  }
}

// ---------- Settings panel: 定时扫描 + 异常通知 ----------

const settingsToggle = document.getElementById('settingsToggle');
const settingsPanel = document.getElementById('settingsPanel');
const settingsSaveBtn = document.getElementById('settingsSaveBtn');
const notifyTestBtn = document.getElementById('notifyTestBtn');
const settingsStatus = document.getElementById('settingsStatus');

settingsToggle.addEventListener('click', () => {
  const isHidden = settingsPanel.hasAttribute('hidden');
  if (isHidden) {
    settingsPanel.removeAttribute('hidden');
    settingsToggle.classList.add('is-lit');
    loadSettingsIntoForm();
  } else {
    settingsPanel.setAttribute('hidden', '');
    settingsToggle.classList.remove('is-lit');
  }
});

async function loadSettingsIntoForm() {
  try {
    const res = await apiFetch('/api/settings');
    const s = await res.json();

    document.getElementById('schedEnabled').checked = !!s.schedule.enabled;
    document.getElementById('schedTime').value = s.schedule.time || '09:00';
    document.getElementById('schedConcurrency').value = s.schedule.concurrency ?? 3;
    document.getElementById('schedModelConcurrency').value = s.schedule.model_concurrency ?? 4;

    document.getElementById('notifyWecomEnabled').checked = !!s.notify.wecom.enabled;
    document.getElementById('notifyWecomUrl').value = s.notify.wecom.webhook_url || '';

    document.getElementById('notifyTelegramEnabled').checked = !!s.notify.telegram.enabled;
    document.getElementById('notifyTelegramToken').value = s.notify.telegram.bot_token || '';
    document.getElementById('notifyTelegramChatId').value = s.notify.telegram.chat_id || '';
    document.getElementById('notifyTelegramPublicBaseUrl').value = s.notify.telegram.public_base_url || '';

    document.getElementById('notifyBarkEnabled').checked = !!s.notify.bark.enabled;
    document.getElementById('notifyBarkKey').value = s.notify.bark.key || '';
    document.getElementById('notifyBarkServer').value = s.notify.bark.server || 'https://api.day.app';

    document.getElementById('notifyEmailEnabled').checked = !!s.notify.email.enabled;
    document.getElementById('notifyEmailHost').value = s.notify.email.smtp_host || '';
    document.getElementById('notifyEmailPort').value = s.notify.email.smtp_port ?? 587;
    document.getElementById('notifyEmailUser').value = s.notify.email.username || '';
    document.getElementById('notifyEmailPass').value = s.notify.email.password || '';
    document.getElementById('notifyEmailFrom').value = s.notify.email.from_addr || '';
    document.getElementById('notifyEmailTo').value = s.notify.email.to_addr || '';
    document.getElementById('notifyEmailTls').checked = s.notify.email.use_tls !== false;

    const hist = s.history || {};
    document.getElementById('histRetentionDays').value = hist.retention_days ?? 180;
    document.getElementById('histMaxSizeMb').value = hist.max_size_mb ?? 50;
    document.getElementById('histAutoCleanup').checked = hist.auto_cleanup_enabled !== false;

    const ad = s.address_discovery || {};
    document.getElementById('adEnabled').checked = !!ad.enabled;
    document.getElementById('adUrl').value = ad.url || '';
    document.getElementById('adInterval').value = ad.interval_minutes ?? 30;
    document.getElementById('adGroup').value = ad.group || '';
    document.getElementById('adTags').value = (ad.tags || []).join(',');
    renderAddressDiscoveryStatus(ad);
  } catch (e) {
    // ignore, apiFetch already handles auth redirect
  }
  refreshHistoryStats();
  refreshShareStatus();
  refreshTotpStatus();
  refreshMetricsStatus();
  refreshCustomTests();
  refreshCoreTests();
}

function buildSettingsPayload() {
  return {
    schedule: {
      enabled: document.getElementById('schedEnabled').checked,
      time: document.getElementById('schedTime').value || '09:00',
      concurrency: clampConcurrency(document.getElementById('schedConcurrency').value),
      model_concurrency: clampModelConcurrency(document.getElementById('schedModelConcurrency').value),
    },
    notify: {
      wecom: {
        enabled: document.getElementById('notifyWecomEnabled').checked,
        webhook_url: document.getElementById('notifyWecomUrl').value.trim(),
      },
      telegram: {
        enabled: document.getElementById('notifyTelegramEnabled').checked,
        bot_token: document.getElementById('notifyTelegramToken').value.trim(),
        chat_id: document.getElementById('notifyTelegramChatId').value.trim(),
        public_base_url: document.getElementById('notifyTelegramPublicBaseUrl').value.trim(),
      },
      bark: {
        enabled: document.getElementById('notifyBarkEnabled').checked,
        key: document.getElementById('notifyBarkKey').value.trim(),
        server: document.getElementById('notifyBarkServer').value.trim() || 'https://api.day.app',
      },
      email: {
        enabled: document.getElementById('notifyEmailEnabled').checked,
        smtp_host: document.getElementById('notifyEmailHost').value.trim(),
        smtp_port: parseInt(document.getElementById('notifyEmailPort').value, 10) || 587,
        username: document.getElementById('notifyEmailUser').value.trim(),
        password: document.getElementById('notifyEmailPass').value,
        from_addr: document.getElementById('notifyEmailFrom').value.trim(),
        to_addr: document.getElementById('notifyEmailTo').value.trim(),
        use_tls: document.getElementById('notifyEmailTls').checked,
      },
    },
    history: {
      retention_days: parseInt(document.getElementById('histRetentionDays').value, 10) || 180,
      max_size_mb: parseInt(document.getElementById('histMaxSizeMb').value, 10) || 50,
      auto_cleanup_enabled: document.getElementById('histAutoCleanup').checked,
    },
  };
}

settingsSaveBtn.addEventListener('click', async () => {
  settingsStatus.textContent = '保存中…';
  try {
    const res = await apiFetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildSettingsPayload()),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      settingsStatus.textContent = `保存失败：${err.detail || res.status}`;
      return;
    }
    const savedSettings = await res.json();
    const adRes = await apiFetch('/api/settings/address-discovery', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildAddressDiscoveryPayload()),
    });
    if (!adRes.ok) {
      const err = await adRes.json().catch(() => ({}));
      settingsStatus.textContent = `地址自动发现保存失败：${err.detail || adRes.status}`;
      return;
    }
    renderAddressDiscoveryStatus(await adRes.json());
    // Telegram 配了 bot_token 才会尝试注册命令菜单/webhook，结果通过 _telegram_sync 带回来——
    // 不把这个结果亮出来的话，用户填完 public_base_url 保存后完全不知道是不是真的注册成功了，
    // 只能等到发消息测试时才发现"根本没反应"，再回头猜是哪一步配错了。
    const tgSync = savedSettings._telegram_sync;
    let statusText = '已保存 ✓';
    if (tgSync) {
      if (tgSync.webhook) {
        statusText += '（Telegram 菜单+交互命令已注册成功）';
      } else if (tgSync.commands) {
        statusText += '（Telegram 命令菜单已注册，但没填公网地址，交互命令不会生效）';
      }
    } else if (document.getElementById('notifyTelegramEnabled').checked && document.getElementById('notifyTelegramToken').value.trim()) {
      statusText += '（Telegram 同步失败，可能是 Bot Token 不对或服务器连不上 Telegram，看服务端日志）';
    }
    settingsStatus.textContent = statusText;
    setTimeout(() => { settingsStatus.textContent = ''; }, 5000);
  } catch (e) {
    settingsStatus.textContent = '保存失败，请检查网络';
  }
});

// ---------- 地址自动发现 ----------

function buildAddressDiscoveryPayload() {
  return {
    enabled: document.getElementById('adEnabled').checked,
    url: document.getElementById('adUrl').value.trim(),
    interval_minutes: parseInt(document.getElementById('adInterval').value, 10) || 30,
    group: document.getElementById('adGroup').value.trim(),
    tags: document.getElementById('adTags').value.split(',').map((t) => t.trim()).filter(Boolean),
  };
}

function renderAddressDiscoveryStatus(ad) {
  const box = document.getElementById('adStatus');
  if (!ad || !ad.last_run_at) {
    box.textContent = '还没有运行过。';
    return;
  }
  const icon = { ok: '✅', cf_blocked: '🛡️ 被拦截', error: '❌' }[ad.last_status] || '';
  const foundText = (ad.last_found || []).length ? `（${(ad.last_found || []).join(', ')}）` : '';
  box.innerHTML = `上次运行：${escapeHtml(ad.last_run_at)} ${icon}<br/>${escapeHtml(ad.last_message || '')}${foundText ? '<br/>' + escapeHtml(foundText) : ''}`;
}

document.getElementById('adTestBtn').addEventListener('click', async () => {
  const box = document.getElementById('adStatus');
  const url = document.getElementById('adUrl').value.trim();
  if (!url) {
    box.textContent = '先填一下目标网址。';
    return;
  }
  box.textContent = '测试中…（先保存一下当前配置，再实际发一次请求，最多等 10 秒左右）';
  try {
    const saveRes = await apiFetch('/api/settings/address-discovery', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildAddressDiscoveryPayload()),
    });
    if (!saveRes.ok) {
      const err = await saveRes.json().catch(() => ({}));
      box.textContent = `保存配置失败：${err.detail || saveRes.status}`;
      return;
    }
    const res = await apiFetch('/api/settings/address-discovery/test', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) {
      box.textContent = `测试失败：${data.detail || res.status}`;
      return;
    }
    const icon = { ok: '✅', cf_blocked: '🛡️ 被拦截', error: '❌' }[data.status] || '';
    const foundText = (data.found || []).length ? `<br/>提取到：${escapeHtml(data.found.join(', '))}` : '';
    box.innerHTML = `${icon} ${escapeHtml(data.message || '')}${foundText}`;
  } catch (e) {
    box.textContent = '测试失败，请检查网络';
  }
});

// ---------- 历史趋势数据：文件大小/条数展示 + 按天数删除 ----------

const histStatsText = document.getElementById('histStatsText');

async function refreshHistoryStats() {
  try {
    const res = await apiFetch('/api/history/stats');
    const s = await res.json();
    const sizeKb = (s.size_bytes / 1024).toFixed(1);
    histStatsText.textContent = `共 ${s.count} 条记录，占用 ${sizeKb} KB`;
  } catch (e) {
    histStatsText.textContent = '';
  }
}

async function deleteHistory(mode, days) {
  const label = mode === 'all' ? '全部历史记录' : `${days} 天前的历史记录`;
  if (!confirm(`确定要删除${label}吗？此操作不可撤销。`)) return;
  try {
    await apiFetch('/api/history', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(mode === 'all' ? { mode: 'all' } : { mode: 'days', days }),
    });
    await refreshHistoryStats();
  } catch (e) {
    // apiFetch 已处理鉴权跳转
  }
}

document.getElementById('histDelete30Btn').addEventListener('click', () => deleteHistory('days', 30));
document.getElementById('histDelete60Btn').addEventListener('click', () => deleteHistory('days', 60));
document.getElementById('histDelete180Btn').addEventListener('click', () => deleteHistory('days', 180));
document.getElementById('histDelete365Btn').addEventListener('click', () => deleteHistory('days', 365));
document.getElementById('histDeleteAllBtn').addEventListener('click', () => deleteHistory('all'));

// ---------- 只读分享链接（多 token，各自可命名/设过期时间/单独吊销） ----------

const shareEnabledEl = document.getElementById('shareEnabled');
const shareTokenList = document.getElementById('shareTokenList');

async function refreshShareStatus() {
  try {
    const res = await apiFetch('/api/share/settings');
    const s = await res.json();
    shareEnabledEl.checked = !!s.enabled;
    renderShareTokenList(s.tokens || []);
  } catch (e) {
    // ignore
  }
}

function renderShareTokenList(tokens) {
  if (!tokens.length) {
    shareTokenList.innerHTML = '<p class="results-empty">还没有生成任何分享链接。</p>';
    return;
  }
  shareTokenList.innerHTML = '';
  tokens.forEach((t) => {
    const url = `${window.location.origin}/share.html?token=${t.token}`;
    const row = document.createElement('div');
    row.className = 'share-token-row';
    row.innerHTML = `
      <span class="share-token-row__label">${escapeHtml(t.label || '(未命名)')}</span>
      <input type="text" class="settings-input" readonly value="${escapeHtml(url)}" />
      <span class="panel__hint">${t.expires_at ? '过期于 ' + escapeHtml(t.expires_at.slice(0, 10)) : '永久有效'}</span>
      <button class="btn" data-act="copy">📋 复制</button>
      <button class="btn btn--danger" data-act="revoke">🗑 吊销</button>
    `;
    row.querySelector('[data-act="copy"]').addEventListener('click', () => {
      navigator.clipboard?.writeText(url);
    });
    row.querySelector('[data-act="revoke"]').addEventListener('click', async () => {
      if (!confirm(`确定要吊销"${t.label || '(未命名)'}"这个链接吗？`)) return;
      await apiFetch(`/api/share/tokens/${encodeURIComponent(t.token)}`, { method: 'DELETE' });
      refreshShareStatus();
    });
    shareTokenList.appendChild(row);
  });
}

shareEnabledEl.addEventListener('change', async () => {
  await apiFetch('/api/share/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled: shareEnabledEl.checked }),
  });
  refreshShareStatus();
});

document.getElementById('shareCreateBtn').addEventListener('click', async () => {
  const label = document.getElementById('shareTokenLabel').value.trim();
  const expireDaysRaw = document.getElementById('shareTokenExpireDays').value.trim();
  const expires_days = expireDaysRaw ? parseInt(expireDaysRaw, 10) : null;
  try {
    await apiFetch('/api/share/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, expires_days }),
    });
    document.getElementById('shareTokenLabel').value = '';
    document.getElementById('shareTokenExpireDays').value = '';
    refreshShareStatus();
  } catch (e) {
    // ignore
  }
});

// ---------- 两步验证 (TOTP) ----------

const totpStatusText = document.getElementById('totpStatusText');
const totpSetupBtn = document.getElementById('totpSetupBtn');
const totpDisableBtn = document.getElementById('totpDisableBtn');
const totpSetupPanel = document.getElementById('totpSetupPanel');
const totpSecretText = document.getElementById('totpSecretText');

async function refreshTotpStatus() {
  try {
    const res = await apiFetch('/api/totp/status');
    const s = await res.json();
    totpStatusText.textContent = s.enabled ? '当前状态：已开启' : '当前状态：未开启';
    totpSetupBtn.style.display = s.enabled ? 'none' : '';
    totpDisableBtn.style.display = s.enabled ? '' : 'none';
    if (s.enabled) totpSetupPanel.style.display = 'none';
  } catch (e) {
    // ignore
  }
}

totpSetupBtn.addEventListener('click', async () => {
  try {
    const res = await apiFetch('/api/totp/setup', { method: 'POST' });
    const data = await res.json();
    totpSecretText.value = data.secret;
    totpSetupPanel.style.display = 'flex';
  } catch (e) {
    // ignore
  }
});

document.getElementById('totpConfirmBtn').addEventListener('click', async () => {
  const code = document.getElementById('totpConfirmCode').value.trim();
  if (!code) return;
  try {
    const res = await apiFetch('/api/totp/enable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    if (res.ok) {
      settingsStatus.textContent = '两步验证已开启';
      setTimeout(() => { settingsStatus.textContent = ''; }, 2000);
      refreshTotpStatus();
    } else {
      const err = await res.json().catch(() => ({}));
      settingsStatus.textContent = err.detail || '验证码不正确';
    }
  } catch (e) {
    // ignore
  }
});

totpDisableBtn.addEventListener('click', async () => {
  const password = window.prompt('请输入当前登录密码以确认关闭两步验证：');
  if (!password) return;
  try {
    const res = await apiFetch('/api/totp/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    if (res.ok) {
      refreshTotpStatus();
    } else {
      const err = await res.json().catch(() => ({}));
      settingsStatus.textContent = err.detail || '密码不正确';
    }
  } catch (e) {
    // ignore
  }
});

// ---------- Prometheus 指标 ----------

const metricsEnabledEl = document.getElementById('metricsEnabled');
const metricsUrlText = document.getElementById('metricsUrlText');

async function refreshMetricsStatus() {
  try {
    const res = await apiFetch('/api/metrics/settings');
    const s = await res.json();
    metricsEnabledEl.checked = !!s.enabled;
    metricsUrlText.value = s.enabled && s.has_token ? '已启用（点击"重新生成 token"以查看完整地址）' : '';
  } catch (e) {
    // ignore
  }
}

metricsEnabledEl.addEventListener('change', async () => {
  try {
    const res = await apiFetch('/api/metrics/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: metricsEnabledEl.checked }),
    });
    const data = await res.json();
    metricsUrlText.value = data.token ? `${window.location.origin}/api/metrics?token=${data.token}` : '';
  } catch (e) {
    // ignore
  }
});

document.getElementById('metricsRegenerateBtn').addEventListener('click', async () => {
  if (!confirm('重新生成后，旧的抓取 token 会立即失效，确定继续吗？')) return;
  try {
    const res = await apiFetch('/api/metrics/regenerate', { method: 'POST' });
    const data = await res.json();
    metricsUrlText.value = data.token ? `${window.location.origin}/api/metrics?token=${data.token}` : '';
  } catch (e) {
    // ignore
  }
});

// ---------- 自定义语言性测试用例 ----------

let pendingCustomRules = [];

const customRuleType = document.getElementById('customRuleType');
const customRuleWord = document.getElementById('customRuleWord');
const customRuleWords = document.getElementById('customRuleWords');
const customRuleList = document.getElementById('customRuleList');
const customTestList = document.getElementById('customTestList');

customRuleType.addEventListener('change', () => {
  customRuleWord.style.display = customRuleType.value === 'keyword_count' ? '' : 'none';
  customRuleWords.style.display = customRuleType.value === 'forbidden_words' ? '' : 'none';
});

document.getElementById('customRuleAddBtn').addEventListener('click', () => {
  const type = customRuleType.value;
  const n = parseInt(document.getElementById('customRuleN').value, 10);
  let rule = { type };
  if (type === 'keyword_count') {
    rule.word = customRuleWord.value.trim();
    rule.count = n || 0;
  } else if (type === 'forbidden_words') {
    rule.words = customRuleWords.value.split(',').map((w) => w.trim()).filter(Boolean);
  } else {
    rule.n = n || 0;
  }
  pendingCustomRules.push(rule);
  renderPendingRules();
});

function renderPendingRules() {
  customRuleList.textContent = pendingCustomRules.length
    ? '待保存的规则：' + pendingCustomRules.map((r) => JSON.stringify(r)).join(' | ')
    : '';
}

document.getElementById('customTestSaveBtn').addEventListener('click', async () => {
  const name = document.getElementById('customTestName').value.trim();
  const prompt = document.getElementById('customTestPrompt').value.trim();
  if (!prompt) {
    settingsStatus.textContent = 'prompt 不能为空';
    return;
  }
  try {
    await apiFetch('/api/custom-tests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, prompt, rules: pendingCustomRules }),
    });
    document.getElementById('customTestName').value = '';
    document.getElementById('customTestPrompt').value = '';
    pendingCustomRules = [];
    renderPendingRules();
    refreshCustomTests();
  } catch (e) {
    // ignore
  }
});

async function refreshCustomTests() {
  try {
    const res = await apiFetch('/api/custom-tests');
    const tests = await res.json();
    if (!tests.length) {
      customTestList.innerHTML = '<p class="results-empty">还没有自定义用例。</p>';
      return;
    }
    customTestList.innerHTML = '';
    tests.forEach((t) => {
      const row = document.createElement('div');
      row.className = 'share-token-row';
      row.innerHTML = `
        <span class="share-token-row__label">${escapeHtml(t.name)}</span>
        <span class="panel__hint">${escapeHtml(t.prompt).slice(0, 60)}${t.prompt.length > 60 ? '…' : ''}</span>
        <button class="btn btn--danger" data-act="del">🗑 删除</button>
      `;
      row.querySelector('[data-act="del"]').addEventListener('click', async () => {
        if (!confirm(`确定要删除用例"${t.name}"吗？`)) return;
        await apiFetch(`/api/custom-tests/${encodeURIComponent(t.id)}`, { method: 'DELETE' });
        refreshCustomTests();
      });
      customTestList.appendChild(row);
    });
  } catch (e) {
    // ignore
  }
}

// ---------- 自定义核心测试用例（高风险：需要密码二次确认） ----------

const coreTestList = document.getElementById('coreTestList');

document.getElementById('coreTestSaveBtn').addEventListener('click', async () => {
  const name = document.getElementById('coreTestName').value.trim();
  const prompt = document.getElementById('coreTestPrompt').value.trim();
  const harness = document.getElementById('coreTestHarness').value;
  const password = document.getElementById('coreTestPassword').value;
  if (!prompt || !harness.trim()) {
    settingsStatus.textContent = 'prompt 和 harness 不能为空';
    return;
  }
  if (!password) {
    settingsStatus.textContent = '请输入密码以确认';
    return;
  }
  try {
    const res = await apiFetch('/api/custom-tests/core', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, prompt, harness, password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      settingsStatus.textContent = err.detail || '保存失败，请检查密码是否正确';
      return;
    }
    document.getElementById('coreTestName').value = '';
    document.getElementById('coreTestPrompt').value = '';
    document.getElementById('coreTestHarness').value = '';
    document.getElementById('coreTestPassword').value = '';
    refreshCoreTests();
  } catch (e) {
    // ignore
  }
});

async function refreshCoreTests() {
  try {
    const res = await apiFetch('/api/custom-tests/core');
    const tests = await res.json();
    if (!tests.length) {
      coreTestList.innerHTML = '<p class="results-empty">还没有自定义核心测试用例。</p>';
      return;
    }
    coreTestList.innerHTML = '';
    tests.forEach((t) => {
      const row = document.createElement('div');
      row.className = 'share-token-row';
      row.innerHTML = `
        <span class="share-token-row__label">⚠️ ${escapeHtml(t.name)}</span>
        <span class="panel__hint">${escapeHtml(t.prompt).slice(0, 60)}${t.prompt.length > 60 ? '…' : ''}</span>
        <button class="btn btn--danger" data-act="del">🗑 删除</button>
      `;
      row.querySelector('[data-act="del"]').addEventListener('click', async () => {
        if (!confirm(`确定要删除核心测试用例"${t.name}"吗？`)) return;
        await apiFetch(`/api/custom-tests/core/${encodeURIComponent(t.id)}`, { method: 'DELETE' });
        refreshCoreTests();
      });
      coreTestList.appendChild(row);
    });
  } catch (e) {
    // ignore
  }
}

// ---------- 审计日志导出 ----------

document.getElementById('auditExportBtn').addEventListener('click', async () => {
  try {
    const res = await apiFetch('/api/audit-log/export');
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'audit_log.csv';
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    // ignore
  }
});

notifyTestBtn.addEventListener('click', async () => {
  settingsStatus.textContent = '发送中…';
  try {
    const res = await apiFetch('/api/notify/test', { method: 'POST' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      settingsStatus.textContent = `发送失败：${data.detail || res.status}`;
      return;
    }
    settingsStatus.textContent = `已发送到：${(data.channels || []).join(', ')}`;
  } catch (e) {
    settingsStatus.textContent = '发送失败，请检查网络';
  }
});

// ---------- 归档 ----------

const archiveList = document.getElementById('archiveList');

async function refreshArchives() {
  try {
    const res = await apiFetch('/api/archives');
    const archives = await res.json();
    if (!archives.length) {
      archiveList.innerHTML = '<p class="results-empty">还没有归档。</p>';
      return;
    }
    archiveList.innerHTML = '';
    archives.forEach((a) => {
      const row = document.createElement('div');
      row.className = 'share-token-row';
      row.innerHTML = `
        <span class="share-token-row__label">📦 ${escapeHtml(a.label)}</span>
        <span class="panel__hint">${escapeHtml(a.created_at.slice(0, 10))} · ${a.host_count}台主机 · ${a.model_count}个模型</span>
        <button class="btn" data-act="view">👁 查看</button>
        <button class="btn btn--danger" data-act="del">🗑 删除归档</button>
      `;
      const detailBox = document.createElement('div');
      detailBox.className = 'archive-detail';
      detailBox.hidden = true;
      row.querySelector('[data-act="view"]').addEventListener('click', async () => {
        if (!detailBox.hidden) {
          detailBox.hidden = true;
          return;
        }
        detailBox.hidden = false;
        detailBox.innerHTML = '<p class="results-empty">加载中…</p>';
        try {
          const dres = await apiFetch(`/api/archives/${encodeURIComponent(a.id)}`);
          const detail = await dres.json();
          const hosts = detail.hosts || [];
          detailBox.innerHTML = hosts.length
            ? `<ul class="host-list">${hosts.map((h) => `<li class="host-item"><span class="host-item__main"><span class="host-item__url">${escapeHtml(h.url)}</span></span></li>`).join('')}</ul>`
            : '<p class="results-empty">这个归档里没有主机记录。</p>';
        } catch (e) {
          detailBox.innerHTML = '<p class="results-empty">加载失败。</p>';
        }
      });
      row.querySelector('[data-act="del"]').addEventListener('click', async () => {
        if (!confirm(`确定要彻底删除归档"${a.label}"吗？此操作不可撤销，删除后这些地址也不会再被查重拦截。`)) return;
        await apiFetch(`/api/archives/${encodeURIComponent(a.id)}`, { method: 'DELETE' });
        refreshArchives();
      });
      archiveList.appendChild(row);
      archiveList.appendChild(detailBox);
    });
    renderArchiveCompareUI(archives);
  } catch (e) {
    // ignore
  }
}

// ---------- 归档对比：任选两份归档看差异 ----------

const archiveCompareA = document.getElementById('archiveCompareA');
const archiveCompareB = document.getElementById('archiveCompareB');
const archiveCompareBtn = document.getElementById('archiveCompareBtn');
const archiveCompareResult = document.getElementById('archiveCompareResult');

function renderArchiveCompareUI(archives) {
  if (!archives.length) {
    archiveCompareA.innerHTML = '<option value="">（没有归档）</option>';
    archiveCompareB.innerHTML = '<option value="">（没有归档）</option>';
    return;
  }
  const options = archives
    .map((a) => `<option value="${escapeHtml(a.id)}">${escapeHtml(a.label)}（${escapeHtml(a.created_at.slice(0, 10))}）</option>`)
    .join('');
  archiveCompareA.innerHTML = options;
  archiveCompareB.innerHTML = options;
  // 默认选最新的两份（archives 已经是按创建时间倒序），方便最常见的"比较最近两次"场景一键就能对比
  if (archives.length >= 2) {
    archiveCompareA.value = archives[1].id;
    archiveCompareB.value = archives[0].id;
  }
}

function renderHostStatusChange(item) {
  const labelOf = (s) => ({ ok: '正常', all_down: '模型全挂', unreachable: '不可达' }[s] || s || '（首次出现）');
  return `<li>${escapeHtml(item.host)}：${labelOf(item.from)} → ${labelOf(item.to)}</li>`;
}

function renderViabilityChange(item) {
  const [host, model] = item.key.split('|');
  const arrow = item.to === true ? '恢复 ✅' : item.to === false ? '变差 ❌' : '（首次出现）';
  return `<li>${escapeHtml(model)} @ ${escapeHtml(host)}：${arrow}</li>`;
}

archiveCompareBtn.addEventListener('click', async () => {
  const a = archiveCompareA.value;
  const b = archiveCompareB.value;
  if (!a || !b) {
    archiveCompareResult.innerHTML = '<p class="results-empty">先选两份归档。</p>';
    return;
  }
  if (a === b) {
    archiveCompareResult.innerHTML = '<p class="results-empty">选的是同一份归档，没什么好对比的。</p>';
    return;
  }
  archiveCompareResult.innerHTML = '<p class="results-empty">对比中…</p>';
  try {
    const res = await apiFetch(`/api/archives/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      archiveCompareResult.innerHTML = `<p class="results-empty">对比失败：${escapeHtml(err.detail || res.statusText)}</p>`;
      return;
    }
    const data = await res.json();
    const d = data.diff;
    const sections = [];
    if (d.hosts_added.length) {
      sections.push(`<div><b>新增主机（${d.hosts_added.length}）</b><ul>${d.hosts_added.map((h) => `<li>${escapeHtml(h)}</li>`).join('')}</ul></div>`);
    }
    if (d.hosts_removed.length) {
      sections.push(`<div><b>消失的主机（${d.hosts_removed.length}）</b><ul>${d.hosts_removed.map((h) => `<li>${escapeHtml(h)}</li>`).join('')}</ul></div>`);
    }
    if (d.hosts_status_changed.length) {
      sections.push(`<div><b>主机状态变化（${d.hosts_status_changed.length}）</b><ul>${d.hosts_status_changed.map(renderHostStatusChange).join('')}</ul></div>`);
    }
    if (d.viability_changed.length) {
      sections.push(`<div><b>模型可用性变化（${d.viability_changed.length}）</b><ul>${d.viability_changed.map(renderViabilityChange).join('')}</ul></div>`);
    }
    if (d.models_added.length) {
      sections.push(`<div><b>新出现的模型（${d.models_added.length}）</b><ul>${d.models_added.map((k) => `<li>${escapeHtml(k.replace('|', ' @ '))}</li>`).join('')}</ul></div>`);
    }
    archiveCompareResult.innerHTML = sections.length
      ? `<div class="archive-compare__result">${sections.join('')}</div>`
      : '<p class="results-empty">这两份归档之间没有差异。</p>';
  } catch (e) {
    archiveCompareResult.innerHTML = '<p class="results-empty">对比失败，请重试。</p>';
  }
});

document.getElementById('archiveCreateBtn').addEventListener('click', async () => {
  if (!confirm('确定要归档当前记录吗？归档后当前的主机地址/排行榜/扫描结果会被清空(数据保留在归档里，可以随时查看，不会丢失)。')) return;
  const label = document.getElementById('archiveLabelInput').value.trim();
  try {
    await apiFetch('/api/archives', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label }),
    });
    document.getElementById('archiveLabelInput').value = '';
    await fetchHosts();
    await refreshLeaderboardTable();
    await refreshArchives();
  } catch (e) {
    // ignore
  }
});

// ---------- 模型汇总（含归档） ----------

const modelsAllList = document.getElementById('modelsAllList');
let modelsAllCache = [];
let modelsAllShowArchived = false;

async function refreshModelsAll() {
  try {
    const res = await apiFetch('/api/models/all');
    modelsAllCache = await res.json();
    renderModelsAll();
  } catch (e) {
    // ignore
  }
}

function renderModelsAll() {
  const archivedCount = modelsAllCache.filter((m) => m.source === 'archive').length;
  const showArchivedBtn = document.getElementById('modelsAllShowArchivedBtn');
  showArchivedBtn.style.display = archivedCount ? '' : 'none';
  showArchivedBtn.textContent = modelsAllShowArchived
    ? `📦 隐藏归档中的记录（${archivedCount} 条）`
    : `📦 显示归档中的记录（${archivedCount} 条已隐藏）`;

  const visible = modelsAllShowArchived ? modelsAllCache : modelsAllCache.filter((m) => m.source !== 'archive');

  if (!visible.length) {
    modelsAllList.innerHTML = `<p class="results-empty">${modelsAllCache.length ? '当前工作区暂无记录，点上面按钮查看归档里的。' : '还没有扫描到任何模型。'}</p>`;
    return;
  }
  modelsAllList.innerHTML = '';
  visible.forEach((m) => {
    const row = document.createElement('div');
    row.className = 'lb-row';
    row.dataset.host = m.host;
    row.dataset.model = m.model;
    const okBadge = m.last_known_ok === true ? '🟢' : m.last_known_ok === false ? '🔴' : '⚪';
    row.innerHTML = `
      <span class="lb-row__rank">${okBadge}</span>
      <span class="lb-row__info">
        <div class="lb-row__model">${escapeHtml(m.model)}</div>
        <div class="lb-row__host">@ ${escapeHtml(m.host)} <span class="host-tag">${escapeHtml(m.source_label)}</span></div>
      </span>
      <span class="lb-row__stats" data-role="stats"></span>
    `;
    modelsAllList.appendChild(row);
  });
}

document.getElementById('modelsAllShowArchivedBtn').addEventListener('click', () => {
  modelsAllShowArchived = !modelsAllShowArchived;
  renderModelsAll();
});

document.getElementById('modelsAllRefreshBtn').addEventListener('click', refreshModelsAll);

document.getElementById('modelsAllQuickTestBtn').addEventListener('click', async () => {
  if (!modelsAllCache.length) return;
  try {
    const res = await apiFetch('/api/models/quick-test-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const results = await res.json();
    applyModelTestResults(results, (r) => (r.ok ? `#${r.rank} · ${r.elapsed ?? '?'}s` : '离线'));
  } catch (e) {
    // ignore
  }
});

document.getElementById('modelsAllHeadlessTestBtn').addEventListener('click', async () => {
  const onlineItems = modelsAllCache.filter((m) => m.last_known_ok !== false).map((m) => ({ host: m.host, model: m.model }));
  if (!onlineItems.length) {
    alert('没有已知在线的模型，建议先点一下"一键测试全部在线状态"');
    return;
  }
  try {
    const res = await apiFetch('/api/models/headless-test-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items: onlineItems }),
    });
    const results = await res.json();
    applyModelTestResults(
      results.map((r) => ({ host: r.host, model: r.model, ok: r.supported })),
      (r) => (r.ok ? '🌐 支持无头浏览器' : '🌐 不支持')
    );
  } catch (e) {
    // ignore
  }
});

function applyModelTestResults(results, labelFn) {
  results.forEach((r) => {
    const row = modelsAllList.querySelector(`.lb-row[data-host="${CSS.escape(r.host)}"][data-model="${CSS.escape(r.model)}"]`);
    if (row) row.querySelector('[data-role="stats"]').textContent = labelFn(r);
  });
}

// ---------- Init ----------

async function init() {
  await fetchHosts();
  refreshArchives();
  refreshModelsAll();
  try {
    // 一次性拉取当前状态用于首屏渲染（不是轮询循环，只在页面加载这一刻调用一次）；
    // 之后的所有增量日志/状态变化都交给 WS。
    const res = await apiFetch('/api/scan/status?since=0');
    const data = await res.json();
    appendLogs(data.logs);
    setRunningUI(data.running);
    if (data.results) renderResults(data.results);
  } catch (e) {
    // backend not reachable yet
  }
  wsConnect();
}

init();
