// ---------- 基础: 鉴权请求封装 ----------

async function apiFetch(url, options) {
  const res = await fetch(url, options);
  if (res.status === 401) {
    window.location.href = '/login.html';
    throw new Error('unauthenticated');
  }
  return res;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

// ---------- 时钟 ----------

const hudClock = document.getElementById('hudClock');
function tickClock() {
  hudClock.textContent = new Date().toLocaleTimeString('zh-CN', { hour12: false });
}
tickClock();
setInterval(tickClock, 1000);

// =========================================================================
// 主机管理（含失败区）
// =========================================================================

let allHostsCache = [];

function isHostFailed(h) {
  return h.last_scan_status === 'unreachable' || h.last_scan_status === 'all_down';
}

async function fetchHosts() {
  try {
    const res = await apiFetch('/api/hosts');
    allHostsCache = await res.json();
    renderHosts();
  } catch (e) {
    // ignore
  }
}

function renderHosts() {
  const normal = allHostsCache.filter((h) => !isHostFailed(h));
  const failed = allHostsCache.filter((h) => isHostFailed(h));

  document.getElementById('hudHostCount').textContent = `${normal.length} 正常`;
  const hostList = document.getElementById('hudHostList');
  hostList.innerHTML = normal.length ? '' : '<p class="hud-list-empty">还没有添加主机地址。</p>';
  normal.forEach((h) => hostList.appendChild(buildHudHostItem(h)));

  const failedZone = document.getElementById('hudFailedZone');
  const failedList = document.getElementById('hudFailedList');
  failedZone.hidden = failed.length === 0;
  failedList.innerHTML = '';
  failed.forEach((h) => failedList.appendChild(buildHudHostItem(h)));
}

function buildHudHostItem(h) {
  const div = document.createElement('div');
  const failed = isHostFailed(h);
  div.className = 'hud-list-item';
  if (failed) div.style.borderColor = 'rgba(255,75,75,0.5)';
  const statusText = h.last_scan_status === 'unreachable' ? '⛔ 不可达'
    : h.last_scan_status === 'all_down' ? '⛔ 全部模型不通'
    : h.enabled === false ? '（已禁用）' : '';
  div.innerHTML = `
    <div>${escapeHtml(h.url)} ${statusText}</div>
    <div class="hud-list-item__sub">
      ${h.group ? `📁 ${escapeHtml(h.group)} ` : ''}${(h.tags || []).join(', ')}
    </div>
    <div class="hud-row" style="margin-top:6px;">
      <button class="hud-btn" data-act="toggle" style="flex:1;">${h.enabled === false ? '启用' : '禁用'}</button>
      <button class="hud-btn hud-btn--danger" data-act="remove" style="flex:1;">删除</button>
    </div>
  `;
  div.querySelector('[data-act="toggle"]').addEventListener('click', () => patchHost(h.url, { enabled: h.enabled === false }));
  div.querySelector('[data-act="remove"]').addEventListener('click', () => removeHost(h.url));
  return div;
}

// ---------- 批量粘贴 ----------

const hudBatchToggle = document.getElementById('hudBatchToggle');
const hudBatchPanel = document.getElementById('hudBatchPanel');
const hudBatchInput = document.getElementById('hudBatchInput');
const hudBatchParseBtn = document.getElementById('hudBatchParseBtn');
const hudBatchCancelBtn = document.getElementById('hudBatchCancelBtn');
const hudBatchPreview = document.getElementById('hudBatchPreview');

hudBatchToggle.addEventListener('click', () => {
  const showing = !hudBatchPanel.hidden;
  hudBatchPanel.hidden = showing;
  if (!showing) hudBatchInput.focus();
});
hudBatchCancelBtn.addEventListener('click', () => {
  hudBatchPanel.hidden = true;
  hudBatchInput.value = '';
  hudBatchPreview.innerHTML = '';
});

// Matches ip[:port], with or without a leading http(s)://
const HUD_IP_PORT_RE = /(?:https?:\/\/)?(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?/g;
const HUD_DEFAULT_PORT = '11434';

function hudIsPrivateIp(ip) {
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

function hudParseAddresses(text) {
  const seen = new Set();
  const results = [];
  let match;
  HUD_IP_PORT_RE.lastIndex = 0;
  while ((match = HUD_IP_PORT_RE.exec(text)) !== null) {
    const ip = match[1];
    const port = match[2] || HUD_DEFAULT_PORT;
    const url = `http://${ip}:${port}`;
    if (seen.has(url)) continue;
    seen.add(url);
    results.push({ url, ip, private: hudIsPrivateIp(ip) });
  }
  return results;
}

hudBatchParseBtn.addEventListener('click', async () => {
  const parsed = hudParseAddresses(hudBatchInput.value);
  if (!parsed.length) {
    hudBatchPreview.innerHTML = '<li>没有识别到任何 ip:port 地址。</li>';
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
  hudBatchPreview.innerHTML = toAdd
    .map((p) => `<li><span class="${p.private ? 'tag-private' : 'tag-public'}">${p.private ? '内网' : '公网'}</span> ${escapeHtml(p.url)}</li>`)
    .join('');

  const group = document.getElementById('hudHostGroup').value.trim();
  const tags = document.getElementById('hudHostTags').value.split(',').map((t) => t.trim()).filter(Boolean);

  for (const p of toAdd) {
    await addHost(p.url, group, tags, false);
  }

  if (toAdd.length) {
    hudBatchInput.value = '';
  }
});

document.getElementById('hudHostForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = document.getElementById('hudHostUrl').value.trim();
  if (!url) return;
  const group = document.getElementById('hudHostGroup').value.trim();
  const tags = document.getElementById('hudHostTags').value.split(',').map((t) => t.trim()).filter(Boolean);
  await addHost(url, group, tags, false);
});

async function addHost(url, group, tags, force) {
  try {
    const res = await apiFetch('/api/hosts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, group, tags, force: !!force }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      const detail = err.detail;
      if (detail && typeof detail === 'object' && (detail.code === 'unreachable' || detail.code === 'already_archived')) {
        if (window.confirm(`${detail.message}\n\n仍然要添加这个地址吗？`)) {
          return addHost(url, group, tags, true);
        }
        return;
      }
      alert((detail && detail.message) || detail || '添加失败');
      return;
    }
    document.getElementById('hudHostForm').reset();
    allHostsCache = await res.json();
    renderHosts();
  } catch (e) {
    // ignore
  }
}

async function patchHost(url, changes) {
  try {
    const res = await apiFetch('/api/hosts', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, ...changes }),
    });
    allHostsCache = await res.json();
    renderHosts();
  } catch (e) {
    // ignore
  }
}

async function removeHost(url) {
  if (!confirm(`确定要删除 ${url} 吗？`)) return;
  try {
    const res = await apiFetch('/api/hosts', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    allHostsCache = await res.json();
    renderHosts();
  } catch (e) {
    // ignore
  }
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
    renderHosts();
  } catch (e) {
    // ignore
  }
}

document.getElementById('hudHostEnableAllBtn').addEventListener('click', () => bulkToggleHosts(true, 'normal'));
document.getElementById('hudHostDisableAllBtn').addEventListener('click', () => bulkToggleHosts(false, 'normal'));
document.getElementById('hudFailedEnableAllBtn').addEventListener('click', () => bulkToggleHosts(true, 'failed'));
document.getElementById('hudFailedDisableAllBtn').addEventListener('click', () => bulkToggleHosts(false, 'failed'));

document.getElementById('hudFailedDeleteAllBtn').addEventListener('click', async () => {
  if (!confirm('确定要一键删除"失败区"里的全部链接吗？此操作不可撤销。')) return;
  try {
    const res = await apiFetch('/api/hosts/failed', { method: 'DELETE' });
    const data = await res.json();
    allHostsCache = data.hosts;
    renderHosts();
  } catch (e) {
    // ignore
  }
});

// =========================================================================
// 扫描控制台：6种测试开关(绿=开红=关) + 开始/停止 + 实时日志
// =========================================================================

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

// 刷新页面时，把按钮的绿/红显示同步成上次保存的选择，而不是每次都变回默认全关
document.querySelectorAll('.hud-toggle[data-toggle]').forEach((btn) => {
  const key = btn.dataset.toggle;
  if (key === 'core' || key === 'control' || key === 'language' || key === 'headless') {
    btn.dataset.on = String(scanToggleState[key]);
  }
});

function syncMasterToggle() {
  const allOn = scanToggleState.core && scanToggleState.control && scanToggleState.language && scanToggleState.headless;
  document.querySelector('[data-toggle="all"]').dataset.on = String(allOn);
}

document.querySelectorAll('.hud-toggle[data-toggle]').forEach((btn) => {
  const key = btn.dataset.toggle;
  if (key === 'quick') {
    // 快速在线测试不是一个"可选功能"，而是扫描流水线本身的第一步：
    // 后端必须先知道每个模型是否可用(可用性测试)，才能决定要不要继续跑后面的
    // 核心/控制性/语言性/无头浏览器测试。关掉它 = 整个扫描没法进行，所以这里
    // 不做成可关闭的开关，但点击时给出解释，而不是让它看起来像个卡死的按钮。
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
        document.querySelector(`[data-toggle="${k}"]`).dataset.on = String(turnOn);
      });
      btn.dataset.on = String(turnOn);
      saveScanToggleState();
      return;
    }
    scanToggleState[key] = !scanToggleState[key];
    btn.dataset.on = String(scanToggleState[key]);
    syncMasterToggle();
    saveScanToggleState();
  });
});
syncMasterToggle(); // 页面加载时，根据恢复出来的4个开关状态，同步"全部功能测试"主开关的颜色

let scanPollTimer = null;
let lastLogSeq = 0;
let wasRunning = false;

function setScanRunningUI(running) {
  document.getElementById('hudStartBtn').disabled = running;
  document.getElementById('hudStopBtn').disabled = !running;
  document.getElementById('hudScanStatus').textContent = running ? '扫描中…' : '待机';
}

function appendHudLogs(logs) {
  if (!logs || !logs.length) return;
  const box = document.getElementById('hudLog');
  logs.forEach((l) => {
    lastLogSeq += 1;
    const line = document.createElement('div');
    line.textContent = typeof l === 'string' ? l : JSON.stringify(l);
    box.appendChild(line);
  });
  box.scrollTop = box.scrollHeight;
}

document.getElementById('hudStartBtn').addEventListener('click', async () => {
  const anyDeepTestOn = scanToggleState.core || scanToggleState.control || scanToggleState.language || scanToggleState.headless;
  if (!anyDeepTestOn) {
    const ok = confirm('当前 3/4/5/6 测试开关都是关闭(红)状态，本次只会跑"快速在线测试"。\n\n确定要这样开始吗？');
    if (!ok) return;
  }
  const concurrency = parseInt(document.getElementById('hudConcurrency').value, 10) || 3;
  const model_concurrency = parseInt(document.getElementById('hudModelConcurrency').value, 10) || 4;
  try {
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
      alert(err.detail || '启动失败');
      return;
    }
    setScanRunningUI(true);
    pollScan();
  } catch (e) {
    // ignore
  }
});

document.getElementById('hudStopBtn').addEventListener('click', async () => {
  try {
    await apiFetch('/api/scan/stop', { method: 'POST' });
  } catch (e) {
    // ignore
  }
});

async function pollScan() {
  clearTimeout(scanPollTimer);
  try {
    const res = await apiFetch(`/api/scan/status?since=${lastLogSeq}`);
    const data = await res.json();
    appendHudLogs(data.logs);
    setScanRunningUI(data.running);
    if (!data.running && wasRunning) {
      refreshAllData();
    }
    wasRunning = data.running;
    if (data.running) scanPollTimer = setTimeout(pollScan, 1200);
  } catch (e) {
    scanPollTimer = setTimeout(pollScan, 2000);
  }
}

// =========================================================================
// 6个排行榜 + 每行6个测试按钮
// =========================================================================

const CATEGORY_CARD_MAP = { core: 'lbCardCore', control: 'lbCardControl', language: 'lbCardLanguage', headless: 'lbCardHeadless' };
const CATEGORY_LABEL_CN = { core: '核心', control: '控制性', language: '语言性', headless: '无头浏览器' };

function buildRowActionsHtml(host, model) {
  const modes = [
    ['all', '1全部'], ['quick', '2快速'], ['core', '3核心'],
    ['control', '4控制'], ['language', '5语言'], ['headless', '6🌐'],
  ];
  return `<div class="hud-row-actions">${modes.map(([m, label]) =>
    `<button data-mode="${m}" data-host="${escapeHtml(host)}" data-model="${escapeHtml(model)}">${label}</button>`
  ).join('')}</div><div class="hud-row-result" data-role="result"></div>`;
}

function wireRowActions(container) {
  container.querySelectorAll('.hud-row-actions button').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const { mode, host, model } = btn.dataset;
      const resultEl = btn.closest('.hud-list-item')?.querySelector('[data-role="result"]');
      if (resultEl) resultEl.textContent = '测试中…';
      try {
        const res = await apiFetch('/api/models/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host, model, mode }),
        });
        const data = await res.json();
        if (resultEl) resultEl.textContent = formatTestResult(mode, data);
        if (mode !== 'quick' && mode !== 'headless') refreshAllLeaderboards();
      } catch (e) {
        if (resultEl) resultEl.textContent = '请求失败';
      }
    });
  });
}

function formatTestResult(mode, data) {
  if (mode === 'quick') return data.ok ? `⚡ 在线 (${data.elapsed ?? '?'}s)` : `⚡ 离线: ${data.error || ''}`;
  if (mode === 'headless') return data.supported ? '🌐 支持无头浏览器' : '🌐 不支持';
  if (data.error) return `❌ ${data.error}`;
  const cats = data.categories || {};
  return Object.entries(cats).map(([c, v]) => `${CATEGORY_LABEL_CN[c] || c}:${v.status === 'pass' ? '✅' : '❌'}(${v.passed}/${v.total})`).join(' ');
}

function renderDeepCard(lbData) {
  const box = document.getElementById('lbCardDeep');
  const rows = [];
  const seen = new Set();
  Object.entries(lbData || {}).forEach(([cat, catData]) => {
    (catData.ranked || []).concat(catData.failed || []).forEach((r) => {
      const key = `${r.host}|${r.model}`;
      if (seen.has(key)) return;
      seen.add(key);
      rows.push(r);
    });
  });
  if (!rows.length) {
    box.innerHTML = '<p class="hud-list-empty">还没有深度测试结果。</p>';
    return;
  }
  box.innerHTML = rows.map((r) => `
    <div class="hud-list-item">
      <div>${escapeHtml(r.model)}</div>
      <div class="hud-list-item__sub">@ ${escapeHtml(r.host)}${r.family_hint ? ' · ' + escapeHtml(r.family_hint) : ''}</div>
      ${buildRowActionsHtml(r.host, r.model)}
    </div>
  `).join('');
  wireRowActions(box);
}

function renderQuickCard(quickData) {
  const box = document.getElementById('lbCardQuick');
  const rows = (quickData.ranked || []).concat(quickData.failed || []);
  if (!rows.length) {
    box.innerHTML = '<p class="hud-list-empty">还没有快速测试结果。</p>';
    return;
  }
  box.innerHTML = rows.map((r) => `
    <div class="hud-list-item">
      <div>${r.ok ? '🟢' : '🔴'} ${escapeHtml(r.model)} ${r.ok ? `· #${r.rank} · ${r.elapsed ?? '?'}s` : ''}</div>
      <div class="hud-list-item__sub">@ ${escapeHtml(r.host)}</div>
      ${buildRowActionsHtml(r.host, r.model)}
    </div>
  `).join('');
  wireRowActions(box);
}

function renderCategoryCard(category, catData) {
  const box = document.getElementById(CATEGORY_CARD_MAP[category]);
  if (!box) return;
  const rows = (catData.ranked || []).concat(catData.failed || []);
  if (!rows.length) {
    box.innerHTML = `<p class="hud-list-empty">还没有${CATEGORY_LABEL_CN[category]}测试结果。</p>`;
    return;
  }
  box.innerHTML = rows.map((r) => `
    <div class="hud-list-item">
      <div>${r.status === 'pass' || r.rank ? '✅' : '❌'} ${escapeHtml(r.model)} ${r.rank ? `· #${r.rank} · ${r.elapsed_total ?? '?'}s` : ''}</div>
      <div class="hud-list-item__sub">@ ${escapeHtml(r.host)}</div>
      ${buildRowActionsHtml(r.host, r.model)}
    </div>
  `).join('');
  wireRowActions(box);
}

async function refreshAllLeaderboards() {
  try {
    const [deepRes, quickRes] = await Promise.all([
      apiFetch('/api/leaderboard'),
      apiFetch('/api/leaderboard/quick'),
    ]);
    const deepData = await deepRes.json();
    const quickData = await quickRes.json();
    renderDeepCard(deepData);
    renderQuickCard(quickData);
    ['core', 'control', 'language', 'headless'].forEach((cat) => {
      renderCategoryCard(cat, deepData[cat] || { ranked: [], failed: [] });
    });
  } catch (e) {
    // ignore
  }
}

// =========================================================================
// 地球
// =========================================================================

const canvas = document.getElementById('globeCanvas');
const ctx = canvas.getContext('2d');
const tooltip = document.getElementById('hudTooltip');

let W = 0, H = 0, cx = 0, cy = 0, R = 0;
let rotY = 0.4;
let autoRotate = true;
let dragging = false;
let dragStartX = 0, dragStartRotY = 0;
const TILT_X = 0.42;

let globeData = { points: [], unlocated: [] };
let countryClusters = [];
let company = { name: '', address: '', lat: null, lon: null };
let hoveredCluster = null;

function resizeCanvas() {
  const rect = canvas.parentElement.getBoundingClientRect();
  W = canvas.width = rect.width;
  H = canvas.height = rect.height;
  cx = W / 2;
  cy = H / 2;
  R = Math.min(W, H) * 0.36;
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

// 简化版世界大陆轮廓（经度,纬度），用于在指挥中心地球上画出可辨认的陆地形状。
// 精度是示意性的（低多边形风格，服务于 HUD 视觉效果），不是精确海岸线数据。
const LAND_POLYGONS = [
  // 北美洲（含中美地峡，不含格陵兰）
  [[-168,65.5],[-165,60],[-155,58],[-135,58],[-130,55],[-125,49],[-124,42],[-124,36],[-117,32],
   [-115,29],[-106,23],[-97,16],[-92,15],[-90,14],[-85,10.5],[-83,9],[-79,8.5],[-77,7.5],[-77,9],
   [-83,9.5],[-86,13],[-90,16],[-94,18],[-97,20],[-97,26],[-94,29],[-89,29],[-85,30],[-81,25],
   [-80,26],[-80.5,28],[-81,31],[-78,34],[-75,36],[-74,40],[-70,41],[-67,45],[-64,45],[-60,46],
   [-55,51],[-56,53],[-62,56],[-65,60],[-68,63],[-64,64],[-60,60],[-65,68],[-75,62],[-80,62],
   [-85,67],[-90,68],[-95,69],[-100,70],[-110,70],[-120,70],[-130,70],[-140,70],[-150,70],
   [-156,71],[-163,68],[-166,68]],
  // 格陵兰
  [[-73,60],[-58,60],[-45,61],[-42,65],[-22,70],[-20,75],[-25,79],[-40,82],[-55,82],[-65,80],
   [-70,76],[-73,70]],
  // 南美洲
  [[-77,7],[-80,-5],[-81,-15],[-75,-18],[-71,-18],[-70,-23],[-68,-27],[-70,-33],[-73,-40],
   [-74,-46],[-72,-52],[-68,-54],[-65,-55],[-68,-52],[-62,-50],[-58,-42],[-57,-35],[-58,-33],
   [-54,-25],[-48,-25],[-40,-15],[-35,-8],[-38,-5],[-45,-2],[-50,0],[-51,2],[-55,5],[-60,8],
   [-65,10],[-70,11],[-73,9]],
  // 非洲
  [[-17,15],[-16,12],[-13,8],[-10,5],[-9,5],[-5,4],[3,5],[8,4],[9,2],[9,-2],[12,-5],[12,-6],
   [13,-10],[13,-15],[12,-17],[13,-22],[15,-27],[18,-30],[20,-34],[25,-33.5],[27,-31],[32,-29],
   [32,-26],[35,-24],[40,-25],[44,-24],[44,-14],[40,-7],[42,0],[45,5],[51,10],[49,12],[45,11],
   [42,11],[42,15],[38,18],[35,21],[35,27],[32,31],[25,31.5],[25,32],[20,31],[10,33],[8,37],
   [3,37],[-1,35],[-5,35],[-6,33],[-8,32],[-9,30],[-15,27],[-17,21]],
  // 马达加斯加
  [[43,-12],[45,-16],[47,-20],[47,-25],[45,-25],[43,-21],[43,-16]],
  // 欧洲主体
  [[-9,36],[-9,43],[-1,43],[3,43],[7,44],[10,44],[13,45],[14,46],[19,45],[20,40],[23,38],
   [24,35],[27,37],[29,41],[30,46],[28,46],[26,50],[24,54],[20,54],[18,54],[14,54],[12,54],
   [8,53],[5,51],[3,51],[-1,49],[-5,48],[-9,43.5]],
  // 斯堪的纳维亚
  [[5,58],[8,58],[11,59],[11,63],[14,66],[16,68],[20,69],[25,70],[29,69],[30,65],[28,61],
   [24,60],[20,59],[18,57],[13,55],[10,57]],
  // 不列颠群岛
  [[-8,51],[-6,53],[-5,55],[-3,58],[-1,58],[0,53],[-1,51],[-5,50]],
  // 亚洲大陆
  [[27,41],[30,46],[35,50],[45,50],[55,51],[60,55],[65,55],[70,58],[75,60],[80,65],[90,68],
   [100,70],[110,72],[120,73],[130,72],[140,70],[143,62],[140,55],[135,52],[130,46],[127,40],
   [126,37],[124,40],[122,38],[121,31],[119,26],[110,20],[108,16],[106,10],[103,5],[101,3],
   [100,6],[98,8],[95,15],[92,20],[89,22],[88,22],[80,7],[77,8],[73,15],[70,21],[68,24],
   [66,25],[61,25],[58,27],[56,27],[52,30],[48,30],[47,29],[44,29],[42,29],[36,32],[36,36],
   [35,36],[33,36],[29,36],[26,35],[27,37]],
  // 日本列岛
  [[130,31],[132,33],[135,34],[137,35],[140,36],[141,39],[141,41],[144,43],[142,45],[140,43],
   [139,40],[137,37],[135,35],[133,34],[131,32]],
  // 东南亚岛屿（印尼/菲律宾示意）
  [[95,5],[100,6],[104,1],[110,-3],[113,-8],[119,-9],[122,-8],[121,-2],[117,1],[112,3],
   [108,2],[104,6],[98,8]],
  // 澳大利亚
  [[113,-22],[114,-26],[115,-32],[118,-34],[122,-34],[126,-32],[129,-32],[132,-32],[136,-35],
   [138,-35],[140,-38],[144,-38],[147,-38],[150,-37],[153,-28],[153,-25],[150,-23],[147,-19],
   [145,-16],[143,-12],[141,-11],[136,-12],[132,-12],[130,-12],[128,-14],[125,-15],[122,-18],
   [119,-20],[115,-20]],
  // 塔斯马尼亚
  [[146,-41],[148,-41],[148,-43],[146,-43]],
  // 新西兰
  [[173,-41],[175,-37],[178,-38],[178,-40],[175,-41.5]],
  // 南极洲（示意冰盖轮廓）
  [[-180,-65],[-150,-66],[-120,-65],[-90,-70],[-60,-68],[-30,-70],[0,-68],[30,-67],[60,-66],
   [90,-66],[120,-65],[150,-66],[180,-65],[180,-90],[-180,-90]],
];

// ip-api.com 返回的是英文国家名，这里映射成中文简称给地球上的标签用；
// 覆盖不到的国家会自动退回显示 country_code（两位字母缩写），再退回英文名前几个字符。
const COUNTRY_NAME_CN = {
  'United States': '美国', 'China': '中国', 'Japan': '日本', 'South Korea': '韩国',
  'Korea, Republic of': '韩国', 'Hong Kong': '中国香港', 'Macao': '中国澳门', 'Macau': '中国澳门',
  'Taiwan': '中国台湾', 'Singapore': '新加坡', 'India': '印度', 'Indonesia': '印度尼西亚',
  'Malaysia': '马来西亚', 'Thailand': '泰国', 'Vietnam': '越南', 'Philippines': '菲律宾',
  'United Kingdom': '英国', 'Germany': '德国', 'France': '法国', 'Netherlands': '荷兰',
  'Belgium': '比利时', 'Switzerland': '瑞士', 'Sweden': '瑞典', 'Norway': '挪威',
  'Denmark': '丹麦', 'Finland': '芬兰', 'Ireland': '爱尔兰', 'Poland': '波兰',
  'Austria': '奥地利', 'Italy': '意大利', 'Spain': '西班牙', 'Portugal': '葡萄牙',
  'Russia': '俄罗斯', 'Ukraine': '乌克兰', 'Turkey': '土耳其', 'Greece': '希腊',
  'Czechia': '捷克', 'Czech Republic': '捷克', 'Romania': '罗马尼亚', 'Hungary': '匈牙利',
  'Canada': '加拿大', 'Mexico': '墨西哥', 'Brazil': '巴西', 'Argentina': '阿根廷',
  'Chile': '智利', 'Colombia': '哥伦比亚', 'Australia': '澳大利亚', 'New Zealand': '新西兰',
  'South Africa': '南非', 'Egypt': '埃及', 'Israel': '以色列', 'United Arab Emirates': '阿联酋',
  'Saudi Arabia': '沙特阿拉伯', 'Iran': '伊朗', 'Pakistan': '巴基斯坦', 'Bangladesh': '孟加拉国',
  'Iceland': '冰岛', 'Luxembourg': '卢森堡', 'Bulgaria': '保加利亚', 'Croatia': '克罗地亚',
  'Slovakia': '斯洛伐克', 'Slovenia': '斯洛文尼亚', 'Serbia': '塞尔维亚', 'Lithuania': '立陶宛',
  'Latvia': '拉脱维亚', 'Estonia': '爱沙尼亚', 'Cyprus': '塞浦路斯', 'Malta': '马耳他',
  'Moldova': '摩尔多瓦', 'Belarus': '白俄罗斯', 'Kazakhstan': '哈萨克斯坦', 'Mongolia': '蒙古',
  'Nigeria': '尼日利亚', 'Kenya': '肯尼亚', 'Morocco': '摩洛哥', 'Algeria': '阿尔及利亚',
  'Peru': '秘鲁', 'Venezuela': '委内瑞拉', 'Ecuador': '厄瓜多尔', 'Panama': '巴拿马',
  'Cuba': '古巴', 'Seychelles': '塞舌尔', 'Cambodia': '柬埔寨', 'Laos': '老挝',
  'Myanmar': '缅甸', 'Sri Lanka': '斯里兰卡', 'Nepal': '尼泊尔',
};

function countryLabel(name, code) {
  if (COUNTRY_NAME_CN[name]) return COUNTRY_NAME_CN[name];
  if (code) return code;
  if (!name) return '?';
  return name.length > 8 ? name.slice(0, 8) : name;
}

function project(lat, lon) {
  const latR = (lat * Math.PI) / 180;
  const lonR = (lon * Math.PI) / 180;
  let x = Math.cos(latR) * Math.sin(lonR);
  let y = Math.sin(latR);
  let z = Math.cos(latR) * Math.cos(lonR);

  const x1 = x * Math.cos(rotY) + z * Math.sin(rotY);
  const z1 = -x * Math.sin(rotY) + z * Math.cos(rotY);
  const y1 = y;

  const y2 = y1 * Math.cos(TILT_X) - z1 * Math.sin(TILT_X);
  const z2 = y1 * Math.sin(TILT_X) + z1 * Math.cos(TILT_X);
  const x2 = x1;

  return { sx: cx + x2 * R, sy: cy - y2 * R, front: z2 > -0.05, z: z2 };
}

function drawSphereBase() {
  // 浅色玻璃拟态主题下的地球本体：淡蓝紫渐变球体，配合半透明白高光，
  // 呼应页面背景的蓝紫粉渐变，不再是深色 HUD 那套暗色调。
  const grad = ctx.createRadialGradient(cx - R * 0.3, cy - R * 0.3, R * 0.1, cx, cy, R);
  grad.addColorStop(0, '#EAF0FF');
  grad.addColorStop(0.55, '#C9D6FA');
  grad.addColorStop(1, '#9FB0EE');
  ctx.beginPath();
  ctx.arc(cx, cy, R, 0, Math.PI * 2);
  ctx.fillStyle = grad;
  ctx.fill();
  ctx.strokeStyle = 'rgba(122,92,250,0.35)';
  ctx.lineWidth = 1;
  ctx.stroke();
}

// 沿着一串经纬度点画路径，只保留正面(朝向我们的这半球)的线段，
// 背面的点会打断路径（不再画穿透地球背面的线），这样地球才像一个
// 实心球体，而不是一个能看到背面网格的线框球。
function pathFrontOnly(points, close) {
  let started = false;
  let first = null;
  points.forEach((p, i) => {
    if (p.front) {
      if (!started) { ctx.moveTo(p.sx, p.sy); started = true; if (i === 0) first = p; }
      else ctx.lineTo(p.sx, p.sy);
    } else {
      started = false;
    }
  });
  if (close && first && points[points.length - 1].front) ctx.closePath();
}

function drawGraticule() {
  ctx.strokeStyle = 'rgba(122,92,250,0.16)';
  ctx.lineWidth = 1;
  for (let lon = -180; lon < 180; lon += 30) {
    const pts = [];
    for (let lat = -90; lat <= 90; lat += 6) pts.push(project(lat, lon));
    ctx.beginPath();
    pathFrontOnly(pts, false);
    ctx.stroke();
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const pts = [];
    for (let lon = -180; lon <= 180; lon += 6) pts.push(project(lat, lon));
    ctx.beginPath();
    pathFrontOnly(pts, false);
    ctx.stroke();
  }
}

// 画世界大陆轮廓（只画朝向我们的这半球，背面部分自然不画，随地球旋转露出）。
function drawLandmasses() {
  LAND_POLYGONS.forEach((poly) => {
    const pts = poly.map(([lon, lat]) => project(lat, lon));
    const frontCount = pts.filter((p) => p.front).length;
    if (frontCount < 3) return; // 这块陆地此刻整体在背面，不画
    ctx.beginPath();
    pathFrontOnly(pts, true);
    // 和 globe.css 里的 --hud-land / --hud-land-line 对应的蓝紫色调
    // （注：Canvas2D 的 fillStyle 不支持 var()，这里必须写字面量颜色值，
    // 和 CSS 变量保持同步靠人工对齐，不是引用同一份数据）
    ctx.fillStyle = 'rgba(43,108,255,0.28)';
    ctx.fill('nonzero');
    ctx.strokeStyle = 'rgba(122,92,250,0.5)';
    ctx.lineWidth = 1;
    ctx.stroke();
  });
}

function statusColor(cluster) {
  // 和 globe.css 里的 --hud-red / --hud-green / --hud-amber 保持同一套配色
  if (cluster.ok_count === 0) return '#E23D74';
  if (cluster.ok_count >= cluster.model_count) return '#17B685';
  return '#B45BD1';
}

function drawArc(from, to, color) {
  if (!from.front || !to.front) return;
  const mx = (from.sx + to.sx) / 2;
  const my = (from.sy + to.sy) / 2;
  const dx = mx - cx, dy = my - cy;
  const dist = Math.sqrt(dx * dx + dy * dy) || 1;
  const lift = 0.18 + Math.min(0.25, Math.hypot(from.sx - to.sx, from.sy - to.sy) / (R * 6));
  const ctrlX = mx + (dx / dist) * R * lift;
  const ctrlY = my + (dy / dist) * R * lift;
  ctx.beginPath();
  ctx.moveTo(from.sx, from.sy);
  ctx.quadraticCurveTo(ctrlX, ctrlY, to.sx, to.sy);
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.2;
  ctx.globalAlpha = 0.55;
  ctx.stroke();
  ctx.globalAlpha = 1;
}

function drawMarker(p, radius, color, glow) {
  if (!p.front) return;
  if (glow) {
    ctx.beginPath();
    ctx.arc(p.sx, p.sy, radius * 2.4, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.globalAlpha = 0.14;
    ctx.fill();
    ctx.globalAlpha = 1;
  }
  ctx.beginPath();
  ctx.arc(p.sx, p.sy, radius, 0, Math.PI * 2);
  ctx.fillStyle = color;
  ctx.fill();
  ctx.strokeStyle = 'rgba(255,255,255,0.5)';
  ctx.lineWidth = 1;
  ctx.stroke();
}

function render() {
  ctx.clearRect(0, 0, W, H);
  drawSphereBase();
  drawLandmasses();
  drawGraticule();

  const hasCompany = company.lat != null && company.lon != null;
  const companyProj = hasCompany ? project(company.lat, company.lon) : null;

  if (companyProj) {
    countryClusters.forEach((c) => {
      const p = project(c.lat, c.lon);
      drawArc(companyProj, p, statusColor(c));
    });
  }

  countryClusters.forEach((c) => {
    const p = project(c.lat, c.lon);
    c._proj = p;
    const radius = 3.5 + Math.min(9, Math.sqrt(c.host_count) * 2.2);
    drawMarker(p, radius, statusColor(c), c === hoveredCluster);
    if (p.front) {
      const label = countryLabel(c.country, c.country_code) + (c.estimated_count > 0 ? '*' : '');
      ctx.font = "600 11px 'IBM Plex Mono', ui-monospace, monospace";
      ctx.textBaseline = 'middle';
      ctx.lineWidth = 3;
      ctx.strokeStyle = 'rgba(255,255,255,0.85)';
      ctx.strokeText(label, p.sx + radius + 4, p.sy);
      ctx.fillStyle = c === hoveredCluster ? '#2B6CFF' : '#1B1F3B';
      ctx.fillText(label, p.sx + radius + 4, p.sy);
    }
  });

  if (companyProj && companyProj.front) {
    const pulse = 1 + 0.25 * Math.sin(Date.now() / 400);
    drawMarker(companyProj, 5 * pulse, '#F0A63C', true);
  }

  if (autoRotate && !dragging) rotY += 0.0018;
  requestAnimationFrame(render);
}
requestAnimationFrame(render);

canvas.addEventListener('mousedown', (e) => {
  dragging = true;
  autoRotate = false;
  dragStartX = e.clientX;
  dragStartRotY = rotY;
});
window.addEventListener('mouseup', () => {
  if (dragging) {
    dragging = false;
    setTimeout(() => { autoRotate = true; }, 2500);
  }
});
window.addEventListener('mousemove', (e) => {
  if (dragging) {
    rotY = dragStartRotY + (e.clientX - dragStartX) * 0.005;
    return;
  }
  handleHover(e);
});

function handleHover(e) {
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  let hit = null;
  for (const c of countryClusters) {
    if (!c._proj || !c._proj.front) continue;
    const d = Math.hypot(c._proj.sx - mx, c._proj.sy - my);
    if (d < 14) { hit = c; break; }
  }
  hoveredCluster = hit;
  if (hit) {
    tooltip.hidden = false;
    tooltip.style.left = `${mx + 16}px`;
    tooltip.style.top = `${my + 8}px`;
    const estimatedNote = hit.estimated_count > 0
      ? `<br/><span style="color:var(--hud-amber);">*其中 ${hit.estimated_count} 条是内网地址，用本服务器出口IP估算位置，非精确坐标</span>`
      : '';
    tooltip.innerHTML = `<b>${escapeHtml(hit.country)}</b><br/>${hit.host_count} 条链接 · ${hit.model_count} 个模型（${hit.ok_count} 在线）${estimatedNote}`;
    canvas.style.cursor = 'pointer';
  } else {
    tooltip.hidden = true;
    canvas.style.cursor = 'grab';
  }
}

canvas.addEventListener('click', () => {
  if (hoveredCluster) openCountryDetail(hoveredCluster.country);
});

function buildCountryClusters(points) {
  const byCountry = {};
  points.forEach((p) => {
    if (!p.located || p.lat == null || p.lon == null) return;
    const key = p.country || '未知';
    if (!byCountry[key]) byCountry[key] = { country: key, country_code: p.country_code || '', lat: 0, lon: 0, host_count: 0, model_count: 0, ok_count: 0, estimated_count: 0, _n: 0 };
    const c = byCountry[key];
    c.lat += p.lat; c.lon += p.lon; c._n += 1;
    c.host_count += 1;
    c.model_count += p.model_count;
    c.ok_count += p.ok_count;
    if (p.location_is_estimated) c.estimated_count += 1;
  });
  return Object.values(byCountry).map((c) => ({ ...c, lat: c.lat / c._n, lon: c.lon / c._n }));
}

let companyFieldsInitialized = false;

async function loadGlobeData() {
  // 地球点位数据 和 公司锚点数据 是两个独立接口，拆开各自 try/catch，互不连累。
  let pointsOk = false;
  try {
    const pointsRes = await apiFetch('/api/globe/points');
    if (!pointsRes.ok) {
      console.error('/api/globe/points 返回了非 200 状态', pointsRes.status);
    } else {
      const data = await pointsRes.json();
      // 正常响应一定有 points/unlocated 这两个数组字段；不是这个形状说明后端出错了
      // （比如返回了 {"detail": "..."} 这种错误体），不能当成正常数据往下用。
      if (Array.isArray(data.points) && Array.isArray(data.unlocated)) {
        globeData = data;
        pointsOk = true;
      } else {
        console.error('/api/globe/points 返回的数据格式不对', data);
      }
    }
  } catch (e) {
    console.error('加载地球点位数据失败', e);
  }

  try {
    const companyRes = await apiFetch('/api/globe/company');
    if (companyRes.ok) {
      company = await companyRes.json();
      // 公司锚点输入框只在页面第一次加载时用服务器数据填一次；不要在之后每 6 秒的
      // 定时轮询里反复覆盖它——不然用户刚填到一半、还没点"保存锚点"，服务器上还是
      // 旧值（通常是空的），几秒后轮询一来就会把用户正在打的字给冲掉，看起来像是
      // "输入后过几秒自动清空"。保存成功后表单里本来就是用户刚输入的值，也不需要
      // 再从服务器同步回填。
      if (!companyFieldsInitialized) {
        document.getElementById('companyName').value = company.name || '';
        document.getElementById('companyAddress').value = company.address || '';
        document.getElementById('companyLat').value = company.lat ?? '';
        document.getElementById('companyLon').value = company.lon ?? '';
        companyFieldsInitialized = true;
      }
    } else {
      console.error('/api/globe/company 返回了非 200 状态', companyRes.status);
    }
  } catch (e) {
    console.error('加载公司锚点数据失败', e);
  }

  if (pointsOk) {
    try {
      countryClusters = buildCountryClusters(globeData.points);
      renderSummary();
      renderUnlocatedList();
      // Cesium 视图当前可见时，数据轮询刷新也要同步过去；
      // 不可见（未初始化/在用经典 2D 视图）时跳过，避免无谓的实体更新开销。
      const cesiumEl = document.getElementById('cesiumGlobe');
      if (cesiumEl && !cesiumEl.hidden && typeof renderCesiumClusters === 'function') {
        renderCesiumClusters(countryClusters);
      }
    } catch (e) {
      console.error('渲染地球数据失败', e);
    }
  }
}

function renderSummary() {
  const totalModels = globeData.points.reduce((s, p) => s + p.model_count, 0) + globeData.unlocated.reduce((s, p) => s + p.model_count, 0);
  document.getElementById('sumCountries').textContent = countryClusters.length;
  document.getElementById('sumPoints').textContent = globeData.points.length;
  document.getElementById('sumUnlocated').textContent = globeData.unlocated.length;
  document.getElementById('sumModels').textContent = totalModels;
}

function renderUnlocatedList() {
  const box = document.getElementById('hudUnlocatedList');
  if (!globeData.unlocated.length) {
    box.innerHTML = '<p class="hud-list-empty">没有内网/未定位的主机。</p>';
    return;
  }
  box.innerHTML = globeData.unlocated.map((p) => `
    <div class="hud-list-item">
      ${escapeHtml(p.domain_or_ip)}:${p.port ?? '-'}
      <div class="hud-list-item__sub">${p.model_count} 个模型 · ${p.ok_count} 在线</div>
    </div>
  `).join('');
}

document.getElementById('companySaveBtn').addEventListener('click', async () => {
  const name = document.getElementById('companyName').value.trim();
  const address = document.getElementById('companyAddress').value.trim();
  const latRaw = document.getElementById('companyLat').value;
  const lonRaw = document.getElementById('companyLon').value;
  const lat = latRaw === '' ? null : parseFloat(latRaw);
  const lon = lonRaw === '' ? null : parseFloat(lonRaw);
  try {
    const res = await apiFetch('/api/globe/company', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, address, lat, lon }),
    });
    company = await res.json();
  } catch (e) {
    // ignore
  }
});

// ---------- 国家详情弹窗 ----------

let currentCountryModels = [];

async function openCountryDetail(country) {
  document.getElementById('hudDetailTitle').textContent = `📍 ${country}`;
  document.getElementById('hudCountryModalOverlay').hidden = false;
  const modelsBox = document.getElementById('hudDetailModels');
  modelsBox.innerHTML = '<p class="hud-list-empty">加载中…</p>';
  try {
    const res = await apiFetch(`/api/globe/country/${encodeURIComponent(country)}`);
    const data = await res.json();
    currentCountryModels = data.models || [];
    renderCountryModels();
  } catch (e) {
    modelsBox.innerHTML = '<p class="hud-list-empty">加载失败。</p>';
  }
}

function renderCountryModels() {
  const modelsBox = document.getElementById('hudDetailModels');
  if (!currentCountryModels.length) {
    modelsBox.innerHTML = '<p class="hud-list-empty">这个国家/地区下没有已知模型。</p>';
    return;
  }
  modelsBox.innerHTML = currentCountryModels.map((m) => `
    <div class="hud-list-item">
      <div>${m.ok === true ? '🟢' : m.ok === false ? '🔴' : '⚪'} ${escapeHtml(m.model)}</div>
      <div class="hud-list-item__sub">@ ${escapeHtml(m.host)} ${m.city ? '· ' + escapeHtml(m.city) : ''}</div>
      ${buildRowActionsHtml(m.host, m.model)}
    </div>
  `).join('');
  wireRowActions(modelsBox);
}

document.getElementById('hudModalCloseBtn').addEventListener('click', () => {
  document.getElementById('hudCountryModalOverlay').hidden = true;
});
document.getElementById('hudCountryModalOverlay').addEventListener('click', (e) => {
  if (e.target.id === 'hudCountryModalOverlay') e.target.hidden = true;
});

document.getElementById('hudDetailQuickBtn').addEventListener('click', async () => {
  if (!currentCountryModels.length) return;
  try {
    const res = await apiFetch('/api/models/quick-test-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items: currentCountryModels.map((m) => ({ host: m.host, model: m.model })) }),
    });
    await res.json();
    openCountryDetail(document.getElementById('hudDetailTitle').textContent.replace('📍 ', ''));
  } catch (e) {
    // ignore
  }
});

document.getElementById('hudDetailHeadlessBtn').addEventListener('click', async () => {
  const onlineItems = currentCountryModels.filter((m) => m.ok !== false).map((m) => ({ host: m.host, model: m.model }));
  if (!onlineItems.length) {
    alert('这个国家/地区下没有已知在线的模型，建议先点"测在线"');
    return;
  }
  try {
    await apiFetch('/api/models/headless-test-batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items: onlineItems }),
    });
    alert('无头浏览器测试完成，可以在下方各排行榜/主机列表查看最新结果。');
  } catch (e) {
    // ignore
  }
});

// =========================================================================
// 设置 / 定时任务弹窗
// =========================================================================

document.getElementById('hudSettingsBtn').addEventListener('click', async () => {
  document.getElementById('hudSettingsModalOverlay').hidden = false;
  try {
    const res = await apiFetch('/api/settings');
    const s = await res.json();
    document.getElementById('hudSchedEnabled').checked = !!s.schedule.enabled;
    document.getElementById('hudSchedTime').value = s.schedule.time || '09:00';
    document.getElementById('hudSchedConcurrency').value = s.schedule.concurrency ?? 3;
    document.getElementById('hudSchedModelConcurrency').value = s.schedule.model_concurrency ?? 4;
    ['core', 'control', 'language', 'headless'].forEach((k) => {
      const btn = document.querySelector(`[data-sched-toggle="${k}"]`);
      const val = s.schedule[`enable_${k}`];
      btn.dataset.on = String(val !== undefined ? val : (k === 'headless' ? false : true));
    });
    window.__hudFullSettings = s;
  } catch (e) {
    // ignore
  }
});

document.getElementById('hudSettingsModalCloseBtn').addEventListener('click', () => {
  document.getElementById('hudSettingsModalOverlay').hidden = true;
});
document.getElementById('hudSettingsModalOverlay').addEventListener('click', (e) => {
  if (e.target.id === 'hudSettingsModalOverlay') e.target.hidden = true;
});

document.querySelectorAll('[data-sched-toggle]').forEach((btn) => {
  btn.addEventListener('click', () => {
    btn.dataset.on = String(btn.dataset.on !== 'true');
  });
});

document.getElementById('hudSchedSaveBtn').addEventListener('click', async () => {
  const base = window.__hudFullSettings || { notify: {}, history: {} };
  const schedule = {
    enabled: document.getElementById('hudSchedEnabled').checked,
    time: document.getElementById('hudSchedTime').value || '09:00',
    concurrency: parseInt(document.getElementById('hudSchedConcurrency').value, 10) || 3,
    model_concurrency: parseInt(document.getElementById('hudSchedModelConcurrency').value, 10) || 4,
    enable_core: document.querySelector('[data-sched-toggle="core"]').dataset.on === 'true',
    enable_control: document.querySelector('[data-sched-toggle="control"]').dataset.on === 'true',
    enable_language: document.querySelector('[data-sched-toggle="language"]').dataset.on === 'true',
    enable_headless: document.querySelector('[data-sched-toggle="headless"]').dataset.on === 'true',
  };
  try {
    await apiFetch('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ schedule, notify: base.notify, history: base.history }),
    });
    document.getElementById('hudSettingsModalOverlay').hidden = true;
  } catch (e) {
    // ignore
  }
});

// =========================================================================
// 统一刷新 + 实时轮询（不需要手动刷新）
// =========================================================================

async function refreshAllData() {
  await Promise.all([fetchHosts(), loadGlobeData(), refreshAllLeaderboards()]);
}

async function init() {
  await refreshAllData();
  try {
    const res = await apiFetch('/api/scan/status?since=0');
    const data = await res.json();
    lastLogSeq = 0;
    appendHudLogs(data.logs);
    setScanRunningUI(data.running);
    wasRunning = data.running;
    if (data.running) pollScan();
  } catch (e) {
    console.error('加载扫描状态/日志失败', e);
  }
  setInterval(refreshAllData, 6000);
}

init();
