if (window.localStorage.getItem('ollama-scanner-theme') === 'light') {
  document.documentElement.setAttribute('data-theme', 'light');
}

function getShareToken() {
  const params = new URLSearchParams(window.location.search);
  return params.get('token') || '';
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str == null ? '' : String(str);
  return div.innerHTML;
}

const CATEGORY_LABELS = {
  core: '核心测试',
  control: '控制性 (Agent工具调用)',
  language: '语言性',
};

let shareActiveCategory = 'core';
let shareLastData = null;

const shareRanked = document.getElementById('shareRanked');
const shareFailed = document.getElementById('shareFailed');
const shareRankedTitle = document.getElementById('shareRankedTitle');
const shareTabs = document.querySelectorAll('.lb-tab');

shareTabs.forEach((tab) => {
  tab.addEventListener('click', () => {
    shareActiveCategory = tab.dataset.cat;
    shareTabs.forEach((t) => t.classList.toggle('is-active', t === tab));
    renderShareCategory();
  });
});

function renderShareCategory() {
  if (!shareLastData) return;
  const catData = shareLastData[shareActiveCategory] || { label: '', ranked: [], failed: [] };
  shareRankedTitle.textContent = `排行榜（${catData.label || CATEGORY_LABELS[shareActiveCategory] || ''} · 全部通过）`;
  renderShareTable(shareRanked, catData.ranked, true);
  renderShareTable(shareFailed, catData.failed, false);
}

function renderShareTable(container, entries, ranked) {
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
      : `${entry.status || ''}`;
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

async function loadShareData() {
  const token = getShareToken();
  if (!token) {
    shareRanked.innerHTML = '<p class="results-empty">链接缺少访问凭证，请检查完整链接是否被截断。</p>';
    shareFailed.innerHTML = '';
    return;
  }
  try {
    const res = await fetch(`/api/public/leaderboard/${encodeURIComponent(token)}`);
    if (!res.ok) {
      shareRanked.innerHTML = '<p class="results-empty">链接无效或分享功能未开启，请联系分享者获取新链接。</p>';
      shareFailed.innerHTML = '';
      return;
    }
    shareLastData = await res.json();
    renderShareCategory();
  } catch (e) {
    shareRanked.innerHTML = '<p class="results-empty">加载失败，请检查网络后刷新重试。</p>';
  }
}

loadShareData();
