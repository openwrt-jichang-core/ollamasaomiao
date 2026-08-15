// 视图切换：不改动原有 globe.js 的任何逻辑，只是显隐两套 DOM，
// 首次切到 Cesium 视图时才真正初始化引擎（避免没用到时也占用 GPU/内存）。
//
// 这段逻辑原来是写在 globe.html 里的内联 <script>，被 CSP 的
// script-src 'self' 挡住了从未真正执行过——按钮点了没反应，
// 不是 Cesium 没装好，是这段代码压根没跑。挪成独立文件才能通过 CSP。
document.getElementById('cesiumToggleBtn')?.addEventListener('click', () => {
  const canvas = document.getElementById('globeCanvas');
  const cesiumEl = document.getElementById('cesiumGlobe');
  const btn = document.getElementById('cesiumToggleBtn');
  const showingCesium = !cesiumEl.hidden;
  if (showingCesium) {
    cesiumEl.hidden = true;
    canvas.hidden = false;
    btn.textContent = '🛰 Cesium 3D 视图';
  } else {
    canvas.hidden = true;
    cesiumEl.hidden = false;
    btn.textContent = '🗺 经典 2D 视图';
    try {
      initCesiumGlobe('cesiumGlobe');
      if (typeof countryClusters !== 'undefined') {
        renderCesiumClusters(countryClusters);
      }
    } catch (e) {
      alert('Cesium 引擎或离线瓦片没有就位，请先按 README 里「离线瓦片获取方式」放好文件。\n\n' + e.message);
      cesiumEl.hidden = true;
      canvas.hidden = false;
      btn.textContent = '🛰 Cesium 3D 视图';
    }
  }
});
