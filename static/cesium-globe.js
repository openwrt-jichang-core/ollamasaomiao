/*
 * Cesium 离线 3D 地球——作为原有 Canvas2D 手绘地球（globeCanvas）的可选替代视图。
 *
 * 前置条件（我这边不能帮你做，见 README 里"离线瓦片获取方式"一节）：
 *   1. 把 Cesium 引擎本体放到 static/vendor/cesium/（Cesium.js + Widgets/widgets.css）
 *   2. 把 Z1~Z7 的离线瓦片金字塔放到 static/tiles/{z}/{x}/{y}.png
 *
 * 这个文件只做"点位可视化"这一件事：初始化离线 Viewer、渲染国家聚合点、
 * flyTo、以及 requestRenderMode 下的手动重绘。不重新实现原来 globe.js 里
 * 的 tooltip/悬停高亮/国家详情弹层这些交互——那些逻辑量大，需要单独一轮
 * 把交互层从 Canvas2D 迁移过来，这里先把地图渲染这个地基打对。
 */

let cesiumViewer = null;
let cesiumEntitiesByCountry = new Map();

function statusColorFor(cluster) {
  // 和现有图例语义对齐：ok_count 覆盖 host_count 记全绿，0 记全红，介于中间记黄
  if (cluster.host_count === 0) return Cesium.Color.GRAY;
  if (cluster.ok_count >= cluster.host_count) return Cesium.Color.fromCssColorString('#3ddc84');
  if (cluster.ok_count === 0) return Cesium.Color.fromCssColorString('#ff5566');
  return Cesium.Color.fromCssColorString('#ffcc4d');
}

function initCesiumGlobe(containerId) {
  if (cesiumViewer) return cesiumViewer;

  // 关键：不使用 Cesium Ion 云服务，纯离线运行。
  // 不设置 Ion.defaultAccessToken（保持空），并且不使用任何 IonImageryProvider/IonTerrainProvider。
  Cesium.Ion.defaultAccessToken = '';

  cesiumViewer = new Cesium.Viewer(containerId, {
    imageryProvider: new Cesium.UrlTemplateImageryProvider({
      url: 'tiles/{z}/{x}/{y}.png',
      minimumLevel: 1,
      maximumLevel: 7,
      credit: '', // 离线自建瓦片，没有第三方版权信息要展示
    }),
    baseLayerPicker: false,   // 默认会枚举一堆 Ion 图层选项，离线环境下全是死链
    geocoder: false,          // 默认调地理编码服务，离线环境下会一直报错
    homeButton: false,
    sceneModePicker: false,
    navigationHelpButton: false,
    animation: false,
    timeline: false,
    fullscreenButton: false,
    infoBox: false,
    selectionIndicator: false,
    requestRenderMode: true,          // 静止时不循环渲染，省 GPU/电量
    maximumRenderTimeChange: Infinity, // 配合上面：只在我们显式 requestRender() 时才画
  });

  cesiumViewer.scene.globe.showGroundAtmosphere = false;
  cesiumViewer.scene.skyAtmosphere.show = false;
  cesiumViewer.creditDisplay.container.style.display = 'none';

  cesiumViewer.scene.requestRender();
  return cesiumViewer;
}

/** 用国家聚合数据（buildCountryClusters() 的输出）刷新地图上的点位。 */
function renderCesiumClusters(clusters) {
  if (!cesiumViewer) return;
  const seen = new Set();

  clusters.forEach((c) => {
    if (c.lat == null || c.lon == null) return;
    seen.add(c.country);
    const color = statusColorFor(c);
    let entity = cesiumEntitiesByCountry.get(c.country);
    if (!entity) {
      entity = cesiumViewer.entities.add({
        id: `country:${c.country}`,
        position: Cesium.Cartesian3.fromDegrees(c.lon, c.lat),
        point: {
          pixelSize: 10,
          color,
          outlineColor: Cesium.Color.WHITE,
          outlineWidth: 1,
          disableDepthTestDistance: Number.POSITIVE_INFINITY,
        },
        label: {
          text: `${c.country} (${c.host_count})`,
          font: '12px "IBM Plex Mono"',
          pixelOffset: new Cesium.Cartesian2(0, -16),
          fillColor: Cesium.Color.WHITE,
          showBackground: true,
          backgroundColor: Cesium.Color.fromCssColorString('#000000aa'),
        },
      });
      cesiumEntitiesByCountry.set(c.country, entity);
    } else {
      // 数据变了但相机没动：requestRenderMode 下这类"数据驱动"的更新
      // 不会自动触发重绘，必须在改完属性之后手动调 requestRender()。
      entity.point.color = color;
      entity.label.text = `${c.country} (${c.host_count})`;
    }
  });

  // 清理掉这一轮数据里已经不存在的国家点位
  for (const [country, entity] of cesiumEntitiesByCountry) {
    if (!seen.has(country)) {
      cesiumViewer.entities.remove(entity);
      cesiumEntitiesByCountry.delete(country);
    }
  }

  cesiumViewer.scene.requestRender(); // 关键的手动重绘触发
}

/** 平滑飞到某个国家聚合点，飞行动画期间给容器加 class 降级毛玻璃模糊。 */
function flyToCountry(country) {
  if (!cesiumViewer) return;
  const entity = cesiumEntitiesByCountry.get(country);
  if (!entity) return;

  // 项目里现有的毛玻璃面板类名是 .hud-panel / .hud-topbar（见 globe.css），
  // 不是通用的 .glass-panel，这里直接选实际存在的两个类。
  const panels = document.querySelectorAll('.hud-panel, .hud-topbar');
  panels.forEach((p) => p.classList.add('glass-panel--flying'));

  cesiumViewer.camera.flyTo({
    destination: Cesium.Cartesian3.fromDegrees(
      Cesium.Cartographic.fromCartesian(entity.position.getValue(cesiumViewer.clock.currentTime)).longitude * 180 / Math.PI,
      Cesium.Cartographic.fromCartesian(entity.position.getValue(cesiumViewer.clock.currentTime)).latitude * 180 / Math.PI,
      2000000
    ),
    duration: 1.2,
    complete: () => {
      panels.forEach((p) => p.classList.remove('glass-panel--flying'));
      cesiumViewer.scene.requestRender(); // flyTo 结束后再催一帧，避免停在半路的残影
    },
  });
}
