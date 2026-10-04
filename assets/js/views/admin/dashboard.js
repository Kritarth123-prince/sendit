/** Admin dashboard: live counters and 30-day charts (Chart.js from cdnjs, pinned with SRI). */
import { api } from '../../core/api.js';
import { h, icon, clear, debounce } from '../../core/dom.js';
import { bus } from '../../core/bus.js';
import { bytes } from '../../core/format.js';
import { errorState, skeleton } from '../../core/ui.js';
import { loadLib } from '../../features/lib-loader.js';

let offs = [], charts = [];
const loadChart = () => loadLib('chart');

export default {
  title: 'Admin',
  async mount(el) {
    const kpis = h('div.kpis');
    const chartsEl = h('div.grid-cards', { style: { gridTemplateColumns: 'repeat(auto-fill,minmax(340px,1fr))' } });
    el.append(h('div.view-head', h('div.grow', h('h1.view-title', { text: 'Admin dashboard' }), h('div.view-sub', { text: 'Updates live as people use FastTransfer.' }))), kpis, h('div.section-gap', chartsEl));
    const tile = (label, value) => h('div.kpi', h('div.kpi-value', { text: String(value) }), h('div.kpi-label', { text: label }));
    async function loadStats() {
      try {
        const { data: s } = await api.get('/admin/stats');
        clear(kpis).append(
          tile('Users', s.users_total), tile('Active users', s.users_active), tile('Disabled users', (s.users_disabled || 0) + (s.users_suspended || 0)),
          tile('Files', s.files_total), tile('Storage used', bytes(s.storage_used_bytes)), tile('Storage available', s.storage_available_bytes ? bytes(s.storage_available_bytes) : '—'),
          tile('Uploads today', s.uploads_today), tile('Downloads today', s.downloads_today), tile('Shares created today', s.shares_created_today ?? 0),
          tile('Active shares', s.shares_active), tile('Expired shares', s.shares_expired), tile('Trash', bytes(s.trash_bytes)),
          tile('Version storage', bytes(s.version_bytes)), tile('Failed uploads today', s.failed_uploads_today ?? 0), tile('Saved by deduplication', bytes(s.dedup_saved_bytes || 0)));
      } catch (e) { clear(kpis).append(errorState(e, loadStats)); }
    }
    let chartData = null;
    async function loadCharts() {
      clear(chartsEl).append(skeleton(2));
      try {
        const [{ data }, Chart] = await Promise.all([api.get('/admin/stats/charts', { days: 30 }), loadChart()]);
        chartData = data;
        drawCharts(Chart);
      } catch (e) { clear(chartsEl).append(errorState(e, loadCharts)); }
    }
    /** Charts take their colours from the active palette and theme (CSS tokens), so they are redrawn when either changes. */
    function drawCharts(Chart) {
      const data = chartData;
      if (!data || !Chart) return;
      charts.forEach((c) => c.destroy()); charts = [];
      clear(chartsEl);
      const css = getComputedStyle(document.documentElement);
      const token = (name, fallback) => css.getPropertyValue(name).trim() || fallback;
      const text = token('--text2', '#b0aca3');
      const grid = token('--border', 'rgba(255,255,255,.08)');
      const accent = token('--accent', '#d6b37a');
      const accent2 = token('--accent2', '#f1dba8');
      const tint = 'rgba(' + token('--accent-rgb', '214,179,122') + ',.15)';
      const base = { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: text } } }, scales: { x: { ticks: { color: text }, grid: { color: grid } }, y: { ticks: { color: text }, grid: { color: grid }, beginAtZero: true } } };
      const card = (title, cfg) => { const c = h('canvas', { 'aria-label': title, role: 'img' }); chartsEl.append(h('div.card', h('div.card-title', { text: title }), h('div', { style: { height: '240px' } }, c))); charts.push(new Chart(c, cfg)); };
      const s = data.series || {};
      const labels = Object.keys(s.uploads || s.downloads || {}).map((d) => d.slice(5));
      const vals = (k) => Object.values(s[k] || {});
      card('Storage over time', { type: 'line', data: { labels, datasets: [{ label: 'Storage (MB)', data: vals('storage_bytes').map((v) => Math.round(v / 1048576)), borderColor: accent, backgroundColor: tint, fill: true, tension: .3 }] }, options: base });
      card('Uploads and downloads', { type: 'bar', data: { labels, datasets: [{ label: 'Uploads', data: vals('uploads'), backgroundColor: '#34d399' }, { label: 'Downloads', data: vals('downloads'), backgroundColor: accent }] }, options: base });
      card('New users', { type: 'line', data: { labels, datasets: [{ label: 'New users', data: vals('new_users'), borderColor: '#60a5fa', tension: .3 }] }, options: base });
      const kinds = data.kinds || [];
      card('File types', { type: 'doughnut', data: { labels: kinds.map((k) => k.kind), datasets: [{ data: kinds.map((k) => k.count), borderColor: token('--bg2', '#131317'), backgroundColor: [accent, '#34d399', '#60a5fa', '#f87171', accent2, '#fbbf24', '#fb923c', '#94a3b8', '#f472b6', '#2dd4bf', '#64748b'] }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: text } } } } });
      const top = data.top_downloads || [];
      chartsEl.append(h('div.card', h('div.card-title', { text: 'Most downloaded files' }), top.length ? h('div.list', ...top.map((f) => h('div.list-item', icon('download', 16), h('div.li-main', h('div.li-title.ellipsis', { text: f.name }), h('div.li-sub', { text: (f.owner?.display_name || '') })), h('strong', { text: String(f.download_count) })))) : h('p.text2', { text: 'No downloads yet.' })));
    }
    const recolour = () => { if (chartData) loadChart().then(drawCharts).catch(() => {}); };
    const refresh = debounce(() => { loadStats(); }, 1500);
    offs = ['user.created', 'user.updated', 'user.deleted', 'file.created', 'file.deleted', 'file.purged', 'share.created', 'share.revoked', 'stats.updated', 'upload.failed'].map((t) => bus.on(t, refresh));
    offs.push(bus.on('ui:accent', recolour), bus.on('ui:theme', recolour));
    loadStats(); loadCharts();
  },
  unmount() { offs.forEach((o) => o()); charts.forEach((c) => c.destroy()); charts = []; },
};
