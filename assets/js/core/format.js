/**
 * Formatting helpers: en-GB, 24-hour clock.
 * @module core/format
 */
const dtf = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
const df = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
const tf = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });

const toDate = (iso) => (iso instanceof Date ? iso : iso ? new Date(iso) : null);

/** 1024-based sizes with one decimal: "7.2 GB". */
export function bytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return (n >= 100 ? Math.round(n) : n.toFixed(1).replace(/\.0$/, '')) + ' ' + u[i];
}
export function dateTime(iso) { const d = toDate(iso); return d ? dtf.format(d) : ''; }
export function date(iso) { const d = toDate(iso); return d ? df.format(d) : ''; }
export function time(iso) { const d = toDate(iso); return d ? tf.format(d) : ''; }

/** "just now", "2 min ago", "3 h ago", "Yesterday", or a date. */
export function relative(iso) {
  const d = toDate(iso);
  if (!d) return '';
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 0) return 'in ' + countdown(iso);
  if (s < 45) return 'just now';
  if (s < 3600) return Math.max(1, Math.round(s / 60)) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  if (s < 172800) return 'Yesterday';
  if (s < 7 * 86400) return Math.round(s / 86400) + ' days ago';
  return date(d);
}

/** "Today" | "Yesterday" | "03 Oct 2026" */
export function dayLabel(iso) {
  const d = toDate(iso);
  if (!d) return '';
  const start = new Date(); start.setHours(0, 0, 0, 0);
  const t = d.getTime();
  if (t >= start.getTime()) return 'Today';
  if (t >= start.getTime() - 86400000) return 'Yesterday';
  return date(d);
}

/** Time remaining until iso: "2 d 4 h", "3 h 10 min", "5 min", "Expired". */
export function countdown(iso) {
  const d = toDate(iso);
  if (!d) return '';
  let s = Math.round((d.getTime() - Date.now()) / 1000);
  if (s <= 0) return 'Expired';
  const days = Math.floor(s / 86400); s -= days * 86400;
  const hrs = Math.floor(s / 3600); s -= hrs * 3600;
  const mins = Math.max(1, Math.floor(s / 60));
  if (days > 0) return days + ' d ' + hrs + ' h';
  if (hrs > 0) return hrs + ' h ' + mins + ' min';
  return mins + ' min';
}

export function percent(part, whole) {
  if (!whole) return 0;
  return Math.min(100, Math.max(0, Math.round((part / whole) * 1000) / 10));
}

const KINDS = {
  image: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'avif', 'heic', 'ico'],
  video: ['mp4', 'webm', 'mov', 'avi', 'mkv', 'm4v', 'ogv'],
  audio: ['mp3', 'wav', 'aac', 'flac', 'm4a', 'opus', 'ogg', 'oga'],
  pdf: ['pdf'],
  document: ['doc', 'docx', 'odt', 'rtf'],
  spreadsheet: ['xls', 'xlsx', 'ods', 'csv'],
  presentation: ['ppt', 'pptx', 'odp', 'key'],
  code: ['php', 'js', 'mjs', 'ts', 'tsx', 'jsx', 'py', 'java', 'c', 'h', 'cpp', 'hpp', 'cs', 'go', 'rs', 'rb', 'sh', 'bash', 'css', 'scss', 'html', 'htm', 'json', 'xml', 'yaml', 'yml', 'sql', 'kt', 'swift'],
  text: ['txt', 'md', 'markdown', 'log', 'ini', 'conf'],
  archive: ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'tgz'],
};
export function kindOf(ext, mime = '') {
  ext = String(ext || '').toLowerCase();
  for (const [k, list] of Object.entries(KINDS)) if (list.includes(ext)) return k;
  if (mime.startsWith('image/')) return 'image';
  if (mime.startsWith('video/')) return 'video';
  if (mime.startsWith('audio/')) return 'audio';
  if (mime.startsWith('text/')) return 'text';
  return 'other';
}
export { kindIconName as kindIcon } from './icons.js';

export function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

/** File extension of a name, lower-case, without the dot. */
export function extOf(name) {
  const i = String(name).lastIndexOf('.');
  return i > 0 ? String(name).slice(i + 1).toLowerCase() : '';
}
