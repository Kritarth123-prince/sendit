/**
 * QR codes rendered locally (qrcode-generator from cdnjs, version-pinned with Subresource
 * Integrity via lib-loader) — the URL is never sent to a third-party QR service.
 * @module features/qr
 */
import { loadLib } from './lib-loader.js';

const lib = () => loadLib('qrcode');

function draw(qrcode, text, size) {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount();
  const quiet = 4;
  const scale = Math.max(2, Math.floor(size / (n + quiet * 2)));
  const px = (n + quiet * 2) * scale;
  const c = document.createElement('canvas');
  c.width = c.height = px;
  const g = c.getContext('2d');
  g.fillStyle = '#ffffff'; g.fillRect(0, 0, px, px);
  g.fillStyle = '#000000';
  for (let r = 0; r < n; r++) for (let col = 0; col < n; col++) if (qr.isDark(r, col)) g.fillRect((col + quiet) * scale, (r + quiet) * scale, scale, scale);
  return c;
}

/** Render a QR code canvas into container. */
export async function renderQr(container, text, { size = 220 } = {}) {
  const q = await lib();
  const c = draw(q, text, size);
  c.setAttribute('role', 'img');
  c.setAttribute('aria-label', 'QR code');
  c.style.maxWidth = '100%';
  container.replaceChildren(c);
  return c;
}

/** PNG data URL for downloading. */
export async function qrPngDataUrl(text, size = 512) {
  const q = await lib();
  return draw(q, text, size).toDataURL('image/png');
}
