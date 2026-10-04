/**
 * Lazy loader for the few third-party libraries the app uses (pdf.js, highlight.js,
 * qrcode-generator, Chart.js), served from cdnjs only. The CSP allows script-src for exactly these
 * version folders (app/Support/Csp.php CDN_SCRIPTS — keep the two lists in step; checked by
 * tests/js/csp.test.mjs). Each script is pinned to an exact version and protected with
 * Subresource Integrity, so a tampered CDN file never runs.
 * @module features/lib-loader
 */

const CDN = 'https://cdnjs.cloudflare.com/ajax/libs/';

export const LIBS = {
  pdfjs: {
    src: CDN + 'pdf.js/3.11.174/pdf.min.js',
    integrity: 'sha384-/1qUCSGwTur9vjf/z9lmu/eCUYbpOTgSjmpbMQZ1/CtX2v/WcAIKqRv+U1DUCG6e',
    global: 'pdfjsLib',
    what: 'The viewer',
    // The worker is started from a blob: wrapper that importScripts() this URL (worker-src blob:).
    worker: CDN + 'pdf.js/3.11.174/pdf.worker.min.js',
  },
  hljs: {
    src: CDN + 'highlight.js/11.9.0/highlight.min.js',
    integrity: 'sha384-F/bZzf7p3Joyp5psL90p/p89AZJsndkSoGwRpXcZhleCWhd8SnRuoYo4d0yirjJp',
    global: 'hljs',
    what: 'The viewer',
  },
  qrcode: {
    src: CDN + 'qrcode-generator/1.4.4/qrcode.min.js',
    integrity: 'sha384-mZT2gIty7ZDdOGkxfP6joZcYdMW1Jvj9dRlfpTmaJAKKXTqzygtB22k7FLe+KZC1',
    global: 'qrcode',
    what: 'The QR code generator',
  },
  chart: {
    src: CDN + 'Chart.js/4.4.1/chart.umd.min.js',
    integrity: 'sha384-bs/nf9FbdNouRbMiFcrcZfLXYPKiPaGVGplVbv7dLGECccEXDW+S3zjqSKR5ZEaD',
    global: 'Chart',
    what: 'The charts',
  },
};

const pending = new Map();

/**
 * Load a library once and resolve with its global.
 * @param {'pdfjs'|'hljs'|'qrcode'|'chart'} name
 * @returns {Promise<any>}
 */
export function loadLib(name) {
  const lib = LIBS[name];
  if (!lib) return Promise.reject(new Error('Unknown library ' + name));
  if (window[lib.global]) return Promise.resolve(window[lib.global]);
  if (pending.has(name)) return pending.get(name);
  const p = new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = lib.src;
    s.integrity = lib.integrity;
    s.crossOrigin = 'anonymous';
    s.referrerPolicy = 'no-referrer';
    s.async = true;
    const fail = () => {
      pending.delete(name);
      s.remove();
      reject(new Error(navigator.onLine === false
        ? 'You are offline, so ' + lib.what.toLowerCase() + ' could not be loaded.'
        : lib.what + ' could not be loaded. Check your connection and try again.'));
    };
    s.addEventListener('load', () => (window[lib.global] ? resolve(window[lib.global]) : fail()));
    s.addEventListener('error', fail);
    document.head.appendChild(s);
  });
  pending.set(name, p);
  return p;
}
