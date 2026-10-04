<?php
declare(strict_types=1);

namespace FT\Controllers\Web;

use FT\Http\Request;
use FT\Http\Response;
use FT\Support\ClientConfig;
use FT\Support\Csp;

/**
 * Progressive Web App endpoints (docs/ARCHITECTURE.md §12.6):
 *
 *  - GET /manifest.webmanifest  web app manifest for the install prompt / home-screen icon
 *  - GET /service-worker.js     generated service worker (version + precache list embedded)
 *  - GET /offline               small self-contained page shown when a navigation fails offline
 *
 * The worker caches only versioned static assets (cache-first, one cache per version + asset
 * fingerprint, old caches deleted on activate). It never caches the API, share pages, file
 * content, thumbnails, navigations, or any response that is not a 200 of the expected type —
 * an HTML page where JS/CSS was expected is the host's cookie check and must not be stored.
 */
final class PwaController
{
    /** Browser chrome and splash screen: the dark page background of the default (Champagne) palette. */
    public const THEME_COLOUR = '#0c0c0f';
    public const BACKGROUND_COLOUR = '#0c0c0f';

    /** Static asset types the worker may cache: extension => expected Content-Type fragment. */
    private const TYPES = [
        'js' => 'javascript', 'mjs' => 'javascript', 'css' => 'text/css', 'png' => 'image/png',
        'svg' => 'image/svg+xml', 'ico' => 'image/', 'webp' => 'image/webp', 'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg', 'woff2' => 'font/woff2',
    ];

    /** GET /manifest.webmanifest */
    public function manifest(Request $req): Response
    {
        $base = $req->basePath();
        $name = self::appName();
        $icon = static fn (string $file, int $size, string $purpose): array => [
            'src' => $base . 'assets/icons/' . $file, 'sizes' => $size . 'x' . $size, 'type' => 'image/png', 'purpose' => $purpose,
        ];
        $manifest = [
            'id'               => $base,
            'name'             => $name,
            'short_name'       => mb_substr($name, 0, 12),
            'description'      => 'Your private cloud drive: upload, share and sync files across all your devices.',
            'lang'             => 'en-GB',
            'dir'              => 'ltr',
            'start_url'        => $base . '#/',
            'scope'            => $base,
            'display'          => 'standalone',
            'display_override' => ['standalone', 'minimal-ui'],
            'orientation'      => 'any',
            'theme_color'      => self::THEME_COLOUR,
            'background_color' => self::BACKGROUND_COLOUR,
            'categories'       => ['productivity', 'utilities'],
            'icons'            => [
                $icon('icon-192.png', 192, 'any'),
                $icon('icon-512.png', 512, 'any'),
                $icon('maskable-512.png', 512, 'maskable'),
            ],
            'shortcuts'        => [
                ['name' => 'My Files', 'short_name' => 'Files', 'url' => $base . '#/files', 'icons' => [$icon('icon-192.png', 192, 'any')]],
                ['name' => 'Uploads', 'short_name' => 'Uploads', 'url' => $base . '#/uploads', 'icons' => [$icon('icon-192.png', 192, 'any')]],
                ['name' => 'Shared With Me', 'short_name' => 'Shared', 'url' => $base . '#/shared', 'icons' => [$icon('icon-192.png', 192, 'any')]],
            ],
        ];
        $json = json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        return new Response((string) $json, 200, [
            'Content-Type'           => 'application/manifest+json; charset=utf-8',
            'Cache-Control'          => 'no-cache',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }

    /** GET /service-worker.js */
    public function serviceWorker(Request $req): Response
    {
        $base = $req->basePath();
        $assets = self::assets();
        $hash = substr(hash('sha256', FT_VERSION . '|' . $base . '|' . json_encode($assets)), 0, 12);
        $etag = '"sw-' . $hash . '"';
        $headers = [
            'Content-Type'           => 'application/javascript; charset=utf-8',
            'Cache-Control'          => 'no-cache',
            'Service-Worker-Allowed' => $base,
            'ETag'                   => $etag,
            'X-Content-Type-Options' => 'nosniff',
        ];
        $inm = (string) ($req->header('If-None-Match') ?? '');
        if ($inm !== '' && in_array($etag, array_map('trim', explode(',', $inm)), true)) {
            return new Response('', 304, $headers);
        }
        return new Response(self::script($base, array_keys($assets), $hash), 200, $headers);
    }

    /** GET /offline */
    public function offline(Request $req): Response
    {
        $nonce = Csp::nonce();
        $e = static fn (mixed $s): string => htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $vars = ['nonce' => $nonce, 'base' => $req->basePath(), 'appName' => self::appName(), 'e' => $e];
        $html = (static function (array $vars): string {
            extract($vars, EXTR_SKIP);
            ob_start();
            require FT_ROOT . '/views/offline.php';
            return (string) ob_get_clean();
        })($vars);
        return new Response($html, 200, [
            'Content-Type'            => 'text/html; charset=utf-8',
            'Content-Security-Policy' => Csp::header($nonce),
            // Cacheable by the service worker (not no-store); the browser revalidates it.
            'Cache-Control'           => 'no-cache',
            'X-FT-Page'               => 'offline',
            'X-Content-Type-Options'  => 'nosniff',
            'X-Frame-Options'         => 'SAMEORIGIN',
            'Referrer-Policy'         => 'strict-origin-when-cross-origin',
        ]);
    }

    // ------------------------------------------------------------------ internals

    private static function appName(): string
    {
        try {
            return ClientConfig::appName();
        } catch (\Throwable) {
            return 'FastTransfer';
        }
    }

    /**
     * Static assets to precache: every JS module under assets/js, the stylesheets, the icons and
     * images. Keys are web paths relative to the base; values fingerprint the file (mtime + size)
     * so a deployment changes the worker script and therefore rolls the cache.
     * @return array<string,string>
     */
    public static function assets(): array
    {
        $root = FT_ROOT . '/assets';
        $out = [];
        $add = static function (string $abs) use (&$out, $root): void {
            $rel = 'assets/' . ltrim(str_replace('\\', '/', substr($abs, strlen($root))), '/');
            $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
            if (!isset(self::TYPES[$ext]) || !preg_match('~^[A-Za-z0-9._/-]+$~', $rel) || str_contains($rel, '/.')) {
                return;
            }
            $out[$rel] = (int) @filemtime($abs) . ':' . (int) @filesize($abs);
        };
        if (is_dir($root . '/js')) {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/js', \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if ($f instanceof \SplFileInfo && $f->isFile() && strtolower($f->getExtension()) === 'js') {
                    $add($f->getPathname());
                }
            }
        }
        foreach (['css' => ['css'], 'icons' => ['png', 'svg', 'ico', 'webp'], 'img' => ['png', 'svg', 'webp', 'jpg', 'jpeg']] as $dir => $exts) {
            $path = $root . '/' . $dir;
            if (!is_dir($path)) {
                continue;
            }
            foreach (scandir($path) ?: [] as $name) {
                if ($name[0] !== '.' && is_file($path . '/' . $name) && in_array(strtolower(pathinfo($name, PATHINFO_EXTENSION)), $exts, true)) {
                    $add($path . '/' . $name);
                }
            }
        }
        ksort($out);
        return $out;
    }

    /** @param string[] $paths */
    private static function script(string $base, array $paths, string $hash): string
    {
        $flags = JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
        return strtr(self::TEMPLATE, [
            '__VERSION__' => (string) json_encode(FT_VERSION, $flags),
            '__BASE__'    => (string) json_encode($base, $flags),
            '__HASH__'    => (string) json_encode($hash, $flags),
            '__LIST__'    => (string) json_encode(array_values($paths), $flags),
            '__TYPES__'   => (string) json_encode(self::TYPES, $flags),
        ]);
    }

    private const TEMPLATE = <<<'JS'
/* FastTransfer service worker — generated by the server (PwaController); do not edit. */
'use strict';
const FT_VERSION = __VERSION__;
const BASE = __BASE__;
const PREFIX = 'ft-static-';
const CACHE = PREFIX + FT_VERSION + '-' + __HASH__;
const OFFLINE_URL = BASE + 'offline';
const PRECACHE = __LIST__;
const TYPES = __TYPES__;

/** Path relative to BASE, or null when the URL is outside this app. */
function relPath(url) {
  if (url.origin !== self.location.origin || !url.pathname.startsWith(BASE)) return null;
  return url.pathname.slice(BASE.length);
}

/** Requests the worker must never touch: API, share pages, file content, thumbnails, PHP routes. */
function bypass(url, rel) {
  if (rel === null) return true;
  if (/^(api\/|s\/|service-worker\.js$|manifest\.webmanifest$)/.test(rel)) return true;
  if (/^index\.php/.test(rel) && url.searchParams.has('r')) return true;
  if (/(^|\/)(files|thumbnail|content|download|zip)(\/|$)/.test(rel) && !rel.startsWith('assets/')) return true;
  return false;
}

function isStatic(rel) {
  if (!rel.startsWith('assets/')) return false;
  const ext = (rel.split('.').pop() || '').toLowerCase();
  return Object.prototype.hasOwnProperty.call(TYPES, ext);
}

/** Only a plain 200 of the expected type is stored (an HTML page instead of JS/CSS is the host's cookie check). */
function cacheable(res, rel) {
  if (!res || res.status !== 200 || res.type !== 'basic' || res.redirected) return false;
  const cc = (res.headers.get('Cache-Control') || '').toLowerCase();
  if (cc.includes('no-store') || cc.includes('private')) return false;
  const ext = (rel.split('?')[0].split('.').pop() || '').toLowerCase();
  const want = TYPES[ext];
  if (!want) return false;
  return (res.headers.get('Content-Type') || '').toLowerCase().includes(want);
}

async function precache() {
  const cache = await caches.open(CACHE);
  const queue = PRECACHE.slice();
  const worker = async () => {
    while (queue.length) {
      const rel = queue.shift();
      try {
        const res = await fetch(BASE + rel, { cache: 'no-cache', credentials: 'same-origin' });
        if (cacheable(res, rel)) await cache.put(BASE + rel, res);
      } catch (e) { /* best effort: missing files are fetched on demand */ }
    }
  };
  await Promise.all([worker(), worker(), worker(), worker()]);
  try {
    const off = await fetch(OFFLINE_URL, { cache: 'no-cache', credentials: 'same-origin' });
    if (off.status === 200 && off.headers.get('X-FT-Page') === 'offline') await cache.put(OFFLINE_URL, off);
  } catch (e) { /* offline page falls back to a minimal inline one */ }
}

self.addEventListener('install', (event) => {
  event.waitUntil(precache().then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k.startsWith(PREFIX) && k !== CACHE).map((k) => caches.delete(k)));
    if (self.registration.navigationPreload) { try { await self.registration.navigationPreload.enable(); } catch (e) { /* unsupported */ } }
    await self.clients.claim();
  })());
});

async function offlineResponse() {
  const hit = await caches.match(OFFLINE_URL, { cacheName: CACHE });
  if (hit) return hit;
  return new Response('<!doctype html><html lang="en-GB"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline · FastTransfer</title><body style="font-family:system-ui,sans-serif;background:#0c0c0f;color:#ece9e3;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center"><div><h1>You are offline</h1><p>Check your connection, then try again.</p></div>',
    { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

/** Navigations: always the network (pages carry a CSRF token and the signed-in user); offline page on failure. */
async function navigate(event) {
  try {
    const pre = await event.preloadResponse;
    if (pre) return pre;
    return await fetch(event.request);
  } catch (e) {
    return offlineResponse();
  }
}

/** Versioned static assets: cache first (the whole cache is per version, so ?v= is ignored). */
async function cacheFirst(request, rel) {
  const cache = await caches.open(CACHE);
  const key = BASE + rel;
  const hit = await cache.match(key);
  if (hit) return hit;
  const res = await fetch(request);
  if (cacheable(res, rel)) {
    try { await cache.put(key, res.clone()); } catch (e) { /* quota */ }
  }
  return res;
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  let url;
  try { url = new URL(req.url); } catch (e) { return; }
  const rel = relPath(url);
  if (bypass(url, rel)) return;
  if (req.mode === 'navigate') { event.respondWith(navigate(event)); return; }
  if (isStatic(rel)) event.respondWith(cacheFirst(req, rel));
});

// ---------------------------------------------------------------- Web Push

function sameOriginUrl(u) {
  try {
    const x = new URL(u || BASE, self.registration.scope);
    if (x.origin === self.location.origin) return x.href;
  } catch (e) { /* fall through */ }
  return new URL(BASE, self.location.origin).href;
}

self.addEventListener('push', (event) => {
  // The payload is shown as-is: nothing is fetched from the server.
  let p = {};
  if (event.data) {
    try { p = event.data.json() || {}; } catch (e) { p = { body: event.data.text() }; }
  }
  const title = String(p.title || 'FastTransfer').slice(0, 120);
  const options = {
    body: String(p.body || '').slice(0, 400),
    icon: BASE + 'assets/icons/icon-192.png',
    badge: BASE + 'assets/icons/badge-72.png',
    lang: 'en-GB',
    data: { url: sameOriginUrl(p.url), id: p.notification_id || null },
  };
  if (p.tag) { options.tag = String(p.tag).slice(0, 64); options.renotify = true; }
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = sameOriginUrl(event.notification.data && event.notification.data.url);
  event.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const app = all.find((c) => { try { const p = new URL(c.url).pathname; return p === BASE || p === BASE + 'index.php'; } catch (e) { return false; } });
    if (app && 'focus' in app) {
      await app.focus();
      app.postMessage({ type: 'ft:navigate', url: target });
      return;
    }
    if (self.clients.openWindow) await self.clients.openWindow(target);
  })());
});

// ---------------------------------------------------------------- Background Sync & messages

self.addEventListener('sync', (event) => {
  if (event.tag !== 'ft-retry-uploads') return;
  event.waitUntil(self.clients.matchAll({ type: 'window' }).then((all) => all.forEach((c) => c.postMessage({ type: 'ft:retry-uploads' }))));
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'ft:skip-waiting') self.skipWaiting();
});
JS;
}
