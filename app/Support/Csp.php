<?php
declare(strict_types=1);

namespace FT\Support;

/**
 * Content-Security-Policy for server-rendered HTML pages (docs/ARCHITECTURE.md §12.5).
 *
 * One random nonce per request: every <script> tag a page emits (the module entry point and the
 * tiny theme bootstrap) carries it, so injected markup can never execute script. There are no
 * inline event handlers anywhere in the app, which is what makes this strict policy possible.
 *
 * Headers are sent from PHP because byethost rejects `Header` directives in .htaccess.
 *
 * Third-party scripts are allowed only from the exact cdnjs library folders the front end loads
 * (assets/js/features/lib-loader.js), never from the whole CDN: a version-pinned path prefix
 * cannot be used to pull in some other library hosted there. Each of those scripts also carries
 * Subresource Integrity. Keep CDN_SCRIPTS and lib-loader.js in step (tests/js/csp.test.mjs).
 */
final class Csp
{
    /** Exact cdnjs folders (path prefixes) the front end loads scripts and the pdf.js worker from. */
    public const CDN_SCRIPTS = [
        'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/',
        'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/',
        'https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/',
        'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/',
    ];

    /** The pdf.js worker (a blob: wrapper that importScripts() it; pdf.js may also start it directly). */
    public const CDN_WORKERS = [
        'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/',
    ];

    private static ?string $nonce = null;

    /** Per-request nonce (base64, 128 bits). Stable for the rest of the request. */
    public static function nonce(): string
    {
        return self::$nonce ??= base64_encode(random_bytes(16));
    }

    /** The exact policy of §12.5 for the given nonce. */
    public static function header(string $nonce): string
    {
        if (!preg_match('~^[A-Za-z0-9+/_=-]{16,128}$~', $nonce)) {
            // Never let a malformed value reach the header (header injection / policy bypass).
            throw new \InvalidArgumentException('Invalid CSP nonce');
        }
        $scripts = implode(' ', self::CDN_SCRIPTS);
        $workers = implode(' ', self::CDN_WORKERS);
        return "default-src 'self'; script-src 'self' 'nonce-{$nonce}' {$scripts}; "
            . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            . "font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; media-src 'self' blob:; "
            . "connect-src 'self'; worker-src 'self' blob: {$workers}; frame-src 'self'; "
            . "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'";
    }

    /**
     * Headers every HTML page of the app should carry: the CSP plus "never cache" (the shell
     * embeds a CSRF token and the signed-in user, so no shared or back/forward cache may keep it).
     * Other modules (login page, share pages) may reuse this.
     *
     * @return array<string,string>
     */
    public static function pageHeaders(?string $nonce = null): array
    {
        return [
            'Content-Security-Policy' => self::header($nonce ?? self::nonce()),
            'Cache-Control'           => 'no-store, no-cache, must-revalidate, private',
            'Pragma'                  => 'no-cache',
            'Expires'                 => '0',
            'Vary'                    => 'Cookie',
            'X-Content-Type-Options'  => 'nosniff',
            'X-Frame-Options'         => 'SAMEORIGIN',
            'Referrer-Policy'         => 'strict-origin-when-cross-origin',
        ];
    }

    /** Tests only. */
    public static function reset(): void
    {
        self::$nonce = null;
    }
}
