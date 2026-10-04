<?php
declare(strict_types=1);

namespace FT\Texts;

use FT\Core\ApiException;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Support\Capabilities;

/**
 * Link previews (OpenGraph / <title>) for clipboard URLs — hardened against SSRF.
 *
 * The server fetches a URL a user typed, so every hop is treated as hostile input:
 *  - only http/https, only ports 80/443, no credentials in the URL, no single-label or
 *    internal-looking host names (localhost, *.local, *.internal, *.home.arpa, *.lan);
 *  - IP literals are parsed the way resolvers do (decimal "2130706433", octal "0177.0.0.1",
 *    hex "0x7f.1", short "127.1") and the canonical dotted form is used for the request;
 *  - host names are resolved HERE; if ANY address is not public unicast (private, loopback,
 *    link-local, CGNAT, multicast, reserved, documentation, IPv4-mapped/compatible, NAT64,
 *    6to4, Teredo, ULA, site-local…) the URL is refused, and the vetted address is pinned with
 *    CURLOPT_RESOLVE so a second DNS answer (rebinding) cannot redirect the connection; the
 *    address curl actually connected to is compared with the pinned one afterwards;
 *  - redirects are followed manually (at most 3), each hop re-validated from scratch;
 *  - proxies are disabled, 5 s connect / 10 s total for the whole chain, body capped at
 *    512 KiB, no content decoding (no compression bombs), only text/html is parsed;
 *  - results are plain, length-limited strings; image/favicon URLs are only http(s).
 * Failures are soft: network problems return a minimal preview (domain + favicon guess).
 */
final class UrlMeta
{
    public const MAX_URL = 2048;
    public const MAX_BODY = 524288;
    public const MAX_REDIRECTS = 3;
    public const CONNECT_TIMEOUT = 5;
    public const TOTAL_TIMEOUT = 10;
    public const ALLOWED_PORTS = [80, 443];

    private const BLOCKED_SUFFIXES = ['localhost', 'local', 'internal', 'lan', 'home.arpa', 'localdomain', 'intranet', 'onion'];

    /** IPv4 ranges that are never fetched: [network, prefix]. */
    private const V4_BLOCKED = [
        ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
        ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
        ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
    ];

    /** IPv6 ranges refused even inside 2000::/3 (global unicast): [network, prefix]. */
    private const V6_BLOCKED = [
        ['2001::', 23],      // IETF protocol assignments (Teredo 2001::/32, benchmarking, ORCHID…)
        ['2001:db8::', 32],  // documentation
        ['2002::', 16],      // 6to4 (embeds an arbitrary IPv4 address)
        ['3fff::', 20],      // documentation (RFC 9637)
    ];

    /**
     * Fetch preview metadata.
     * @return array{url:string,title:?string,description:?string,image:?string,favicon:?string,domain:string,site_name:?string,ok:bool,fetched_at:string}
     * @throws ApiException VALIDATION_FAILED for URLs that may not be fetched, FEATURE_UNAVAILABLE without curl
     */
    public static function fetch(string $url): array
    {
        $target = self::validateUrl($url);
        if (!Capabilities::hasCurl()) {
            throw ApiException::unavailable('Link previews are not available on this server.');
        }
        $deadline = microtime(true) + self::TOTAL_TIMEOUT;
        for ($hop = 0; ; $hop++) {
            if (microtime(true) >= $deadline - 0.2) {
                return self::minimal($target);
            }
            $res = self::request($target, $deadline);
            if ($res['status'] === 0) {
                return self::minimal($target);
            }
            if ($res['status'] >= 300 && $res['status'] < 400 && $res['location'] !== null) {
                if ($hop >= self::MAX_REDIRECTS) {
                    return self::minimal($target);
                }
                try {
                    $target = self::validateUrl(self::resolveUrl($target['url'], $res['location']));
                } catch (ApiException) {
                    Logger::security('Link preview redirect to a refused address blocked', ['host' => $target['host']]);
                    return self::minimal($target);
                }
                continue;
            }
            if ($res['status'] < 200 || $res['status'] >= 400 || !self::isHtml($res['content_type']) || strlen($res['body']) < 100) {
                return self::minimal($target);
            }
            return self::parse($res['body'], $target['url'], $res['content_type']);
        }
    }

    /**
     * Validate and normalise a URL for fetching. $resolver (tests) maps a host name to a list of
     * IP strings; by default DNS is queried. Throws VALIDATION_FAILED when it must not be fetched.
     * @return array{url:string,scheme:string,host:string,port:int,ip:string,ip_literal:bool}
     */
    public static function validateUrl(string $url, ?callable $resolver = null): array
    {
        $url = trim($url);
        if ($url === '' || strlen($url) > self::MAX_URL) {
            throw self::refuse('Enter a web address (http or https).');
        }
        if (preg_match('/[\x00-\x20\x7F\\\\]/', $url)) {
            throw self::refuse('This web address contains characters that are not allowed.');
        }
        $p = parse_url($url);
        if ($p === false || !isset($p['scheme'], $p['host'])) {
            throw self::refuse('Enter a full web address, for example https://example.com.');
        }
        $scheme = strtolower((string) $p['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw self::refuse('Only http and https addresses can be previewed.');
        }
        if (isset($p['user']) || isset($p['pass'])) {
            throw self::refuse('Addresses with a user name or password cannot be previewed.');
        }
        $defaultPort = $scheme === 'https' ? 443 : 80;
        $port = isset($p['port']) ? (int) $p['port'] : $defaultPort;
        if (!in_array($port, self::ALLOWED_PORTS, true)) {
            throw self::refuse('Only addresses on the standard web ports (80 and 443) can be previewed.');
        }

        $host = strtolower((string) $p['host']);
        $host = rtrim($host, '.');
        $ipLiteral = false;
        $ips = [];
        if (str_starts_with($host, '[')) {
            $inner = substr($host, 1, -1);
            if (!str_ends_with($host, ']') || str_contains($inner, '%') || @inet_pton($inner) === false || !str_contains($inner, ':')) {
                throw self::refuse('This web address is not valid.');
            }
            $ips = [$inner];
            $ipLiteral = true;
            $hostForUrl = '[' . self::canonicalIp($inner) . ']';
        } elseif (self::looksNumeric($host)) {
            $v4 = self::parseIpv4Literal($host);
            if ($v4 === null) {
                throw self::refuse('This web address is not valid.');
            }
            $ips = [$v4];
            $ipLiteral = true;
            $hostForUrl = $v4;
        } else {
            if (preg_match('/[^\x20-\x7E]/', $host)) {
                $ascii = function_exists('idn_to_ascii') ? @idn_to_ascii($host, 0, defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : 1) : false;
                if (!is_string($ascii) || $ascii === '') {
                    throw self::refuse('This web address is not valid.');
                }
                $host = strtolower($ascii);
            }
            if (!self::isValidHostname($host)) {
                throw self::refuse('This web address is not valid.');
            }
            foreach (self::BLOCKED_SUFFIXES as $suffix) {
                if ($host === $suffix || str_ends_with($host, '.' . $suffix)) {
                    throw self::refuse('Addresses on local or internal networks cannot be previewed.');
                }
            }
            $ips = $resolver !== null ? (array) $resolver($host) : self::resolve($host);
            $ips = array_values(array_filter(array_map('strval', $ips), static fn ($ip) => $ip !== ''));
            if ($ips === []) {
                throw self::refuse('We could not find that website.');
            }
            $hostForUrl = $host;
        }
        foreach ($ips as $ip) {
            if (!self::isPublicIp($ip)) {
                throw self::refuse('Addresses on local or internal networks cannot be previewed.');
            }
        }
        $pinned = null;
        foreach ($ips as $ip) {
            if (str_contains($ip, '.') && !str_contains($ip, ':')) {
                $pinned = $ip;
                break;
            }
        }
        $pinned ??= self::canonicalIp($ips[0]);
        $path = isset($p['path']) && $p['path'] !== '' ? (string) $p['path'] : '/';
        if ($path[0] !== '/') {
            $path = '/' . $path;
        }
        $norm = $scheme . '://' . $hostForUrl . ($port !== $defaultPort ? ':' . $port : '') . $path . (isset($p['query']) ? '?' . $p['query'] : '');
        return ['url' => $norm, 'scheme' => $scheme, 'host' => $ipLiteral ? trim($hostForUrl, '[]') : $host, 'port' => $port, 'ip' => $pinned, 'ip_literal' => $ipLiteral];
    }

    /** True only for globally routable unicast addresses (see class comment). */
    public static function isPublicIp(string $ip): bool
    {
        $ip = trim($ip, '[] ');
        if ($ip === '' || str_contains($ip, '%')) {
            return false;
        }
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        if (strlen($bin) === 4) {
            return self::isPublicV4Bin($bin);
        }
        if (strlen($bin) !== 16) {
            return false;
        }
        // ::/96 (unspecified, loopback, IPv4-compatible) and ::ffff:0:0/96 (IPv4-mapped)
        if (str_starts_with($bin, str_repeat("\0", 10)) && (substr($bin, 10, 2) === "\0\0" || substr($bin, 10, 2) === "\xff\xff")) {
            return false;
        }
        // 64:ff9b::/96 and 64:ff9b:1::/48 (NAT64) — fall outside 2000::/3 anyway, kept explicit.
        if (str_starts_with($bin, "\x00\x64\xff\x9b")) {
            return false;
        }
        // Only global unicast 2000::/3 (this excludes fc00::/7 ULA, fe80::/10 link-local,
        // fec0::/10 site-local, ff00::/8 multicast, 100::/64 discard, ::/8 …).
        if ((ord($bin[0]) & 0xE0) !== 0x20) {
            return false;
        }
        foreach (self::V6_BLOCKED as [$net, $prefix]) {
            if (self::inPrefix($bin, (string) inet_pton($net), $prefix)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Parse an IPv4 literal the way inet_aton() / URL parsers do: 1–4 dot-separated parts,
     * each decimal, octal (leading 0) or hex (0x). Returns the dotted quad, or null when the
     * host is not a valid numeric address.
     */
    public static function parseIpv4Literal(string $host): ?string
    {
        $host = rtrim(strtolower(trim($host)), '.');
        if ($host === '') {
            return null;
        }
        $parts = explode('.', $host);
        if (count($parts) > 4) {
            return null;
        }
        $nums = [];
        foreach ($parts as $part) {
            if ($part === '') {
                return null;
            }
            if (preg_match('/^0x([0-9a-f]*)$/', $part, $m)) {
                $hex = ltrim($m[1], '0');
                if (strlen($hex) > 8) {
                    return null;
                }
                $n = $hex === '' ? 0 : hexdec($hex);
            } elseif (preg_match('/^0[0-7]*$/', $part)) {
                $oct = ltrim($part, '0');
                if (strlen($oct) > 11) {
                    return null;
                }
                $n = $oct === '' ? 0 : octdec($oct);
            } elseif (preg_match('/^[1-9][0-9]*$/', $part)) {
                if (strlen($part) > 10) {
                    return null;
                }
                $n = (int) $part;
            } else {
                return null;
            }
            if (!is_int($n) && !(is_float($n) && $n <= 4294967295)) {
                return null;
            }
            $nums[] = (int) $n;
        }
        $count = count($nums);
        $last = $nums[$count - 1];
        $limits = [1 => 0xFFFFFFFF, 2 => 0xFFFFFF, 3 => 0xFFFF, 4 => 0xFF];
        if ($last < 0 || $last > $limits[$count]) {
            return null;
        }
        $value = 0;
        for ($i = 0; $i < $count - 1; $i++) {
            if ($nums[$i] < 0 || $nums[$i] > 255) {
                return null;
            }
            $value |= $nums[$i] << (24 - 8 * $i);
        }
        $value |= $last;
        return long2ip($value);
    }

    /** Resolve a possibly relative URL against a base URL (absolute http(s) result or the input). */
    public static function resolveUrl(string $base, string $rel): string
    {
        $rel = trim($rel);
        if ($rel === '') {
            return $base;
        }
        if (preg_match('~^[a-z][a-z0-9+.-]*:~i', $rel)) {
            return $rel;
        }
        $b = parse_url($base);
        if ($b === false || !isset($b['scheme'], $b['host'])) {
            return $rel;
        }
        $authority = $b['scheme'] . '://' . (str_contains((string) $b['host'], ':') ? '[' . trim((string) $b['host'], '[]') . ']' : $b['host']) . (isset($b['port']) ? ':' . $b['port'] : '');
        if (str_starts_with($rel, '//')) {
            return $b['scheme'] . ':' . $rel;
        }
        if ($rel[0] === '#') {
            return preg_replace('/#.*$/', '', $base) . $rel;
        }
        if ($rel[0] === '?') {
            return $authority . ($b['path'] ?? '/') . $rel;
        }
        if ($rel[0] === '/') {
            return $authority . self::removeDots($rel);
        }
        $dir = isset($b['path']) ? preg_replace('~/[^/]*$~', '/', (string) $b['path']) : '/';
        return $authority . self::removeDots(($dir === '' ? '/' : $dir) . $rel);
    }

    /**
     * Extract preview fields from an HTML document (only the <head>, at most 256 KiB).
     * @return array{url:string,title:?string,description:?string,image:?string,favicon:?string,domain:string,site_name:?string,ok:bool,fetched_at:string}
     */
    public static function parse(string $html, string $url, ?string $contentType = null): array
    {
        $html = substr($html, 0, 262144);
        $end = stripos($html, '</head>');
        $head = $end !== false ? substr($html, 0, $end) : $html;
        $head = self::toUtf8($head, $contentType);

        $meta = [];
        // Tag patterns skip over quoted attribute values, which may legally contain ">".
        $tag = '((?:[^>"\']|"[^"]*"|\'[^\']*\')*)>';
        if (preg_match_all('/<meta\b' . $tag . '/i', $head, $mm)) {
            foreach ($mm[1] as $attrs) {
                $a = self::attributes($attrs);
                $key = strtolower(trim($a['property'] ?? ($a['name'] ?? ($a['itemprop'] ?? ''))));
                if ($key !== '' && isset($a['content']) && !isset($meta[$key])) {
                    $meta[$key] = $a['content'];
                }
            }
        }
        $titleTag = null;
        if (preg_match('/<title\b[^>]*>(.*?)<\/title>/is', $head, $tm)) {
            $titleTag = $tm[1];
        }
        $icon = null;
        if (preg_match_all('/<link\b' . $tag . '/i', $head, $lm)) {
            $best = 0;
            foreach ($lm[1] as $attrs) {
                $a = self::attributes($attrs);
                $rel = strtolower($a['rel'] ?? '');
                if (!isset($a['href']) || !preg_match('/(^|\s)(shortcut icon|icon|apple-touch-icon)(\s|$)/', $rel)) {
                    continue;
                }
                $score = str_contains($rel, 'shortcut') ? 3 : (str_contains($rel, 'apple') ? 1 : 2);
                if ($score > $best) {
                    $best = $score;
                    $icon = $a['href'];
                }
            }
        }
        $p = parse_url($url);
        $host = strtolower((string) ($p['host'] ?? ''));
        $origin = ($p['scheme'] ?? 'https') . '://' . (str_contains($host, ':') ? '[' . $host . ']' : $host) . (isset($p['port']) ? ':' . $p['port'] : '');
        $title = self::text($meta['og:title'] ?? $meta['twitter:title'] ?? $titleTag, 200);
        $desc = self::text($meta['og:description'] ?? $meta['twitter:description'] ?? $meta['description'] ?? null, 500);
        $image = $meta['og:image'] ?? $meta['og:image:url'] ?? $meta['og:image:secure_url'] ?? $meta['twitter:image'] ?? $meta['twitter:image:src'] ?? null;
        return [
            'url'         => $url,
            'title'       => $title,
            'description' => $desc,
            'image'       => self::safeUrl($image, $url),
            'favicon'     => self::safeUrl($icon, $url) ?? $origin . '/favicon.ico',
            'domain'      => (string) preg_replace('/^www\./', '', $host),
            'site_name'   => self::text($meta['og:site_name'] ?? null, 100),
            'ok'          => true,
            'fetched_at'  => (string) Db::iso(Db::now()),
        ];
    }

    // ------------------------------------------------------------------ internals

    /** @return array{status:int,location:?string,content_type:?string,body:string} */
    private static function request(array $target, float $deadline): array
    {
        $remaining = max(1, (int) floor($deadline - microtime(true)));
        $status = 0;
        $location = null;
        $ctype = null;
        $body = '';
        $ch = curl_init();
        if ($ch === false) {
            return ['status' => 0, 'location' => null, 'content_type' => null, 'body' => ''];
        }
        $opts = [
            CURLOPT_URL            => $target['url'],
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS      => 0,
            CURLOPT_CONNECTTIMEOUT => min(self::CONNECT_TIMEOUT, $remaining),
            CURLOPT_TIMEOUT        => min(self::TOTAL_TIMEOUT, $remaining),
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_PROXY          => '',
            CURLOPT_NOPROXY        => '*',
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (compatible; FastTransfer-LinkPreview/2.0)',
            CURLOPT_HTTPHEADER     => ['Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.1', 'Accept-Language: en-GB,en;q=0.8', 'Accept-Encoding: identity'],
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$status, &$location, &$ctype): int {
                if (preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $m)) {
                    $status = (int) $m[1];
                    $location = null;
                    $ctype = null;
                } elseif (stripos($line, 'location:') === 0) {
                    $location = trim(substr($line, 9));
                } elseif (stripos($line, 'content-type:') === 0) {
                    $ctype = trim(substr($line, 13));
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION  => static function ($ch, string $data) use (&$body, &$status, &$ctype): int {
                if ($status >= 300 || !self::isHtml($ctype)) {
                    return 0; // nothing worth reading: abort the transfer
                }
                $room = self::MAX_BODY - strlen($body);
                if ($room <= 0) {
                    return 0;
                }
                $body .= substr($data, 0, $room);
                return strlen($data) > $room ? 0 : strlen($data);
            },
        ];
        if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP')) {
            $opts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        }
        if (!$target['ip_literal']) {
            $ip = str_contains($target['ip'], ':') ? '[' . $target['ip'] . ']' : $target['ip'];
            $opts[CURLOPT_RESOLVE] = [$target['host'] . ':' . $target['port'] . ':' . $ip];
        }
        curl_setopt_array($ch, $opts);
        @curl_exec($ch);
        $primary = (string) curl_getinfo($ch, CURLINFO_PRIMARY_IP);
        curl_close($ch);
        if ($status !== 0 && $primary !== '' && @inet_pton(trim($primary, '[]')) !== @inet_pton($target['ip'])) {
            // Defence in depth: the connection did not go where we vetted. Never use the answer.
            Logger::security('Link preview connected to an unexpected address', ['host' => $target['host']]);
            return ['status' => 0, 'location' => null, 'content_type' => null, 'body' => ''];
        }
        return ['status' => $status, 'location' => $location, 'content_type' => $ctype, 'body' => $body];
    }

    /** @return string[] */
    private static function resolve(string $host): array
    {
        $ips = [];
        if (function_exists('dns_get_record')) {
            $records = @dns_get_record($host, DNS_A | DNS_AAAA);
            foreach (is_array($records) ? $records : [] as $r) {
                if (isset($r['ip'])) {
                    $ips[] = (string) $r['ip'];
                } elseif (isset($r['ipv6'])) {
                    $ips[] = (string) $r['ipv6'];
                }
            }
        }
        if ($ips === [] && function_exists('gethostbynamel')) {
            $list = @gethostbynamel($host);
            if (is_array($list)) {
                $ips = $list;
            }
        }
        return array_values(array_unique($ips));
    }

    private static function isPublicV4Bin(string $bin): bool
    {
        foreach (self::V4_BLOCKED as [$net, $prefix]) {
            if (self::inPrefix($bin, (string) inet_pton($net), $prefix)) {
                return false;
            }
        }
        return true;
    }

    private static function inPrefix(string $addr, string $net, int $prefix): bool
    {
        if (strlen($addr) !== strlen($net)) {
            return false;
        }
        $bytes = intdiv($prefix, 8);
        if (substr($addr, 0, $bytes) !== substr($net, 0, $bytes)) {
            return false;
        }
        $bits = $prefix % 8;
        if ($bits === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $bits)) & 0xFF;
        return (ord($addr[$bytes]) & $mask) === (ord($net[$bytes]) & $mask);
    }

    private static function canonicalIp(string $ip): string
    {
        $bin = @inet_pton(trim($ip, '[]'));
        return $bin === false ? $ip : (string) inet_ntop($bin);
    }

    /** Host made only of digits, dots and hex prefixes, i.e. something resolvers read as an IPv4 number. */
    private static function looksNumeric(string $host): bool
    {
        if (!preg_match('/^[0-9a-fx.]+$/', $host)) {
            return false;
        }
        foreach (explode('.', $host) as $part) {
            if ($part !== '' && !preg_match('/^(0x[0-9a-f]*|[0-9]+)$/', $part)) {
                return false;
            }
        }
        return true;
    }

    private static function isValidHostname(string $host): bool
    {
        if (strlen($host) > 253 || !str_contains($host, '.')) {
            return false; // single-label names resolve through local search domains
        }
        foreach (explode('.', $host) as $label) {
            if (!preg_match('/^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/', $label)) {
                return false;
            }
        }
        // a TLD is never all-numeric (that would be an IPv4 form)
        return !ctype_digit((string) substr($host, (int) strrpos($host, '.') + 1));
    }

    private static function isHtml(?string $ctype): bool
    {
        if ($ctype === null) {
            return false;
        }
        $t = strtolower(trim(explode(';', $ctype)[0]));
        return $t === 'text/html' || $t === 'application/xhtml+xml';
    }

    private static function minimal(array $target): array
    {
        $host = $target['host'];
        $origin = $target['scheme'] . '://' . (str_contains($host, ':') ? '[' . $host . ']' : $host) . ($target['port'] !== ($target['scheme'] === 'https' ? 443 : 80) ? ':' . $target['port'] : '');
        return [
            'url'         => $target['url'],
            'title'       => null,
            'description' => null,
            'image'       => null,
            'favicon'     => $origin . '/favicon.ico',
            'domain'      => (string) preg_replace('/^www\./', '', $host),
            'site_name'   => null,
            'ok'          => false,
            'fetched_at'  => (string) Db::iso(Db::now()),
        ];
    }

    /** @return array<string,string> lower-cased attribute => decoded value */
    private static function attributes(string $attrs): array
    {
        $out = [];
        if (preg_match_all('/([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|\'([^\']*)\'|([^\s"\'>]+))/', $attrs, $m, PREG_SET_ORDER)) {
            foreach ($m as $x) {
                $val = $x[3] !== '' ? $x[3] : (($x[4] ?? '') !== '' ? $x[4] : ($x[5] ?? ''));
                $key = strtolower($x[1]);
                if (!isset($out[$key])) {
                    $out[$key] = html_entity_decode($val, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                }
            }
        }
        return $out;
    }

    private static function text(?string $v, int $max): ?string
    {
        if ($v === null) {
            return null;
        }
        $v = html_entity_decode(strip_tags($v), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $v = trim((string) preg_replace('/\s+/u', ' ', (string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $v)));
        if ($v === '') {
            return null;
        }
        return mb_strlen($v) > $max ? rtrim(mb_substr($v, 0, $max - 1)) . '…' : $v;
    }

    private static function safeUrl(?string $v, string $base): ?string
    {
        if ($v === null) {
            return null;
        }
        $v = trim(html_entity_decode($v, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        if ($v === '' || str_starts_with(strtolower($v), 'data:')) {
            return null;
        }
        $abs = self::resolveUrl($base, $v);
        if (strlen($abs) > self::MAX_URL || !preg_match('~^https?://[^\s"\'<>\\\\]+$~i', $abs)) {
            return null;
        }
        return $abs;
    }

    private static function toUtf8(string $s, ?string $contentType): string
    {
        $charset = null;
        if ($contentType !== null && preg_match('/charset\s*=\s*["\']?([\w.:-]+)/i', $contentType, $m)) {
            $charset = $m[1];
        } elseif (preg_match('/<meta[^>]+charset\s*=\s*["\']?([\w.:-]+)/i', $s, $m)) {
            $charset = $m[1];
        }
        if ($charset !== null && !in_array(strtolower($charset), ['utf-8', 'utf8'], true)) {
            try {
                $conv = @mb_convert_encoding($s, 'UTF-8', $charset);
                if (is_string($conv)) {
                    $s = $conv;
                }
            } catch (\Throwable) {
                // unknown charset: fall through to scrubbing
            }
        }
        return mb_scrub($s, 'UTF-8');
    }

    private static function removeDots(string $path): string
    {
        $q = '';
        if (($pos = strpos($path, '?')) !== false) {
            $q = substr($path, $pos);
            $path = substr($path, 0, $pos);
        }
        $out = [];
        foreach (explode('/', $path) as $seg) {
            if ($seg === '..') {
                if (count($out) > 1) {
                    array_pop($out);
                }
            } elseif ($seg !== '.') {
                $out[] = $seg;
            }
        }
        $r = implode('/', $out);
        return ($r === '' || $r[0] !== '/' ? '/' . ltrim($r, '/') : $r) . $q;
    }

    private static function refuse(string $message): ApiException
    {
        return ApiException::validation(['url' => $message], $message);
    }
}
