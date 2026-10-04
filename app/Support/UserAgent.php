<?php
declare(strict_types=1);

namespace FT\Support;

/**
 * Turns a User-Agent string into a short, human label for the Security Centre and the device
 * list ("Chrome on Android", "Safari on iPhone", "Edge on Windows", "Firefox on Linux").
 *
 * This is deliberately a small ordered rule list rather than a full UA database: the labels are
 * only a hint for people recognising their own devices, never a security decision. Order matters
 * because most browsers embed the tokens of the engines they are derived from (Edge and Opera
 * both claim to be Chrome and Safari, Chrome on iOS claims to be Safari, …).
 */
final class UserAgent
{
    /** [regex, label] — first match wins. */
    private const BROWSERS = [
        ['~\bEdg(?:e|A|iOS)?/~', 'Edge'],
        ['~\bSamsungBrowser/~', 'Samsung Internet'],
        ['~\b(?:OPR|OPiOS|OPT|Opera)/~', 'Opera'],
        ['~\bBrave\b~i', 'Brave'],
        ['~\bVivaldi/~', 'Vivaldi'],
        ['~\bYaBrowser/~', 'Yandex Browser'],
        ['~\bUCBrowser/~', 'UC Browser'],
        ['~\bDuckDuckGo/~', 'DuckDuckGo'],
        ['~\bFocus/~', 'Firefox Focus'],
        ['~\b(?:Firefox|FxiOS)/~', 'Firefox'],
        ['~\bMSIE |\bTrident/~', 'Internet Explorer'],
        ['~\bCriOS/~', 'Chrome'],
        ['~\bwv\).*Chrome/|; wv\)~', 'Android WebView'],
        ['~\b(?:Chrome|Chromium)/~', 'Chrome'],
        ['~\bVersion/[\d.]+.*Safari/|\bSafari/.*\b(?:iPhone|iPad|Macintosh)\b|\b(?:iPhone|iPad).*AppleWebKit~', 'Safari'],
    ];

    /** Non-browser clients (API scripts, CLI tools). */
    private const CLIENTS = [
        ['~^FastTransfer~i', 'FastTransfer client'],
        ['~\bcurl/~i', 'curl'],
        ['~\bWget/~i', 'Wget'],
        ['~\bpython-requests/|\bpython-urllib|\bhttpx/|\baiohttp/~i', 'Python script'],
        ['~\bPostmanRuntime/~i', 'Postman'],
        ['~\bokhttp/~i', 'Android app'],
        ['~\bGo-http-client/~i', 'Go client'],
        ['~\bnode-fetch|\bundici|\baxios/~i', 'Node.js script'],
        ['~\bPowerShell/~i', 'PowerShell'],
        ['~\bJava/|\bApache-HttpClient/~i', 'Java client'],
        ['~\b(?:bot|crawler|spider)\b~i', 'Bot'],
    ];

    /** [regex, label] — first match wins. */
    private const SYSTEMS = [
        ['~\biPhone\b~', 'iPhone'],
        ['~\biPad\b~', 'iPad'],
        ['~\biPod\b~', 'iPod'],
        ['~\bAndroid\b~', 'Android'],
        ['~\bCrOS\b~', 'ChromeOS'],
        ['~\bWindows Phone\b~', 'Windows Phone'],
        ['~\bWindows\b|\bWin64\b|\bWin32\b~', 'Windows'],
        ['~\bMacintosh\b|\bMac OS X\b~', 'macOS'],
        ['~\bUbuntu\b~', 'Ubuntu'],
        ['~\bFedora\b~', 'Fedora'],
        ['~\bLinux\b|\bX11\b~', 'Linux'],
        ['~\bFreeBSD\b~', 'FreeBSD'],
    ];

    /** Short label such as "Chrome on Android". Never empty. */
    public static function describe(?string $ua): string
    {
        $p = self::parse($ua);
        if ($p['client'] !== null) {
            return $p['client'];
        }
        if ($p['browser'] !== null && $p['os'] !== null) {
            return $p['browser'] . ' on ' . $p['os'];
        }
        return $p['browser'] ?? ($p['os'] !== null ? 'Browser on ' . $p['os'] : 'Unknown device');
    }

    /** @return array{browser:?string,os:?string,client:?string,mobile:bool} */
    public static function parse(?string $ua): array
    {
        $ua = trim((string) $ua);
        $out = ['browser' => null, 'os' => null, 'client' => null, 'mobile' => false];
        if ($ua === '') {
            return $out;
        }
        $ua = substr($ua, 0, 512);
        foreach (self::SYSTEMS as [$re, $label]) {
            if (preg_match($re, $ua)) {
                $out['os'] = $label;
                break;
            }
        }
        // iPadOS 13+ reports itself as a Mac; a Mac with touch support cannot be detected server-side.
        if (!str_contains($ua, 'Mozilla/')) {
            foreach (self::CLIENTS as [$re, $label]) {
                if (preg_match($re, $ua)) {
                    $out['client'] = $label;
                    return $out;
                }
            }
        }
        foreach (self::BROWSERS as [$re, $label]) {
            if (preg_match($re, $ua)) {
                $out['browser'] = $label;
                break;
            }
        }
        if ($out['browser'] === null) {
            foreach (self::CLIENTS as [$re, $label]) {
                if (preg_match($re, $ua)) {
                    $out['client'] = $label;
                    return $out;
                }
            }
        }
        $out['mobile'] = in_array($out['os'], ['iPhone', 'iPod', 'Android', 'Windows Phone'], true)
            || str_contains($ua, 'Mobile');
        return $out;
    }
}
