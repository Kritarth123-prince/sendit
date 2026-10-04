<?php
declare(strict_types=1);

namespace FT\Core;

/**
 * Minimal .env loader. Shared hosts (byethost/iFastNet) cannot set real
 * environment variables, so secrets live in a .env file that is kept outside
 * the web root when possible and is always denied by .htaccess.
 *
 * Precedence: values set with Env::set() > real process environment > first .env file found.
 *
 * Syntax: NAME=value, optional "export ", quoted values ("…" with \n \t escapes, or '…').
 * In an unquoted value, whitespace followed by "#" starts a comment, and a value that is only a
 * comment ("NAME=   # note") is empty — quote a value that must contain " #".
 */
final class Env
{
    /** @var array<string,string> */
    private static array $vars = [];
    /** @var array<string,string> */
    private static array $overrides = [];
    private static ?string $loadedFrom = null;

    /** @param string[] $candidates */
    public static function load(array $candidates): void
    {
        $custom = getenv('FT_ENV_FILE');
        if (is_string($custom) && $custom !== '') {
            array_unshift($candidates, $custom);
        }
        foreach ($candidates as $path) {
            if (is_file($path) && is_readable($path)) {
                self::$vars = self::parse((string) file_get_contents($path));
                self::$loadedFrom = $path;
                return;
            }
        }
    }

    /** @return array<string,string> */
    public static function parse(string $contents): array
    {
        $out = [];
        $contents = str_replace(["\r\n", "\r"], "\n", $contents);
        if (strncmp($contents, "\xEF\xBB\xBF", 3) === 0) {
            $contents = substr($contents, 3); // strip UTF-8 BOM (Notepad on Windows adds one)
        }
        foreach (explode("\n", $contents) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (strncmp($line, 'export ', 7) === 0) {
                $line = trim(substr($line, 7));
            }
            $eq = strpos($line, '=');
            if ($eq === false) {
                continue;
            }
            $key = trim(substr($line, 0, $eq));
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $key)) {
                continue;
            }
            $val = trim(substr($line, $eq + 1));
            if ($val !== '' && ($val[0] === '"' || $val[0] === "'")) {
                $q = $val[0];
                $end = strrpos($val, $q);
                $val = $end > 0 ? substr($val, 1, $end - 1) : substr($val, 1);
                if ($q === '"') {
                    $val = strtr($val, ['\\n' => "\n", '\\r' => "\r", '\\t' => "\t", '\\"' => '"', '\\\\' => '\\']);
                }
            } elseif ($val !== '' && $val[0] === '#') {
                $val = ''; // "NAME=   # note": only a comment, so the value is empty
            } elseif (preg_match('/^(.*?)\s+#/', $val, $m)) {
                $val = rtrim($m[1]); // "NAME=value  # note" (space or tab before the #)
            }
            $out[$key] = $val;
        }
        return $out;
    }

    public static function get(string $key, ?string $default = null): ?string
    {
        if (array_key_exists($key, self::$overrides)) {
            return self::$overrides[$key];
        }
        $real = getenv($key);
        if (is_string($real) && $real !== '') {
            return $real;
        }
        if (array_key_exists($key, self::$vars) && self::$vars[$key] !== '') {
            return self::$vars[$key];
        }
        return $default;
    }

    public static function bool(string $key, bool $default = false): bool
    {
        $v = self::get($key);
        if ($v === null) {
            return $default;
        }
        return in_array(strtolower(trim($v)), ['1', 'true', 'yes', 'on'], true);
    }

    public static function int(string $key, int $default = 0): int
    {
        $v = self::get($key);
        return ($v !== null && is_numeric($v)) ? (int) $v : $default;
    }

    /** Test/installer hook. */
    public static function set(string $key, ?string $value): void
    {
        if ($value === null) {
            unset(self::$overrides[$key]);
        } else {
            self::$overrides[$key] = $value;
        }
    }

    public static function loadedFrom(): ?string
    {
        return self::$loadedFrom;
    }
}
