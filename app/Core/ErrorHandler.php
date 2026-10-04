<?php
declare(strict_types=1);

namespace FT\Core;

/**
 * Global error handling: raw PHP errors are never shown to users. Technical details go to
 * storage/logs; users get a safe JSON error (API) or a friendly HTML page (web).
 */
final class ErrorHandler
{
    private static bool $jsonMode = false;

    public static function register(): void
    {
        ini_set('display_errors', Config::isDebug() && PHP_SAPI === 'cli' ? '1' : '0');
        ini_set('log_errors', '1');
        error_reporting(E_ALL);

        set_error_handler(static function (int $errno, string $errstr, string $errfile = '', int $errline = 0): bool {
            if (!(error_reporting() & $errno)) {
                return false; // silenced with @
            }
            if (in_array($errno, [E_USER_ERROR, E_RECOVERABLE_ERROR], true)) {
                throw new \ErrorException($errstr, 0, $errno, $errfile, $errline);
            }
            Logger::warning('php', $errstr, ['errno' => $errno, 'at' => basename($errfile) . ':' . $errline]);
            return true;
        });

        set_exception_handler([self::class, 'handle']);

        register_shutdown_function(static function (): void {
            $e = error_get_last();
            if ($e !== null && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
                Logger::error('php', 'Fatal: ' . $e['message'], ['at' => basename($e['file']) . ':' . $e['line']]);
                self::emit(ApiException::server());
            }
        });
    }

    /** Called by the Router for API routes so uncaught errors become JSON. */
    public static function jsonMode(bool $on = true): void
    {
        self::$jsonMode = $on;
    }

    public static function isJsonMode(): bool
    {
        return self::$jsonMode;
    }

    public static function handle(\Throwable $e): void
    {
        if ($e instanceof ApiException) {
            if ($e->status >= 500) {
                Logger::exception('app', $e);
            }
            self::emit($e);
            return;
        }
        if ($e instanceof \PDOException) {
            Logger::exception('db', $e);
        } else {
            Logger::exception('app', $e);
        }
        $safe = ApiException::server();
        if (Config::isDebug()) {
            $safe = new ApiException('SERVER_ERROR', get_class($e) . ': ' . $e->getMessage() . ' @ ' . basename($e->getFile()) . ':' . $e->getLine(), 500);
        }
        self::emit($safe);
    }

    public static function emit(ApiException $e): void
    {
        if (PHP_SAPI === 'cli') {
            fwrite(STDERR, "[{$e->errorCode}] {$e->getMessage()}\n");
            return;
        }
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        if (headers_sent()) {
            echo "\n";
            return;
        }
        http_response_code($e->status);
        foreach ($e->headers as $k => $v) {
            header($k . ': ' . $v);
        }
        $wantsJson = self::$jsonMode
            || str_contains((string) ($_SERVER['HTTP_ACCEPT'] ?? ''), 'application/json')
            || str_contains((string) ($_SERVER['REQUEST_URI'] ?? ''), '/api/')
            || str_contains((string) ($_GET['r'] ?? ''), '/api/');
        if ($wantsJson) {
            header('Content-Type: application/json; charset=utf-8');
            header('Cache-Control: no-store');
            header('X-FT-Api: 1'); // lets the client distinguish real API errors from host-injected HTML
            header('X-Content-Type-Options: nosniff');
            $err = ['code' => $e->errorCode, 'message' => $e->getMessage()];
            if ($e->details !== []) {
                $err['details'] = $e->details;
            }
            echo json_encode(['success' => false, 'error' => $err], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            return;
        }
        header('Content-Type: text/html; charset=utf-8');
        $title = $e->status === 404 ? 'Not found' : ($e->status === 403 ? 'Access denied' : 'Something went wrong');
        $msg = htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8');
        $t = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
        // The reference matches the "req" field in storage/logs, so an administrator can find the cause.
        $ref = $e->status >= 500 && RequestContext::id() !== null
            ? '<p style="font-size:12px">Reference: <code>' . htmlspecialchars((string) RequestContext::id(), ENT_QUOTES, 'UTF-8') . '</code> (see storage/logs)</p>'
            : '';
        echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . "<title>{$t}</title><style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;background:#0a0a12;color:#e8e6f0;padding:16px}"
            . '.b{max-width:420px;text-align:center}h1{font-size:20px;margin:12px 0 8px}p{color:#a9a7bb;font-size:14px;line-height:1.5}a{color:#dcbd85}</style></head>'
            . "<body><div class=\"b\"><div style=\"font-size:44px\">⚠️</div><h1>{$t}</h1><p>{$msg}</p>{$ref}<p><a href=\"./\">Back to FastTransfer</a></p></div></body></html>";
    }
}
