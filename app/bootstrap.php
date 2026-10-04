<?php
/**
 * FastTransfer bootstrap — loaded by every entry point (index.php, maintenance.php, tests).
 *
 * Responsibilities: constants, autoloader, environment, error handling, timezone.
 * Nothing here may produce output.
 */
declare(strict_types=1);

if (defined('FT_ROOT')) {
    return;
}

define('FT_ROOT', dirname(__DIR__));
define('FT_APP', __DIR__);
define('FT_VERSION', '2.0.0');
define('FT_START', microtime(true));

if (PHP_VERSION_ID < 80000) {
    http_response_code(500);
    exit('FastTransfer requires PHP 8.0 or newer.');
}

// PSR-4 style autoloader: FT\Foo\Bar => app/Foo/Bar.php
spl_autoload_register(static function (string $class): void {
    if (strncmp($class, 'FT\\', 3) !== 0) {
        return;
    }
    $rel = str_replace('\\', '/', substr($class, 3));
    $file = FT_APP . '/' . $rel . '.php';
    if (is_file($file)) {
        require $file;
    }
});

date_default_timezone_set('UTC');
mb_internal_encoding('UTF-8');

FT\Core\Env::load([
    dirname(FT_ROOT) . '/.env',   // preferred: outside the web root
    FT_ROOT . '/.env',            // fallback: app root (denied by .htaccess)
]);

FT\Core\ErrorHandler::register();
