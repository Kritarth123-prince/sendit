<?php
/**
 * FastTransfer — front controller.
 *
 * Every web page, REST API call (/api/v1/…), public share page (/s/{token}), real-time
 * stream and legacy URL (?share=…, ?download=…) enters here. Routes are declared in
 * app/routes/*.php. The pre-upgrade single-file app is preserved outside the web root
 * (see docs/UPGRADE.md).
 */
declare(strict_types=1);

require __DIR__ . '/app/bootstrap.php';

FT\Support\HostCompat::apply();

$request = FT\Http\Request::capture();

// Legacy single-file URLs (?share=, ?download=, ?serve=, ?logout, …) are handled by the
// legacy shim so links and bookmarks made before the upgrade keep working.
if ($request->path() === '/' && class_exists(FT\Legacy\LegacyRoutes::class) && FT\Legacy\LegacyRoutes::matches($_GET)) {
    $_GET['r'] = '/legacy';
    FT\Http\Request::reset();
    $request = FT\Http\Request::capture();
}

// Not installed yet (no .env / database / pending migrations): only the installer is reachable.
if (!FT\Support\Install::isReady() && !str_starts_with($request->path(), '/install')) {
    $target = $request->basePath() . (FT\Core\Config::get('app.pretty_urls') ? 'install' : 'index.php?r=/install');
    if ($request->wantsJson()) {
        FT\Core\ErrorHandler::jsonMode(true);
        FT\Core\ErrorHandler::emit(new FT\Core\ApiException('NOT_INSTALLED', 'FastTransfer is not installed or needs an upgrade. An administrator must open /install.', 503));
        exit;
    }
    header('Location: ' . $target, true, 302);
    exit;
}

$router = new FT\Http\Router();
$router->loadRouteFiles(__DIR__ . '/app/routes');

// Background maintenance on hosts without cron: runs after the response is sent, at most
// once per PSEUDO_CRON_INTERVAL, time-boxed and lock-protected.
if (FT\Core\Config::get('pseudo_cron.enabled') && FT\Support\Install::isReady() && class_exists(FT\Maintenance\PseudoCron::class)) {
    FT\Core\Lifecycle::onTerminate('pseudo_cron', [FT\Maintenance\PseudoCron::class, 'maybeRun']);
}

$router->dispatch($request);
