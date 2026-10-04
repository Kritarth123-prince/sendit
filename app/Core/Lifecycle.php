<?php
declare(strict_types=1);

namespace FT\Core;

use FT\Http\Response;
use FT\Support\Capabilities;

/**
 * Work that should run AFTER the response has been sent (job queue slice, pseudo-cron).
 *
 * With PHP-FPM/LiteSpeed the connection is closed first. On hosts without that ability
 * (e.g. byethost free) the client keeps waiting until PHP exits, so callbacks receive a small
 * time budget (see budget()) and must respect it.
 */
final class Lifecycle
{
    /** @var array<string,callable> */
    private static array $callbacks = [];
    private static bool $terminated = false;

    /** Register a callback once per key. */
    public static function onTerminate(string $key, callable $fn): void
    {
        self::$callbacks[$key] = $fn;
    }

    /** Seconds of post-response work allowed for this request. */
    public static function budget(): float
    {
        return Capabilities::canFinishEarly() ? 6.0 : 1.5;
    }

    public static function terminate(): void
    {
        if (self::$terminated || self::$callbacks === []) {
            return;
        }
        self::$terminated = true;
        Response::finishEarly();
        foreach (self::$callbacks as $key => $fn) {
            try {
                $fn();
            } catch (\Throwable $e) {
                Logger::exception('app', $e, ['terminate' => $key]);
            }
        }
        self::$callbacks = [];
    }

    /** For tests. */
    public static function reset(): void
    {
        self::$callbacks = [];
        self::$terminated = false;
    }
}
