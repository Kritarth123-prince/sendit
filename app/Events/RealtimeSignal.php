<?php
declare(strict_types=1);

namespace FT\Events;

use FT\Storage\Paths;

/**
 * Cheap cross-request "something changed" signal. When an event is published, the latest
 * event id is written to runtime/rt/u<userId>.seq for every recipient. Long-poll/SSE loops
 * watch this tiny file (no database connection held) and only query MySQL when it changes —
 * essential on shared hosts with very few MySQL connections per account.
 */
final class RealtimeSignal
{
    public static function bump(int $userId, int $eventId): void
    {
        $file = self::file($userId);
        $current = self::read($userId);
        if ($eventId > $current) {
            @file_put_contents($file, (string) $eventId, LOCK_EX);
        }
    }

    public static function read(int $userId): int
    {
        $file = self::file($userId);
        clearstatcache(true, $file);
        if (!is_file($file)) {
            return 0;
        }
        $v = @file_get_contents($file);
        return ($v !== false && ctype_digit(trim($v))) ? (int) trim($v) : 0;
    }

    private static function file(int $userId): string
    {
        return Paths::runtime('rt') . '/u' . max(0, $userId) . '.seq';
    }
}
