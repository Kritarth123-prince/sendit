<?php
declare(strict_types=1);

namespace FT\Core;

/**
 * Per-request ambient context (request id, current user, IP, user agent, client device id).
 * Populated by the Router/Auth; read by Logger, Audit and EventBus so callers do not have to
 * thread these values through every function.
 */
final class RequestContext
{
    private static ?string $id = null;
    private static ?int $userId = null;
    private static ?string $ip = null;
    private static ?string $userAgent = null;
    private static ?string $clientId = null;
    private static bool $cli = false;

    public static function init(?string $ip, ?string $userAgent, ?string $clientId = null): void
    {
        self::$id = bin2hex(random_bytes(6));
        self::$ip = $ip;
        self::$userAgent = $userAgent !== null ? mb_substr($userAgent, 0, 255) : null;
        self::$clientId = $clientId;
    }

    public static function initCli(): void
    {
        self::$cli = true;
        self::$id = 'cli-' . bin2hex(random_bytes(4));
        self::$ip = null;
        self::$userAgent = 'cli';
    }

    public static function id(): ?string
    {
        return self::$id;
    }

    public static function setUserId(?int $userId): void
    {
        self::$userId = $userId;
    }

    public static function userId(): ?int
    {
        return self::$userId;
    }

    public static function ip(): ?string
    {
        return self::$ip;
    }

    public static function userAgent(): ?string
    {
        return self::$userAgent;
    }

    /** Random per-browser id sent by the web client in X-Client-Id (used as event "origin"). */
    public static function clientId(): ?string
    {
        return self::$clientId;
    }

    public static function isCli(): bool
    {
        return self::$cli || PHP_SAPI === 'cli';
    }
}
