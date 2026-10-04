<?php
declare(strict_types=1);

namespace FT\Core;

/**
 * Throw this from any service/controller to produce a consistent error response:
 *   {"success":false,"error":{"code":"FILE_NOT_FOUND","message":"…","details":{…}}}
 * The message MUST be safe to show to end users. Put technical detail in logs, not here.
 */
class ApiException extends \RuntimeException
{
    /** @param array<string,mixed> $details */
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly int $status = 400,
        public readonly array $details = [],
        public readonly array $headers = [],
    ) {
        parent::__construct($message, $status);
    }

    public static function badRequest(string $message = 'The request is invalid.', string $code = 'BAD_REQUEST', array $details = []): self
    {
        return new self($code, $message, 400, $details);
    }

    /** @param array<string,string> $fieldErrors field => message */
    public static function validation(array $fieldErrors, string $message = 'Please check the highlighted fields.'): self
    {
        return new self('VALIDATION_FAILED', $message, 422, ['fields' => $fieldErrors]);
    }

    public static function unauthorized(string $message = 'Please sign in to continue.'): self
    {
        return new self('UNAUTHENTICATED', $message, 401);
    }

    public static function forbidden(string $message = 'You do not have permission to do that.', string $code = 'FORBIDDEN'): self
    {
        return new self($code, $message, 403);
    }

    public static function csrf(): self
    {
        return new self('CSRF_TOKEN_INVALID', 'Your session has expired. Please reload the page and try again.', 419);
    }

    public static function notFound(string $what = 'resource', string $code = 'NOT_FOUND'): self
    {
        return new self($code, "The requested {$what} could not be found.", 404);
    }

    public static function fileNotFound(): self
    {
        return new self('FILE_NOT_FOUND', 'The requested file could not be found.', 404);
    }

    public static function conflict(string $message, string $code = 'CONFLICT', array $details = []): self
    {
        return new self($code, $message, 409, $details);
    }

    public static function quotaExceeded(int $needed = 0, int $available = 0): self
    {
        return new self('QUOTA_EXCEEDED', 'Not enough storage space. Free up space or ask an administrator for a larger quota.', 413, [
            'needed_bytes' => $needed,
            'available_bytes' => max(0, $available),
        ]);
    }

    public static function tooLarge(string $message = 'The file is too large.'): self
    {
        return new self('PAYLOAD_TOO_LARGE', $message, 413);
    }

    public static function tooManyRequests(int $retryAfter = 60): self
    {
        return new self('RATE_LIMITED', 'Too many requests. Please wait a moment and try again.', 429, ['retry_after' => $retryAfter], ['Retry-After' => (string) $retryAfter]);
    }

    public static function methodNotAllowed(): self
    {
        return new self('METHOD_NOT_ALLOWED', 'This method is not allowed for this endpoint.', 405);
    }

    public static function unavailable(string $message = 'This feature is not available on this server.', string $code = 'FEATURE_UNAVAILABLE'): self
    {
        return new self($code, $message, 503);
    }

    public static function server(string $message = 'Something went wrong on our side. Please try again.'): self
    {
        return new self('SERVER_ERROR', $message, 500);
    }
}
