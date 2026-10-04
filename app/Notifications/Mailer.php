<?php
declare(strict_types=1);

namespace FT\Notifications;

use FT\Core\Config;
use FT\Core\Logger;
use FT\Jobs\Queue;

/**
 * Outgoing e-mail. mail() is disabled on many shared hosts and is never used.
 *
 * Drivers (MAIL_DRIVER):
 *   none — e-mail is off (send() returns false, queue() does nothing);
 *   log  — only metadata (recipient, subject, size) is written to the "mail" log channel. Bodies
 *          are never logged: they can contain password-reset links and codes;
 *   smtp — a small SMTP client over stream_socket_client: STARTTLS (SMTP_ENCRYPTION=tls),
 *          implicit TLS (ssl) or none; EHLO, AUTH PLAIN/LOGIN, MAIL FROM/RCPT TO/DATA with
 *          dot-stuffing and CRLF line endings, QUIT. Connect timeout 5 s, 10 s per operation.
 *          Byethost only allows outbound SMTP on port 587 (STARTTLS).
 *
 * Header injection: addresses and subjects containing CR/LF are rejected (InvalidArgumentException);
 * non-ASCII header text is RFC 2047 encoded.
 */
final class Mailer
{
    private const CONNECT_TIMEOUT = 5;
    private const IO_TIMEOUT = 10;
    private const MAX_BODY_BYTES = 1048576;

    public static function driver(): string
    {
        $d = strtolower(trim((string) Config::get('mail.driver', 'none')));
        return in_array($d, ['none', 'log', 'smtp'], true) ? $d : 'none';
    }

    /** True when e-mail can be sent (log driver, or SMTP with a host and a sender address). */
    public static function enabled(): bool
    {
        return match (self::driver()) {
            'log'   => true,
            'smtp'  => (string) Config::get('smtp.host', '') !== '' && self::fromAddress() !== null,
            default => false,
        };
    }

    public static function isValidAddress(string $address): bool
    {
        return strlen($address) <= 254
            && !preg_match('/[\r\n\0<>"\s,;]/', $address)
            && filter_var($address, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Send one message now. Returns true on success (or when written to the log driver), false
     * when e-mail is off or delivery failed (logged without the body).
     * @throws \InvalidArgumentException for unsafe/invalid recipient or subject (header injection)
     */
    public static function send(string $to, string $subject, string $text, ?string $html = null): bool
    {
        self::assertSafe($to, $subject);
        $driver = self::driver();
        if ($driver === 'none') {
            return false;
        }
        $from = self::fromAddress();
        if ($from === null) {
            Logger::warning('mail', 'E-mail not sent: MAIL_FROM is not set or invalid', ['subject' => $subject]);
            return false;
        }
        $fromName = (string) Config::get('mail.from_name', '') ?: Notifier::siteName();
        $message = self::buildMessage($from, $fromName, $to, $subject, $text, $html);

        if ($driver === 'log') {
            Logger::info('mail', 'E-mail written to the log (MAIL_DRIVER=log); the body is not recorded', [
                'to' => $to, 'subject' => $subject, 'bytes' => strlen($message),
            ]);
            return true;
        }
        try {
            self::smtpSend($from, $to, $message);
            Logger::info('mail', 'E-mail sent', ['to' => $to, 'subject' => $subject, 'bytes' => strlen($message)]);
            return true;
        } catch (\Throwable $e) {
            Logger::warning('mail', 'E-mail delivery failed', ['to' => $to, 'subject' => $subject, 'error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Queue a message for delivery after the response (Mailer::sendJob). Returns the job id, or
     * 0 when e-mail is off.
     * @throws \InvalidArgumentException for unsafe/invalid recipient or subject
     */
    public static function queue(string $to, string $subject, string $text, ?string $html = null): int
    {
        self::assertSafe($to, $subject);
        if (!self::enabled()) {
            return 0;
        }
        return Queue::push(self::class . '::sendJob', [
            'to' => $to, 'subject' => $subject, 'text' => $text, 'html' => $html,
        ], 0, 'default', 3);
    }

    /**
     * Queue handler. Invalid input is dropped (retrying cannot fix it); an SMTP failure throws so
     * the queue retries with back-off.
     * @param array<string,mixed> $payload {to, subject, text, html?}
     */
    public static function sendJob(array $payload): void
    {
        $to = is_string($payload['to'] ?? null) ? $payload['to'] : '';
        $subject = is_string($payload['subject'] ?? null) ? $payload['subject'] : '';
        $text = is_string($payload['text'] ?? null) ? $payload['text'] : '';
        $html = is_string($payload['html'] ?? null) ? $payload['html'] : null;
        try {
            $ok = self::send($to, $subject, $text, $html);
        } catch (\InvalidArgumentException $e) {
            Logger::warning('mail', 'Queued e-mail dropped: ' . $e->getMessage());
            return;
        }
        if (!$ok && self::driver() === 'smtp') {
            throw new \RuntimeException('E-mail delivery failed; it will be retried.');
        }
    }

    // ------------------------------------------------------------------ message encoding

    /**
     * Build a complete RFC 5322 message (headers + body) with CRLF line endings: text/plain, or
     * multipart/alternative (text + html) when $html is given; quoted-printable UTF-8 bodies.
     */
    public static function buildMessage(
        string $from,
        string $fromName,
        string $to,
        string $subject,
        string $text,
        ?string $html = null,
        ?int $time = null,
        ?string $boundary = null,
        ?string $messageId = null
    ): string {
        self::assertSafe($to, $subject);
        if (!self::isValidAddress($from)) {
            throw new \InvalidArgumentException('Invalid sender address');
        }
        $fromName = trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', $fromName));
        $domain = (string) preg_replace('/[^A-Za-z0-9.-]/', '', substr((string) strrchr($from, '@'), 1)) ?: 'localhost';
        $messageId ??= bin2hex(random_bytes(12)) . '@' . $domain;
        $headers = [
            'Date: ' . gmdate('D, d M Y H:i:s', $time ?? time()) . ' +0000',
            'From: ' . self::formatAddress($from, $fromName),
            'To: <' . $to . '>',
            'Subject: ' . self::encodeHeader($subject),
            'Message-ID: <' . $messageId . '>',
            'MIME-Version: 1.0',
            'Auto-Submitted: auto-generated',
            'X-Auto-Response-Suppress: All',
        ];
        $text = self::qp($text);
        if ($html === null || $html === '') {
            $headers[] = 'Content-Type: text/plain; charset=UTF-8';
            $headers[] = 'Content-Transfer-Encoding: quoted-printable';
            $body = $text;
        } else {
            $boundary ??= '=_ft_' . bin2hex(random_bytes(12));
            $headers[] = 'Content-Type: multipart/alternative; boundary="' . $boundary . '"';
            $body = "This is a multi-part message in MIME format.\r\n\r\n"
                . '--' . $boundary . "\r\n"
                . "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
                . $text . "\r\n"
                . '--' . $boundary . "\r\n"
                . "Content-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
                . self::qp($html) . "\r\n"
                . '--' . $boundary . "--\r\n";
        }
        return implode("\r\n", $headers) . "\r\n\r\n" . $body;
    }

    /**
     * Header text: printable ASCII is kept as is; anything else becomes RFC 2047 encoded-words
     * (UTF-8, base64) folded onto continuation lines, split on character boundaries.
     * @throws \InvalidArgumentException when the value contains CR or LF
     */
    public static function encodeHeader(string $value): string
    {
        if (preg_match('/[\r\n]/', $value)) {
            throw new \InvalidArgumentException('Header values must not contain line breaks');
        }
        if (preg_match('/^[\x20-\x7E]*$/', $value) && strlen($value) <= 900) {
            return $value;
        }
        if (!mb_check_encoding($value, 'UTF-8')) {
            $value = mb_convert_encoding($value, 'UTF-8', 'UTF-8');
        }
        $words = [];
        $chunk = '';
        foreach (mb_str_split($value, 1, 'UTF-8') as $ch) {
            if ($chunk !== '' && strlen($chunk) + strlen($ch) > 39) {
                $words[] = '=?UTF-8?B?' . base64_encode($chunk) . '?=';
                $chunk = '';
            }
            $chunk .= $ch;
        }
        if ($chunk !== '') {
            $words[] = '=?UTF-8?B?' . base64_encode($chunk) . '?=';
        }
        return implode("\r\n ", $words);
    }

    /** SMTP transparency (RFC 5321 §4.5.2): a line starting with "." gets one more ".". */
    public static function dotStuff(string $data): string
    {
        $data = self::crlf($data);
        $data = (string) preg_replace('/^\./m', '..', $data);
        return $data;
    }

    // ------------------------------------------------------------------ SMTP

    /**
     * Run one SMTP transaction over an already-connected stream (separate from connecting so the
     * protocol can be unit-tested with a socket pair).
     * @param resource $fp
     * @param array{helo?:string,encryption?:string,user?:string,password?:string} $opts
     */
    public static function smtpConverse($fp, array $opts, string $from, string $to, string $message): void
    {
        if (!self::isValidAddress($from) || !self::isValidAddress($to)) {
            throw new \InvalidArgumentException('Invalid envelope address');
        }
        $helo = (string) preg_replace('/[^A-Za-z0-9.-]/', '', (string) ($opts['helo'] ?? 'localhost')) ?: 'localhost';
        $enc = strtolower((string) ($opts['encryption'] ?? 'none'));
        self::expect($fp, [220]);
        $caps = self::ehlo($fp, $helo);
        if ($enc === 'tls') {
            if (!isset($caps['STARTTLS'])) {
                throw new \RuntimeException('The SMTP server does not offer STARTTLS.');
            }
            self::command($fp, 'STARTTLS', [220]);
            $method = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
            if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
                $method |= STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
            }
            if (@stream_socket_enable_crypto($fp, true, $method) !== true) {
                throw new \RuntimeException('Could not start TLS with the SMTP server.');
            }
            $caps = self::ehlo($fp, $helo);
        }
        $user = (string) ($opts['user'] ?? '');
        if ($user !== '') {
            $password = (string) ($opts['password'] ?? '');
            $mechs = strtoupper(trim(($caps['AUTH'] ?? '') . ' ' . ($caps['AUTH='] ?? '')));
            $mechs = preg_split('/\s+/', $mechs) ?: [];
            if (in_array('PLAIN', $mechs, true) || !in_array('LOGIN', $mechs, true)) {
                self::command($fp, 'AUTH PLAIN ' . base64_encode("\0" . $user . "\0" . $password), [235], true);
            } else {
                self::command($fp, 'AUTH LOGIN', [334]);
                self::command($fp, base64_encode($user), [334], true);
                self::command($fp, base64_encode($password), [235], true);
            }
        }
        self::command($fp, 'MAIL FROM:<' . $from . '>', [250]);
        self::command($fp, 'RCPT TO:<' . $to . '>', [250, 251]);
        self::command($fp, 'DATA', [354]);
        $data = self::dotStuff($message);
        if (!str_ends_with($data, "\r\n")) {
            $data .= "\r\n";
        }
        self::write($fp, $data . ".\r\n");
        self::expect($fp, [250]);
        try {
            self::command($fp, 'QUIT', [221]);
        } catch (\Throwable) {
            // The message was accepted; a sloppy QUIT does not matter.
        }
    }

    private static function smtpSend(string $from, string $to, string $message): void
    {
        if (strlen($message) > self::MAX_BODY_BYTES) {
            throw new \RuntimeException('Message too large');
        }
        $host = (string) Config::get('smtp.host', '');
        if ($host === '' || !preg_match('/^[A-Za-z0-9.-]+$/', $host)) {
            throw new \RuntimeException('SMTP_HOST is not set or invalid');
        }
        $port = (int) Config::get('smtp.port', 587);
        $enc = strtolower((string) Config::get('smtp.encryption', 'tls'));
        $ctx = stream_context_create(['ssl' => [
            'verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => $host,
            'SNI_enabled' => true, 'allow_self_signed' => false,
        ]]);
        $remote = ($enc === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . max(1, min(65535, $port));
        $fp = @stream_socket_client($remote, $errno, $errstr, self::CONNECT_TIMEOUT, STREAM_CLIENT_CONNECT, $ctx);
        if (!is_resource($fp)) {
            throw new \RuntimeException('Could not connect to the SMTP server (' . (int) $errno . ').');
        }
        stream_set_timeout($fp, self::IO_TIMEOUT);
        try {
            $appHost = (string) parse_url((string) Config::get('app.url', ''), PHP_URL_HOST);
            self::smtpConverse($fp, [
                'helo'       => $appHost !== '' ? $appHost : 'localhost',
                'encryption' => $enc,
                'user'       => (string) Config::get('smtp.user', ''),
                'password'   => (string) Config::get('smtp.password', ''),
            ], $from, $to, $message);
        } finally {
            @fclose($fp);
        }
    }

    /** @param resource $fp @return array<string,string> capability keyword => parameters */
    private static function ehlo($fp, string $helo): array
    {
        self::write($fp, 'EHLO ' . $helo . "\r\n");
        [$code, $lines] = self::reply($fp);
        if ($code !== 250) {
            self::command($fp, 'HELO ' . $helo, [250]);
            return [];
        }
        $caps = [];
        foreach (array_slice($lines, 1) as $line) {
            $line = trim($line);
            if (str_starts_with(strtoupper($line), 'AUTH=')) {
                $caps['AUTH='] = trim(substr($line, 5));
                continue;
            }
            $parts = preg_split('/\s+/', $line, 2) ?: [''];
            $caps[strtoupper($parts[0])] = $parts[1] ?? '';
        }
        return $caps;
    }

    /** @param resource $fp @param int[] $ok */
    private static function command($fp, string $cmd, array $ok, bool $secret = false): void
    {
        if (preg_match('/[\r\n]/', $cmd)) {
            throw new \InvalidArgumentException('SMTP command contains a line break');
        }
        self::write($fp, $cmd . "\r\n");
        try {
            self::expect($fp, $ok);
        } catch (\RuntimeException $e) {
            // Never echo credentials back into logs or errors.
            throw new \RuntimeException(($secret ? 'SMTP authentication failed' : 'SMTP ' . strtok($cmd, ' :')) . ': ' . $e->getMessage());
        }
    }

    /** @param resource $fp @param int[] $ok */
    private static function expect($fp, array $ok): void
    {
        [$code, $lines] = self::reply($fp);
        if (!in_array($code, $ok, true)) {
            throw new \RuntimeException('unexpected reply ' . $code . ' ' . mb_substr(trim((string) end($lines)), 0, 120));
        }
    }

    /** @param resource $fp @return array{0:int,1:array<int,string>} */
    private static function reply($fp): array
    {
        $lines = [];
        for ($i = 0; $i < 100; $i++) {
            $line = fgets($fp, 1024);
            if ($line === false) {
                $meta = stream_get_meta_data($fp);
                throw new \RuntimeException(!empty($meta['timed_out']) ? 'the SMTP server timed out' : 'the SMTP connection was closed');
            }
            $line = rtrim($line, "\r\n");
            if (!preg_match('/^(\d{3})([ -]?)(.*)$/', $line, $m)) {
                throw new \RuntimeException('malformed SMTP reply');
            }
            $lines[] = $m[3];
            if ($m[2] !== '-') {
                return [(int) $m[1], $lines];
            }
        }
        throw new \RuntimeException('SMTP reply too long');
    }

    /** @param resource $fp */
    private static function write($fp, string $data): void
    {
        $len = strlen($data);
        for ($done = 0; $done < $len;) {
            $n = @fwrite($fp, substr($data, $done, 8192));
            if ($n === false || $n === 0) {
                $meta = stream_get_meta_data($fp);
                throw new \RuntimeException(!empty($meta['timed_out']) ? 'the SMTP server timed out' : 'could not write to the SMTP server');
            }
            $done += $n;
        }
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Sender: MAIL_FROM; else SMTP_USER when it is an address (most providers require the
     * authenticated mailbox anyway); the log driver falls back to a placeholder.
     */
    private static function fromAddress(): ?string
    {
        foreach ([(string) Config::get('mail.from', ''), (string) Config::get('smtp.user', '')] as $candidate) {
            $candidate = trim($candidate);
            if ($candidate !== '' && self::isValidAddress($candidate)) {
                return $candidate;
            }
        }
        if (self::driver() === 'log') {
            $host = strtolower((string) parse_url((string) Config::get('app.url', ''), PHP_URL_HOST));
            $candidate = 'noreply@' . ($host !== '' && str_contains($host, '.') ? $host : 'example.invalid');
            return self::isValidAddress($candidate) ? $candidate : 'noreply@example.invalid';
        }
        return null;
    }

    private static function assertSafe(string $to, string $subject): void
    {
        if (preg_match('/[\r\n]/', $to . $subject)) {
            throw new \InvalidArgumentException('Line breaks are not allowed in e-mail addresses or subjects.');
        }
        if (!self::isValidAddress($to)) {
            throw new \InvalidArgumentException('Invalid recipient address.');
        }
        if (mb_strlen($subject) > 255) {
            throw new \InvalidArgumentException('The subject is too long.');
        }
    }

    private static function formatAddress(string $address, string $name): string
    {
        if ($name === '') {
            return '<' . $address . '>';
        }
        if (preg_match('/^[A-Za-z0-9 !#$%&\'*+\/=?^_`{|}~.-]+$/', $name)) {
            return '"' . $name . '" <' . $address . '>';
        }
        return self::encodeHeader($name) . ' <' . $address . '>';
    }

    private static function crlf(string $s): string
    {
        return (string) preg_replace("/\r\n|\r|\n/", "\r\n", $s);
    }

    private static function qp(string $s): string
    {
        if (!mb_check_encoding($s, 'UTF-8')) {
            $s = mb_convert_encoding($s, 'UTF-8', 'UTF-8');
        }
        return quoted_printable_encode(self::crlf($s));
    }
}
