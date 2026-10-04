<?php
declare(strict_types=1);

namespace FT\Notifications;

use FT\Core\Config;
use FT\Core\Logger;
use FT\Core\Settings;
use FT\Jobs\Queue;

/**
 * Slack incoming-webhook notifications (the legacy feature, kept compatible).
 *
 *     Slack::notify('upload', ['Name' => 'report.pdf', 'By' => 'Alice', 'Size' => '1.2 MB', 'Folder' => 'Work']);
 *
 * notify() only queues a job (outbound HTTP never delays the user's request) and only when the
 * event is enabled in setting `slack_events` and a webhook is configured: setting
 * `slack_webhook_override` (stored encrypted), else env SLACK_WEBHOOK. Webhooks must be
 * https://hooks.slack.com/services/… — anything else is ignored (SSRF protection). The webhook URL
 * is a secret: it is resolved at delivery time and never stored in jobs, logs or responses.
 *
 * Message format (as before): Block Kit section with "<emoji> *UPPER-CASE TITLE*" and one
 * "*Key:* value" line per field. Times are 24-hour (UTC). For the "favorite" event pass
 * ['added' => false] to announce a removal; keys starting with "_" are never displayed.
 */
final class Slack
{
    /** event => [emoji, title] */
    public const EVENTS = [
        'upload'          => ['📤', 'New File Uploaded'],
        'delete'          => ['🗑️', 'File Deleted'],
        'batch_delete'    => ['🗑️', 'Batch Delete'],
        'share'           => ['🔗', 'File Shared'],
        'download'        => ['⬇️', 'File Downloaded'],
        'comment'         => ['💬', 'New Comment'],
        'text'            => ['📝', 'Text Saved'],
        'favorite'        => ['⭐', 'Added to Favourites'],
        'version_restore' => ['🕐', 'Version Restored'],
    ];

    private const WEBHOOK_PATTERN = '~^https://hooks\.slack\.com/services/[A-Za-z0-9_/-]{8,200}$~';
    private const PREVIEW_FIELDS = ['Comment', 'Preview'];
    private const NAME_FIELDS = ['Name', 'File'];

    /** Queue a Slack message for an event (no-op when disabled or not configured). Never throws. */
    public static function notify(string $event, array $fields): void
    {
        try {
            if (!isset(self::EVENTS[$event]) || !self::isEnabled($event) || !self::isValidWebhook(self::webhookUrl())) {
                return;
            }
            $clean = self::cleanFields($fields);
            if ($event === 'favorite' && array_key_exists('added', $fields)) {
                $clean['added'] = (bool) $fields['added']; // control flag, read by buildMessage()
            }
            Queue::push(self::class . '::deliverJob', [
                'event'  => $event,
                'fields' => $clean,
                'at'     => time(),
            ], 0, 'default', 2);
        } catch (\Throwable $e) {
            Logger::warning('app', 'Slack notification could not be queued', ['event' => $event, 'error' => $e->getMessage()]);
        }
    }

    /** @return string[] events switched on in setting slack_events */
    public static function enabledEvents(): array
    {
        $raw = Settings::string('slack_events', (string) Settings::DEFAULTS['slack_events']);
        $out = [];
        foreach (preg_split('/[\s,;]+/', strtolower($raw)) ?: [] as $e) {
            if (isset(self::EVENTS[$e])) {
                $out[$e] = true;
            }
        }
        return array_keys($out);
    }

    public static function isEnabled(string $event): bool
    {
        return in_array($event, self::enabledEvents(), true);
    }

    /** The configured webhook (admin override first, then SLACK_WEBHOOK); '' when none. */
    public static function webhookUrl(): string
    {
        $override = trim(Settings::string('slack_webhook_override', ''));
        return $override !== '' ? $override : trim((string) Config::get('slack.webhook', ''));
    }

    public static function isValidWebhook(string $url): bool
    {
        return $url !== '' && (bool) preg_match(self::WEBHOOK_PATTERN, $url) && !str_contains($url, '..') && strpos($url, '//', 8) === false;
    }

    /**
     * Block Kit payload for an event.
     * @param array<string,mixed> $fields display label => value
     * @return array{text:string,blocks:array<int,array<string,mixed>>}
     */
    public static function buildMessage(string $event, array $fields, ?int $time = null): array
    {
        [$emoji, $title] = self::EVENTS[$event] ?? ['📁', ucfirst(str_replace('_', ' ', $event))];
        if ($event === 'favorite') {
            // Either the documented ['added' => bool] flag or an "Action" field ("Removed from favourites").
            $action = is_string($fields['Action'] ?? null) ? $fields['Action'] : '';
            if ((array_key_exists('added', $fields) && !$fields['added']) || stripos(ltrim($action), 'removed') === 0) {
                [$emoji, $title] = ['☆', 'Removed from Favourites'];
            }
            unset($fields['Action']); // the heading already says it
        }
        $fields = self::cleanFields($fields);
        if (!array_key_exists('Time', $fields)) {
            $with = [];
            $timeValue = gmdate('d M Y, H:i', $time ?? time()) . ' UTC';
            foreach ($fields as $k => $v) {
                $with[$k] = $v;
                if ($k === 'By') {
                    $with['Time'] = $timeValue;
                }
            }
            if (!array_key_exists('Time', $with)) {
                $with['Time'] = $timeValue;
            }
            $fields = $with;
        }
        $lines = [$emoji . ' *' . strtoupper($title) . '*'];
        foreach ($fields as $k => $v) {
            $v = self::escape($v);
            if (in_array($k, self::NAME_FIELDS, true)) {
                $v = '`' . str_replace('`', "'", $v) . '`';
            }
            $lines[] = '*' . self::escape($k) . ':* ' . $v;
        }
        $text = implode("\n", $lines);
        return ['text' => $text, 'blocks' => [['type' => 'section', 'text' => ['type' => 'mrkdwn', 'text' => $text]]]];
    }

    /**
     * Queue handler. Re-checks the configuration (it may have changed since queueing); 429/5xx and
     * network errors are rethrown so the queue retries, other failures are logged.
     * @param array<string,mixed> $payload {event, fields, at}
     */
    public static function deliverJob(array $payload): void
    {
        $event = is_string($payload['event'] ?? null) ? $payload['event'] : '';
        $webhook = self::webhookUrl();
        if (!isset(self::EVENTS[$event]) || !self::isEnabled($event) || !self::isValidWebhook($webhook)) {
            return;
        }
        $fields = is_array($payload['fields'] ?? null) ? $payload['fields'] : [];
        $at = isset($payload['at']) ? (int) $payload['at'] : time();
        $res = self::post($webhook, self::buildMessage($event, $fields, $at));
        if ($res['status'] >= 200 && $res['status'] < 300) {
            return;
        }
        Logger::warning('app', 'Slack delivery failed', ['event' => $event, 'status' => $res['status'], 'error' => $res['error']]);
        if ($res['status'] === 0 || $res['status'] === 429 || $res['status'] >= 500) {
            throw new \RuntimeException('Slack is unavailable (HTTP ' . $res['status'] . ')');
        }
    }

    /** Admin "Send test message" button (A6): posts synchronously; true when Slack accepted it. */
    public static function test(string $webhook): bool
    {
        $webhook = trim($webhook);
        if (!self::isValidWebhook($webhook)) {
            return false;
        }
        $site = Notifier::siteName();
        $text = '⚡ *' . strtoupper($site) . ': SLACK CONNECTION TEST SUCCESSFUL!*' . "\n*Time:* " . gmdate('d M Y, H:i') . ' UTC';
        $res = self::post($webhook, ['text' => $text, 'blocks' => [['type' => 'section', 'text' => ['type' => 'mrkdwn', 'text' => $text]]]]);
        $ok = $res['status'] >= 200 && $res['status'] < 300;
        Logger::info('app', 'Slack test message ' . ($ok ? 'delivered' : 'failed'), ['status' => $res['status']]);
        return $ok;
    }

    /** @param array<string,mixed> $message @return array{status:int,body:string,error:?string} */
    private static function post(string $webhook, array $message): array
    {
        $json = json_encode($message, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        return Notifier::httpPost($webhook, (string) $json, ['Content-Type: application/json; charset=utf-8'], 'app');
    }

    /**
     * Scalars only, short values, no control keys or line breaks.
     * @param array<string,mixed> $fields
     * @return array<string,string>
     */
    private static function cleanFields(array $fields): array
    {
        $out = [];
        foreach ($fields as $k => $v) {
            if (!is_string($k) || $k === '' || $k === 'added' || $k[0] === '_' || count($out) >= 12) {
                continue;
            }
            if (is_bool($v)) {
                $v = $v ? 'Yes' : 'No';
            } elseif (is_int($v) || is_float($v)) {
                $v = (string) $v;
            } elseif (!is_string($v)) {
                continue;
            }
            $v = trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $v));
            $limit = in_array($k, self::PREVIEW_FIELDS, true) ? 80 : 200;
            if (mb_strlen($v) > $limit) {
                $v = mb_substr($v, 0, $limit) . '…';
            }
            $key = mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $k)), 0, 40);
            $out[$key] = $v;
        }
        return $out;
    }

    /** Slack mrkdwn needs &, < and > escaped (otherwise "<!channel>" etc. would be interpreted). */
    private static function escape(string $s): string
    {
        return str_replace(['&', '<', '>'], ['&amp;', '&lt;', '&gt;'], $s);
    }
}
