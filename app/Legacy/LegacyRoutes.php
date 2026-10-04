<?php
declare(strict_types=1);

namespace FT\Legacy;

/**
 * Recognises URLs of the pre-upgrade single-file app (every handler there was triggered by a
 * query parameter on the root URL, e.g. "/?share=<token>" or "/?download=<name>"). index.php asks
 * matches($_GET) for requests to "/" and, when true, routes them to /legacy (LegacyController)
 * so bookmarks and share links made before the upgrade keep working.
 *
 * Only the presence of a trigger key matters; values are validated by the controller. The host's
 * JavaScript cookie check appends "?i=1..3" — that is deliberately NOT a trigger.
 */
final class LegacyRoutes
{
    /** Every query trigger the legacy index.php reacted to (inventory §A). */
    public const TRIGGERS = [
        'share', 'download', 'serve', 'logout', 'download_zip', 'delete_day', 'delete_texts_day',
        'bulk_share', 'activity_stream', 'activity_poll', 'fetch_meta', 'ocr_search', 'ocr_file',
        'push_subscribe', 'push_vapid_key', 'collab_get', 'collab_save', 'collab_presence', 'batch_zip',
        'get_comments', 'add_comment', 'delete_comment', 'get_versions', 'restore_version', 'serve_version',
        'trends_data', 'test_slack', 'save_slack', 'search_api', 'add_tag', 'remove_tag', 'batch_delete',
        'batch_move', 'batch_tag', 'create_share', 'revoke_share', 'create_folder', 'delete_folder',
        'move_file', 'toggle_fav', 'delete_file', 'delete_text', 'toggle_perm_text', 'toggle_perm_file',
        '__host_check',
    ];

    /** @param array<string,mixed> $get the query parameters of a request to the app root */
    public static function matches(array $get): bool
    {
        if (isset($get['r']) && is_string($get['r']) && $get['r'] !== '' && $get['r'] !== '/') {
            return false; // an explicit route (non-rewrite URL style) always wins
        }
        foreach (self::TRIGGERS as $key) {
            if (array_key_exists($key, $get)) {
                return true;
            }
        }
        return false;
    }

    /** The legacy share token rule: alphanumerics only (the old app stripped everything else). */
    public static function cleanToken(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $t = preg_replace('/[^A-Za-z0-9]/', '', $value) ?? '';
        return ($t !== '' && strlen($t) <= 64) ? $t : null;
    }

    /**
     * The legacy filename rule (sanitizeFileName): basename, no control characters, anything
     * outside [A-Za-z0-9._ -] became "_". Used to look up files.legacy_name.
     */
    public static function cleanName(mixed $value): ?string
    {
        if (!is_string($value) || $value === '' || strlen($value) > 1024) {
            return null;
        }
        $name = basename(str_replace('\\', '/', $value));
        $name = preg_replace('/\p{C}+/u', '', $name) ?? '';
        $name = preg_replace('/[^A-Za-z0-9._ \-]/', '_', $name) ?? '';
        if ($name === '' || $name === '.' || $name === '..' || $name[0] === '.') {
            return null;
        }
        return mb_substr($name, 0, 255);
    }
}
