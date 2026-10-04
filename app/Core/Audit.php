<?php
declare(strict_types=1);

namespace FT\Core;

/**
 * Durable activity/audit log. This is the source for per-file activity timelines, the
 * Security Centre's security events, and the admin activity view.
 *
 * Action naming: "<area>.<verb>", e.g.
 *   file.upload file.download file.preview file.rename file.move file.trash file.restore
 *   file.purge file.version_upload file.version_restore file.comment file.edit
 *   folder.create folder.rename folder.move folder.trash folder.restore folder.purge
 *   share.create share.update share.revoke share.access share.download share.expired
 *   auth.login auth.login_failed auth.logout auth.2fa_enabled auth.2fa_disabled
 *   auth.password_changed auth.session_revoked auth.token_created auth.token_revoked
 *   admin.user_create admin.user_update admin.user_disable admin.user_enable admin.user_delete
 *   admin.password_reset admin.role_change admin.quota_change admin.force_logout admin.settings
 *   system.maintenance system.migration system.import
 */
final class Audit
{
    /**
     * @param array{
     *   user_id?:?int, actor_label?:?string, category?:string, target_type?:?string,
     *   target_id?:?int, owner_id?:?int, detail?:?string, meta?:array<string,mixed>
     * } $o
     */
    public static function log(string $action, array $o = []): void
    {
        try {
            Db::insert('audit_logs', [
                'user_id'     => array_key_exists('user_id', $o) ? $o['user_id'] : RequestContext::userId(),
                'actor_label' => isset($o['actor_label']) ? mb_substr((string) $o['actor_label'], 0, 100) : null,
                'action'      => mb_substr($action, 0, 48),
                'category'    => $o['category'] ?? (str_starts_with($action, 'auth.') ? 'security' : (str_starts_with($action, 'admin.') ? 'admin' : (str_starts_with($action, 'system.') ? 'system' : 'activity'))),
                'target_type' => $o['target_type'] ?? null,
                'target_id'   => isset($o['target_id']) ? (int) $o['target_id'] : null,
                'owner_id'    => isset($o['owner_id']) ? (int) $o['owner_id'] : null,
                'detail'      => isset($o['detail']) ? mb_substr((string) $o['detail'], 0, 500) : null,
                'meta'        => isset($o['meta']) ? json_encode(Logger::redact($o['meta']), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null,
                'ip'          => RequestContext::ip(),
                'user_agent'  => RequestContext::userAgent(),
                'created_at'  => Db::now(),
            ]);
        } catch (\Throwable $e) {
            Logger::exception('app', $e, ['audit_action' => $action]);
        }
    }
}
