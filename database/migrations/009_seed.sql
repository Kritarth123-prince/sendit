-- 009_seed: roles, permissions and default runtime settings (idempotent).

INSERT IGNORE INTO roles (id, slug, name, description) VALUES
  (1, 'admin', 'Admin', 'Full access including user management and system settings'),
  (2, 'user',  'User',  'Own drive: upload, organise, share and collaborate'),
  (3, 'guest', 'Guest', 'Read-only: sees only what others share with them');

INSERT IGNORE INTO permissions (slug, description) VALUES
  ('files.view',        'See own files and files shared with them'),
  ('files.upload',      'Upload files and create folders in own drive'),
  ('files.edit',        'Rename, move, tag and version own files'),
  ('files.delete',      'Move own files to trash and empty own trash'),
  ('files.share',       'Create share links and share with other users'),
  ('files.comment',     'Comment on files they can comment on'),
  ('texts.manage',      'Use the text/URL clipboard'),
  ('search.use',        'Search'),
  ('api.tokens',        'Create personal API tokens'),
  ('admin.access',      'Open the admin area'),
  ('admin.users',       'Create, edit, disable and delete users'),
  ('admin.storage',     'View storage, set quotas, manage all trash'),
  ('admin.shares',      'View and revoke any share'),
  ('admin.activity',    'View the global audit/activity log'),
  ('admin.system',      'Change system settings, run maintenance and migrations');

-- admin: everything
INSERT IGNORE INTO role_permissions (role_id, permission_id)
  SELECT 1, id FROM permissions;

-- user: everything except admin.*
INSERT IGNORE INTO role_permissions (role_id, permission_id)
  SELECT 2, id FROM permissions WHERE slug NOT LIKE 'admin.%';

-- guest: view, comment (where a share allows it), search
INSERT IGNORE INTO role_permissions (role_id, permission_id)
  SELECT 3, id FROM permissions WHERE slug IN ('files.view', 'files.comment', 'search.use');

INSERT IGNORE INTO settings (`key`, `value`, is_secret, updated_at) VALUES
  ('site_name',                    'FastTransfer', 0, UTC_TIMESTAMP()),
  ('default_quota_bytes',          '1073741824',   0, UTC_TIMESTAMP()),
  ('guest_quota_bytes',            '0',            0, UTC_TIMESTAMP()),
  ('max_upload_bytes',             '209715200',    0, UTC_TIMESTAMP()),
  ('blocked_extensions',           '',             0, UTC_TIMESTAMP()),
  ('trash_retention_days',         '30',           0, UTC_TIMESTAMP()),
  ('version_retention_count',      '5',            0, UTC_TIMESTAMP()),
  ('version_retention_days',       '0',            0, UTC_TIMESTAMP()),
  ('auto_expire_hours',            '72',           0, UTC_TIMESTAMP()),
  ('text_auto_expire_hours',       '72',           0, UTC_TIMESTAMP()),
  ('dedup_scope',                  'user',         0, UTC_TIMESTAMP()),
  ('event_retention_days',         '7',            0, UTC_TIMESTAMP()),
  ('audit_retention_days',         '365',          0, UTC_TIMESTAMP()),
  ('login_history_retention_days', '180',          0, UTC_TIMESTAMP()),
  ('notification_retention_days',  '90',           0, UTC_TIMESTAMP()),
  ('upload_session_ttl_hours',     '24',           0, UTC_TIMESTAMP()),
  ('bundle_ttl_hours',             '24',           0, UTC_TIMESTAMP()),
  ('quota_warning_percent',        '90',           0, UTC_TIMESTAMP()),
  ('session_idle_minutes',         '720',          0, UTC_TIMESTAMP()),
  ('remember_days',                '30',           0, UTC_TIMESTAMP()),
  ('login_max_attempts',           '5',            0, UTC_TIMESTAMP()),
  ('login_window_minutes',         '15',           0, UTC_TIMESTAMP()),
  ('registration_enabled',         '0',            0, UTC_TIMESTAMP()),
  ('ocr_enabled',                  '1',            0, UTC_TIMESTAMP()),
  ('slack_events',                 'upload,delete,share,download,comment,text,favorite,version_restore,batch_delete', 0, UTC_TIMESTAMP());
