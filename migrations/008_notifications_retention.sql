-- Migration 008: Bound the notifications table's growth.
--
-- `send_message` fans out one notification row per recipient per channel message
-- (migration 007), so the table grows as members × messages and never shrinks on
-- its own. Notifications are only a transient *signal* — they drive the live OS
-- notification and (soon) an unread badge; they are NOT the source of truth for
-- messages (that's `messages`, fetched normally when a channel opens). So they
-- don't need long retention and can be pruned on a schedule.
--
-- Retention (both tunable — the point is a hard bound, not the exact number):
--   * read notifications        → dropped 1 day after being read (short grace so
--                                 a second device can still observe the read).
--   * any notification          → dropped after 7 days (a week-old "new message"
--                                 ping is a stale signal; the message persists).
--
-- Requires pg_cron (enabled in migration 001). Idempotent — safe to re-run.

-- Index the age-based prune predicate.
CREATE INDEX IF NOT EXISTS idx_notifications_created_at
  ON notifications (created_at);

-- (Re)schedule the hourly prune.
SELECT cron.unschedule('cleanup-notifications')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-notifications');

SELECT cron.schedule(
  'cleanup-notifications',
  '0 * * * *',  -- hourly
  $$DELETE FROM notifications
     WHERE (read_at IS NOT NULL AND read_at < now() - interval '1 day')
        OR created_at < now() - interval '7 days'$$
);
