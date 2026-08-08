-- ============================================================
-- Rift self-hosted server — 006: scheduled cleanup
-- ============================================================
-- One job. There used to be four: two swept the auth-challenge and token tables
-- that GoTrue replaced, and one pruned `notifications` — a table that existed
-- only to be counted and therefore only to be cleaned up. Read cursors don't
-- accumulate, so nothing prunes them.
--
-- Messages are never swept here. A self-hosted server is somebody's own
-- hardware and their own retention policy; deleting their history on a timer is
-- the central tier's bargain, not this one's.

SELECT cron.unschedule('cleanup-expired-invites')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-expired-invites');

SELECT cron.schedule(
  'cleanup-expired-invites',
  '0 * * * *',
  $$DELETE FROM invites WHERE expires_at IS NOT NULL AND expires_at < now()$$
);
