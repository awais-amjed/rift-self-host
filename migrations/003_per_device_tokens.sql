-- Migration 003: Allow one session token per device instead of per user.
--
-- tokens.user_id previously had a UNIQUE constraint, so a login on one device
-- deleted/replaced the token of every other device — two devices logged in at
-- once would invalidate each other in an endless refresh ping-pong.
--
-- Dropping the constraint lets each device hold its own token row. Expired
-- rows are already garbage-collected by the cleanup-expired-tokens cron job,
-- and verify_challenge now always inserts a fresh row per successful login.

ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_user_id_key;

-- The non-unique idx_tokens_user_id index from 001 remains for lookups.
