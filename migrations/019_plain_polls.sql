-- ============================================================
-- Rift self-hosted server — 019: polls where encryption is off
-- ============================================================
-- `messages_poll_sealed` let only a sealed message carry a poll, so that a
-- member's poll could never be the one thing they wrote that the server can
-- read. A channel whose encryption was turned off (015) is exactly a place
-- where everything a member writes is read by the server, and there the
-- check refused every poll: the client posted it in the clear like the rest
-- of the channel, and the insert failed. Found driving the web app Oct 17.
--
-- What keeps a clear poll out of an encrypted channel is now
-- `messages_insert`, which already decides where a member may post in the
-- clear: a poll may not be addressed to a bot, nor posted by one, so the only
-- clear poll it lets through is a member's in a channel that is not
-- encrypted. What the check also said without saying it — a webhook, which
-- always writes in the clear, posts no poll — is kept as its own check.
-- ============================================================

ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_poll_sealed;
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_poll_has_sender;
ALTER TABLE messages ADD CONSTRAINT messages_poll_has_sender
  CHECK (poll IS NULL OR sender_id IS NOT NULL);

COMMENT ON COLUMN messages.poll IS
  'The rules of a poll, in the clear because the server enforces them: how '
  'many options, whether several may be picked, when voting stops. The '
  'question and options are in the body, sealed unless the channel''s '
  'encryption is off.';
