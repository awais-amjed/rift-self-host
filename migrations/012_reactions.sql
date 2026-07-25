-- Migration 012: Message reactions (channels + server DMs).
--
-- Reactions are deliberately NOT end-to-end encrypted (ARCHITECTURE.md §4): the
-- server stores who reacted to which message with which emoji, in the clear.
-- This is an accepted metadata trade-off for a Discord-like reaction UX — an
-- emoji tally can't be aggregated blindly the way an opaque ciphertext can.
--
-- One row per (message, user, emoji); toggling re-adds/removes it. Cascade on
-- message + user delete so reactions never outlive their target. Access is via
-- the service-role edge functions (toggle_reaction / list_reactions), so RLS is
-- enabled with no policies to lock out direct anon/authenticated access.
--
-- Idempotent — safe to re-run.

-- ── Channel message reactions ─────────────────────────────
CREATE TABLE IF NOT EXISTS message_reactions (
  message_id  BIGINT      NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id     UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  emoji       TEXT        NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 32),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id, emoji)
);

CREATE INDEX IF NOT EXISTS idx_message_reactions_message_id
  ON message_reactions (message_id);

ALTER TABLE message_reactions ENABLE ROW LEVEL SECURITY;

-- ── Server DM reactions ───────────────────────────────────
CREATE TABLE IF NOT EXISTS dm_message_reactions (
  message_id  BIGINT      NOT NULL REFERENCES dm_messages(id) ON DELETE CASCADE,
  user_id     UUID        NOT NULL REFERENCES users(id)       ON DELETE CASCADE,
  emoji       TEXT        NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 32),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id, emoji)
);

CREATE INDEX IF NOT EXISTS idx_dm_message_reactions_message_id
  ON dm_message_reactions (message_id);

ALTER TABLE dm_message_reactions ENABLE ROW LEVEL SECURITY;
