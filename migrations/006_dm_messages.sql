-- Migration 006: E2E direct messages between members of this server
-- (ARCHITECTURE.md §4, Design 1 — encrypt to identity).
--
-- Same opaque-envelope shape as channel messages, but keyed by the DM pair:
-- the message key is derived client-side via X25519 DH between the two
-- members' chat identities, so there is no keyring — nothing to store beyond
-- the envelope. key_version is 1 for DMs (no rotation; kept for wire-format
-- symmetry with channel messages).
--
-- Signatures bind to the conversation: the signed context id is
-- "dm:<lowerUserId>:<higherUserId>" (uuid string sort), so an envelope can't
-- be replayed into another conversation or a channel.

CREATE TABLE IF NOT EXISTS dm_messages (
  id           BIGSERIAL   PRIMARY KEY,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sender_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext   TEXT        NOT NULL,
  nonce        TEXT        NOT NULL,
  signature    TEXT        NOT NULL,
  key_version  INTEGER     NOT NULL,
  CHECK (sender_id <> recipient_id)
);

-- Pair-scoped history walks (both directions of one conversation).
CREATE INDEX IF NOT EXISTS idx_dm_messages_pair
  ON dm_messages (LEAST(sender_id, recipient_id),
                  GREATEST(sender_id, recipient_id), id);

-- Conversation-list scans from either side.
CREATE INDEX IF NOT EXISTS idx_dm_messages_sender    ON dm_messages (sender_id, id);
CREATE INDEX IF NOT EXISTS idx_dm_messages_recipient ON dm_messages (recipient_id, id);
