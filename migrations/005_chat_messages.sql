-- Migration 005: E2E chat — messages, channel keyring, chat public keys.
--
-- The server only ever stores ciphertext (see ARCHITECTURE.md §4):
-- - messages holds the E2E envelope per message (AES-256-GCM body + Ed25519
--   signature over "chatmsg:v1:<channel>:<key_version>:<nonce>:<ciphertext>").
-- - channel_keyring holds the symmetric channel key sealed per member
--   (ephemeral-static X25519, "sealed box") — the server can't read any entry.
-- - users.chat_public_key is the member's X25519 chat identity (base64),
--   published by the client after login; NULL until first publish.
--
-- Key rotation is versioned: (channel_id, key_version, user_id) is unique, and
-- clients insert a whole keyring version in one statement WITHOUT
-- ON CONFLICT — the first writer wins atomically, losers refetch and re-wrap
-- the winner's key (locked race decision).

ALTER TABLE users ADD COLUMN IF NOT EXISTS chat_public_key TEXT;

CREATE TABLE IF NOT EXISTS messages (
  id          BIGSERIAL   PRIMARY KEY,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  channel_id  UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  sender_id   UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  ciphertext  TEXT        NOT NULL,
  nonce       TEXT        NOT NULL,
  signature   TEXT        NOT NULL,
  key_version INTEGER     NOT NULL
);

-- History pagination + live "fetch after latest" both walk (channel_id, id).
CREATE INDEX IF NOT EXISTS idx_messages_channel_id_id
  ON messages (channel_id, id);

CREATE TABLE IF NOT EXISTS channel_keyring (
  id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  channel_id           UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  key_version          INTEGER     NOT NULL,
  user_id              UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  wrapped_by           UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  ephemeral_public_key TEXT        NOT NULL,
  ciphertext           TEXT        NOT NULL,
  nonce                TEXT        NOT NULL,
  UNIQUE (channel_id, key_version, user_id)
);

CREATE INDEX IF NOT EXISTS idx_channel_keyring_user_id
  ON channel_keyring (user_id);
