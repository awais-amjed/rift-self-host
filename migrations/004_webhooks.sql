-- ============================================================
-- Rift self-hosted server — 004: Messages from things that cannot log in
-- ============================================================
-- One endpoint anybody may call, one statement behind it, and the rate
-- limiting that makes that safe to offer.
--
-- Was 1 file: 013_webhooks.
-- Merged unchanged and in the same order, so this applies exactly what
-- they applied. The sections below are those files, each still carrying
-- the reasoning it was written with.
-- ============================================================

-- ============================================================
-- Rift self-hosted server — 013: webhooks (unencrypted messages)
-- ============================================================
-- The first thing in this schema that writes a message the server can read.
--
-- An incoming webhook is a URL an outside service POSTs to, which appears as a
-- message. The point of one is that **nobody runs anything**: GitHub is never
-- going to implement SIWS, and a community should not have to keep a process
-- alive to receive build notifications. That is also why a bot cannot replace
-- it — a bot is a program somebody hosts, and this exists precisely for the
-- case where there is no program.
--
-- Encryption was the whole obstacle. The server holds no channel key and never
-- will, so it cannot seal what arrives at that URL. Three ways out were on the
-- table (BOTS.md §2 argues them at length); this is the third:
--
--   * escrow the channel key server-side — turns "readable by a member who is
--     present" into "readable by a process, forever". Refused.
--   * a plaintext *channel* type — makes encryption the thing people turn off
--     for convenience, which is how it stops meaning anything.
--   * a plaintext *message* inside an ordinary encrypted channel.
--
-- So `key_version = 0` means **this body is not encrypted**. The column already
-- exists, every client already branches on it, and the CHECK simply widens by
-- one. A CI feed can sit in #dev next to the argument about the build it broke,
-- and #dev stays encrypted for everything a person says in it.
--
-- ---------- what the client must do with these ----------
--
-- ARCHITECTURE.md §4 locks in that every message is Ed25519-signed and an
-- unverifiable one is never rendered. That rule is untouched **for
-- key_version >= 1**. At version 0 there is no signer at all: GitHub holds no
-- Rift key, and the row is attested by the server that accepted the POST and by
-- nothing else.
--
-- Hence `origin_name` rather than a `sender_id` pointing anywhere. A webhook
-- message is not from a person, must never be attributed to one, and must be
-- rendered with its origin visible. A client that draws these like ordinary
-- messages has broken the only promise this migration makes.
--
-- ---------- why the name is on the message ----------
--
-- `webhook_id` is a reference for management: which integration posted this,
-- what to rate-limit, what to revoke. It is deliberately NOT what the row is
-- rendered from. Deleting a webhook must not rewrite the history it posted, and
-- ON DELETE SET NULL would otherwise leave rows with no name and no sender.
--
-- So the display name is denormalised onto the message at insert and frozen
-- there. Deleting a webhook then removes the credential and leaves the record,
-- which is the same shape as a deleted member's messages surviving them.

-- ============================================================
-- 1. Messages may be unencrypted
-- ============================================================

ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS webhook_id  UUID,
  ADD COLUMN IF NOT EXISTS origin_name TEXT;

-- A member's row still carries all three. A webhook's carries none of them:
-- there is no key, so there is no nonce, and no keypair, so no signature.
ALTER TABLE messages ALTER COLUMN sender_id DROP NOT NULL;
ALTER TABLE messages ALTER COLUMN nonce     DROP NOT NULL;
ALTER TABLE messages ALTER COLUMN signature DROP NOT NULL;

ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_key_version_check;
ALTER TABLE messages ADD  CONSTRAINT messages_key_version_check
  CHECK (key_version >= 0);

-- Exactly one origin. Both set is a message pretending to be two things;
-- neither is a message from nobody.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_one_origin;
ALTER TABLE messages ADD  CONSTRAINT messages_one_origin
  CHECK ((sender_id IS NOT NULL) <> (origin_name IS NOT NULL));

-- A non-member message is always in the clear. Nothing without a seed can
-- produce a sealed envelope, so the reverse would be unopenable by anyone.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_origin_is_plain;
ALTER TABLE messages ADD  CONSTRAINT messages_origin_is_plain
  CHECK (origin_name IS NULL OR key_version = 0);

-- ...and for now, the converse: version 0 is *only* reachable by a webhook.
-- Bot commands (BOTS.md §4) will relax this to let a member write a plaintext
-- row addressed to a bot. Until they exist, a member sending version 0 is a
-- modified client trying to publish in the clear under a person's name, and
-- there is no reason to accept it.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_plain_is_origin;
ALTER TABLE messages ADD  CONSTRAINT messages_plain_is_origin
  CHECK (key_version >= 1 OR origin_name IS NOT NULL);

-- Envelope fields are required exactly when there is an envelope.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_envelope_complete;
ALTER TABLE messages ADD  CONSTRAINT messages_envelope_complete
  CHECK (key_version = 0 OR (nonce IS NOT NULL AND signature IS NOT NULL));

ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_origin_name_len;
ALTER TABLE messages ADD  CONSTRAINT messages_origin_name_len
  CHECK (origin_name IS NULL OR length(origin_name) BETWEEN 1 AND 80);

COMMENT ON COLUMN messages.key_version IS
  '0 = the body is NOT encrypted (webhook; later, bot commands). >= 1 = sealed '
  'under that channel key version, signed, and dropped by clients if the '
  'signature does not verify.';
COMMENT ON COLUMN messages.origin_name IS
  'Display name for a message no member sent. Frozen at insert so deleting the '
  'webhook does not rewrite its history. NULL for a member message.';

-- ============================================================
-- 2. The webhooks themselves
-- ============================================================
-- The URL *is* the credential — that is what makes a webhook usable by a
-- service that cannot log in, and it is also its weakness: a URL ends up in CI
-- config, in a screenshot, in a paste. So it is stored hashed (shown once, at
-- creation, and never again) and it is rate-limited.

CREATE TABLE IF NOT EXISTS webhooks (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  server_id    UUID        NOT NULL REFERENCES servers(id)  ON DELETE CASCADE,
  channel_id   UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  -- Who minted it, so a member can manage their own under RLS. SET NULL rather
  -- than CASCADE: the integration outlives whoever set it up.
  created_by   UUID        REFERENCES users(id) ON DELETE SET NULL,
  name         TEXT        NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  -- SHA-256 of the secret, hex. The secret itself is never stored.
  secret_hash  TEXT        NOT NULL UNIQUE,
  last_used_at TIMESTAMPTZ,
  -- Fixed window, reset on first post of a new minute. Coarse on purpose: the
  -- job is to bound a leaked URL, not to shape traffic.
  rate_window  TIMESTAMPTZ,
  rate_count   INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_webhooks_channel ON webhooks (channel_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_server  ON webhooks (server_id);

-- Deleting a webhook leaves its messages: they render from `origin_name`.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_webhook_id_fkey;
ALTER TABLE messages ADD  CONSTRAINT messages_webhook_id_fkey
  FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_messages_webhook
  ON messages (webhook_id) WHERE webhook_id IS NOT NULL;

-- ============================================================
-- 3. Attestation
-- ============================================================
-- Replaces 001's `attest_message`, which stamped `sender_id := auth.uid()`
-- unconditionally. That is still right for a member — and it is why a webhook
-- row comes out with a NULL sender for free, since the service role has no
-- `auth.uid()`. What it needs on top is to stop a *member* claiming to be one.

CREATE OR REPLACE FUNCTION attest_message()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.sender_id  := auth.uid();
    NEW.created_at := now();
    NEW.edited_at  := NULL;

    -- A member's insert is never a webhook's, whatever it sent. Only the
    -- service role (no auth.uid()) reaches the other branch, and it gets there
    -- through post_webhook_message below.
    IF NEW.sender_id IS NOT NULL THEN
      NEW.webhook_id  := NULL;
      NEW.origin_name := NULL;
    END IF;
    RETURN NEW;
  END IF;

  -- An edit may only change the envelope. Identity, placement and time of
  -- sending are the server's word and stay put; edited_at is stamped here
  -- rather than trusted from the client.
  NEW.id         := OLD.id;
  NEW.sender_id  := OLD.sender_id;
  NEW.created_at := OLD.created_at;
  IF TG_TABLE_NAME = 'messages' THEN
    NEW.channel_id  := OLD.channel_id;
    -- The displayed name is frozen; the reference is not.
    --
    -- `webhook_id` is deliberately NOT pinned here, and that is not an
    -- oversight. `ON DELETE SET NULL` is implemented as an UPDATE, so this
    -- trigger fires during the cascade — pinning the column put the id back,
    -- and the FK then rejected its own cascade. Deleting a webhook that had
    -- ever posted was impossible.
    --
    -- Nothing is lost by leaving it open: `authenticated` holds a column-level
    -- UPDATE grant on (ciphertext, nonce, signature, key_version) only, so no
    -- member can write `webhook_id` by hand in the first place.
    NEW.origin_name := OLD.origin_name;
  ELSE
    NEW.recipient_id := OLD.recipient_id;
  END IF;
  IF NEW.ciphertext IS DISTINCT FROM OLD.ciphertext THEN
    NEW.edited_at := now();
  ELSE
    NEW.edited_at := OLD.edited_at;
  END IF;
  RETURN NEW;
END; $$;

-- ---------- the NULL that would have gone quiet ----------
-- `ring_channel_members` excluded the sender with `u.id <> NEW.sender_id`.
-- Against a NULL sender that comparison is NULL, not true, so the WHERE dropped
-- **every** row and a webhook message would have woken nobody at all — silently,
-- and only for the messages a human did not send.
CREATE OR REPLACE FUNCTION ring_channel_members()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
  v_targets   UUID[];
BEGIN
  SELECT server_id INTO v_server_id FROM channels WHERE id = NEW.channel_id;
  IF v_server_id IS NULL THEN RETURN NEW; END IF;

  SELECT array_agg(u.id) INTO v_targets
    FROM users u
   WHERE u.server_id = v_server_id
     AND u.id IS DISTINCT FROM NEW.sender_id
     AND NOT u.is_banned
     AND NOT has_unread_before(u.id, 'channel', NEW.channel_id, NEW.id);

  PERFORM ring_devices(v_server_id, v_targets);
  RETURN NEW;
END; $$;

-- `validate_message_mentions` needs no change and is left alone deliberately.
-- Its join has `u.id <> NEW.sender_id`, so against a NULL sender it keeps
-- nothing — a webhook cannot mention anybody, cannot @all, and therefore cannot
-- be used to ring every phone on a server from a URL. That is the behaviour we
-- want; it is only an accident that it is also the behaviour we already had.

-- ============================================================
-- 4. Security
-- ============================================================

ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;

-- New tables arrive writable by `authenticated` and new functions executable by
-- PUBLIC. Neither default is wanted here.
REVOKE ALL ON webhooks FROM anon, authenticated;

-- No INSERT and no UPDATE grant at all: creating one has to mint a secret, and
-- a secret the caller chose is not a secret. That goes through create_webhook.
-- SELECT is column-scoped so `secret_hash` never leaves the database, even to
-- the admin who made it.
GRANT SELECT (id, created_at, server_id, channel_id, created_by, name,
              last_used_at)
  ON webhooks TO authenticated;
GRANT DELETE ON webhooks TO authenticated;

DROP POLICY IF EXISTS webhooks_select ON webhooks;
CREATE POLICY webhooks_select ON webhooks FOR SELECT TO authenticated
  USING (server_id = app.server_id() AND app.can_manage_channels());

-- Whoever may delete the channel may delete what posts into it.
DROP POLICY IF EXISTS webhooks_delete ON webhooks;
CREATE POLICY webhooks_delete ON webhooks FOR DELETE TO authenticated
  USING (server_id = app.server_id() AND app.can_manage_channels());

-- A member may not write a webhook row's columns by hand.
DROP POLICY IF EXISTS messages_insert ON messages;
CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    app.channel_server_id(channel_id) = app.server_id()
    AND sender_id = auth.uid()
    AND webhook_id IS NULL
    AND origin_name IS NULL
  );

-- ============================================================
-- 5. Managing them
-- ============================================================

-- 32 bytes, hex. URL-safe by construction, which base64 is not, and this ends
-- up in a URL that gets pasted into CI config by hand.
CREATE OR REPLACE FUNCTION new_webhook_secret() RETURNS TEXT
  LANGUAGE sql VOLATILE SET search_path = public, extensions AS $$
  SELECT encode(gen_random_bytes(32), 'hex')
$$;

-- Returns the secret **once**. There is no way to read it back afterwards; a
-- lost URL is replaced by deleting the webhook and making another.
CREATE OR REPLACE FUNCTION create_webhook(
  p_channel_id UUID,
  p_name       TEXT
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_server_id UUID;
  v_secret    TEXT;
  v_id        UUID;
  v_count     INTEGER;
BEGIN
  IF NOT app.can_manage_channels() THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  SELECT server_id INTO v_server_id FROM channels WHERE id = p_channel_id;
  IF v_server_id IS NULL OR v_server_id <> app.server_id() THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  IF p_name IS NULL OR length(trim(p_name)) = 0 THEN
    RETURN jsonb_build_object('reason', 'bad_name');
  END IF;

  -- A ceiling per channel, so a compromised admin account cannot quietly leave
  -- a hundred ways back in.
  SELECT count(*) INTO v_count FROM webhooks WHERE channel_id = p_channel_id;
  IF v_count >= 10 THEN
    RETURN jsonb_build_object('reason', 'too_many');
  END IF;

  v_secret := new_webhook_secret();

  INSERT INTO webhooks (server_id, channel_id, created_by, name, secret_hash)
  VALUES (
    v_server_id, p_channel_id, auth.uid(), left(trim(p_name), 80),
    encode(digest(v_secret, 'sha256'), 'hex')
  )
  RETURNING id INTO v_id;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'id',     v_id,
    'secret', v_secret
  );
END; $$;

REVOKE ALL ON FUNCTION create_webhook(UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION create_webhook(UUID, TEXT) TO authenticated;

REVOKE ALL ON FUNCTION new_webhook_secret() FROM PUBLIC;

-- ============================================================
-- 6. Posting through one
-- ============================================================
-- The lookup, the rate check and the insert are one statement so a caller
-- cannot sit between them. It runs as the service role — reached only by the
-- `webhook` edge function, which is the part that can be called without a JWT.
--
-- The rule lives here rather than in the edge function for the usual reason:
-- an edge function is one way to reach a row, and the row should be able to
-- defend itself against the next one.

CREATE OR REPLACE FUNCTION post_webhook_message(
  p_secret TEXT,
  p_text   TEXT
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_hook       webhooks%ROWTYPE;
  v_id         BIGINT;
  v_window     TIMESTAMPTZ := date_trunc('minute', now());
  v_per_minute CONSTANT INTEGER := 30;
BEGIN
  IF p_secret IS NULL OR length(p_secret) <> 64 THEN
    RETURN jsonb_build_object('reason', 'no_such_webhook');
  END IF;

  SELECT * INTO v_hook FROM webhooks
   WHERE secret_hash = encode(digest(p_secret, 'sha256'), 'hex')
   FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('reason', 'no_such_webhook');
  END IF;

  IF p_text IS NULL OR length(trim(p_text)) = 0 THEN
    RETURN jsonb_build_object('reason', 'empty');
  END IF;
  -- The same ceiling `ciphertext` already carries. A webhook body is plain
  -- text in that column, so the column's limit is the limit.
  IF length(p_text) > 16384 THEN
    RETURN jsonb_build_object('reason', 'too_long');
  END IF;

  IF v_hook.rate_window IS DISTINCT FROM v_window THEN
    UPDATE webhooks SET rate_window = v_window, rate_count = 0
     WHERE id = v_hook.id;
    v_hook.rate_count := 0;
  ELSIF v_hook.rate_count >= v_per_minute THEN
    RETURN jsonb_build_object('reason', 'rate_limited');
  END IF;

  INSERT INTO messages (
    channel_id, ciphertext, nonce, signature, key_version,
    webhook_id, origin_name
  ) VALUES (
    v_hook.channel_id, p_text, NULL, NULL, 0,
    v_hook.id, v_hook.name
  )
  RETURNING id INTO v_id;

  UPDATE webhooks
     SET rate_count = rate_count + 1, last_used_at = now()
   WHERE id = v_hook.id;

  RETURN jsonb_build_object(
    'reason',     'ok',
    'message_id', v_id,
    'channel_id', v_hook.channel_id,
    'server_id',  v_hook.server_id
  );
END; $$;

-- Not `authenticated`, and certainly not PUBLIC: the only caller is the edge
-- function holding the service key. A member reaching this would be able to
-- post under any name in any channel by guessing a secret, without the rate
-- limit ever having to be right.
REVOKE ALL ON FUNCTION post_webhook_message(TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION post_webhook_message(TEXT, TEXT) TO service_role;
