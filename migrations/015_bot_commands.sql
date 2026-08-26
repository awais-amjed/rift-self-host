-- ============================================================
-- Rift self-hosted server — 015: bot commands
-- ============================================================
-- BOTS.md phase 2, and the migration where the rule the whole design rests on
-- finally becomes a policy rather than a sentence:
--
--   **A bot hears what you tell it, not what you say.**
--
-- 013 made a message the server can read. 014 made a user that can never hold a
-- channel key. This joins them: a member may write one of those plaintext rows
-- *addressed to a bot*, and a bot may read exactly the rows addressed to it.
--
-- ---------- why the CHECK moves to the policy ----------
--
-- 013 said `key_version >= 1 OR origin_name IS NOT NULL` — a member could not
-- write in the clear at all, because at the time nothing legitimate would. That
-- has to relax now, and the obvious relaxation is wrong:
--
--   CHECK (key_version >= 1 OR origin_name IS NOT NULL OR to_bot IS NOT NULL)
--
-- `to_bot` references a user, and a bot that is removed takes its FK with it.
-- Whatever the action — SET NULL, or a future one — a row that satisfied the
-- constraint at insert would stop satisfying it later, and the same trigger
-- that already broke webhook deletion once (013) would break it again.
--
-- So the split is: **CHECKs guard the shape of a row, policies guard who may
-- write one.** `messages_one_origin` still says every message has exactly one
-- origin. Whether a member is *allowed* to send in the clear is an
-- insert-time question about the sender, which is what a policy is for and
-- what nothing later can retroactively violate.

-- ============================================================
-- 1. Addressing
-- ============================================================

ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS to_bot UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_messages_to_bot
  ON messages (to_bot, id) WHERE to_bot IS NOT NULL;

COMMENT ON COLUMN messages.to_bot IS
  'The bot this message is addressed to — a `/` command. Plaintext by '
  'necessity: the bot holds no channel key, so a sealed command would be one '
  'it could not open. NULL for every ordinary message.';

-- A member may now write in the clear, but only as a command. See the header
-- for why this is not a CHECK.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_plain_is_origin;

-- ============================================================
-- 2. Who is a bot
-- ============================================================

CREATE OR REPLACE FUNCTION app.is_bot() RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((SELECT u.is_bot FROM users u WHERE u.id = auth.uid()), false)
$$;

-- Is this a bot on my server that could actually act on a command? A command
-- addressed to a person would be a plaintext message with no reader that wanted
-- it, and a command addressed to a banned bot is a message nobody will collect.
CREATE OR REPLACE FUNCTION app.is_addressable_bot(p_user UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_user AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = app.server_id())
$$;

-- ============================================================
-- 3. What a bot may read
-- ============================================================
-- The one-sentence rule, as a policy. A member's view is unchanged: a command
-- is an ordinary (unencrypted, badged) message in the channel, and the room can
-- see what was asked of the bot in it.

DROP POLICY IF EXISTS messages_select ON messages;
CREATE POLICY messages_select ON messages FOR SELECT TO authenticated
  USING (
    app.channel_server_id(channel_id) = app.server_id()
    AND (
      NOT app.is_bot()
      -- Addressed to me, or written by me. Nothing else — not the message
      -- before it, not the one that mentions it, not the rest of the channel
      -- it is sitting in.
      OR to_bot = auth.uid()
      OR sender_id = auth.uid()
    )
  );

-- `app.can_see_message` is what the reaction policies consult, and it is
-- SECURITY DEFINER — so it reads past RLS and answered "yes, same server" for
-- every message, to everybody. For a member that matched `messages_select`
-- exactly. For a bot it would have been a way to read who reacted to
-- conversations it cannot see: not content, but the shape of a room, one emoji
-- at a time.
CREATE OR REPLACE FUNCTION app.can_see_message(p_message BIGINT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM messages m
                  WHERE m.id = p_message
                    AND app.channel_server_id(m.channel_id) = app.server_id()
                    AND (NOT app.is_bot()
                         OR m.to_bot = auth.uid()
                         OR m.sender_id = auth.uid()))
$$;

-- ============================================================
-- 4. What may be written
-- ============================================================

DROP POLICY IF EXISTS messages_insert ON messages;
CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    app.channel_server_id(channel_id) = app.server_id()
    AND sender_id = auth.uid()
    AND webhook_id IS NULL
    AND origin_name IS NULL
    -- Plaintext is a command or it is nothing. This is the line that stops
    -- "the server cannot read this" quietly becoming "unless somebody's client
    -- decided otherwise".
    AND (key_version >= 1 OR to_bot IS NOT NULL)
    -- ...and a command has to be addressed to something that can answer one.
    AND (to_bot IS NULL OR app.is_addressable_bot(to_bot))
    -- A *sealed* message addressed to a bot is the confusing shape: it looks
    -- addressed, the bot may read the row, and the body is one it can never
    -- open. Refuse it rather than deliver an unopenable command.
    AND (to_bot IS NULL OR key_version = 0)
  );

-- Editing a command is not a thing. `messages_update_own` already scopes to the
-- sender and the UPDATE grant names four columns, none of them `to_bot` — but
-- an edit of the *body* would silently change what a bot was asked to do,
-- after it may already have acted. The attestation trigger pins the address;
-- this pins the instruction.
-- **`to_bot` is deliberately not pinned here, and the body check is narrow.**
-- `ON DELETE SET NULL` is implemented as an UPDATE, so this trigger fires
-- during the cascade when a bot is removed. Pinning the column would put the id
-- back and the FK would reject its own cascade; refusing every update would
-- make deleting a bot that ever received a command impossible. That is exactly
-- what 013 did to webhook deletion, and it is worth only making once.
--
-- Nothing is lost: `authenticated` holds a column-level UPDATE grant on
-- (ciphertext, nonce, signature, key_version) alone, so no member can write
-- `to_bot` by hand in the first place.
CREATE OR REPLACE FUNCTION pin_bot_command()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF OLD.to_bot IS NOT NULL
     AND NEW.ciphertext IS DISTINCT FROM OLD.ciphertext THEN
    RAISE EXCEPTION 'command_cannot_be_edited';
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS messages_pin_bot_command ON messages;
CREATE TRIGGER messages_pin_bot_command BEFORE UPDATE ON messages
  FOR EACH ROW EXECUTE FUNCTION pin_bot_command();

-- ============================================================
-- 5. What a bot publishes about itself
-- ============================================================
-- The command list, so a client can offer `/play` without asking the bot —
-- which matters because the bot is usually asleep, and because a menu that
-- costs a round trip per keystroke is not a menu.
--
-- Plaintext and world-readable by design: it is an advertisement, the same way
-- a public server listing is (ARCHITECTURE.md §3). It also carries the bot's
-- own statement of what it does with what it is given (BOTS.md §8), which is
-- worth more here than any amount of key management — a bot reads the command
-- either way; what the user needs is to know that before typing.

ALTER TABLE users ADD COLUMN IF NOT EXISTS manifest JSONB;

COMMENT ON COLUMN users.manifest IS
  'A bot''s published command list and data declaration (BOTS.md §4, §8). '
  'Written by the bot itself; NULL for a person. Advertisement, not evidence — '
  'a client renders it, and nothing is authorised by what it claims.';

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_manifest_is_bot;
ALTER TABLE users ADD  CONSTRAINT users_manifest_is_bot
  CHECK (manifest IS NULL OR is_bot);

-- Bounded, because it is a column any member can read and the bot writes it
-- unattended. A manifest is a short list of verbs, not a payload.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_manifest_size;
ALTER TABLE users ADD  CONSTRAINT users_manifest_size
  CHECK (manifest IS NULL OR length(manifest::text) <= 8192);

-- A bot maintains its own; nobody maintains anybody else's. Added to the
-- existing column grant rather than replacing it — `display_name`,
-- `chat_public_key` and `avatar_path` stay exactly as they were.
GRANT UPDATE (manifest) ON users TO authenticated;

-- No new policy: `users_update_self` (002) already allows a member to update
-- their own row, and policies are OR'd — a second one saying the same thing in
-- narrower words would widen nothing and add a place to disagree. The CHECK
-- above is what keeps a person from holding a manifest; the grant is what keeps
-- anybody from writing somebody else's.
