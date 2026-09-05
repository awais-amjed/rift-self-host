-- ============================================================
-- Rift self-hosted server — 005: Bots, commands and replies
-- ============================================================
-- A bot is a user whose seed lives in a config file. What it may read is the
-- whole design: addressed messages only, and channel keys never — except by
-- an explicit grant, which is the last file here.
--
-- Was 4 files: 014_bots, 015_bot_commands, 016_bot_replies, 017_bot_channel_grants.
-- Merged unchanged and in the same order, so this applies exactly what
-- they applied. The sections below are those files, each still carrying
-- the reasoning it was written with.
-- ============================================================

-- ============================================================
-- Rift self-hosted server — 014: bot identity
-- ============================================================
-- BOTS.md phase 1: a bot that exists and does nothing.
--
-- **A bot is a user whose seed lives in a config file instead of on a phone.**
-- There is no separate bot API, no bot token format, no second auth path — the
-- same `users` row, the same SIWS login, the same JWT, the same RLS. That is
-- not a shortcut. It is what stops the bot surface drifting away from the app
-- surface: a capability the app has, a bot has, under the same policies.
--
-- So this migration adds almost nothing. One flag saying which rows are bots,
-- one flag on invites saying which invites mint them, and one guard that is the
-- whole reason the flag has to exist at all.
--
-- ---------- the guard is the feature ----------
--
-- BOTS.md §2: bots never hold channel keys. Not because a policy forbids
-- reading, but because a wrapped key *is* read access — arithmetic, not a rule,
-- and unlike a rule it cannot be taken back. Everything a bot legitimately does
-- happens over messages the server can already read (§3, migration 013).
--
-- §6 names the way that goes wrong, and it is not an attacker. `get_channel_key`
-- returns `members_missing` — members with a published chat key and no entry at
-- the current version — and **any member's client heals them**, automatically,
-- as a courtesy. A bot publishes a chat key like everybody else. Left alone, the
-- first member to open the channel would wrap the key for it, silently, having
-- been asked to do nothing.
--
-- The three edge functions that walk that list are filtered too, but filters are
-- the half that gets forgotten: there are three of them today and the fourth
-- thing to read `users` will not know it was supposed to. So the rule lives on
-- the row. A keyring entry for a bot is refused by the database, and the three
-- filters become an optimisation rather than the boundary.
--
-- Phase 5 (moderation bots) is the one case that needs the opposite, and it
-- arrives as an explicit per-channel grant — at which point this trigger
-- consults that grant instead of refusing outright. Until then there is no way
-- to key a bot at all, which is the correct amount of ways.

-- ============================================================
-- 1. The flag
-- ============================================================

ALTER TABLE users   ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE invites ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN users.is_bot IS
  'This row is a program, not a person. Set from the invite at registration and '
  'never afterwards — see 014. Bots cannot hold channel keys (channel_keyring '
  'refuses them), and clients list them separately from members.';
COMMENT ON COLUMN invites.is_bot IS
  'This invite mints a bot. Chosen when the invite is created; an ordinary '
  'invite can never produce one.';

CREATE INDEX IF NOT EXISTS idx_users_bots
  ON users (server_id) WHERE is_bot;

-- ============================================================
-- 2. Registration carries it
-- ============================================================
-- Replaces 003's `register_user`. Two changes, both on the last INSERT:
-- `is_bot` comes from the invite, and `can_create_tokens` no longer comes from
-- nowhere.
--
-- That second one is not cosmetic. 003 passed a literal `true`, so every member
-- who ever joined could mint invites regardless of what their invite said. For
-- a person that is a deliberate (if undocumented) openness; for a bot it is a
-- program that can hand out membership of somebody else's server. A bot gets
-- what its invite grants and nothing by default.

CREATE OR REPLACE FUNCTION register_user(
  p_invite_code  TEXT,
  p_user_id      UUID,
  p_public_key   TEXT,
  p_stable_id    TEXT,
  p_username     TEXT,
  p_display_name TEXT
) RETURNS JSONB
  LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
  v_invite invites%ROWTYPE;
BEGIN
  SELECT * INTO v_invite FROM invites WHERE code = p_invite_code FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('reason', 'not_found');
  END IF;
  IF v_invite.expires_at IS NOT NULL AND v_invite.expires_at <= now() THEN
    DELETE FROM invites WHERE id = v_invite.id;
    RETURN jsonb_build_object('reason', 'expired');
  END IF;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses >= v_invite.max_uses THEN
    RETURN jsonb_build_object('reason', 'exhausted');
  END IF;

  IF EXISTS (SELECT 1 FROM users WHERE id = p_user_id) THEN
    RETURN jsonb_build_object('reason', 'already_registered');
  END IF;
  IF EXISTS (SELECT 1 FROM users
              WHERE server_id = v_invite.server_id
                AND (public_key = p_public_key OR stable_id = p_stable_id)) THEN
    RETURN jsonb_build_object('reason', 'identity_taken');
  END IF;
  IF EXISTS (SELECT 1 FROM users
              WHERE server_id = v_invite.server_id AND username = p_username) THEN
    RETURN jsonb_build_object('reason', 'username_taken');
  END IF;

  INSERT INTO users (
    id, server_id, username, display_name, public_key, stable_id,
    is_server_admin, is_channel_manager, can_create_tokens, is_bot
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name,
    p_public_key, p_stable_id,
    v_invite.is_server_admin, v_invite.is_channel_manager,
    -- A person keeps the old openness; a bot is granted only what was ticked.
    CASE WHEN v_invite.is_bot THEN v_invite.can_create_tokens ELSE true END,
    v_invite.is_bot
  );

  -- Start every channel's cursor at whatever is already there. Without this a
  -- new member's first sight of the server is every channel screaming with
  -- unread counts for messages sent before they arrived — which they can't
  -- decrypt anyway, since keys are only wrapped for them going forward.
  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT p_user_id, 'channel', c.id,
         COALESCE((SELECT max(m.id) FROM messages m WHERE m.channel_id = c.id), 0)
    FROM channels c
   WHERE c.server_id = v_invite.server_id;

  UPDATE invites SET uses = uses + 1 WHERE id = v_invite.id;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses + 1 >= v_invite.max_uses THEN
    DELETE FROM invites WHERE id = v_invite.id;
  END IF;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'server_id', v_invite.server_id,
    'is_bot', v_invite.is_bot
  );
END; $$;

-- ============================================================
-- 3. `is_bot` is set once, at registration
-- ============================================================
-- Members may UPDATE (display_name, chat_public_key, avatar_path) and nothing
-- else, so no client can write this column today. The trigger is for the paths
-- that are not a client: `set_user_permissions` and `moderate_user` are
-- SECURITY DEFINER and run as the owner, and a future one that does `UPDATE
-- users SET ...` without naming its columns would carry whatever it was handed.
--
-- Turning a person into a bot, or a bot into a person, is not an edit anybody
-- should be able to make — it changes who may hold the keys to a room.

CREATE OR REPLACE FUNCTION pin_is_bot()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  NEW.is_bot := OLD.is_bot;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS users_pin_is_bot ON users;
CREATE TRIGGER users_pin_is_bot BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION pin_is_bot();

-- ============================================================
-- 4. A bot may not be given a channel key
-- ============================================================
-- The boundary, on the row rather than in the three callers that walk past it.
--
-- A trigger rather than a CHECK because the fact lives on another table:
-- `channel_keyring.user_id` → `users.is_bot`. Refusing loudly rather than
-- silently dropping the row, because a client that wrapped a key for a bot
-- believes it did something and would otherwise carry on believing it.

CREATE OR REPLACE FUNCTION refuse_bot_keyring()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.is_bot) THEN
    RAISE EXCEPTION 'bot_cannot_hold_channel_key';
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS channel_keyring_refuse_bots ON channel_keyring;
CREATE TRIGGER channel_keyring_refuse_bots
  BEFORE INSERT OR UPDATE ON channel_keyring
  FOR EACH ROW EXECUTE FUNCTION refuse_bot_keyring();

-- ============================================================
-- 5. Invites that mint bots
-- ============================================================
-- `invites_insert` already carries the delegation rule — you can only grant
-- what you hold — and it is untouched: ticking "this is a bot" is not a
-- permission, so it needs no authority of its own beyond being allowed to make
-- an invite at all.
--
-- What it does need is to be a *decision*. An invite is minted with `is_bot`
-- and cannot be changed afterwards (there is no UPDATE grant on invites), so
-- one link never quietly becomes the other kind.

DROP POLICY IF EXISTS invites_insert ON invites;
CREATE POLICY invites_insert ON invites FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND created_by = auth.uid()
    AND app.can_invite()
    AND (NOT is_server_admin    OR app.is_admin())
    AND (NOT is_channel_manager OR app.can_manage_channels())
    AND (NOT can_create_tokens  OR app.can_invite())
    -- A bot invite may not carry admin. Ending somebody's membership is the
    -- same weight as granting a role, and neither belongs to a program that
    -- joined from a config file. A channel manager bot is a deliberate choice
    -- an operator can still make.
    AND (NOT is_bot OR NOT is_server_admin)
  );


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


-- ============================================================
-- Rift self-hosted server — 016: bot replies
-- ============================================================
-- BOTS.md phase 3. A bot could be asked something and had no way to answer.
--
-- Two of the three shapes in §5 land here:
--
--   * **a channel message** — public output, the poll result, the dice roll.
--     Everyone sees it, badged, exactly like a webhook's;
--   * **an ephemeral reply** — only the person who asked. Errors,
--     confirmations, and anything the room does not need.
--
-- Panels (living state: a queue, a score) are still planned, because they need
-- a declarative block set and that is a design rather than a column.
--
-- ---------- and a bug from 013, in the same place ----------
--
-- `unread_counts` filters with `m.sender_id <> auth.uid()`. Against a webhook's
-- NULL sender that comparison is NULL rather than true, so **every webhook
-- message has been invisible to the unread badge since 013 shipped**: a channel
-- of seven messages, four of them from webhooks, reported three.
--
-- This is the same NULL that silenced `ring_channel_members`, which 013 caught
-- and fixed one function away from this one. Worth stating plainly: the fix
-- there was `IS DISTINCT FROM`, and the reason it did not get applied here is
-- that nothing looked for a second instance of the same shape.

-- ============================================================
-- 1. A reply, and who it is for
-- ============================================================

ALTER TABLE messages
  -- Which command this answers. Lets a client anchor a reply to the line that
  -- caused it rather than leaving two unrelated-looking rows next to each
  -- other. CASCADE: a reply to a deleted command is a reply to nothing.
  ADD COLUMN IF NOT EXISTS reply_to BIGINT REFERENCES messages(id) ON DELETE CASCADE,
  -- Only this member may see the row. CASCADE for the same reason: a private
  -- answer outlives neither its question nor the person it was for.
  ADD COLUMN IF NOT EXISTS ephemeral_for UUID REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_messages_reply_to
  ON messages (reply_to) WHERE reply_to IS NOT NULL;

COMMENT ON COLUMN messages.ephemeral_for IS
  'A bot reply only this member sees (BOTS.md §5). Enforced by messages_select '
  'rather than by clients agreeing to hide it, and excluded from unread and '
  'from waking anybody else.';

-- **CASCADE, not SET NULL, and that is the whole reason it is safe.** 013 and
-- 015 both had to route around `SET NULL` firing an UPDATE that a BEFORE
-- trigger then fought. Here the row genuinely has no meaning without its
-- referent, so it goes with it and no trigger ever sees the update.

-- ============================================================
-- 2. A bot may answer
-- ============================================================
-- 015 said plaintext is a command or it is nothing. A bot's reply is the third
-- thing: unencrypted by the same necessity — it holds no channel key — and
-- addressed to nobody, because it is the answer rather than the question.

DROP POLICY IF EXISTS messages_insert ON messages;
CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    app.channel_server_id(channel_id) = app.server_id()
    AND sender_id = auth.uid()
    AND webhook_id IS NULL
    AND origin_name IS NULL
    -- Sealed, or a command, or a bot answering one.
    AND (key_version >= 1 OR to_bot IS NOT NULL OR app.is_bot())
    AND (to_bot IS NULL OR app.is_addressable_bot(to_bot))
    AND (to_bot IS NULL OR key_version = 0)
    -- A bot has no channel key, so it can only ever write in the clear. Saying
    -- so here means a bot that somehow acquired one still could not seal a
    -- message that its readers would then have to open.
    AND (NOT app.is_bot() OR key_version = 0)
    -- Only a bot may address a reply to one person. A member with something
    -- private to say has DMs; a member able to write a message only one other
    -- member can see, inside a channel, is a way to hold a conversation that
    -- the room cannot audit and the operator's retention settings do not
    -- describe.
    AND (ephemeral_for IS NULL OR app.is_bot())
  );

-- ============================================================
-- 3. Who sees what
-- ============================================================

DROP POLICY IF EXISTS messages_select ON messages;
CREATE POLICY messages_select ON messages FOR SELECT TO authenticated
  USING (
    app.channel_server_id(channel_id) = app.server_id()
    -- 015: a bot reads what it is addressed and what it wrote. Nothing else.
    AND (
      NOT app.is_bot()
      OR to_bot = auth.uid()
      OR sender_id = auth.uid()
    )
    -- 016: an ephemeral reply is for one person. The bot that wrote it can
    -- still see it, which is what lets a bot edit or withdraw its own answer.
    AND (
      ephemeral_for IS NULL
      OR ephemeral_for = auth.uid()
      OR sender_id = auth.uid()
    )
  );

CREATE OR REPLACE FUNCTION app.can_see_message(p_message BIGINT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM messages m
                  WHERE m.id = p_message
                    AND app.channel_server_id(m.channel_id) = app.server_id()
                    AND (NOT app.is_bot()
                         OR m.to_bot = auth.uid()
                         OR m.sender_id = auth.uid())
                    AND (m.ephemeral_for IS NULL
                         OR m.ephemeral_for = auth.uid()
                         OR m.sender_id = auth.uid()))
$$;

-- ============================================================
-- 4. Counting, and waking
-- ============================================================
-- `SECURITY INVOKER`, so RLS already hides an ephemeral row from everybody it
-- is not for — that half needs no change. What it needs is the NULL fix.

CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT jsonb_build_object(
    'channels', COALESCE((
      SELECT jsonb_object_agg(channel_id, n) FROM (
        SELECT m.channel_id, count(*) AS n
          FROM messages m
          LEFT JOIN read_state r
            ON r.user_id = auth.uid()
           AND r.scope = 'channel'
           AND r.scope_id = m.channel_id
         -- IS DISTINCT FROM, not <>. A webhook's sender is NULL, and `NULL <>
         -- uid` is NULL rather than true — so every webhook message was
         -- dropped from this count in silence.
         WHERE m.sender_id IS DISTINCT FROM auth.uid()
           AND m.id > COALESCE(r.last_read_id, 0)
         GROUP BY m.channel_id
      ) c), '{}'::jsonb),
    'dms', COALESCE((
      SELECT jsonb_object_agg(sender_id, n) FROM (
        SELECT d.sender_id, count(*) AS n
          FROM dm_messages d
          LEFT JOIN read_state r
            ON r.user_id = auth.uid()
           AND r.scope = 'dm'
           AND r.scope_id = d.sender_id
         WHERE d.recipient_id = auth.uid()
           AND d.id > COALESCE(r.last_read_id, 0)
         GROUP BY d.sender_id
      ) d), '{}'::jsonb)
  );
$$;

-- An ephemeral reply wakes one phone or none. Without this a bot answering
-- somebody quietly would buzz the whole server about a message none of them
-- can read — the loudest possible way to deliver a private answer.
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
     -- A bot has no phone, and would be woken for every message in a room it
     -- cannot read.
     AND NOT u.is_bot
     AND (NEW.ephemeral_for IS NULL OR u.id = NEW.ephemeral_for)
     AND NOT has_unread_before(u.id, 'channel', NEW.channel_id, NEW.id);

  PERFORM ring_devices(v_server_id, v_targets);
  RETURN NEW;
END; $$;


-- ============================================================
-- Rift self-hosted server — 017: moderation grants
-- ============================================================
-- BOTS.md phase 5, last on the list on purpose: it is the only part of the bot
-- design that spends the trust model rather than working around it.
--
-- Everything so far has held one line — a bot never holds a channel key, so it
-- hears what it is told and nothing else. A moderation bot cannot work that
-- way. It has to read every message, and there is no cryptographic middle
-- ground: it either holds the key or it does not.
--
-- So this is an **explicit, per-channel, admin-only grant**, and four rules are
-- what make it something you can offer rather than something you regret.
--
--   1. **Bots are still excluded from the healing sweep.** 014 made that a
--      refusal on the row rather than a filter, and that stays: the trigger now
--      consults a grant instead of refusing outright, so the only way a bot is
--      ever keyed is somebody deciding it should be.
--   2. **Forward-only.** A member joining gets every historical key version —
--      the full-scrollback decision in ARCHITECTURE.md §4. A bot gets the key
--      from *after* the grant. It has no business reading what was said before
--      somebody chose to let it listen, and "we'll rotate later" is not the
--      same promise.
--   3. **Revoking rotates.** The bot keeps what it already saw — nobody can
--      take back what has been unwrapped — and gets nothing further.
--   4. **The channel says who is listening.** Not in this file, but it is the
--      reason `bot_channel_keys` is readable by every member rather than only
--      by admins: the person whose messages are being read is not the person
--      who clicked the button, and a warning that only the admin sees reaches
--      the wrong audience entirely.
--
-- ---------- the two rotation signals ----------
--
-- `sweep_channel_keys` already knows how to notice one thing: a member sealed
-- into the current version who has since been banned. That signal is good
-- because it **clears itself** — the next version is sealed only to people
-- still eligible, so the same check comes back false once the rotation lands.
-- No flag to set and nothing to reset.
--
-- Both new signals are built the same way:
--
--   * a **granted** bot whose grant starts above the current version — the
--     grant was just made, and the rotation is what makes it forward-only;
--   * a **revoked** bot still sealed into the current version — same shape as
--     the ban, for the same reason.
--
-- Neither needs a flag, and an admin who grants and revokes twice in a minute
-- leaves nothing behind to reconcile.

-- ============================================================
-- 1. The grant
-- ============================================================

CREATE TABLE IF NOT EXISTS bot_channel_keys (
  channel_id       UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id           UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  -- Who decided. Kept for the channel's own notice: "granted by" is the half
  -- of the sentence that makes it answerable to somebody.
  granted_by       UUID        REFERENCES users(id) ON DELETE SET NULL,
  granted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- The first key version this bot may hold. Set to *one past* the current
  -- version at grant time, so the rotation that follows is what it reads from
  -- and everything before it stays shut.
  from_key_version INTEGER     NOT NULL CHECK (from_key_version >= 1),
  PRIMARY KEY (channel_id, bot_id)
);

CREATE INDEX IF NOT EXISTS idx_bot_channel_keys_bot ON bot_channel_keys (bot_id);

COMMENT ON TABLE bot_channel_keys IS
  'Which bots may hold which channel keys, and from which version (migration '
  '017). Readable by every member on purpose — the channel shows who is '
  'listening, and the people being read are not the people who granted it.';

-- ============================================================
-- 2. The refusal, now with an exception
-- ============================================================
-- Replaces 014's blanket refusal. Same shape, same loudness — a client that
-- wrapped a key for a bot it should not have believes it did something, and
-- would otherwise carry on believing it.

CREATE OR REPLACE FUNCTION refuse_bot_keyring()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_from INTEGER;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.is_bot) THEN
    RETURN NEW;
  END IF;

  SELECT from_key_version INTO v_from FROM bot_channel_keys
   WHERE channel_id = NEW.channel_id AND bot_id = NEW.user_id;

  IF v_from IS NULL THEN
    RAISE EXCEPTION 'bot_cannot_hold_channel_key';
  END IF;
  -- Forward-only, enforced where the row is written rather than trusted to
  -- whichever client happens to be doing the wrapping.
  IF NEW.key_version < v_from THEN
    RAISE EXCEPTION 'bot_key_version_before_grant';
  END IF;
  RETURN NEW;
END; $$;

-- ============================================================
-- 3. Granting and revoking
-- ============================================================
-- **Admin only, not channel manager.** Every other bot decision is scoped to
-- what the bot can be told; this one hands out the plaintext of a room. It is
-- the same weight as a ban — it changes what somebody else's messages mean —
-- and 003 already reserves that for `app.is_admin()`.

CREATE OR REPLACE FUNCTION grant_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current INTEGER;
BEGIN
  IF NOT app.is_admin() THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF app.channel_server_id(p_channel) IS DISTINCT FROM app.server_id() THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = app.server_id()) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  -- One past the current version. A channel with no key yet starts the bot at
  -- 1, which is the version its first member will bootstrap — there is no
  -- history to keep it out of.
  INSERT INTO bot_channel_keys (channel_id, bot_id, granted_by, from_key_version)
  VALUES (p_channel, p_bot, auth.uid(), GREATEST(v_current + 1, 1))
  ON CONFLICT (channel_id, bot_id) DO NOTHING;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'from_key_version', (SELECT from_key_version FROM bot_channel_keys
                          WHERE channel_id = p_channel AND bot_id = p_bot)
  );
END; $$;

-- Revoking drops the grant *and* the keys already sealed to the bot. The
-- second half does not take back what it has read — nothing can — it stops the
-- server serving it anything more, and leaves the rotation to the sweep, which
-- will now see a bot sealed into the current version with no grant.
CREATE OR REPLACE FUNCTION revoke_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.is_admin() THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF app.channel_server_id(p_channel) IS DISTINCT FROM app.server_id() THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  DELETE FROM bot_channel_keys
   WHERE channel_id = p_channel AND bot_id = p_bot;
  DELETE FROM channel_keyring
   WHERE channel_id = p_channel AND user_id = p_bot;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

REVOKE ALL ON FUNCTION grant_bot_channel_key(UUID, UUID)  FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_bot_channel_key(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION grant_bot_channel_key(UUID, UUID)  TO authenticated;
GRANT EXECUTE ON FUNCTION revoke_bot_channel_key(UUID, UUID) TO authenticated;

-- ============================================================
-- 4. Security
-- ============================================================

ALTER TABLE bot_channel_keys ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bot_channel_keys FROM anon, authenticated;

-- Readable by every member of the server, which is rule 4. Writing goes
-- through the two functions above; there is no INSERT, UPDATE or DELETE grant,
-- so "who may listen" cannot be changed by anything that skipped the check.
GRANT SELECT ON bot_channel_keys TO authenticated;

DROP POLICY IF EXISTS bot_channel_keys_select ON bot_channel_keys;
CREATE POLICY bot_channel_keys_select ON bot_channel_keys
  FOR SELECT TO authenticated
  USING (app.channel_server_id(channel_id) = app.server_id());

-- ============================================================
-- 5. What the sweep needs to know
-- ============================================================
-- The sweep is an edge function and computes its own rotation signal, but the
-- two facts it needs are per-channel joins it should not have to invent. One
-- view, so the client, the sweep and the channel notice all read the same
-- answer.

CREATE OR REPLACE VIEW channel_bot_listeners
  WITH (security_invoker = true) AS
  SELECT g.channel_id,
         g.bot_id,
         u.username,
         u.display_name,
         g.granted_at,
         g.from_key_version,
         gb.display_name AS granted_by_name
    FROM bot_channel_keys g
    JOIN users u  ON u.id = g.bot_id
    LEFT JOIN users gb ON gb.id = g.granted_by;

GRANT SELECT ON channel_bot_listeners TO authenticated;
