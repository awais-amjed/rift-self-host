-- ============================================================
-- Rift self-hosted server — 009: Panels, and bots in a call
-- ============================================================
-- Bots draw interfaces with the app's own components rather than shipping
-- their own, and a bot in a voice channel is sealed a key it cannot invert
-- unless a member deliberately grants it one.
--
-- Was 5 files: 028_bot_grant_notice, 029_panels, 030_bot_server_grants, 031_bot_voice, 032_bot_voice_keys.
-- Merged unchanged and in the same order, so this applies exactly what
-- they applied. The sections below are those files, each still carrying
-- the reasoning it was written with.
-- ============================================================

-- ============================================================
-- Rift self-hosted server — 028: saying it in the channel
-- ============================================================
-- 017 built the moderation grant and four rules to make it safe to offer. The
-- fourth — *the channel says who is listening* — has been half done since:
-- there is a standing marker in the header, and it tells whoever arrives
-- later. It tells nobody who was already in the room when the grant was made.
--
-- A header chip is easy to have never noticed. A line in the scrollback is not.
--
-- Two other things 017 could not have known, both of which arrived later:
--
--   * `MANAGE_BOTS` is a permission now (018). The grant was gated on
--     `app.is_admin()`, which is the same people today — `ADMINISTRATOR`
--     implies every bit — and stops being the same people the moment somebody
--     makes a role for it.
--   * Private channels exist (020). The grant checked that a channel was on
--     your server and not that you could see it, so an administrator could key
--     a bot into a room they are deliberately outside of. Now it is the same
--     `app.can_see_channel` every other channel operation asks: for a private
--     channel, only somebody in it can let a bot in.

-- ============================================================
-- 1. A message from nobody
-- ============================================================
-- `attest_message` stamps `sender_id := auth.uid()` and, for a member's insert,
-- clears the origin — which is right, and which makes it impossible for a
-- function running on a member's behalf to write a row attributed to the
-- server rather than to them.
--
-- 019 restored 001's early return for a caller with no session, because nothing
-- without one is a client. So this drops the claim for exactly one statement
-- and puts it back. The alternative is a second attestation path, and two ways
-- to write a message is two things that can disagree about who sent it.

-- A message the server wrote about itself, not an outside service posting to a
-- URL. They are the same *shape* — an origin instead of a sender, `key_version`
-- 0 — and a client that could not tell them apart badged this one WEBHOOK,
-- which is wrong in the one way that matters: it says an integration somebody
-- installed is involved when nothing outside the server is.
--
-- A column rather than reading the name, and rather than reading `webhook_id`:
-- that one is nulled when a webhook is deleted while its messages stay (013),
-- so keying off it would turn every message a removed integration ever posted
-- into a system announcement.
ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT false;

-- No column grant, so no client can claim to be the server. Written only by
-- `app.post_system_message`, which is `SECURITY DEFINER` and owns the table.

CREATE OR REPLACE FUNCTION app.post_system_message(
  p_channel UUID,
  p_text    TEXT
) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_claims TEXT := current_setting('request.jwt.claims', true);
BEGIN
  PERFORM set_config('request.jwt.claims', '', true);

  -- `key_version` 0 and an origin rather than a sender: the same shape a
  -- webhook's message has (013), because it is the same fact — a row in an
  -- encrypted channel that no key was needed to write and none is needed to
  -- read. It is badged as plaintext like any other.
  INSERT INTO messages (channel_id, origin_name, ciphertext, key_version, is_system)
  VALUES (p_channel, 'Rift', p_text, 0, true);

  PERFORM set_config('request.jwt.claims', COALESCE(v_claims, ''), true);
END; $$;

REVOKE ALL ON FUNCTION app.post_system_message(UUID, TEXT) FROM PUBLIC;

-- ============================================================
-- 2. The grant, and the sentence it leaves behind
-- ============================================================

CREATE OR REPLACE FUNCTION grant_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current INTEGER;
  v_bot     TEXT;
  v_by      TEXT;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  -- Not "is it on my server". A private channel answers to the people in it,
  -- and an administrator standing outside one is not among them.
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  SELECT display_name INTO v_bot FROM users
   WHERE id = p_bot AND is_bot AND NOT is_banned AND server_id = app.server_id();
  IF v_bot IS NULL THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  IF EXISTS (SELECT 1 FROM bot_channel_keys
              WHERE channel_id = p_channel AND bot_id = p_bot) THEN
    RETURN jsonb_build_object('reason', 'already_granted');
  END IF;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  -- One past the current version. A channel with no key yet starts the bot at
  -- 1, which is the version its first member will bootstrap — there is no
  -- history to keep it out of.
  INSERT INTO bot_channel_keys (channel_id, bot_id, granted_by, from_key_version)
  VALUES (p_channel, p_bot, auth.uid(), GREATEST(v_current + 1, 1));

  SELECT display_name INTO v_by FROM users WHERE id = auth.uid();
  PERFORM app.post_system_message(
    p_channel,
    COALESCE(v_by, 'An admin') || ' gave ' || v_bot || ' the key to this '
      || 'channel. It can read every message sent here from now on — but '
      || 'nothing said before.'
  );

  RETURN jsonb_build_object(
    'reason', 'ok',
    'from_key_version', (SELECT from_key_version FROM bot_channel_keys
                          WHERE channel_id = p_channel AND bot_id = p_bot)
  );
END; $$;

CREATE OR REPLACE FUNCTION revoke_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bot TEXT;
  v_by  TEXT;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  SELECT u.display_name INTO v_bot
    FROM bot_channel_keys g JOIN users u ON u.id = g.bot_id
   WHERE g.channel_id = p_channel AND g.bot_id = p_bot;
  IF v_bot IS NULL THEN
    RETURN jsonb_build_object('reason', 'ok');
  END IF;

  DELETE FROM bot_channel_keys
   WHERE channel_id = p_channel AND bot_id = p_bot;
  -- Dropping the sealed keys does not take back what has been read — nothing
  -- can. It stops the server serving any more, and leaves the rotation to the
  -- sweep, which now sees a bot sealed into the current version with no grant.
  DELETE FROM channel_keyring
   WHERE channel_id = p_channel AND user_id = p_bot;

  SELECT display_name INTO v_by FROM users WHERE id = auth.uid();
  PERFORM app.post_system_message(
    p_channel,
    COALESCE(v_by, 'An admin') || ' took ' || v_bot || '’s access to this '
      || 'channel away. It keeps what it has already read; everything from '
      || 'here is out of its reach.'
  );

  RETURN jsonb_build_object('reason', 'ok');
END; $$;


-- ============================================================
-- Rift self-hosted server — 029: panels
-- ============================================================
-- BOTS.md §5's third reply shape, and the one the popular bot list actually
-- needs. A bot can post text and it can post text privately; what it cannot do
-- is show a thing that *changes* — a queue, a score, a running poll — without
-- posting a new line every time it moves. Ten skips is ten lines of log.
--
-- A panel is a message the bot keeps editing. Edit-in-place already works:
-- `messages.edited_at` and `messages_update_own` have been there since 001, and
-- a bot rewriting its own row needs no new policy. What was missing is a body
-- that is a *structure* rather than a string, and a way to press something.
--
-- ---------- why blocks and not markup ----------
--
-- The obvious shortcut is to let a bot send HTML, or a URL to render. That is a
-- stranger's code inside every member's client: fake login prompts, credential
-- capture, a sandbox story of its own. Non-starter.
--
-- So the bot sends a fixed, versioned vocabulary and *Rift's own widgets* draw
-- it. The bot never controls a pixel, only a structure. Anything not in the
-- list cannot be drawn — which is the safety property, not a shortcoming of
-- the first version.
--
-- ---------- what is deliberately not in v1 ----------
--
-- **Images.** An `image` block with a URL makes every member's client fetch
-- from an address a bot chose, which hands a third party the IP of everybody in
-- the room and a per-member read receipt. In an app whose whole claim is that
-- the server cannot read the messages, that is not a small thing to add for a
-- thumbnail. It comes back when it can point at this server's own attachment
-- bucket.

-- ============================================================
-- 1. A body that is a structure
-- ============================================================

ALTER TABLE messages ADD COLUMN IF NOT EXISTS blocks JSONB;

COMMENT ON COLUMN messages.blocks IS
  'A panel: {"v":1,"blocks":[...]}. Drawn by the client with its own widgets '
  'from a fixed vocabulary; see WIRE.md. Only ever on an unencrypted message, '
  'because a panel is by definition something the bot that wrote it can read.';

-- The shape, not the contents. A malformed block is the client's problem and it
-- has an answer — an unknown type is not drawn — but a `blocks` column holding
-- a string or a number is a row nothing can render at all.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_blocks_shape;
ALTER TABLE messages ADD CONSTRAINT messages_blocks_shape CHECK (
  blocks IS NULL
  OR (jsonb_typeof(blocks) = 'object'
      AND jsonb_typeof(blocks->'blocks') = 'array'
      AND jsonb_array_length(blocks->'blocks') <= 40)
);

-- A panel is plaintext by construction: a bot holds no channel key, so a
-- sealed panel is one its own author could not have written.
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_blocks_are_plain;
ALTER TABLE messages ADD CONSTRAINT messages_blocks_are_plain CHECK (
  blocks IS NULL OR key_version = 0
);

-- ============================================================
-- 2. Pressing something
-- ============================================================
-- A press is not a message. Posting "Skip" into the channel every time somebody
-- presses skip is the log this whole feature exists to stop being.
--
-- So it reuses what a command already established — `to_bot` names the bot,
-- `reply_to` names the panel, the row is signed and unencrypted — and adds one
-- flag that keeps it out of everybody else's view.

ALTER TABLE messages ADD COLUMN IF NOT EXISTS is_interaction BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS action_id TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS action_value TEXT;

COMMENT ON COLUMN messages.is_interaction IS
  'A button press or a menu choice, addressed to a bot. Never rendered as a '
  'message: `messages_select` shows it only to its sender and the bot it names.';

ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_action_shape;
ALTER TABLE messages ADD CONSTRAINT messages_action_shape CHECK (
  -- An interaction is addressed, identified and unencrypted, or it is not one.
  (NOT is_interaction
   OR (to_bot IS NOT NULL AND action_id IS NOT NULL AND key_version = 0))
  -- ...and nothing that is not an interaction carries one.
  AND (is_interaction OR (action_id IS NULL AND action_value IS NULL))
);

ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_action_id_len;
ALTER TABLE messages ADD CONSTRAINT messages_action_id_len CHECK (
  action_id IS NULL OR length(action_id) BETWEEN 1 AND 64
);
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_action_value_len;
ALTER TABLE messages ADD CONSTRAINT messages_action_value_len CHECK (
  action_value IS NULL OR length(action_value) <= 256
);

-- ============================================================
-- 3. Who sees what
-- ============================================================

-- A member writes an interaction; a bot writes a panel. Neither writes the
-- other's, and the column grant is what makes that true of anything that
-- skipped the policy.
GRANT INSERT (channel_id, sender_id, ciphertext, nonce, signature, key_version,
              mentions, mentions_all, to_bot, reply_to, ephemeral_for,
              blocks, is_interaction, action_id, action_value)
  ON messages TO authenticated;

-- Editing a panel is editing a message: `messages_update_own` already scopes
-- that to the sender, which for a panel is the bot that posted it.
GRANT UPDATE (ciphertext, nonce, signature, key_version, blocks) ON messages
  TO authenticated;

DROP POLICY IF EXISTS messages_select ON messages;
CREATE POLICY messages_select ON messages FOR SELECT TO authenticated
  USING (
    app.can_see_channel(channel_id)
    AND (NOT app.is_bot() OR to_bot = auth.uid() OR sender_id = auth.uid())
    AND (ephemeral_for IS NULL OR ephemeral_for = auth.uid()
         OR sender_id = auth.uid())
    -- The press itself is between the presser and the bot. Everybody else sees
    -- the panel change, which is the point — they do not see forty rows saying
    -- who moved it.
    AND (NOT is_interaction OR sender_id = auth.uid() OR to_bot = auth.uid())
  );

DROP POLICY IF EXISTS messages_insert ON messages;
CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    app.can_see_channel(channel_id)
    AND app.has_perm('SEND_MESSAGES')
    AND sender_id = auth.uid()
    AND webhook_id IS NULL AND origin_name IS NULL AND NOT is_system
    AND (key_version >= 1 OR to_bot IS NOT NULL OR app.is_bot())
    AND (to_bot IS NULL OR app.is_addressable_bot(to_bot))
    AND (to_bot IS NULL OR key_version = 0)
    AND (NOT app.is_bot() OR key_version = 0)
    AND (ephemeral_for IS NULL OR app.is_bot())
    -- Only a bot draws a panel. A member posting blocks would be a member
    -- posting an interface, which is the thing the block set exists to prevent.
    AND (blocks IS NULL OR app.is_bot())
    -- ...and only a person presses one. A bot pressing its own button is a
    -- loop, and nothing in the design needs it.
    AND (NOT is_interaction OR NOT app.is_bot())
  );

-- ============================================================
-- 4. An interaction wakes nobody
-- ============================================================
-- `ring_channel_members` already skips a message whose `ephemeral_for` names
-- one person. A press names nobody and would otherwise buzz the whole channel
-- about a row none of them can even read.

CREATE OR REPLACE FUNCTION ring_channel_members()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
  v_targets   UUID[];
BEGIN
  IF NEW.is_interaction THEN RETURN NEW; END IF;

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
     AND app.channel_eligible(NEW.channel_id, u.id)
     AND NOT has_unread_before(u.id, 'channel', NEW.channel_id, NEW.id);

  PERFORM ring_devices(v_server_id, v_targets);
  RETURN NEW;
END; $$;

-- Same for the badge: a press is not unread mail.
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
           AND NOT m.is_interaction
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


-- ============================================================
-- Rift self-hosted server — 030: granting a bot the whole server
-- ============================================================
-- BOTS.md §6's fifth rule, and the one that keeps the per-channel grant
-- honest rather than merely strict.
--
-- Per-channel is the right granularity and it is also unusable for the bots
-- people actually want. By server count the top of Discord's list is almost
-- entirely the read-everything kind — MEE6 (~21M servers, XP per message),
-- Carl-bot and Dyno (automod, logging), Pokétwo (spawns on chat activity). An
-- admin granting one of those a channel at a time, thirty times, will ask for a
-- button. Refusing to build it does not stop the button existing; it means the
-- one somebody eventually builds gets no thought.
--
-- ---------- the carve-out is the whole design ----------
--
-- A server-wide grant covers every channel where `is_private` is false, and
-- **never a private one**. A private channel is always an explicit, individual
-- decision — the same rule 020 wrote `channels.is_private` early to make
-- un-forgettable.
--
-- ---------- intent, not a snapshot ----------
--
-- The grant is a row in `bot_server_grants` *and* an ordinary
-- `bot_channel_keys` row per channel. The first is what covers a channel
-- created next week; without it an admin grants a bot the server, adds a
-- channel, and the bot silently does not work there. The second is the
-- mechanism — it carries `from_key_version`, drives the rotation sweep, and
-- drives the header marker, none of which a "the whole server" flag could do,
-- because forward-only is a fact about one channel's key history.
--
-- Which makes the downgrade almost free. Revoking one channel out of a
-- server-wide grant drops the *intent* row and leaves every other channel's
-- materialised row exactly where it was. An exception list would also work, and
-- would leave somebody a year later asking why one channel is not covered by a
-- grant that says "whole server".

-- ============================================================
-- 1. The intent
-- ============================================================

CREATE TABLE IF NOT EXISTS bot_server_grants (
  server_id  UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  bot_id     UUID        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  granted_by UUID        REFERENCES users(id) ON DELETE SET NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (server_id, bot_id)
);

COMMENT ON TABLE bot_server_grants IS
  'A standing grant covering every public text channel, including ones made '
  'later. The per-channel rows in bot_channel_keys are the mechanism; this is '
  'what makes a channel created tomorrow part of it.';

ALTER TABLE bot_server_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bot_server_grants FROM anon, authenticated;

-- Readable by every member, which is rule 4 again: the people whose messages
-- pay for the grant are not the ones who clicked the button.
GRANT SELECT ON bot_server_grants TO authenticated;

DROP POLICY IF EXISTS bot_server_grants_select ON bot_server_grants;
CREATE POLICY bot_server_grants_select ON bot_server_grants
  FOR SELECT TO authenticated USING (server_id = app.server_id());

-- ============================================================
-- 2. Granting, one channel at a time
-- ============================================================
-- It loops over `grant_bot_channel_key` rather than writing rows itself, so
-- every rule lives in one place: the permission, forward-only, the refusal on
-- a channel the caller cannot see, and the sentence it leaves in each one.
--
-- Each channel says so separately, and that is not noise. A member reads the
-- channel they are in; "a bot was given the whole server" posted somewhere else
-- is a notice they never see.

CREATE OR REPLACE FUNCTION app.materialise_bot_server_grant(
  p_server UUID,
  p_bot    UUID
) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_channel UUID;
BEGIN
  FOR v_channel IN
    SELECT id FROM channels
     WHERE server_id = p_server
       AND channel_type = 'text'
       -- The carve-out. A voice channel is excluded too, for a duller reason:
       -- it has no keyring, so there is nothing for a key grant to mean.
       AND NOT is_private
  LOOP
    PERFORM grant_bot_channel_key(p_bot, v_channel);
  END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION grant_bot_server_key(p_bot UUID) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = v_server) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_server_grants (server_id, bot_id, granted_by)
  VALUES (v_server, p_bot, auth.uid())
  ON CONFLICT (server_id, bot_id) DO NOTHING;

  PERFORM app.materialise_bot_server_grant(v_server, p_bot);
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION revoke_bot_server_key(p_bot UUID) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server  UUID := app.server_id();
  v_channel UUID;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  DELETE FROM bot_server_grants WHERE server_id = v_server AND bot_id = p_bot;

  FOR v_channel IN
    SELECT channel_id FROM bot_channel_keys g
      JOIN channels c ON c.id = g.channel_id
     WHERE c.server_id = v_server AND g.bot_id = p_bot
  LOOP
    PERFORM revoke_bot_channel_key(p_bot, v_channel);
  END LOOP;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

REVOKE ALL ON FUNCTION app.materialise_bot_server_grant(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_bot_server_key(UUID)  FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_bot_server_key(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION grant_bot_server_key(UUID)  TO authenticated;
GRANT EXECUTE ON FUNCTION revoke_bot_server_key(UUID) TO authenticated;

-- ============================================================
-- 3. Revoking one channel downgrades the grant
-- ============================================================
-- Not an exception list. Dropping the intent row leaves every other channel's
-- materialised row exactly where it was, so the grant stops being "the whole
-- server" and becomes the set of channels it currently covers — which is what
-- the admin just said they wanted.
--
-- Written into `revoke_bot_channel_key` rather than as a trigger on
-- `bot_channel_keys`, and that distinction is the whole of it. A trigger fires
-- for *every* deletion of that row, including the one §4 does when a channel is
-- made private — so closing one channel would have cancelled the grant on all
-- the others. Downgrading is a thing a person decides, not a thing a row does.

CREATE OR REPLACE FUNCTION revoke_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bot TEXT;
  v_by  TEXT;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  SELECT u.display_name INTO v_bot
    FROM bot_channel_keys g JOIN users u ON u.id = g.bot_id
   WHERE g.channel_id = p_channel AND g.bot_id = p_bot;
  IF v_bot IS NULL THEN
    RETURN jsonb_build_object('reason', 'ok');
  END IF;

  -- Naming one channel is saying "not the whole server any more". The other
  -- channels keep the rows they already have.
  DELETE FROM bot_server_grants
   WHERE bot_id = p_bot
     AND server_id = app.channel_server_id(p_channel);

  DELETE FROM bot_channel_keys
   WHERE channel_id = p_channel AND bot_id = p_bot;
  -- Dropping the sealed keys does not take back what has been read — nothing
  -- can. It stops the server serving any more, and leaves the rotation to the
  -- sweep, which now sees a bot sealed into the current version with no grant.
  DELETE FROM channel_keyring
   WHERE channel_id = p_channel AND user_id = p_bot;

  SELECT display_name INTO v_by FROM users WHERE id = auth.uid();
  PERFORM app.post_system_message(
    p_channel,
    COALESCE(v_by, 'An admin') || ' took ' || v_bot || '’s access to this '
      || 'channel away. It keeps what it has already read; everything from '
      || 'here is out of its reach.'
  );

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ============================================================
-- 4. A channel made later, and a channel closed later
-- ============================================================

CREATE OR REPLACE FUNCTION apply_bot_server_grants()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_bot UUID;
BEGIN
  IF NEW.channel_type <> 'text' OR NEW.is_private THEN RETURN NULL; END IF;

  FOR v_bot IN
    SELECT bot_id FROM bot_server_grants WHERE server_id = NEW.server_id
  LOOP
    -- Bypasses `grant_bot_channel_key`'s permission check on purpose: the
    -- decision was made when the server-wide grant was, and the person
    -- creating a channel now is not necessarily the one who made it.
    INSERT INTO bot_channel_keys (channel_id, bot_id, granted_by, from_key_version)
    VALUES (NEW.id, v_bot, NULL, 1)
    ON CONFLICT (channel_id, bot_id) DO NOTHING;

    PERFORM app.post_system_message(
      NEW.id,
      (SELECT display_name FROM users WHERE id = v_bot)
        || ' can read this channel: it was created under a server-wide grant.'
    );
  END LOOP;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS channels_apply_bot_grants ON channels;
CREATE TRIGGER channels_apply_bot_grants AFTER INSERT ON channels
  FOR EACH ROW EXECUTE FUNCTION apply_bot_server_grants();

-- Closing a channel takes it out of the server-wide grant, because the grant
-- is defined as "not private" and a channel that just became private is not
-- covered by it any more. The bot keeps what it read; the sweep rotates it out
-- of everything after, exactly as an explicit revoke would.
CREATE OR REPLACE FUNCTION drop_bot_grants_when_closed()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_bot UUID;
BEGIN
  IF OLD.is_private OR NOT NEW.is_private THEN RETURN NULL; END IF;

  FOR v_bot IN
    SELECT g.bot_id FROM bot_channel_keys g
     WHERE g.channel_id = NEW.id
       AND EXISTS (SELECT 1 FROM bot_server_grants s
                    WHERE s.server_id = NEW.server_id AND s.bot_id = g.bot_id)
  LOOP
    DELETE FROM bot_channel_keys WHERE channel_id = NEW.id AND bot_id = v_bot;
    DELETE FROM channel_keyring  WHERE channel_id = NEW.id AND user_id = v_bot;
    PERFORM app.post_system_message(
      NEW.id,
      (SELECT display_name FROM users WHERE id = v_bot)
        || ' lost access when this channel was made private. A server-wide '
        || 'grant never covers a private channel.'
    );
  END LOOP;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS channels_drop_bot_grants ON channels;
CREATE TRIGGER channels_drop_bot_grants AFTER UPDATE OF is_private ON channels
  FOR EACH ROW EXECUTE FUNCTION drop_bot_grants_when_closed();

REVOKE ALL ON FUNCTION apply_bot_server_grants()     FROM PUBLIC;
REVOKE ALL ON FUNCTION drop_bot_grants_when_closed() FROM PUBLIC;


-- ============================================================
-- Rift self-hosted server — 031: what a bot may hear in a call
-- ============================================================
-- BOTS.md's rule is "a bot hears what you tell it, not what you say", and
-- until this migration voice was the one place it was simply false.
--
-- `get_channel_token` never asked whether the caller was a bot. `@everyone`
-- carries CONNECT and SPEAK, a bot holds `@everyone` like anybody else, and the
-- token was minted with `canSubscribe` true. So any bot invited to a server
-- could sit in a call and receive every participant's audio, indefinitely, with
-- nothing said in any channel and nothing shown to anyone in the room.
--
-- Nobody built that on purpose. It is what happens when a rule is enforced in
-- the text path and the voice path is written by asking "what does a member
-- need", which is the same shape as the bug this whole document exists to
-- avoid.
--
-- ---------- publishing is not hearing ----------
--
-- The bot people actually ask for first is a music bot, and a music bot only
-- ever *publishes*. It needs no grant, and after this migration it gets none:
-- its token can play audio into the room and receives nothing back.
--
-- That covers the common case outright, which is what makes the strict default
-- affordable. Transcription, an AI that answers out loud, a recorder — those
-- genuinely need to hear, and they need an explicit grant.
--
-- ---------- unlike a key, this one can be taken back ----------
--
-- §6 grants a bot a channel *key*, and the awkward half of that section is that
-- a key is arithmetic: revoking rotates forward and the bot keeps everything it
-- already unwrapped. Nothing can be done about it.
--
-- Voice is not encrypted end to end — media is DTLS-SRTP to the server's own
-- LiveKit, which the operator runs (ARCHITECTURE.md §5). Subscription is
-- therefore a *permission*, not a key, and permissions really do come back:
-- revoking pushes `canSubscribe: false` onto the bot's live connection and the
-- audio stops mid-call. So this grant is honestly reversible in a way §6's is
-- not, and it is worth saying so rather than describing them as the same thing.
--
-- ---------- no server-wide form ----------
--
-- §6 has a bulk grant because thirty channels one at a time produces a button
-- somebody else builds without thinking. That argument does not carry here:
-- there is no MEE6 of voice, listening to a room full of people is a larger
-- decision than reading a text channel, and "every call on this server, plus
-- the ones made later" is not a thing anybody should be able to click once.
-- Per channel is the only form.

-- ============================================================
-- 1. The grant
-- ============================================================

CREATE TABLE IF NOT EXISTS bot_voice_grants (
  channel_id UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id     UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  granted_by UUID        REFERENCES users(id) ON DELETE SET NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, bot_id)
);

COMMENT ON TABLE bot_voice_grants IS
  'Bots whose LiveKit token may subscribe in this voice channel. Absent a row '
  'a bot publishes and hears nothing. Read by get_channel_token when it mints '
  'the grant, and by every client to draw the recording light.';

CREATE INDEX IF NOT EXISTS bot_voice_grants_bot_idx ON bot_voice_grants (bot_id);

ALTER TABLE bot_voice_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bot_voice_grants FROM anon, authenticated;

-- Readable by anyone who can see the channel, which is §6's fourth rule
-- arriving in voice: the admin grants, and everybody who ever speaks in that
-- room pays for it. They are not the same people, so the notice cannot live in
-- the dialog where the decision was made.
--
-- `can_see_channel` rather than `server_id`: a private voice channel's
-- membership is not public, and neither is what is listening to it.
GRANT SELECT ON bot_voice_grants TO authenticated;

DROP POLICY IF EXISTS bot_voice_grants_select ON bot_voice_grants;
CREATE POLICY bot_voice_grants_select ON bot_voice_grants
  FOR SELECT TO authenticated USING (app.can_see_channel(channel_id));

-- ============================================================
-- 2. Granting and taking back
-- ============================================================
-- Both return a reason rather than raising, matching grant_bot_channel_key —
-- the caller is a dialog, and "forbidden" and "no such bot" are things it draws
-- differently rather than an exception it reports.
--
-- There is no system message on either. A voice channel holds no messages: it
-- carries the columns and ignores them (ARCHITECTURE.md §3), so a line in the
-- scrollback would be a line nothing renders. The notice is the standing
-- marker in the channel and the bot's own page, which are the two carriers of
-- §6's three that a room without a transcript can have.

CREATE OR REPLACE FUNCTION grant_bot_voice_listen(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bot TEXT;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  -- Not "is it on my server". An administrator standing outside a private
  -- voice channel is not among the people whose call this is.
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM channels
                  WHERE id = p_channel AND channel_type = 'voice') THEN
    RETURN jsonb_build_object('reason', 'not_a_voice_channel');
  END IF;

  SELECT display_name INTO v_bot FROM users
   WHERE id = p_bot AND is_bot AND NOT is_banned AND server_id = app.server_id();
  IF v_bot IS NULL THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_voice_grants (channel_id, bot_id, granted_by)
  VALUES (p_channel, p_bot, auth.uid())
  ON CONFLICT (channel_id, bot_id) DO NOTHING;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION revoke_bot_voice_listen(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  DELETE FROM bot_voice_grants
   WHERE channel_id = p_channel AND bot_id = p_bot;

  -- The row is only half of it: a bot already in the call holds a token whose
  -- grant said `canSubscribe`, and a token is good for its hour no matter what
  -- this table says afterwards. The `set_bot_voice_listen` edge function pushes
  -- the new permission onto the live connection, the same way `moderate_user`
  -- does for a mute — which is the bug that taught us the row alone is not the
  -- feature.
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

REVOKE ALL ON FUNCTION grant_bot_voice_listen(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_bot_voice_listen(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION grant_bot_voice_listen(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION revoke_bot_voice_listen(UUID, UUID) TO authenticated;

-- ============================================================
-- 3. A channel that becomes private
-- ============================================================
-- The same re-decision 030 makes for text keys. Whoever granted this was
-- looking at a room the whole server could walk into; a room with a door is a
-- different question, and it should be asked again rather than inherited.

CREATE OR REPLACE FUNCTION drop_bot_voice_grants_when_closed()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF NEW.is_private AND NOT OLD.is_private THEN
    DELETE FROM bot_voice_grants WHERE channel_id = NEW.id;
  END IF;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS channels_drop_bot_voice_grants ON channels;
CREATE TRIGGER channels_drop_bot_voice_grants AFTER UPDATE OF is_private ON channels
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_grants_when_closed();

-- ============================================================
-- 4. What a client draws the recording light from
-- ============================================================
-- The table is readable directly, but the marker needs a name rather than an
-- id, and joining `users` from every client that draws a channel row is a
-- second query per channel. One view, one round trip.

CREATE OR REPLACE VIEW voice_listeners
  WITH (security_invoker = true) AS
  SELECT g.channel_id,
         g.bot_id,
         u.display_name AS bot_name,
         g.granted_at
    FROM bot_voice_grants g
    JOIN users u ON u.id = g.bot_id
   WHERE NOT u.is_banned;

COMMENT ON VIEW voice_listeners IS
  'Bots that can hear each voice channel, with the name to show. '
  'security_invoker, so bot_voice_grants_select is what decides who sees it.';

REVOKE ALL ON voice_listeners FROM anon;
GRANT SELECT ON voice_listeners TO authenticated;


-- ============================================================
-- Rift self-hosted server — 032: the key a bot speaks with
-- ============================================================
-- Voice is end-to-end encrypted from 031 onward, and that broke the one thing
-- BOTS.md §6b had just bought: a bot that publishes into a call but cannot hear
-- it. Encrypting is what makes a bot audible, holding the key is what makes it
-- a listener, and with one key per room those are the same act — §2's "write but
-- not read is not expressible with a key", arriving in voice.
--
-- ---------- two directions, two keys ----------
--
-- The room runs in LiveKit's per-participant key mode, so participants need not
-- share one key. Members use the channel key. A bot uses
--
--     botKey = HMAC-SHA256(channelKey, 'voicebot:v1:<botId>')
--
-- Every member holds `channelKey`, so every member derives `botKey` and hears
-- the bot. The bot is handed only `botKey`, and HMAC does not run backwards, so
-- it cannot reach `channelKey` and cannot decrypt one member's audio. Two bots
-- in one call cannot decrypt each other either — the bot id is in the context.
--
-- ---------- and the listening grant is a key grant now ----------
--
-- 031 made "let this bot hear" a flag on a LiveKit token, and said it was
-- revocable because a permission is not arithmetic. Encryption changes that: a
-- bot that may hear needs `channelKey` itself, and a key that has been handed
-- over cannot be taken back. So a granted bot is sealed the channel key here,
-- `is_channel_key` records which of the two it holds, and revoking now means
-- what it means in §6 — rotate forward, and it keeps what it already heard.
--
-- Worth saying plainly rather than leaving 031's sentence standing.

CREATE TABLE IF NOT EXISTS bot_voice_keys (
  channel_id           UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id               UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  key_version          INTEGER     NOT NULL,
  -- false: the derived publish key. true: the channel key itself, which only a
  -- bot with a listening grant may be given.
  is_channel_key       BOOLEAN     NOT NULL DEFAULT false,
  wrapped_by           UUID        REFERENCES users(id) ON DELETE SET NULL,
  ephemeral_public_key TEXT        NOT NULL,
  ciphertext           TEXT        NOT NULL,
  nonce                TEXT        NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, bot_id, key_version)
);

COMMENT ON TABLE bot_voice_keys IS
  'The key a bot encrypts its own media with in one voice channel, sealed to '
  'its chat identity by a member. Derived from the channel key unless the bot '
  'holds a listening grant, in which case it is the channel key.';

CREATE INDEX IF NOT EXISTS bot_voice_keys_bot_idx ON bot_voice_keys (bot_id);

ALTER TABLE bot_voice_keys ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bot_voice_keys FROM anon, authenticated;
GRANT SELECT, INSERT ON bot_voice_keys TO authenticated;

-- ============================================================
-- 1. Who may write one
-- ============================================================
-- Only somebody who holds the channel key can produce either value, so this is
-- the same shape as healing: any member of the room does the work, and the
-- server checks nothing about the bytes because it cannot read them.
--
-- **A bot may not write here.** It has no channel key to derive from, so a row
-- from a bot is either nonsense or a bot handing another bot something it was
-- not given — and `refuse_bot_keyring` already established that the answer to
-- "should a bot be able to write key material" is no.
--
-- What the server *can* check is the flag: `is_channel_key` is only true where
-- a listening grant exists. A member could still seal the channel key and
-- label it false, and no database can catch that — a member holding the key
-- can leak it anywhere, which is true of every channel and is not what this
-- table defends against. What it defends against is the grant meaning one thing
-- in the UI and another in the room.

CREATE OR REPLACE FUNCTION app.may_write_bot_voice_key(
  p_channel UUID,
  p_bot     UUID,
  p_channel_key BOOLEAN
) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = public AS $$
  SELECT NOT app.is_bot()
     AND app.can_see_channel(p_channel)
     AND EXISTS (SELECT 1 FROM channels c
                  WHERE c.id = p_channel AND c.channel_type = 'voice')
     AND EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = app.server_id())
     AND (NOT p_channel_key
          OR EXISTS (SELECT 1 FROM bot_voice_grants g
                      WHERE g.channel_id = p_channel AND g.bot_id = p_bot))
$$;

DROP POLICY IF EXISTS bot_voice_keys_insert ON bot_voice_keys;
CREATE POLICY bot_voice_keys_insert ON bot_voice_keys
  FOR INSERT TO authenticated
  WITH CHECK (
    wrapped_by = auth.uid()
    AND app.may_write_bot_voice_key(channel_id, bot_id, is_channel_key)
  );

-- ============================================================
-- 2. Who may read one
-- ============================================================
-- The bot, because it is the point. And any member who can see the channel,
-- because they are the ones who notice a bot has no key yet and seal one — the
-- same healing loop the text keyring uses, and it needs to see what is already
-- there or every client re-seals every version on every open.
--
-- The sealed bytes are readable by members and that is harmless: a member seals
-- them and already holds everything they were derived from.

DROP POLICY IF EXISTS bot_voice_keys_select ON bot_voice_keys;
CREATE POLICY bot_voice_keys_select ON bot_voice_keys
  FOR SELECT TO authenticated
  USING (bot_id = auth.uid() OR app.can_see_channel(channel_id));

-- ============================================================
-- 3. A grant that changes takes the row with it
-- ============================================================
-- Granting hearing to a bot that already holds a publish key has to replace
-- that row, or the bot keeps encrypting with a key nobody looks for and stays
-- inaudible. Revoking has the same problem in reverse — and worse, leaving the
-- channel key sealed to a bot whose grant is gone is the grant not actually
-- being revoked.
--
-- Dropping the rows is enough: the next member into the call finds the bot
-- missing a key for the current version and seals the right one.

CREATE OR REPLACE FUNCTION drop_bot_voice_keys_on_grant_change()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  DELETE FROM bot_voice_keys
   WHERE channel_id = COALESCE(NEW.channel_id, OLD.channel_id)
     AND bot_id     = COALESCE(NEW.bot_id, OLD.bot_id);
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS bot_voice_grants_reset_keys ON bot_voice_grants;
CREATE TRIGGER bot_voice_grants_reset_keys
  AFTER INSERT OR DELETE ON bot_voice_grants
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_keys_on_grant_change();

-- ============================================================
-- 4. What a client needs to seal
-- ============================================================
-- Bots eligible to speak in a voice channel that have no key for the version
-- in force. Service-role only, like `channel_eligible_members` (021): it is the
-- answer the policies give, computed once, so four hand-written filters do not
-- become four places to forget one.
--
-- Every bot on the server that can see the channel is listed, grant or no
-- grant. Speaking is not the part that needs allowing — a bot with no grant
-- gets the derived key and still cannot hear a word.

CREATE OR REPLACE VIEW bot_voice_key_candidates
  WITH (security_invoker = false) AS
  SELECT c.id  AS channel_id,
         u.id  AS bot_id,
         u.chat_public_key,
         EXISTS (SELECT 1 FROM bot_voice_grants g
                  WHERE g.channel_id = c.id AND g.bot_id = u.id) AS may_listen
    FROM channels c
    JOIN users u ON u.server_id = c.server_id
   WHERE c.channel_type = 'voice'
     AND u.is_bot
     AND NOT u.is_banned
     AND u.chat_public_key IS NOT NULL
     AND (NOT c.is_private
          OR EXISTS (SELECT 1 FROM channel_members m
                      WHERE m.channel_id = c.id AND m.user_id = u.id));

COMMENT ON VIEW bot_voice_key_candidates IS
  'Bots that may speak in each voice channel, and whether they may also hear '
  'it. Read by get_channel_key so a member''s client can seal what is missing.';

REVOKE ALL ON bot_voice_key_candidates FROM anon, authenticated;
