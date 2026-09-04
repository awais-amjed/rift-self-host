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
