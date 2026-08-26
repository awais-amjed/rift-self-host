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
