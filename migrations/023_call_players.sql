-- ============================================================
-- Rift self-hosted server — 023: a bot's player belongs to its call
-- ============================================================
-- A music bot's player is a live panel (022) posted in whatever text channel
-- somebody typed `/play` in, and the app shows it to the people in the bot's
-- call in every channel they read. Every read and every press still went
-- through the channel it was posted in, so a player started from a private
-- text channel was the private channel's: the others in the call heard the
-- music and could neither see what it was nor skip it, and whoever started it
-- was the only one who could stop it.
--
-- The player is the call's, so the call decides who reaches it. A bot names
-- the voice channel it plays to beside the live mark:
--
--   {"v": 1, "live": true, "call": "<voice channel id>", "blocks": [...]}
--
-- and anybody who can see that voice channel may read that one row and press
-- its buttons, wherever it was posted. A private voice channel keeps its
-- player to the people who can join it. Nothing else about the text channel
-- opens: not its other rows, not its name, not the `/play` that started it.
-- Who is actually in the call is LiveKit's to know and not this database's;
-- the app shows the player only to them, and the bot refuses a press from
-- anybody else (BOTS.md §6).
--
--   * `messages_panel_call` keeps `call` honest: a voice channel on this
--     server that the bot could join, on a live panel. Anything else is
--     dropped from the row rather than refused, so a redraw after the bot lost
--     the channel still lands, back to its channel's readers alone.
--   * `messages_select` admits such a row to whoever can see its call.
--   * `messages_insert` lets them press it: a press goes to the panel's own
--     channel, addressed to its bot, as every press does.
--   * `app.announce_message` rings the call's topic too, when that is not the
--     topic the channel's own doorbell already rang.
--   * `call_live_messages` is `channel_live_messages` for a call.
--   * `app.can_read_attachment` lets them read the pictures it draws (its
--     cover), which the bot stored under the channel it posted in.
--
-- A bot or a server from before this keeps the old behaviour: no `call`, and
-- the player is the channel's readers' alone.
-- ============================================================

-- ── What a live panel says about its call ───────────────────

-- The call [blocks] names, if it is a live panel's and reads as an id. The
-- trigger below has already checked everything else by the time it is stored.
CREATE OR REPLACE FUNCTION app.panel_call(p_blocks JSONB) RETURNS UUID
  LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN p_blocks -> 'live' = 'true'::jsonb
     AND p_blocks ->> 'call' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    THEN (p_blocks ->> 'call')::UUID
  END
$$;

CREATE OR REPLACE FUNCTION app.check_panel_call() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_call UUID;
BEGIN
  IF NEW.blocks IS NULL OR NOT (NEW.blocks ? 'call') THEN
    RETURN NEW;
  END IF;
  v_call := app.panel_call(NEW.blocks);
  IF v_call IS NULL
     OR NEW.ephemeral_for IS NOT NULL
     OR NOT EXISTS (
       SELECT 1 FROM channels c
         JOIN channels here ON here.id = NEW.channel_id
        WHERE c.id = v_call
          AND c.channel_type = 'voice'
          AND c.server_id = here.server_id)
     OR NOT channel_joinable_by(v_call, NEW.sender_id) THEN
    NEW.blocks := NEW.blocks - 'call';
  END IF;
  RETURN NEW;
END $$;

-- After `attest_messages`, which sets the sender this asks about.
DROP TRIGGER IF EXISTS messages_panel_call ON messages;
CREATE TRIGGER messages_panel_call BEFORE INSERT OR UPDATE OF blocks ON messages
  FOR EACH ROW EXECUTE FUNCTION app.check_panel_call();

-- A call's players, newest first, without reading every channel.
CREATE INDEX IF NOT EXISTS idx_messages_call_panels
  ON messages ((blocks ->> 'call'), id) WHERE blocks -> 'live' = 'true'::jsonb;

-- ── Who may read one ────────────────────────────────────────
-- As in 008, plus the third way in. `visible_channels` is built once per
-- statement, so the new clause costs a JSON read and a set lookup per row.

DROP POLICY IF EXISTS messages_select ON messages;
CREATE POLICY messages_select ON messages FOR SELECT TO authenticated
  USING (
    (channel_id IN (SELECT unnest(app.visible_channels()))
     OR channel_id IN (SELECT unnest(app.bot_channels()))
     OR (blocks -> 'live' = 'true'::jsonb
         AND blocks ->> 'call' IN (SELECT unnest(app.visible_channels())::TEXT)))
    AND ((SELECT NOT app.is_bot())
         OR to_bot = (SELECT auth.uid())
         OR sender_id = (SELECT auth.uid())
         OR app.bot_reads_version(channel_id, key_version))
    AND (ephemeral_for IS NULL
         OR ephemeral_for = (SELECT auth.uid())
         OR sender_id = (SELECT auth.uid()))
    AND (NOT is_interaction
         OR sender_id = (SELECT auth.uid())
         OR to_bot = (SELECT auth.uid()))
  );

-- ── Who may press one ───────────────────────────────────────

-- Is [p_panel] a live panel in [p_channel], drawn by [p_bot], for a call the
-- caller can see? Asked only of a press into a channel the caller cannot see.
CREATE OR REPLACE FUNCTION app.can_press_call_panel(
  p_channel UUID, p_panel BIGINT, p_bot UUID
) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM messages m
     WHERE m.id = p_panel
       AND m.channel_id = p_channel
       AND m.sender_id = p_bot
       AND m.ephemeral_for IS NULL
       AND app.panel_call(m.blocks) IS NOT NULL
       AND app.can_see_channel(app.panel_call(m.blocks)))
$$;

COMMENT ON FUNCTION app.can_press_call_panel(UUID, BIGINT, UUID) IS
  'Whether the caller may press this bot''s live panel because they can see '
  'the call it plays to, though not the channel it was posted in.';

-- As in 015, with the first line widened to a press on a call's player.
DROP POLICY IF EXISTS messages_insert ON messages;
CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    (app.can_see_channel(channel_id)
     OR (is_interaction AND app.can_press_call_panel(channel_id, reply_to, to_bot)))
    AND app.has_perm('SEND_MESSAGES')
    AND NOT app.timed_out()
    AND sender_id = auth.uid()
    AND webhook_id IS NULL AND origin_name IS NULL AND NOT is_system
    AND (key_version >= 1 OR to_bot IS NOT NULL OR app.is_bot()
         OR NOT app.channel_encrypted(channel_id))
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
    -- A poll is a member asking the channel. A bot has panels for asking, and
    -- a poll addressed to one bot is a question only it could see answered.
    -- Its own bit, on `@everyone` by default, so a server can keep polls to
    -- the roles it picks without taking anybody's voice away.
    AND (poll IS NULL OR (NOT app.is_bot() AND to_bot IS NULL
                          AND app.has_perm('CREATE_POLLS')))
  );

-- ── Who hears it change ─────────────────────────────────────
-- As in 005, plus the call. A player that stops being live (or goes) is the
-- call's news too, so the old row's call counts. Not rung twice on one topic:
-- a public channel and a public call both ring the server's.

CREATE OR REPLACE FUNCTION app.announce_message() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_row     messages%ROWTYPE;
  v_event   TEXT;
  v_payload JSONB;
  v_call    UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_row := OLD;
  ELSE
    v_row := NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    v_event := 'message';
    v_payload := jsonb_build_object(
      'id',           v_row.id,
      'channel_id',   v_row.channel_id,
      'sender_id',    v_row.sender_id,
      'mentions',     COALESCE(to_jsonb(v_row.mentions), '[]'::jsonb),
      'mentions_all', COALESCE(v_row.mentions_all, false));
  ELSE
    v_event := 'message_changed';
    v_payload := jsonb_build_object(
      'message_id', v_row.id,
      'channel_id', v_row.channel_id);
  END IF;

  -- Whoever it is for, and nobody else. An interaction with no bot to answer
  -- it is for nobody, and saying so to a topic called `user:` is worse than
  -- saying nothing.
  IF v_row.is_interaction OR v_row.ephemeral_for IS NOT NULL THEN
    IF COALESCE(v_row.ephemeral_for, v_row.to_bot) IS NOT NULL THEN
      PERFORM realtime.send(v_payload, v_event,
        'user:' || COALESCE(v_row.ephemeral_for, v_row.to_bot), true);
    END IF;
    RETURN NULL;
  END IF;

  PERFORM app.announce_to_channel(v_row.channel_id, v_event, v_payload);
  IF v_row.to_bot IS NOT NULL THEN
    PERFORM realtime.send(v_payload, v_event, 'user:' || v_row.to_bot, true);
  END IF;

  v_call := app.panel_call(v_row.blocks);
  IF v_call IS NULL AND TG_OP = 'UPDATE' THEN
    v_call := app.panel_call(OLD.blocks);
  END IF;
  IF v_call IS NOT NULL
     AND EXISTS (SELECT 1 FROM channels c
                  WHERE c.id IN (v_call, v_row.channel_id) AND c.is_private) THEN
    PERFORM app.announce_to_channel(v_call, v_event, v_payload);
  END IF;
  RETURN NULL;
END $$;

-- ── What a call's bar holds ─────────────────────────────────
-- In two halves, as `channel_live_messages` is (022): ids from the index here,
-- rows under `messages_select` below.

CREATE OR REPLACE FUNCTION app.call_live_ids(p_call UUID)
RETURNS SETOF BIGINT
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.can_see_channel(p_call) THEN RETURN; END IF;

  RETURN QUERY
  SELECT x.id FROM messages x
   WHERE x.blocks ->> 'call' = p_call::TEXT
     AND x.blocks -> 'live' = 'true'::jsonb
   ORDER BY x.id DESC LIMIT 25;
END $$;

COMMENT ON FUNCTION app.call_live_ids(UUID) IS
  'Ids of the live panels playing to a call, newest first, at most 25. '
  'Ids only; `call_live_messages` turns them into rows under RLS.';

CREATE OR REPLACE FUNCTION call_live_messages(p_call UUID)
RETURNS SETOF messages
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT m.* FROM app.call_live_ids(p_call) AS l(id)
    JOIN messages m ON m.id = l.id
   ORDER BY m.id DESC;
$$;

COMMENT ON FUNCTION call_live_messages(UUID) IS
  'The players of a voice call''s bots, from whichever text channel each was '
  'posted in, newest first. Rows are still subject to messages_select.';

-- ── Its pictures ────────────────────────────────────────────
-- As in 016, plus one door: an object under a channel the caller cannot see
-- is still theirs to read when a live panel in that channel, playing to a
-- call they can see, draws it. Only what such a panel names in an `image`
-- block, by its exact path; a player stops drawing a cover and the door
-- closes with it.

CREATE OR REPLACE FUNCTION app.can_read_attachment(p_name TEXT) RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_scope TEXT := split_part(p_name, '/', 1);
  v_me    TEXT := auth.uid()::TEXT;
BEGIN
  IF v_scope ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN app.can_see_channel(v_scope::UUID)
        OR EXISTS (
          SELECT 1 FROM messages m
           WHERE m.channel_id = v_scope::UUID
             AND m.blocks -> 'live' = 'true'::jsonb
             AND m.ephemeral_for IS NULL
             AND m.blocks -> 'blocks' @> jsonb_build_array(
                   jsonb_build_object('type', 'image', 'path', p_name))
             AND app.panel_call(m.blocks) IS NOT NULL
             AND app.can_see_channel(app.panel_call(m.blocks)));
  END IF;
  -- `dm_` and two ids of 36 characters with `_` between: the first starts at
  -- the fourth character, the second at the forty-first.
  IF v_scope ~ '^dm_[0-9a-f-]{36}_[0-9a-f-]{36}$' THEN
    RETURN v_me IS NOT NULL
       AND v_me IN (substr(v_scope, 4, 36), substr(v_scope, 41, 36));
  END IF;
  RETURN false;
END $$;

COMMENT ON FUNCTION app.can_read_attachment(TEXT) IS
  'Whether the caller may read the chat attachment stored as p_name: one sent '
  'in a channel they can see, or in a server DM they are one end of, or a '
  'picture drawn by a live panel playing to a call they can see.';

-- ============================================================
-- Who may call them
-- ============================================================
REVOKE ALL ON FUNCTION app.panel_call(JSONB) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.check_panel_call() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.can_press_call_panel(UUID, BIGINT, UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_message() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.call_live_ids(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION call_live_messages(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.can_read_attachment(TEXT) FROM PUBLIC, anon, authenticated;

-- The policies call these as the member: `panel_call` from `announce_message`
-- and `can_press_call_panel` (both definers, so not the member), and
-- `can_press_call_panel` itself from `messages_insert`.
GRANT EXECUTE ON FUNCTION app.can_press_call_panel(UUID, BIGINT, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION call_live_messages(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION app.can_read_attachment(TEXT) TO authenticated;
-- The definer half, which `call_live_messages` calls and nothing else should.
GRANT EXECUTE ON FUNCTION app.call_live_ids(UUID) TO authenticated;
