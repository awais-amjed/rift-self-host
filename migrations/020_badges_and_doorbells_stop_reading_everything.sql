-- ============================================================
-- Rift self-hosted server — 020: a badge stops reading the whole server
-- ============================================================
-- Two things every member's app does constantly, both of which read far more
-- than the answer needs. Measured on a copy of this schema carrying 200,000
-- messages and 1,000 members.
--
-- ---------- 1. the badges ----------
--
-- `unread_counts()` asked the question from the wrong end: it scanned
-- `messages` and grouped by channel. Two things follow from that, and both
-- are bad.
--
-- The policy on `messages` calls `app.can_see_channel(channel_id)`, so driving
-- from the rows means asking it **once per row** — 606,000 buffer hits for a
-- 200,000-row table. And the count itself is unbounded: a member who has never
-- opened a channel counts every message in it, forever, on every call.
--
--   caught-up member .................. 10,840 ms
--   never-opened channel, 200k unread . 11,184 ms
--
-- This asks from the channel end instead. A server has a handful of channels,
-- so the policy runs a handful of times, and each channel is a walk of
-- `idx_messages_channel` from the member's cursor forward — which is what that
-- index is for. The same two cases:
--
--   caught-up member ..................      1.3 ms
--   never-opened channel, 200k unread .      7.0 ms
--
-- The cap is what makes the second one a constant. `UnreadBadge` draws "99+"
-- above ninety-nine, and a server total is the sum of the channels under it,
-- so a channel that stops counting at a hundred draws exactly what an honest
-- count of five thousand would have drawn. A number nobody can read is not
-- worth a table scan an hour.
--
-- ---------- 2. the prefs it stopped returning ----------
--
-- 009 rewrote this function to keep button presses out of the count and,
-- doing so, dropped the `prefs` key that 003 §4 added. Nothing failed: the
-- client reads `data['prefs']`, got null, and fell back to the defaults — so
-- muting a channel worked until the next re-seed and then quietly didn't, on
-- every device, for everyone. It is back here, unchanged.
--
-- ---------- 3. the doorbell nobody ordered ----------
--
-- `ring_channel_members` built the recipient list — every member of the
-- server, each one weighed by `app.channel_eligible` and `has_unread_before`
-- — and only then called `ring_devices`, which is where the question "is push
-- even turned on here?" was asked. On a server with no `push_config` row, all
-- of that work was done and thrown away on **every message**:
--
--   insert with the trigger disabled ....  8 ms
--   insert with the trigger enabled ..... 25–45 ms
--
-- Push is off until an admin turns it on, so that is the default state of
-- every server that has ever been started. The check moves to the top.

-- ============================================================
-- 1. Counting from the channel end
-- ============================================================

-- How high a badge bothers to count. The client draws "99+" past ninety-nine.
CREATE OR REPLACE FUNCTION unread_cap() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 100 $$;

COMMENT ON FUNCTION unread_cap() IS
  'The most a single scope''s unread count will report. The badge says "99+" '
  'above ninety-nine, so anything past this is a number nobody reads.';

REVOKE ALL ON FUNCTION unread_cap() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION unread_cap() TO authenticated;

CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_channels JSONB := '{}'::jsonb;
  v_chan     RECORD;
  v_cursor   BIGINT;
  v_n        INTEGER;
BEGIN
  -- SECURITY INVOKER, so this is the channels the caller may see and no
  -- others: `channels_select` decides, once per channel, instead of
  -- `messages_select` deciding once per message.
  FOR v_chan IN SELECT c.id FROM channels c LOOP
    SELECT r.last_read_id INTO v_cursor
      FROM read_state r
     WHERE r.user_id = auth.uid()
       AND r.scope   = 'channel'
       AND r.scope_id = v_chan.id;
    v_cursor := COALESCE(v_cursor, 0);

    -- A constant channel and a constant cursor, which is what lets the
    -- planner use `idx_messages_channel (channel_id, id)` as a range: start
    -- at the cursor, walk forward, stop at the cap. Written as a correlated
    -- subquery in one big statement it chose a sequential scan instead, cap
    -- and all, which is how the old shape came to cost eleven seconds.
    SELECT count(*) INTO v_n FROM (
      SELECT 1 FROM messages m
       WHERE m.channel_id = v_chan.id
         AND m.id > v_cursor
         -- IS DISTINCT FROM, not <>. A webhook's sender is NULL, and `NULL <>
         -- uid` is NULL rather than true — so every webhook message was
         -- dropped from this count in silence.
         AND m.sender_id IS DISTINCT FROM auth.uid()
         -- A press is not unread mail.
         AND NOT m.is_interaction
       ORDER BY m.id
       LIMIT unread_cap()
    ) capped;

    IF v_n > 0 THEN
      v_channels := v_channels || jsonb_build_object(v_chan.id::TEXT, v_n);
    END IF;
  END LOOP;

  RETURN jsonb_build_object(
    'channels', v_channels,
    -- DMs stay a grouped read: `idx_dm_messages_recipient (recipient_id, id)`
    -- already makes this the caller's own unread mail rather than the table,
    -- and there is no conversation list to drive the loop from.
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
      ) d), '{}'::jsonb),
    -- Restored from 003 §4. Only what has been set: an absent key means "no
    -- opinion here, ask the next scope out".
    'prefs', jsonb_build_object(
      'servers', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'server'), '{}'::jsonb),
      'channels', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'channel'), '{}'::jsonb),
      'dms', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'dm'), '{}'::jsonb)
    ));
END $$;

COMMENT ON FUNCTION unread_counts() IS
  'Badges and notification levels in one answer: {channels, dms, prefs}. '
  'Channel counts stop at unread_cap().';

REVOKE ALL ON FUNCTION unread_counts() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION unread_counts() TO authenticated;

-- ============================================================
-- 2. Asking whether push is on before deciding who to push
-- ============================================================
-- `app.push_enabled` rather than an inline EXISTS in each trigger, so the two
-- of them cannot drift apart on what "configured" means — and so the next
-- thing that wants to ring has one place to ask.

CREATE OR REPLACE FUNCTION app.push_enabled(p_server_id UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM push_config pc WHERE pc.server_id = p_server_id)
$$;

COMMENT ON FUNCTION app.push_enabled(UUID) IS
  'Whether an admin has turned push on for this server. Asked before working '
  'out who to wake, because until it is true that work has no reader.';

REVOKE ALL ON FUNCTION app.push_enabled(UUID) FROM PUBLIC, anon, authenticated;

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
  -- Before the roster, not after it. This is the line that used to sit inside
  -- ring_devices, one full member walk later.
  IF NOT app.push_enabled(v_server_id) THEN RETURN NEW; END IF;

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
END $$;

CREATE OR REPLACE FUNCTION ring_dm_recipient()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
BEGIN
  SELECT server_id INTO v_server_id FROM users WHERE id = NEW.recipient_id;
  IF v_server_id IS NULL THEN RETURN NEW; END IF;
  -- Cheaper than the unread gate below it, and true far less often.
  IF NOT app.push_enabled(v_server_id) THEN RETURN NEW; END IF;

  IF app.notify_level(NEW.recipient_id, 'dm', NEW.sender_id) = 'none' THEN
    RETURN NEW;
  END IF;
  IF has_unread_before(NEW.recipient_id, 'dm', NEW.sender_id, NEW.id) THEN
    RETURN NEW;
  END IF;

  PERFORM ring_devices(v_server_id, ARRAY[NEW.recipient_id]);
  RETURN NEW;
END $$;
