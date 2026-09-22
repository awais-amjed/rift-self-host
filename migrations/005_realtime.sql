-- ============================================================
-- Rift self-hosted server — 005: what a client is told
-- ============================================================
-- Rift broadcasts; it does not replicate. No table is in `supabase_realtime`
-- and none should be: a published table has every change decoded by Realtime
-- whether or not anybody is watching, and the row that comes out is the
-- stored row — which for a message is ciphertext plus the metadata, sent to
-- everyone subscribed to the table.
--
-- Instead each change a client needs is announced explicitly, by a trigger,
-- onto a topic that only the people entitled to it may join. What is in the
-- payload is then a decision rather than a consequence.
-- ============================================================

-- ============================================================
-- 2. Saying it
-- ============================================================
-- `realtime.send` swallows its own failures (it raises a warning), so a
-- broadcast that cannot be delivered never fails the write that caused it.
-- It does not exist until Realtime has created its schema, which on a new
-- server can be after this runs; until then there is nobody to tell.

CREATE OR REPLACE FUNCTION app.realtime_ready() RETURNS BOOLEAN
  LANGUAGE sql STABLE AS $$
  SELECT to_regprocedure('realtime.send(jsonb,text,text,boolean)') IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app.announce_reaction() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_message BIGINT;
  v_channel UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_message := OLD.message_id;
  ELSE
    v_message := NEW.message_id;
  END IF;
  SELECT m.channel_id INTO v_channel FROM messages m WHERE m.id = v_message;
  IF v_channel IS NOT NULL THEN
    PERFORM app.announce_to_channel(v_channel, 'reaction',
      jsonb_build_object('message_id', v_message, 'channel_id', v_channel));
  END IF;
  RETURN NULL;
END $$;

-- ---------- DMs ----------
-- A new DM rings the recipient. An edit or a delete rings the recipient too:
-- only the sender can make either, and the sender already knows.

CREATE OR REPLACE FUNCTION app.announce_dm() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'INSERT' THEN
    PERFORM realtime.send(
      jsonb_build_object('id', NEW.id, 'sender_id', NEW.sender_id),
      'dm', 'user:' || NEW.recipient_id, true);
  ELSIF TG_OP = 'UPDATE' THEN
    PERFORM realtime.send(jsonb_build_object('message_id', NEW.id),
      'dm_changed', 'user:' || NEW.recipient_id, true);
  ELSE
    PERFORM realtime.send(jsonb_build_object('message_id', OLD.id),
      'dm_changed', 'user:' || OLD.recipient_id, true);
  END IF;
  RETURN NULL;
END $$;

-- Either party can react, so both hear it; the reactor's own devices refresh
-- one message for nothing, which is the cheapest way to keep them in step.
CREATE OR REPLACE FUNCTION app.announce_dm_reaction() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_message BIGINT;
  v_party   UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_message := OLD.message_id;
  ELSE
    v_message := NEW.message_id;
  END IF;
  FOR v_party IN
    SELECT unnest(ARRAY[d.sender_id, d.recipient_id])
      FROM dm_messages d WHERE d.id = v_message
  LOOP
    PERFORM realtime.send(jsonb_build_object('message_id', v_message),
      'dm_reaction', 'user:' || v_party, true);
  END LOOP;
  RETURN NULL;
END $$;

-- ---------- the server's shape ----------
-- `channels`: the sidebar. `members`: the member list. `me`: your own row —
-- a ban, a mute, a role — which is the only one that should make a client
-- re-read the whole server. Watching `users` used to send every member back
-- for the whole server whenever anybody's row moved.

CREATE OR REPLACE FUNCTION app.announce_channels() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_server := OLD.server_id;
  ELSE
    v_server := NEW.server_id;
  END IF;
  PERFORM realtime.send('{}'::jsonb, 'channels', 'server:' || v_server, true);
  RETURN NULL;
END $$;

-- The library changed. An empty payload like `channels`, for the same reason:
-- what a client does with this is re-read the list, and sending the row would
-- be a second copy of it that can disagree with the first.
CREATE OR REPLACE FUNCTION app.announce_soundboard() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_server := OLD.server_id;
  ELSE
    v_server := NEW.server_id;
  END IF;
  PERFORM realtime.send('{}'::jsonb, 'soundboard', 'server:' || v_server, true);
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION app.announce_member() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_row users%ROWTYPE;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_row := OLD;
  ELSE
    v_row := NEW;
  END IF;
  PERFORM realtime.send('{}'::jsonb, 'members', 'server:' || v_row.server_id, true);
  IF TG_OP <> 'INSERT' THEN
    PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || v_row.id, true);
  END IF;
  RETURN NULL;
END $$;

-- ---------- notification levels ----------
-- A level set on one device reaches the others.

CREATE OR REPLACE FUNCTION app.announce_prefs() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_user UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_user := OLD.user_id;
  ELSE
    v_user := NEW.user_id;
  END IF;
  PERFORM realtime.send('{}'::jsonb, 'prefs', 'user:' || v_user, true);
  RETURN NULL;
END $$;

-- ---------- a message addressed to a bot reaches that bot ----------
-- Two cases a bot has that a member does not.
--
-- An interaction is a button press: `messages_select` shows it to the presser
-- and to the bot alone, so it goes to the bot alone.
--
-- An addressed message (`to_bot`) is an ordinary message that members can see
-- too, so the channel still hears it; the bot is told as well, because being
-- addressed is not the same as being granted and a bot usually holds no grant
-- on the channel somebody summoned it in.

CREATE OR REPLACE FUNCTION app.announce_message() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_row     messages%ROWTYPE;
  v_event   TEXT;
  v_payload JSONB;
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
  RETURN NULL;
END $$;

-- ============================================================
-- A seat at a private table is news
-- ============================================================
-- Being added to a private channel would otherwise reach nobody.
--
-- `channels` is announced when the `channels` row moves, which covers a
-- channel created, renamed or deleted. Handing somebody a seat at one moves
-- no such row: it inserts into `channel_members`. The new member's own `users`
-- row does not move either, so not even `me` would fire. They would be in the
-- channel as far as every policy was concerned, and
-- their sidebar did not know until the app was restarted or the server
-- reselected.
--
-- Measured before writing this: a member added to a private channel still had
-- no sign of it fifteen seconds later, and it appeared on the next launch.
--
-- ---------- why `me` and not a new event ----------
--
-- `me` already means "your standing on this server changed — re-read it",
-- which is how a ban, a mute and a role reach the person they happened to,
-- and the client already listens for it on its own topic. A seat at a private
-- table is the same kind of fact, so it travels the same way and no client
-- changes at all. A `channels` event would have been wrong twice over: it
-- goes to the server's topic, where everybody would re-read for one person's
-- news, and the one person it is actually for is exactly the one whose
-- previous read could not see the channel.
--
-- Both ends of the change, so losing a seat is as immediate as gaining one —
-- a private channel that lingers in the sidebar after access was taken away
-- is the worse of the two to leave.

CREATE OR REPLACE FUNCTION app.announce_channel_member() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;

  IF TG_OP = 'DELETE' THEN
    PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || OLD.user_id, true);
    RETURN NULL;
  END IF;

  -- An UPDATE that moved nothing but `can_manage` is news too: it decides
  -- whether the channel's settings are reachable at all.
  PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || NEW.user_id, true);
  IF TG_OP = 'UPDATE' AND OLD.user_id <> NEW.user_id THEN
    PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || OLD.user_id, true);
  END IF;
  RETURN NULL;
END $$;

-- ============================================================
-- A private channel gets a topic of its own
-- ============================================================
-- A message in an **open** channel is announced once, to `server:<id>`, and
-- Realtime fans it out to whoever is listening. A message in a **private**
-- channel was announced once *per member who could see it* — a row in
-- `realtime.messages` each, written by the transaction that sent the
-- message.
--
-- Measured on a private channel reachable by 8,750 people (500 by seat, the
-- rest through a role the channel admits):
--
--   announce to an open channel ......    0.04 ms
--   announce to that private channel .  176    ms
--
-- Four thousand times the cost, and it scales with the membership: the
-- sender's own insert pays for everybody else's notification. A private
-- channel with 50,000 members would take about a second per message, in the
-- writing transaction, holding its locks the whole time.
--
-- The fan-out itself is not the problem — Realtime does the same number of
-- deliveries either way, and does them well (measured at ~97,000 a second).
-- The problem is doing the fan-out *in Postgres*, one INSERT at a time.
--
-- So a private channel now has a topic of its own, `channel:<channel id>`,
-- and the announcement is one row again whatever the membership. That is
-- exactly what `server:<id>` already does for open channels; there was never
-- a reason for private ones to work differently, beyond `server:<id>` being
-- too wide an audience for them.
--
-- ---------- what may be said there, and by whom ----------
--
-- Read by anyone `app.can_see_channel` admits — the same rule that decides
-- whether they may read the messages being announced, so the topic cannot
-- tell them anything the table would not.
--
-- **Written by nobody.** Every other topic here is writable by the members
-- who can join it, because clients send typing indicators and doorbells on
-- them. Nothing is sent here by a client, so nothing may be: a member who
-- could write to it could forge a `message` event naming an id, and send a
-- whole private channel off to re-read the database on request.
--
-- Typing stays on `chat:<channel id>`, which clients do write to. The two
-- are deliberately separate topics rather than one: what the database
-- asserts and what a member claims should not arrive by the same door.
--
-- ---------- what still goes to a person's own topic ----------
--
-- An ephemeral reply — a bot answering one member where nobody else sees it
-- — is still sent to `user:<id>`, because its audience is one person and not
-- a channel. `app.announce_message` decides that before it gets here.

-- ============================================================
-- 1. Who may join a channel's topic
-- ============================================================

CREATE OR REPLACE FUNCTION app.can_use_topic(p_topic TEXT, p_write BOOLEAN)
  RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_kind   TEXT := split_part(p_topic, ':', 1);
  v_rest   TEXT := substr(p_topic, length(split_part(p_topic, ':', 1)) + 2);
  v_me     UUID := auth.uid();
  v_server UUID;
BEGIN
  IF v_me IS NULL THEN
    RETURN FALSE;
  END IF;

  -- Before the ban check, on purpose: a banned member still hears their own
  -- topic, because that is how they learn the ban was lifted.
  IF v_kind = 'user' AND NOT p_write THEN
    RETURN v_rest = v_me::text;
  END IF;

  v_server := app.server_id();  -- null for a banned member, or a stranger
  IF v_server IS NULL THEN
    RETURN FALSE;
  END IF;

  CASE v_kind
    WHEN 'server', 'presence', 'voice' THEN
      RETURN v_rest = v_server::text;
    WHEN 'user' THEN
      -- Only a DM's typing indicator is sent here by a client; everything else
      -- on a user topic comes from the database.
      RETURN v_rest ~ '^[0-9a-f-]{36}$' AND app.is_co_member(v_rest::uuid);
    WHEN 'chat' THEN
      RETURN v_rest ~ '^[0-9a-f-]{36}$' AND app.can_see_channel(v_rest::uuid);
    WHEN 'channel' THEN
      -- Listening only. The database is the only thing that speaks here, and
      -- a member who could speak here could forge a message announcement to
      -- everyone in a private channel.
      RETURN NOT p_write
         AND v_rest ~ '^[0-9a-f-]{36}$'
         AND app.can_see_channel(v_rest::uuid);
    ELSE
      RETURN FALSE;
  END CASE;
END $$;

COMMENT ON FUNCTION app.can_use_topic(TEXT, BOOLEAN) IS
  'Whether the caller may join (p_write false) or send on (p_write true) a '
  'Realtime topic. `channel:<id>` is listen-only: the database speaks there.';

-- ============================================================
-- 2. Saying it once
-- ============================================================

CREATE OR REPLACE FUNCTION app.announce_to_channel(
  p_channel UUID,
  p_event   TEXT,
  p_payload JSONB
) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server  UUID;
  v_private BOOLEAN;
BEGIN
  SELECT c.server_id, c.is_private INTO v_server, v_private
    FROM channels c WHERE c.id = p_channel;
  IF v_server IS NULL THEN
    RETURN;
  END IF;

  -- One row either way. An open channel reaches the whole server, a private
  -- one reaches its own topic, and Realtime does the fanning out — which is
  -- its job, and which it is much better at than a trigger is.
  IF v_private THEN
    PERFORM realtime.send(p_payload, p_event, 'channel:' || p_channel, true);
  ELSE
    PERFORM realtime.send(p_payload, p_event, 'server:' || v_server, true);
  END IF;

  -- A bot joins neither of the topics above — it
  -- hears everything on its own, which is what keeps the SDK to one
  -- subscription (BOTS.md §5) — so it is still told one at a time. That
  -- fanout is bounded by the grants on this channel rather than by its
  -- membership, which is a handful, and is why it can stay a loop.
  PERFORM realtime.send(p_payload, p_event, 'user:' || g.bot_id, true)
     FROM bot_channel_keys g
    WHERE g.channel_id = p_channel;
END $$;

COMMENT ON FUNCTION app.announce_to_channel(UUID, TEXT, JSONB) IS
  'Announce something about a channel to whoever may read it: the server''s '
  'topic for an open channel, the channel''s own for a private one. One row '
  'in either case — the membership does not appear in the cost.';

DROP TRIGGER IF EXISTS messages_announce ON messages;
CREATE TRIGGER messages_announce
  AFTER INSERT OR UPDATE OR DELETE ON messages
  FOR EACH ROW EXECUTE FUNCTION app.announce_message();

DROP TRIGGER IF EXISTS message_reactions_announce ON message_reactions;
CREATE TRIGGER message_reactions_announce
  AFTER INSERT OR DELETE ON message_reactions
  FOR EACH ROW EXECUTE FUNCTION app.announce_reaction();

DROP TRIGGER IF EXISTS dm_messages_announce ON dm_messages;
CREATE TRIGGER dm_messages_announce
  AFTER INSERT OR UPDATE OR DELETE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION app.announce_dm();

DROP TRIGGER IF EXISTS dm_message_reactions_announce ON dm_message_reactions;
CREATE TRIGGER dm_message_reactions_announce
  AFTER INSERT OR DELETE ON dm_message_reactions
  FOR EACH ROW EXECUTE FUNCTION app.announce_dm_reaction();

DROP TRIGGER IF EXISTS channels_announce ON channels;
CREATE TRIGGER channels_announce
  AFTER INSERT OR UPDATE OR DELETE ON channels
  FOR EACH ROW EXECUTE FUNCTION app.announce_channels();

DROP TRIGGER IF EXISTS users_announce ON users;
CREATE TRIGGER users_announce
  AFTER INSERT OR UPDATE OR DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION app.announce_member();

DROP TRIGGER IF EXISTS notification_prefs_announce ON notification_prefs;
CREATE TRIGGER notification_prefs_announce
  AFTER INSERT OR UPDATE OR DELETE ON notification_prefs
  FOR EACH ROW EXECUTE FUNCTION app.announce_prefs();

DROP TRIGGER IF EXISTS channel_members_announce ON channel_members;
CREATE TRIGGER channel_members_announce
  AFTER INSERT OR UPDATE OR DELETE ON channel_members
  FOR EACH ROW EXECUTE FUNCTION app.announce_channel_member();

DROP TRIGGER IF EXISTS soundboard_sounds_announce ON soundboard_sounds;
CREATE TRIGGER soundboard_sounds_announce
  AFTER INSERT OR UPDATE OR DELETE ON soundboard_sounds
  FOR EACH ROW EXECUTE FUNCTION app.announce_soundboard();
