-- ============================================================
-- Rift self-hosted server — 017: Realtime by broadcast, on private topics
-- ============================================================
-- Until this, members heard the database through Postgres Changes: every
-- client watched `messages`, `dm_messages`, `users`, `channels` and
-- `notification_prefs`, and Realtime re-ran the table's read policy for every
-- watcher on every row, on a single thread. A channel message with a thousand
-- members online was a thousand policy checks, and a bigger database does not
-- make that thread any faster. Supabase's own guidance is to stop at about
-- 3,000 watchers and send changes as broadcasts instead.
--
-- So the database now says what happened, once, to the topic whose members
-- should hear it:
--
--   server:<server id>   every member of the server
--   user:<user id>       one person — their DMs, their private channels,
--                        what is addressed to them alone
--
-- and nothing is published to Postgres Changes any more.
--
-- The topics are private, which they never were. Until now anyone holding a
-- server's publishable key — every member, every former member, anyone an
-- invite link was ever shown to — could join `chat:<channel>` and read who was
-- typing in a private channel, or ring a server-wide doorbell and send every
-- member back to the database at once. A private topic is joined only by
-- those `app.can_use_topic` admits.
--
-- What the join rules are attached to is Realtime's own table,
-- `realtime.messages`, which belongs to `supabase_admin` and which Realtime
-- creates when the first client connects — possibly after this has run. The
-- rules themselves are therefore installed by the console, as that role, and
-- checked again whenever it starts. What lives here is the decision they call.
--
-- Every payload is ids and flags. Message bodies are sealed and stay in their
-- tables; a broadcast only says "go and look", exactly as the client-rung
-- doorbells it replaces did.

-- ============================================================
-- 1. Who may use which topic
-- ============================================================
-- [p_write] is a send: a broadcast, or a presence entry. Reading is joining.

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
    ELSE
      RETURN FALSE;
  END CASE;
END $$;

-- The join rules run as the member, so the member has to be able to call it.
-- It answers only about the caller.
REVOKE ALL ON FUNCTION app.can_use_topic(TEXT, BOOLEAN) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.can_use_topic(TEXT, BOOLEAN) TO authenticated;

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

-- Tell whoever can read [p_channel] about [p_event]: the whole server for an
-- open channel, each member for a private one. A private channel's members are
-- the people added to it and the holders of any role it admits — the same two
-- halves `app.in_channel` checks, gathered rather than asked one at a time.
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
  IF NOT v_private THEN
    PERFORM realtime.send(p_payload, p_event, 'server:' || v_server, true);
    RETURN;
  END IF;
  PERFORM realtime.send(p_payload, p_event, 'user:' || member.user_id, true)
     FROM (SELECT cm.user_id FROM channel_members cm
            WHERE cm.channel_id = p_channel
           UNION
           SELECT mr.user_id FROM channel_role_access cra
             JOIN member_roles mr ON mr.role_id = cra.role_id
            WHERE cra.channel_id = p_channel) member;
END $$;

REVOKE ALL ON FUNCTION app.announce_to_channel(UUID, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated;

-- ---------- channel messages ----------
-- `message` for a new one, carrying what an unread badge and a notification
-- need: which channel, who from, and who it names. `message_changed` for an
-- edit, a redrawn panel or a delete — the database noticing replaces the
-- doorbell the author had to remember to ring, which a bot writing through the
-- REST API never could.
--
-- Interactions (a button press) are between the presser and the bot and reach
-- nobody else. An ephemeral reply reaches the one person it is for.

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
  IF v_row.is_interaction THEN
    RETURN NULL;
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

  IF v_row.ephemeral_for IS NOT NULL THEN
    PERFORM realtime.send(v_payload, v_event, 'user:' || v_row.ephemeral_for, true);
  ELSE
    PERFORM app.announce_to_channel(v_row.channel_id, v_event, v_payload);
  END IF;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS messages_announce ON messages;
CREATE TRIGGER messages_announce
  AFTER INSERT OR UPDATE OR DELETE ON messages
  FOR EACH ROW EXECUTE FUNCTION app.announce_message();

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

DROP TRIGGER IF EXISTS message_reactions_announce ON message_reactions;
CREATE TRIGGER message_reactions_announce
  AFTER INSERT OR DELETE ON message_reactions
  FOR EACH ROW EXECUTE FUNCTION app.announce_reaction();

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

DROP TRIGGER IF EXISTS dm_messages_announce ON dm_messages;
CREATE TRIGGER dm_messages_announce
  AFTER INSERT OR UPDATE OR DELETE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION app.announce_dm();

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

DROP TRIGGER IF EXISTS dm_message_reactions_announce ON dm_message_reactions;
CREATE TRIGGER dm_message_reactions_announce
  AFTER INSERT OR DELETE ON dm_message_reactions
  FOR EACH ROW EXECUTE FUNCTION app.announce_dm_reaction();

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

DROP TRIGGER IF EXISTS channels_announce ON channels;
CREATE TRIGGER channels_announce
  AFTER INSERT OR UPDATE OR DELETE ON channels
  FOR EACH ROW EXECUTE FUNCTION app.announce_channels();

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

DROP TRIGGER IF EXISTS users_announce ON users;
CREATE TRIGGER users_announce
  AFTER INSERT OR UPDATE OR DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION app.announce_member();

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

DROP TRIGGER IF EXISTS notification_prefs_announce ON notification_prefs;
CREATE TRIGGER notification_prefs_announce
  AFTER INSERT OR UPDATE OR DELETE ON notification_prefs
  FOR EACH ROW EXECUTE FUNCTION app.announce_prefs();

REVOKE ALL ON FUNCTION app.announce_message()     FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_reaction()    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_dm()          FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_dm_reaction() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_channels()    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_member()      FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_prefs()       FROM PUBLIC, anon, authenticated;

-- ============================================================
-- 3. Nothing is watched any more
-- ============================================================
-- A published table's every change is decoded by Realtime whether or not
-- anybody is watching it.

DO $$
DECLARE
  v_table TEXT;
BEGIN
  FOREACH v_table IN ARRAY ARRAY['messages', 'dm_messages', 'message_reactions',
                                 'dm_message_reactions', 'users', 'channels',
                                 'notification_prefs'] LOOP
    BEGIN
      EXECUTE format('ALTER PUBLICATION supabase_realtime DROP TABLE %I', v_table);
    EXCEPTION WHEN undefined_object OR undefined_table THEN NULL;
    END;
  END LOOP;
END $$;
