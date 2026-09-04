-- ============================================================
-- Rift self-hosted server — 012: per-conversation notification levels
-- ============================================================
-- Until now a member had one setting for a whole server: push on, or push off.
-- That is not how anybody actually reads a chat. One channel is the reason you
-- joined and three others are noise, and the only honest way to tell them apart
-- is to let the member say so.
--
-- Three levels:
--
--   all       every message rings
--   mentions  only a message that names you (or @all) rings
--   none      nothing rings
--
-- ...at three scopes: the **server**, one **channel**, one **conversation**.
-- Channels default to `mentions` and DMs to `all`, which is what people expect
-- from a chat app and, not coincidentally, what stops a busy server from
-- waking every phone on it all day.
--
-- The scopes are a fallback chain, not a fight: **the conversation's own level
-- if it has one, else the server's if it has one, else the default.** So
-- muting a server quiets everything you have not spoken about individually,
-- and a channel you deliberately set to `all` stays loud inside a muted
-- server — which is the case that makes a server-wide switch usable rather
-- than a thing you turn on once and then fight.
--
-- Discord resolves this the other way (a server mute wins over the channels
-- inside it) and then needs per-channel overrides to climb back out. One
-- ordering has to be picked; this one is the one you can predict from the menu
-- in front of you, because a channel showing an explicit level is telling you
-- it is in force.
--
-- ---------- the awkward part ----------
--
-- The server cannot read a message. So it cannot tell, on its own, whether one
-- names you — which is precisely the question `mentions` asks. Three ways out
-- were on the table:
--
--   * ring for every message in a mentions-only channel and let the phone
--     decide after decrypting. Private and instant, but a 20-member channel at
--     200 messages a day is ~190 pointless wakes per device per day.
--   * ring on a cooldown and let the phone decide. Private and cheap, but an
--     @mention can arrive minutes late, which is the one notification nobody
--     will accept being late.
--   * have the sender's client say who it named.
--
-- The third is what this does: `messages.mentions` is a plaintext array of user
-- ids, written by the sender, and `mentions_all` is the @all flag. The trade is
-- stated plainly because it is real — **the operator learns who was addressed
-- in a message**, though never what it said. It is the same class of metadata
-- this schema already keeps in the open for DMs (`dm_messages.recipient_id`)
-- and for reactions (001, which says so in as many words). Message *content*
-- is untouched.
--
-- Two things keep it honest:
--
--   * the column is validated below, not trusted: ids that aren't live members
--     of this server are dropped, the sender is dropped, and the array is
--     capped. A modified client can cause a wake; it cannot cause a hundred.
--   * the phone decrypts before it says anything. A client that lies about who
--     it mentioned buys a silent wake, never a false "mentioned you" — the
--     notification's wording comes from the plaintext or from nothing.
--
-- **This migration is not optional once the client ships it.** The composer sends
-- `mentions`/`mentions_all` on every insert, so a server still on 011 rejects
-- every message with "column does not exist". That is the same contract every
-- migration here has had — run them in order — and it fails loudly, in a toast,
-- rather than quietly.
--
-- Not done here, deliberately: revoking SELECT on `mentions` from members. It
-- would buy nothing today, because there is no per-channel membership — every
-- member holds every channel key and can read the plaintext the column
-- summarises. Column-level grants would also break the next column somebody
-- adds, silently. Revisit it the day channels get their own rosters.

-- ============================================================
-- 1. The setting
-- ============================================================

DO $$ BEGIN
  CREATE TYPE notify_level AS ENUM ('all', 'mentions', 'none');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Its own scope enum rather than borrowing `read_scope`. A read cursor cannot
-- point at a server — there is nothing to be "read up to" — so adding a value
-- there to serve this table would make the type's name a lie and permit a
-- `read_state` row nothing could interpret.
DO $$ BEGIN
  CREATE TYPE notify_scope AS ENUM ('server', 'channel', 'dm');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Keyed like `read_state`, and for the same reason: the question ("what do I
-- want from this") is identical whether the answer is about a server, a channel
-- or a person, so one table answers it for all three and one client path reads
-- it.
--
-- A row exists only where somebody has changed something. The default is the
-- absence of a row, which is what makes joining a server free of writes and
-- makes "reset to default" a DELETE.
CREATE TABLE IF NOT EXISTS notification_prefs (
  user_id    UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope      notify_scope NOT NULL,
  -- Server id for 'server', channel id for 'channel', the other person's user
  -- id for 'dm'.
  scope_id   UUID         NOT NULL,
  level      notify_level NOT NULL,
  updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, scope, scope_id)
);

-- Stamped, not accepted: a client that could name the owner could mute a
-- channel for somebody else — a quiet and very effective way to make sure a
-- person never hears about anything.
CREATE OR REPLACE FUNCTION stamp_notification_pref()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NOT NULL THEN
    NEW.user_id := auth.uid();
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS notification_prefs_stamp ON notification_prefs;
CREATE TRIGGER notification_prefs_stamp BEFORE INSERT OR UPDATE ON notification_prefs
  FOR EACH ROW EXECUTE FUNCTION stamp_notification_pref();

ALTER TABLE notification_prefs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS notification_prefs_own ON notification_prefs;
CREATE POLICY notification_prefs_own ON notification_prefs FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

REVOKE ALL ON notification_prefs FROM anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_prefs TO authenticated;

-- The level actually in force, chain and defaults folded in. SECURITY DEFINER
-- because the ring triggers ask it about *other* people, whose rows no session
-- may read.
--
-- One function rather than three so that the order of the fallback is written
-- down once. Four readers depend on it agreeing with them — the two triggers
-- below, the desktop app and the push isolate — and an order that lived in
-- four places would be four chances to disagree about whether a muted server
-- silences a channel somebody deliberately turned up.
CREATE OR REPLACE FUNCTION app.notify_level(
  p_user UUID, p_scope public.notify_scope, p_scope_id UUID
) RETURNS public.notify_level LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = public AS $$
  SELECT COALESCE(
    -- 1. What this exact thing is set to.
    (SELECT p.level FROM notification_prefs p
      WHERE p.user_id = p_user AND p.scope = p_scope AND p.scope_id = p_scope_id),
    -- 2. Failing that, what the server it belongs to is set to. Skipped when
    --    the question already *is* about a server, which would ask itself.
    CASE WHEN p_scope = 'server' THEN NULL ELSE (
      SELECT p.level FROM notification_prefs p
       WHERE p.user_id = p_user AND p.scope = 'server'
         AND p.scope_id = CASE p_scope
               WHEN 'channel' THEN app.channel_server_id(p_scope_id)
               -- A DM's server is the one both people are members of, which is
               -- the asker's own: identity is per (host, server), so a member
               -- of two servers is two accounts and this is only ever one.
               ELSE (SELECT u.server_id FROM users u WHERE u.id = p_user)
             END)
    END,
    -- 3. The default. A channel is a room full of people talking to each
    --    other; a DM is somebody talking to you; a server nobody has an
    --    opinion about quiets nothing.
    CASE p_scope WHEN 'channel' THEN 'mentions'::notify_level
                 ELSE 'all'::notify_level END
  );
$$;

-- ============================================================
-- 2. Who a message names
-- ============================================================

ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS mentions     UUID[]  NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS mentions_all BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN messages.mentions IS
  'User ids this message names, in plaintext, written by the sender and '
  'validated below. Exists so the server can ring a mentions-only channel '
  'without reading the message. The operator learns who was addressed; not '
  'what was said.';
COMMENT ON COLUMN messages.mentions_all IS
  'The @all flag. A boolean rather than every member listed, because listing '
  'them is exactly the abuse the cap below exists to prevent.';

-- No new grant is needed to write these: `messages` is INSERT-able as a table
-- (002), and the UPDATE grant there names four columns, none of them these —
-- so an edit already cannot rewrite who a message named. The trigger below
-- restates that rather than relying on it, because a grant is easy to widen by
-- accident and this is the half that would go quiet if it were.

-- Validation, not trust. Runs after `attest_messages` (BEFORE triggers fire in
-- name order, and 'v' sorts after 'a'), so `NEW.sender_id` is the server's word
-- by the time this reads it.
CREATE OR REPLACE FUNCTION validate_message_mentions()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_clean UUID[];
BEGIN
  IF TG_OP = 'UPDATE' THEN
    -- Insert-only, see the grant above. An edit keeps whatever it was sent as.
    NEW.mentions     := OLD.mentions;
    NEW.mentions_all := OLD.mentions_all;
    RETURN NEW;
  END IF;

  SELECT COALESCE(array_agg(DISTINCT u.id), '{}')
    INTO v_clean
    FROM unnest(COALESCE(NEW.mentions, '{}')) AS m(id)
    JOIN users u ON u.id = m.id
   WHERE u.server_id = app.channel_server_id(NEW.channel_id)
     AND NOT u.is_banned
     AND u.id <> NEW.sender_id;

  -- A ceiling rather than a rejection: a message that names a lot of people is
  -- a message, and refusing to send it would be a strange way to say "that is
  -- too many pings". Past this, @all is the thing they wanted anyway.
  IF cardinality(v_clean) > 50 THEN
    v_clean := v_clean[1:50];
  END IF;

  NEW.mentions := v_clean;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS validate_message_mentions ON messages;
CREATE TRIGGER validate_message_mentions BEFORE INSERT OR UPDATE ON messages
  FOR EACH ROW EXECUTE FUNCTION validate_message_mentions();

-- `@all` has to mean everybody and nobody in particular, so no one may *be*
-- "all". A CHECK rather than a check in `register_user`, because the rule
-- belongs to the column and there is more than one way to write a row.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_not_reserved;
ALTER TABLE users ADD CONSTRAINT users_username_not_reserved
  CHECK (lower(username) <> 'all');

-- Watched, so a level set on one device reaches the others.
--
-- Without this the setting is per-device in everything but storage: it is
-- written to the server, it is read at sign-in, and the desktop you left open
-- goes on notifying you about a channel you muted on your phone until
-- something else makes it re-seed. Own-row RLS applies to a subscription as it
-- does to a read, so what arrives is only ever your own rows.
--
-- DELETE is why `REPLICA IDENTITY FULL` is here: a default replica identity
-- ships only the primary key on delete, and the key is the whole row's
-- identity — without it a client cannot tell *which* pref was cleared, and
-- clearing one is how "back to the default" is expressed.
ALTER TABLE notification_prefs REPLICA IDENTITY FULL;

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE notification_prefs;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ============================================================
-- 3. Ringing, with the levels applied
-- ============================================================
-- Replaces 010's versions. Both ask `app.notify_level`, so both get the
-- server-then-scope fallback without knowing it exists. The unread gate 010
-- introduced is still here and still does the same job — a doorbell says *look again*, and says nothing new
-- while the badge is already lit — but it now applies only where it can:
--
--   none      never ring.
--   all       ring on the 0→1 unread transition, as before.
--   mentions  ring when this message names you, gate or no gate. A mention is
--             not "one more unread"; it is the message the setting exists for,
--             and suppressing it because something else was already unread
--             would make the level useless.
--
-- A named member is rung at level `all` too, even mid-burst. It costs one wake
-- and it is the one wake nobody minds.

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
   CROSS JOIN LATERAL (
     SELECT app.notify_level(u.id, 'channel', NEW.channel_id) AS level,
            (NEW.mentions_all OR u.id = ANY (NEW.mentions))   AS named
   ) w
   WHERE u.server_id = v_server_id
     AND u.id <> NEW.sender_id
     AND NOT u.is_banned
     AND w.level <> 'none'
     AND (
       w.named
       OR (w.level = 'all'
           AND NOT has_unread_before(u.id, 'channel', NEW.channel_id, NEW.id))
     );

  PERFORM ring_devices(v_server_id, v_targets);
  RETURN NEW;
END; $$;

-- A DM has no room to be in and nobody else to be named among, so it is on or
-- off. `mentions` is not offered for one; if a row somehow says it, it reads as
-- `all`, which is the answer that loses nobody a message.
CREATE OR REPLACE FUNCTION ring_dm_recipient()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
BEGIN
  IF app.notify_level(NEW.recipient_id, 'dm', NEW.sender_id) = 'none' THEN
    RETURN NEW;
  END IF;
  IF has_unread_before(NEW.recipient_id, 'dm', NEW.sender_id, NEW.id) THEN
    RETURN NEW;
  END IF;
  SELECT server_id INTO v_server_id FROM users WHERE id = NEW.recipient_id;
  PERFORM ring_devices(v_server_id, ARRAY[NEW.recipient_id]);
  RETURN NEW;
END; $$;

-- ============================================================
-- 4. Telling the client
-- ============================================================
-- Folded into `unread_counts()` rather than given an endpoint of its own,
-- because every caller of one wants the other: the desktop app asks once per
-- server to draw its badges and decide what may interrupt, and the push
-- isolate asks the same question to decide what is worth a notification. Two
-- round trips to answer one question is a race waiting to happen — badges from
-- one moment, mute state from another.
--
-- Shaped like the counts beside it —
-- `{servers: {...}, channels: {...}, dms: {...}}` — carrying only what has been
-- set. An absent key means "no opinion here, ask the next scope out".

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
         WHERE m.sender_id <> auth.uid()
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
      ) d), '{}'::jsonb),
    'prefs', jsonb_build_object(
      'servers', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::text)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'server'), '{}'::jsonb),
      'channels', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::text)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'channel'), '{}'::jsonb),
      'dms', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::text)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'dm'), '{}'::jsonb)
    )
  );
$$;
