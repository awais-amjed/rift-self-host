-- ============================================================
-- Rift self-hosted server — 010: What a bot may see
-- ============================================================
-- Channel reads, per-bot permissions, and being summoned into a call —
-- each a narrowing of what a grant actually admits.
--
-- Was 6 files: 033_default_role_visible, 034_channel_audience, 035_bot_channel_reads, 036_bot_permissions, 037_bot_voice_summons, 038_summons_expire.
-- Merged unchanged and in the same order, so this applies exactly what
-- they applied. The sections below are those files, each still carrying
-- the reasoning it was written with.
-- ============================================================

-- ============================================================
-- Rift self-hosted server — 033: say which role is the default one
-- ============================================================
-- `member_role_list` is what every client reads to draw the roles beside a
-- name, and it left out the one column that says whether a role means anything.
--
-- Every human member is given the default role when they register (025), so
-- every human wore a "Members" chip — on every row, next to every name, saying
-- what was true of everybody. A badge that never varies is not a badge; it is
-- furniture, and it crowded out the ones somebody should actually notice.
--
-- The column already exists on `roles`. Clients could not see it, so they could
-- not tell "the role everyone has" from "a role somebody chose to give you".

CREATE OR REPLACE VIEW member_role_list
  WITH (security_invoker = true) AS
  SELECT mr.user_id,
         r.id AS role_id,
         r.name,
         r.color,
         r.position,
         r.permissions,
         r.is_default
    FROM member_roles mr
    JOIN roles r ON r.id = mr.role_id;

COMMENT ON VIEW member_role_list IS
  'Which roles each member holds. `is_default` marks the one every member is '
  'given on registration — clients hide its chip, because a badge everybody '
  'wears distinguishes nobody.';

REVOKE ALL ON member_role_list FROM anon;
GRANT SELECT ON member_role_list TO authenticated;


-- ============================================================
-- Rift self-hosted server — 034: who a message here can reach
-- ============================================================
-- `validate_message_mentions` (020) already strips a mention of somebody who
-- cannot enter the channel: it keeps only ids that pass `app.channel_eligible`.
-- That is the right answer and it is silent, which is the problem. The composer
-- offered the whole server roster in a private channel, so a writer could pick
-- a name, watch it highlight in the sent message, and be told nothing when the
-- ping was dropped on the way in.
--
-- A UI cannot answer this on its own without becoming a second copy of
-- `channel_eligible` — it would have to read `channel_members`, read
-- `channel_role_access`, resolve those roles through `member_roles`, and
-- remember the ban clause. Four things to keep in step with a predicate that
-- lives here. So the question is asked here, of the same function the trigger
-- uses, and there is only ever one answer.
--
-- ---------- this tells nobody anything new ----------
--
-- Every input is already readable by the caller: `channel_members_select` and
-- `channel_role_access_select` are granted to whoever can see the channel, and
-- `member_role_list` is server-wide. This resolves what they could already
-- assemble. The `can_see_channel` gate is what keeps that true — without it,
-- an outsider could ask a private channel who is in it.

CREATE OR REPLACE FUNCTION channel_audience(p_channel UUID)
  RETURNS TABLE (user_id UUID)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT u.id
    FROM channels c
    JOIN users u ON u.server_id = c.server_id
   WHERE c.id = p_channel
     -- The caller has to be inside before they may resolve the list. A private
     -- channel's membership is the one thing about it an outsider could
     -- otherwise learn.
     AND app.can_see_channel(p_channel)
     AND app.channel_eligible(p_channel, u.id)
$$;

COMMENT ON FUNCTION channel_audience(UUID) IS
  'Server members a message in this channel can actually reach — the same set '
  '`validate_message_mentions` keeps. Empty for a channel the caller cannot '
  'see. Bots are in it on the same terms as anybody: always in a public '
  'channel, and in a private one only through a role with `channel_role_access`'
  ', since `set_channel_members` refuses to seat a bot by name. That is exactly '
  'who a `/` command can reach — `messages_select` asks `can_see_channel` '
  'before it asks `to_bot`. Declining to @mention them is the composer''s job '
  '(BOTS.md §4).';

REVOKE ALL ON FUNCTION channel_audience(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION channel_audience(UUID) TO authenticated;


-- ============================================================
-- Rift self-hosted server — 035: the half of the grant that was missing
-- ============================================================
-- 017 built the key half of a moderation grant and built it correctly: who may
-- be granted, from which version, what revoking does, and who is told. What it
-- never did was let the bot read a message.
--
-- `messages_select` has said this since 015, and nothing changed it:
--
--     AND (NOT app.is_bot() OR to_bot = auth.uid() OR sender_id = auth.uid())
--
-- A bot reads what it is addressed and what it wrote. That stayed true of a
-- fully granted bot, in a public channel, holding the channel key: zero rows.
-- Meanwhile `grant_bot_channel_key` posts "It can read every message sent here
-- from now on" into the channel, which was a promise nothing kept.
--
-- ---------- the grant is the permission, and it is arithmetic ----------
--
-- `from_key_version` already exists and already means the right thing: the
-- first version this bot may hold, set one past the current one so the
-- rotation that follows is what it reads from. `refuse_ineligible_keyring`
-- enforces it on the way in. This reads it on the way out, so forward-only is
-- the same number in both directions rather than a policy promise on one side
-- and arithmetic on the other.
--
-- A revoke deletes the grant row and the bot's keyring rows, so it stops
-- reading in the same statement. "It keeps what it already saw" is about what
-- has been unwrapped and cannot be recalled — not about a database it still
-- gets to query.
--
-- ---------- what a granted bot still does not see ----------
--
--   * **Anything below `from_key_version`**, which is the whole point.
--   * **`key_version = 0` rows** — webhook posts, system notices, and commands
--     addressed to *other* bots. Those were never sealed under any version, so
--     no grant covers them, and the third kind is the reason to be strict
--     rather than generous: `/ask` to another bot is plaintext and personal.
--     A moderation bot has a blind spot for webhook content, and that is the
--     honest cost of making the boundary a number.
--   * **Somebody else's ephemeral reply**, and **another bot's button press**.
--     Both clauses already say so and both still apply — this widens the first
--     test in the policy, not the ones after it.
--
-- ---------- private channels ----------
--
-- A per-channel grant on a private channel is allowed (BOTS.md §6: the bulk
-- grant is what never covers one). But `can_see_channel` asks about membership,
-- and `set_channel_members` will not seat a bot — so the grant was doubly inert
-- there: no messages, and not even the bot's own wrapped key. Both now admit a
-- granted bot, scoped to its own rows.

-- ============================================================
-- 1. The two questions
-- ============================================================

-- Is there a live grant for me on this channel? Only bots have rows here, so
-- this needs no `is_bot` check of its own.
CREATE OR REPLACE FUNCTION app.bot_reads_channel(p_channel UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM bot_channel_keys g
                  WHERE g.channel_id = p_channel AND g.bot_id = auth.uid())
$$;

-- ...and does it reach this far back? Separate from the above because the
-- keyring and the grant row are per-channel questions and a message is a
-- per-version one.
CREATE OR REPLACE FUNCTION app.bot_reads_version(
  p_channel UUID,
  p_version INTEGER
) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM bot_channel_keys g
                  WHERE g.channel_id = p_channel AND g.bot_id = auth.uid()
                    AND p_version >= g.from_key_version)
$$;

REVOKE ALL ON FUNCTION app.bot_reads_channel(UUID)          FROM PUBLIC;
REVOKE ALL ON FUNCTION app.bot_reads_version(UUID, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.bot_reads_channel(UUID)          TO authenticated;
GRANT EXECUTE ON FUNCTION app.bot_reads_version(UUID, INTEGER) TO authenticated;

-- ============================================================
-- 2. Reading the channel
-- ============================================================
-- Same shape as 029's, with the grant added to the first two tests. The
-- ephemeral and interaction clauses are untouched: a grant is permission to
-- read the channel's conversation, not permission to read a reply somebody was
-- shown alone.

DROP POLICY IF EXISTS messages_select ON messages;
CREATE POLICY messages_select ON messages FOR SELECT TO authenticated
  USING (
    (app.can_see_channel(channel_id) OR app.bot_reads_channel(channel_id))
    AND (NOT app.is_bot()
         OR to_bot = auth.uid()
         OR sender_id = auth.uid()
         OR app.bot_reads_version(channel_id, key_version))
    AND (ephemeral_for IS NULL OR ephemeral_for = auth.uid()
         OR sender_id = auth.uid())
    AND (NOT is_interaction OR sender_id = auth.uid() OR to_bot = auth.uid())
  );

-- ============================================================
-- 3. Reaching its own key
-- ============================================================
-- Reading a sealed message is no use without the thing that opens it. In a
-- public channel `can_see_channel` already returned these; this is what makes a
-- private-channel grant work at all.
--
-- Scoped to the bot's own row rather than the whole keyring: the rest of it is
-- wrapped to other people's X25519 keys and would open for nobody, but it is
-- also a list of who holds a key to this channel, and a bot has no reason to
-- have it.

DROP POLICY IF EXISTS channel_keyring_select ON channel_keyring;
CREATE POLICY channel_keyring_select ON channel_keyring FOR SELECT TO authenticated
  USING (
    app.can_see_channel(channel_id)
    OR (user_id = auth.uid() AND app.bot_reads_channel(channel_id))
  );

-- And its own grant row, which is where `from_key_version` lives — a bot that
-- cannot read this cannot tell a channel it was never granted from one whose
-- history simply starts later.
DROP POLICY IF EXISTS bot_channel_keys_select ON bot_channel_keys;
CREATE POLICY bot_channel_keys_select ON bot_channel_keys
  FOR SELECT TO authenticated
  USING (app.can_see_channel(channel_id) OR bot_id = auth.uid());


-- ============================================================
-- Rift self-hosted server — 036: bots are three permissions, not one
-- ============================================================
-- `MANAGE_BOTS` has been carrying three jobs of very different weight:
--
--   1. **Handing a bot a key** — to read a channel (§6) or hear a call (§6b).
--      This is the one that spends the trust model, and it stays where it is.
--   2. **Bringing a bot into the server at all** — which today needs nothing
--      but `CREATE_INVITE`, the same bit as inviting a friend. Adding a program
--      that will be in every public channel is not the same decision as adding
--      a person, and it should not have been the same bit.
--   3. **Summoning one into a voice channel** — asking the music bot to come
--      and play. This has almost no weight at all: a bot's token is minted with
--      `canSubscribe: false` unless an admin granted listening, so a summoned
--      bot publishes and cannot hear. It is the thing everybody wants to do and
--      the thing an admin least needs to control.
--
-- Lumping 3 in with 1 makes the feature unusable — nobody is giving every
-- member the ability to hand out channel keys so they can queue a song. Leaving
-- 2 under `CREATE_INVITE` makes it invisible. So: three bits, and the light one
-- is on by default.
--
-- ---------- what each server gets ----------
--
-- `SUMMON_BOTS` joins `@everyone`, on the servers that already exist as well as
-- the ones made after this. That is deliberate and it is the conservative
-- direction: the alternative is a permission nobody has, which looks exactly
-- like the feature being broken. An admin who wants it narrower takes the bit
-- off `@everyone` and puts it on a role.
--
-- `ADD_BOTS` is not backfilled onto `@everyone`, which *is* a change in what a
-- plain member may do — creating a bot invite now needs it. Admins are covered
-- without a backfill: `has_perm` treats `ADMINISTRATOR` as every bit. It goes
-- to the `Moderator` role too, since that is the role a server hands to the
-- people who set things up.

-- ============================================================
-- 1. The two new bits
-- ============================================================

CREATE OR REPLACE FUNCTION app.perm_bit(p_name TEXT) RETURNS BIGINT
  LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE p_name
    -- Server
    WHEN 'ADMINISTRATOR'          THEN 1::BIGINT << 0   -- implies every other bit
    WHEN 'MANAGE_SERVER'          THEN 1::BIGINT << 1
    WHEN 'MANAGE_ROLES'           THEN 1::BIGINT << 2
    WHEN 'MANAGE_CHANNELS'        THEN 1::BIGINT << 3
    WHEN 'CREATE_INVITE'          THEN 1::BIGINT << 4
    WHEN 'KICK_MEMBERS'           THEN 1::BIGINT << 5
    WHEN 'BAN_MEMBERS'            THEN 1::BIGINT << 6
    WHEN 'MANAGE_BOTS'            THEN 1::BIGINT << 7   -- the §6 and §6b key grants
    WHEN 'MANAGE_WEBHOOKS'        THEN 1::BIGINT << 8
    -- Text
    WHEN 'VIEW_CHANNEL'           THEN 1::BIGINT << 9
    WHEN 'SEND_MESSAGES'          THEN 1::BIGINT << 10
    WHEN 'ATTACH_FILES'           THEN 1::BIGINT << 11
    WHEN 'ADD_REACTIONS'          THEN 1::BIGINT << 12
    WHEN 'MENTION_ALL'            THEN 1::BIGINT << 13
    WHEN 'MANAGE_MESSAGES'        THEN 1::BIGINT << 14  -- delete anybody's
    -- Voice
    WHEN 'CONNECT'                THEN 1::BIGINT << 15
    WHEN 'SPEAK'                  THEN 1::BIGINT << 16
    WHEN 'SCREEN_SHARE'           THEN 1::BIGINT << 17
    WHEN 'MUTE_MEMBERS'           THEN 1::BIGINT << 18
    WHEN 'DEAFEN_MEMBERS'         THEN 1::BIGINT << 19
    WHEN 'MOVE_MEMBERS'           THEN 1::BIGINT << 20
    -- 020
    WHEN 'CREATE_PRIVATE_CHANNEL' THEN 1::BIGINT << 21
    -- 036
    WHEN 'ADD_BOTS'               THEN 1::BIGINT << 22  -- create a bot invite
    WHEN 'SUMMON_BOTS'            THEN 1::BIGINT << 23  -- bring one into a call
    ELSE NULL
  END
$$;

CREATE OR REPLACE FUNCTION app.perm_all() RETURNS BIGINT
  LANGUAGE sql IMMUTABLE AS $$ SELECT (1::BIGINT << 24) - 1 $$;

-- ============================================================
-- 2. Adding a bot is its own decision
-- ============================================================
-- Same policy as 025's with one clause. The `is_bot` column is already in the
-- insert grant, so this is the only place the answer could live.

DROP POLICY IF EXISTS invites_insert ON invites;
CREATE POLICY invites_insert ON invites FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND created_by = auth.uid()
    AND app.can_invite()
    AND (role_id IS NULL OR app.may_assign_role(role_id))
    AND (NOT is_bot OR app.has_perm('ADD_BOTS'))
  );

-- ============================================================
-- 3. Defaults, for the servers that exist and the ones that do not
-- ============================================================

CREATE OR REPLACE FUNCTION seed_default_roles()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  INSERT INTO roles (server_id, name, position, permissions, is_everyone, is_default)
  VALUES
    (NEW.id, '@everyone', 0,
       app.perm('VIEW_CHANNEL')  | app.perm('SEND_MESSAGES')
     | app.perm('ATTACH_FILES')  | app.perm('ADD_REACTIONS')
     | app.perm('MENTION_ALL')
     | app.perm('CONNECT')       | app.perm('SPEAK')
     | app.perm('SCREEN_SHARE')
     | app.perm('CREATE_PRIVATE_CHANNEL')
     -- Publishing only, and reversible by taking the bit away. The reason it
     -- is here rather than on a role somebody has to invent: a music bot that
     -- needs an admin present to be asked for a song is not a music bot.
     | app.perm('SUMMON_BOTS'), true, false),
    (NEW.id, 'Members',   100, app.perm('CREATE_INVITE'), false, true),
    (NEW.id, 'Moderator', 200,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS')    | app.perm('ADD_BOTS'), false, false),
    (NEW.id, 'Admin',     300, app.perm('ADMINISTRATOR'), false, false)
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;

-- The servers that already exist. `@everyone` gains the summon bit; the
-- moderator role gains `ADD_BOTS`, matched by name because 025 dropped
-- `legacy_key` — a server that renamed it keeps whatever it has, and an admin
-- can add the bit by hand. Nothing is taken away from anybody.
UPDATE roles SET permissions = permissions | app.perm('SUMMON_BOTS')
 WHERE is_everyone;

UPDATE roles SET permissions = permissions | app.perm('ADD_BOTS')
 WHERE name = 'Moderator' AND NOT is_everyone;


-- ============================================================
-- Rift self-hosted server — 037: summoning a bot into a call
-- ============================================================
-- Asking the music bot to come and play. It is the thing people most want a bot
-- for, and until now it did not work at all in a private voice channel and
-- worked only by accident in a public one.
--
-- Two walls stood in a private channel, both keyed on `channel_members`, which
-- `set_channel_members` refuses to seat a bot into:
--
--   * `channel_visible_to` — no token, so `get_channel_token` answers
--     `CHANNEL_NOT_FOUND`;
--   * `bot_voice_key_candidates` — no member's client seals it a media key, and
--     calls are end-to-end encrypted, so there is nothing for it to speak with.
--
-- A summon is the third door, and it is deliberately the smallest one: it lets
-- a bot into **one voice channel**, to **publish**, until somebody dismisses it.
--
-- ---------- why this can be a default permission ----------
--
-- `SUMMON_BOTS` is on `@everyone` (036), which sounds alarming for private
-- channels until you see what a summoned bot gets. Its token is minted with
-- `canSubscribe: false` unless an admin separately granted listening, and its
-- media key is `HMAC(channelKey, 'voicebot:v1:<botId>')` — derived *from* the
-- channel key rather than being it, so members can hear the bot and the bot
-- cannot invert the HMAC to hear them. A summon adds a speaker to the room. It
-- does not add a listener, and it cannot be made into one from here.
--
-- It also does not make the bot a member: `app.sees_channel` is untouched, so a
-- summoned bot cannot list the channel, read its roster, read its messages, or
-- post in it. Only `channel_joinable_by` knows about summons, and only
-- `get_channel_token` asks that.
--
-- ---------- and why the candidates view got narrower ----------
--
-- It used to list every bot on the server for every public voice channel, so
-- members' clients sealed a media key for bots that would never join. Now a
-- summon is what puts a bot on the list. That is less work for every client and
-- one less thing sitting in the database for no reason — and it is what makes
-- dismissing meaningful, because dropping the summon drops the key with it.

-- ============================================================
-- 1. The summon
-- ============================================================

CREATE TABLE IF NOT EXISTS bot_voice_summons (
  channel_id  UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id      UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  -- Who asked. A bot in a call that nobody remembers inviting is the thing
  -- this column answers, and it is the same reason `bot_channel_keys` keeps
  -- `granted_by`.
  summoned_by UUID        REFERENCES users(id) ON DELETE SET NULL,
  summoned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, bot_id)
);

CREATE INDEX IF NOT EXISTS bot_voice_summons_bot ON bot_voice_summons (bot_id);

COMMENT ON TABLE bot_voice_summons IS
  'Bots asked into a voice channel, until dismissed (migration 037). Permission '
  'to publish there and nothing else: it does not make the bot a member, and it '
  'does not let it hear — that is bot_voice_grants and MANAGE_BOTS.';

CREATE OR REPLACE FUNCTION app.bot_summoned_to(p_channel UUID, p_bot UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM bot_voice_summons s
                  WHERE s.channel_id = p_channel AND s.bot_id = p_bot)
$$;

-- ============================================================
-- 2. Who may join a voice channel
-- ============================================================
-- `channel_visible_to` answers "may this person see this channel", which is the
-- question for a person and the wrong one for a summoned bot: it is in the room
-- without being of it. Separating them keeps the summon from leaking anywhere
-- else — every other caller still asks `sees_channel` and still gets no.

CREATE OR REPLACE FUNCTION channel_joinable_by(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.sees_channel(p_channel, p_user)
      OR (EXISTS (SELECT 1 FROM users u WHERE u.id = p_user
                    AND u.is_bot AND NOT u.is_banned)
          AND app.bot_summoned_to(p_channel, p_user))
$$;

REVOKE ALL ON FUNCTION channel_joinable_by(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION channel_joinable_by(UUID, UUID) TO service_role;

-- ============================================================
-- 3. Asking, and asking it to leave
-- ============================================================

CREATE OR REPLACE FUNCTION summon_bot_to_voice(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_type TEXT;
BEGIN
  IF NOT app.has_perm('SUMMON_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  -- The caller's own visibility, not the bot's — a summon is somebody in the
  -- room asking, and the whole point is that the bot cannot see it yet.
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  SELECT channel_type INTO v_type FROM channels WHERE id = p_channel;
  IF v_type IS DISTINCT FROM 'voice' THEN
    RETURN jsonb_build_object('reason', 'not_a_voice_channel');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = app.server_id()) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_voice_summons (channel_id, bot_id, summoned_by)
  VALUES (p_channel, p_bot, auth.uid())
  ON CONFLICT (channel_id, bot_id) DO NOTHING;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- Dismissing takes no permission beyond being able to see the room. Anybody in
-- a call may ask the music bot to stop, and needing the person who summoned it
-- — who may have left — is how a bot ends up playing to an empty room.
CREATE OR REPLACE FUNCTION dismiss_bot_from_voice(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.can_see_channel(p_channel) AND p_bot IS DISTINCT FROM auth.uid() THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  DELETE FROM bot_voice_summons
   WHERE channel_id = p_channel AND bot_id = p_bot;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

REVOKE ALL ON FUNCTION summon_bot_to_voice(UUID, UUID)    FROM PUBLIC;
REVOKE ALL ON FUNCTION dismiss_bot_from_voice(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION summon_bot_to_voice(UUID, UUID)    TO authenticated;
GRANT EXECUTE ON FUNCTION dismiss_bot_from_voice(UUID, UUID) TO authenticated;

-- ============================================================
-- 4. Dismissing takes the key with it
-- ============================================================
-- Same shape as `drop_bot_voice_keys_on_grant_change` (032), and for the same
-- reason: a key sealed under one decision must not outlive it. Without this a
-- dismissed bot keeps a usable media key and only the token stands between it
-- and the room.

CREATE OR REPLACE FUNCTION drop_bot_voice_keys_on_summon_change()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  DELETE FROM bot_voice_keys
   WHERE channel_id = COALESCE(NEW.channel_id, OLD.channel_id)
     AND bot_id     = COALESCE(NEW.bot_id, OLD.bot_id);
  RETURN NULL;
END; $$;

REVOKE ALL ON FUNCTION drop_bot_voice_keys_on_summon_change() FROM PUBLIC;

DROP TRIGGER IF EXISTS bot_voice_summons_reset_keys ON bot_voice_summons;
CREATE TRIGGER bot_voice_summons_reset_keys
  AFTER INSERT OR DELETE ON bot_voice_summons
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_keys_on_summon_change();

-- ============================================================
-- 5. What a client seals, and for whom
-- ============================================================
-- A summon is now what puts a bot on the list, in a private channel and a
-- public one alike. Members' clients stop sealing media keys for bots that
-- will never join, and dropping a summon drops the key with it.

CREATE OR REPLACE VIEW bot_voice_key_candidates
  WITH (security_invoker = false) AS
  SELECT c.id  AS channel_id,
         u.id  AS bot_id,
         u.chat_public_key,
         EXISTS (SELECT 1 FROM bot_voice_grants g
                  WHERE g.channel_id = c.id AND g.bot_id = u.id) AS may_listen
    FROM channels c
    JOIN bot_voice_summons s ON s.channel_id = c.id
    JOIN users u ON u.id = s.bot_id
   WHERE c.channel_type = 'voice'
     AND u.is_bot
     AND NOT u.is_banned
     AND u.chat_public_key IS NOT NULL;

-- ============================================================
-- 6. Security
-- ============================================================

ALTER TABLE bot_voice_summons ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bot_voice_summons FROM anon, authenticated;
GRANT SELECT ON bot_voice_summons TO authenticated;

-- Readable by the room, so a member can see what has been called in, and by the
-- bot itself, which is how it learns where it has been asked to go. `bot_id =
-- auth.uid()` rather than a join through `can_see_channel`: a summoned bot is
-- not in the channel, and that is the point of the summon.
DROP POLICY IF EXISTS bot_voice_summons_select ON bot_voice_summons;
CREATE POLICY bot_voice_summons_select ON bot_voice_summons
  FOR SELECT TO authenticated
  USING (app.can_see_channel(channel_id) OR bot_id = auth.uid());

-- No write grant at all: summoning moves through the functions above, so a row
-- cannot appear without the permission check that justifies it.


-- ============================================================
-- Rift self-hosted server — 038: a summon outliving its reason
-- ============================================================
-- 037 gave a summon two ways to end: somebody dismisses it, or the channel or
-- the bot is deleted. Both are somebody deciding. Nothing ended one because the
-- *reason* for it had gone, and three things fall out of that.
--
--   1. **A channel made private kept its summons.** 031 already drops a
--      listening grant when a channel closes, for the obvious reason: the
--      people who granted it are not necessarily the people in the room now.
--      A summon is the same shape and was left out, so a bot summoned into a
--      public call could still take a token for it after it was closed —
--      `channel_joinable_by` reads the summon and never asks about privacy.
--      That is a privacy boundary crossed by a stale row.
--
--   2. **A summon outlived the call.** Say `/play` while the bot is down and
--      everybody goes home: the row waits. The bot cannot arrive at once,
--      because dismissing took its media key — but the next time a member is in
--      that channel their client seals a new one, and the bot turns up in a
--      conversation nobody invited it to, hours later.
--
--   3. **Nobody could see one.** "Send away" lives on the participant menu,
--      which needs the bot to be *in* the call. A summon whose bot never joined
--      was invisible and unclearable. `voice_summons` below is the view a
--      client can draw it from, the sibling of `voice_listeners`.
--
-- ---------- why an hour, and why not a disconnect hook ----------
--
-- The exact end of a call is LiveKit's to know, not this database's, and asking
-- it would mean a webhook and a new failure mode for a tidy-up. An age is worse
-- at the edges and cannot break: a summon is a request to come and play *now*,
-- so one that has sat unused for an hour has been answered by events. A bot
-- that is already connected is unaffected — dropping the row takes its right to
-- a *new* token, and it is the dismiss path that disconnects.
--
-- Riding on the same hourly job as the invite sweep for the same reason: one
-- schedule to reason about.

-- ============================================================
-- 1. Closing a channel takes its summons with it
-- ============================================================
-- Deliberately not `AFTER UPDATE OF is_private`: 020's `set_channel_private` is
-- the only writer, and matching 031's trigger shape exactly is worth more here
-- than saving a comparison.

CREATE OR REPLACE FUNCTION drop_bot_voice_summons_when_closed()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF NEW.is_private AND NOT OLD.is_private THEN
    DELETE FROM bot_voice_summons WHERE channel_id = NEW.id;
  END IF;
  RETURN NULL;
END; $$;

REVOKE ALL ON FUNCTION drop_bot_voice_summons_when_closed() FROM PUBLIC;

DROP TRIGGER IF EXISTS channels_drop_bot_voice_summons ON channels;
CREATE TRIGGER channels_drop_bot_voice_summons
  AFTER UPDATE ON channels
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_summons_when_closed();

-- ============================================================
-- 2. And so does an hour of nobody using it
-- ============================================================

CREATE OR REPLACE FUNCTION app.expire_bot_voice_summons() RETURNS VOID
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  DELETE FROM bot_voice_summons WHERE summoned_at < now() - interval '1 hour'
$$;

REVOKE ALL ON FUNCTION app.expire_bot_voice_summons() FROM PUBLIC, anon, authenticated;

SELECT cron.unschedule('expire-bot-voice-summons')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'expire-bot-voice-summons');

SELECT cron.schedule(
  'expire-bot-voice-summons',
  '0 * * * *',
  $$SELECT app.expire_bot_voice_summons()$$
);

-- ============================================================
-- 3. What a client draws them from
-- ============================================================
-- The sibling of `voice_listeners` (031), and the same reasoning: the table is
-- readable, but a marker needs a name rather than an id, and joining `users`
-- from every client that draws a channel row is a second query per channel.
--
-- `security_invoker`, so `bot_voice_summons_select` decides who sees a row —
-- the room, or the bot itself.

CREATE OR REPLACE VIEW voice_summons
  WITH (security_invoker = true) AS
  SELECT s.channel_id,
         s.bot_id,
         u.display_name AS bot_name,
         s.summoned_by,
         s.summoned_at
    FROM bot_voice_summons s
    JOIN users u ON u.id = s.bot_id
   WHERE NOT u.is_banned;

COMMENT ON VIEW voice_summons IS
  'Bots asked into each voice channel, with the name to show. Unlike '
  'voice_listeners this is not a warning — a summoned bot publishes and cannot '
  'hear. It is what makes a summon whose bot never turned up visible, and '
  'therefore dismissable.';

REVOKE ALL ON voice_summons FROM anon;
GRANT SELECT ON voice_summons TO authenticated;
