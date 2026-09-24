-- ============================================================
-- Rift self-hosted server — 002: the vocabulary
-- ============================================================
-- The permission bits, the predicates every policy is written in terms of,
-- and the views clients read a member through. Nothing here enforces
-- anything by itself — 008 does that, and it is short because everything it
-- needs to say is already a word defined here.
--
-- All of it is SECURITY DEFINER and `STABLE`, and all of it is scoped to the
-- caller's own server: a helper that could be asked about another server
-- would be a way around every policy that calls it.
-- ============================================================

CREATE OR REPLACE FUNCTION app.server_id() RETURNS UUID
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT u.server_id FROM users u WHERE u.id = auth.uid() AND NOT u.is_banned
$$;

CREATE OR REPLACE FUNCTION app.is_admin() RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((SELECT u.is_server_admin FROM users u
                    WHERE u.id = auth.uid() AND NOT u.is_banned), false)
$$;

CREATE OR REPLACE FUNCTION app.can_manage_channels() RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((SELECT u.is_server_admin OR u.is_channel_manager FROM users u
                    WHERE u.id = auth.uid() AND NOT u.is_banned), false)
$$;

CREATE OR REPLACE FUNCTION app.can_invite() RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((SELECT u.is_server_admin OR u.can_create_tokens FROM users u
                    WHERE u.id = auth.uid() AND NOT u.is_banned), false)
$$;

CREATE OR REPLACE FUNCTION app.channel_server_id(p_channel UUID) RETURNS UUID
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.server_id FROM channels c WHERE c.id = p_channel
$$;

-- Is this person a live member of my server? Used for "may I DM them".
CREATE OR REPLACE FUNCTION app.is_co_member(p_user UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_user AND NOT u.is_banned
                    AND u.server_id = app.server_id())
$$;

-- ...and have they published a chat key? Sealing to someone who hasn't is a
-- message nobody can ever open.
CREATE OR REPLACE FUNCTION app.can_receive_dm(p_user UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_user AND NOT u.is_banned
                    AND u.chat_public_key IS NOT NULL
                    AND u.server_id = app.server_id())
$$;

CREATE OR REPLACE FUNCTION app.can_see_dm(p_message BIGINT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM dm_messages d
                  WHERE d.id = p_message
                    AND auth.uid() IN (d.sender_id, d.recipient_id))
$$;

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

-- The one callers use. `perm_bit` returns NULL for a name it does not know, and
-- NULL propagates through every `&` and `|` below into a policy that quietly
-- denies everything — which reads exactly like a working policy until it is the
-- only thing between somebody and a room they should not be in. So the lookup
-- that policies call refuses instead.
CREATE OR REPLACE FUNCTION app.perm(p_name TEXT) RETURNS BIGINT
  LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE v_bit BIGINT;
BEGIN
  v_bit := app.perm_bit(p_name);
  IF v_bit IS NULL THEN
    RAISE EXCEPTION 'unknown permission: %', p_name;
  END IF;
  RETURN v_bit;
END; $$;

-- ============================================================
-- 3. Effective permissions
-- ============================================================
-- The baseline plus every assigned role, OR'd. `@everyone` is folded in here
-- rather than assigned, which is why it needs no rows and cannot drift.

CREATE OR REPLACE FUNCTION app.permissions_of(p_user UUID) RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((
    SELECT bit_or(r.permissions)
      FROM users u
      JOIN roles r ON r.server_id = u.server_id
     WHERE u.id = p_user
       AND NOT u.is_banned
       AND (r.is_everyone
            OR EXISTS (SELECT 1 FROM member_roles mr
                        WHERE mr.role_id = r.id AND mr.user_id = u.id))
  ), 0)
$$;

CREATE OR REPLACE FUNCTION app.permissions() RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.permissions_of(auth.uid())
$$;

-- `ADMINISTRATOR` implies everything, so it is folded into the mask rather
-- than checked separately — one `&` instead of a branch every caller repeats.
CREATE OR REPLACE FUNCTION app.has_perm(p_name TEXT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT (app.permissions() & (app.perm('ADMINISTRATOR') | app.perm(p_name))) <> 0
$$;

-- Delegation rank: the highest position among the roles actually assigned to
-- you. `@everyone` is position 0 and never assigned, so somebody with no roles
-- ranks 0 and can touch nothing — which is the correct answer.
CREATE OR REPLACE FUNCTION app.max_role_position() RETURNS INTEGER
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((
    SELECT max(r.position)
      FROM member_roles mr
      JOIN roles r ON r.id = mr.role_id
     WHERE mr.user_id = auth.uid()
  ), 0)
$$;

-- The subset rule: you cannot put a permission on a role that you do not hold
-- yourself. Without it, position alone lets somebody mint a role beneath them
-- that outranks them in every way that matters.
CREATE OR REPLACE FUNCTION app.may_hold_perms(p_bits BIGINT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.has_perm('ADMINISTRATOR') OR (p_bits & ~app.permissions()) = 0
$$;

-- ============================================================
-- 3. The one question everything else asks
-- ============================================================

-- Is this person inside this channel — by name, or by a role that is?
CREATE OR REPLACE FUNCTION app.in_channel(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM channel_members cm
                  WHERE cm.channel_id = p_channel AND cm.user_id = p_user)
      OR EXISTS (SELECT 1 FROM channel_role_access cra
                  JOIN member_roles mr ON mr.role_id = cra.role_id
                 WHERE cra.channel_id = p_channel AND mr.user_id = p_user)
$$;

-- May I hold a key to this channel? The question the keyring asks, and the one
-- the sweep resolves into a list.
--
-- A banned member is nobody's business, which is why it is checked here rather
-- than in each caller: a ban is exactly the case where "still in the list" and
-- "may still read" come apart.
CREATE OR REPLACE FUNCTION app.channel_eligible(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1
      FROM channels c
      JOIN users u ON u.id = p_user AND u.server_id = c.server_id
     WHERE c.id = p_channel
       AND NOT u.is_banned
       AND (NOT c.is_private OR app.in_channel(p_channel, p_user)))
$$;

-- Replaces `app.channel_server_id(x) = app.server_id()` everywhere it stood for
-- "may this member touch this channel". Same shape, one more clause.
CREATE OR REPLACE FUNCTION app.can_see_channel(p_channel UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM channels c
     WHERE c.id = p_channel
       AND c.server_id = app.server_id()
       AND (NOT c.is_private OR app.in_channel(p_channel, auth.uid())))
$$;

-- Renaming, deleting, setting retention. A public channel answers to
-- `MANAGE_CHANNELS`; a private one answers to its own members, because the
-- holders of `MANAGE_CHANNELS` cannot see it to manage it.
CREATE OR REPLACE FUNCTION app.can_manage_channel(p_channel UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM channels c
     WHERE c.id = p_channel
       AND c.server_id = app.server_id()
       AND (CASE WHEN c.is_private
                 THEN EXISTS (SELECT 1 FROM channel_members cm
                               WHERE cm.channel_id = p_channel
                                 AND cm.user_id = auth.uid()
                                 AND cm.can_manage)
                 ELSE app.has_perm('MANAGE_CHANNELS') END))
$$;

CREATE OR REPLACE FUNCTION app.can_see_message(p_message BIGINT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM messages m
                  WHERE m.id = p_message
                    AND app.can_see_channel(m.channel_id)
                    AND (NOT app.is_bot() OR m.to_bot = auth.uid()
                         OR m.sender_id = auth.uid()))
$$;

-- ============================================================
-- 2. Visibility without a key
-- ============================================================
-- Voice needs a different question. Joining a call is not holding a key —
-- there is no encryption in the room to hold one for — so `CONNECT` is an
-- ordinary rule, and the only thing that matters is whether the channel is
-- yours to see.
--
-- These live in `public` rather than `app` because PostgREST only exposes
-- `public`, and an edge function calling in is a PostgREST client like any
-- other. They are locked to the service role, which is the only caller that
-- needs to ask about somebody who is not itself.

CREATE OR REPLACE FUNCTION app.sees_channel(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM channels c
      JOIN users u ON u.id = p_user AND u.server_id = c.server_id
     WHERE c.id = p_channel
       AND NOT u.is_banned
       AND (NOT c.is_private OR app.in_channel(p_channel, p_user)))
$$;

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
  -- webhook's message has, because it is the same fact — a row in an
  -- encrypted channel that no key was needed to write and none is needed to
  -- read. It is badged as plaintext like any other.
  INSERT INTO messages (channel_id, origin_name, ciphertext, key_version, is_system)
  VALUES (p_channel, 'Rift', p_text, 0, true);

  PERFORM set_config('request.jwt.claims', COALESCE(v_claims, ''), true);
END; $$;

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

-- ============================================================
-- The other half of a moderation grant
-- ============================================================
-- Granting a bot a channel key settles who may be granted, from which version,
-- what revoking does, and who is told. None of that lets the bot *read* a
-- message, because `messages_select` says:
--
--     AND (NOT app.is_bot() OR to_bot = auth.uid() OR sender_id = auth.uid())
--
-- A bot reads what it is addressed and what it wrote — which, for a fully
-- granted bot in a public channel holding the channel key, is zero rows.
-- Meanwhile `grant_bot_channel_key` posts "It can read every message sent here
-- from now on" into the channel. This is what makes that true.
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

-- ============================================================
-- Bots are three permissions, not one
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
-- The soundboard's pair sits at the end, and the split between them is the
-- point: `USE_SOUNDBOARD` is on `@everyone`, because firing a clip in a call
-- you are already allowed to speak in is an ordinary thing a member does, and
-- a server that disagrees takes it off one role. `MANAGE_SOUNDBOARD` is not,
-- because what the whole server hears is not one member's to decide.
--
-- Neither bit reaches the *listener*: turning a soundboard down is a setting
-- on the device hearing it and has nothing to ask a server about.

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
    WHEN 'CREATE_PRIVATE_CHANNEL' THEN 1::BIGINT << 21
    WHEN 'ADD_BOTS'               THEN 1::BIGINT << 22  -- create a bot invite
    WHEN 'SUMMON_BOTS'            THEN 1::BIGINT << 23  -- bring one into a call
    WHEN 'MANAGE_SOUNDBOARD'      THEN 1::BIGINT << 24  -- add and remove clips
    WHEN 'USE_SOUNDBOARD'         THEN 1::BIGINT << 25  -- fire one in a call
    ELSE NULL
  END
$$;

CREATE OR REPLACE FUNCTION app.perm_all() RETURNS BIGINT
  LANGUAGE sql IMMUTABLE AS $$ SELECT (1::BIGINT << 26) - 1 $$;

CREATE OR REPLACE FUNCTION app.bot_summoned_to(p_channel UUID, p_bot UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM bot_voice_summons s
                  WHERE s.channel_id = p_channel AND s.bot_id = p_bot)
$$;

-- ============================================================
-- 2. Ceilings and ordering
-- ============================================================
-- The cap is here rather than in each function body so there is one number to
-- change, and so a caller reading the source can see that "give me everyone"
-- is not on the menu.

CREATE OR REPLACE FUNCTION app.member_page_max() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 100 $$;

COMMENT ON FUNCTION app.member_page_max() IS
  'Most rows any member query may return. A caller asking for more gets this; '
  'a caller asking for fewer gets what they asked for.';

-- Clamped rather than rejected: a client that asks for 5000 has a bug, but
-- failing its request turns that bug into an empty sidebar. It gets a page.
CREATE OR REPLACE FUNCTION app.member_limit(p_limit INTEGER) RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$
  SELECT LEAST(GREATEST(COALESCE(p_limit, 50), 1), app.member_page_max())
$$;

-- The roster's sort order, stated once. Display name is what the sidebar shows
-- and so what somebody scrolling is reading; `id` breaks the ties, because two
-- people may be called the same thing and a keyset page needs the order to be
-- total or it will skip or repeat a row at the seam.
CREATE OR REPLACE FUNCTION app.member_sort_key(p_name TEXT) RETURNS TEXT
  LANGUAGE sql IMMUTABLE AS $$ SELECT lower(p_name) $$;

-- ============================================================
-- 3. Who is in scope
-- ============================================================
-- The three filters every member query shares, so they cannot disagree about
-- what "the roster" means:
--
--   p_channel — restrict to members who can open that channel, and refuse
--               entirely unless the caller can open it too. This is what
--               `channel_audience` answered as a whole set; asked per query it
--               costs one predicate instead of a full membership download.
--   p_bots    — NULL both, true only bots, false only people. Bots are listed
--               apart everywhere in the UI (BOTS.md §9), so nearly every
--               caller wants one or the other.
--   p_banned  — NULL both, true only banned, false only present members.
--               Defaults to false: a banned member is not in the room, and the
--               one surface that needs them (the moderation modal, to lift the
--               ban) asks for them by name.
--
-- Written as one predicate function rather than repeated in six WHERE clauses.
-- `app.channel_eligible` is not called per row on purpose: it re-reads the
-- channel every time, and the private-channel test only matters when the
-- channel is private. The scalar subquery is evaluated once and the OR
-- short-circuits for every row of a public channel.
-- The people a private channel is open to, gathered once.
--
-- NULL means "everybody in the server", which is what a public channel and a
-- missing channel both mean; an empty array means nobody, which a private
-- channel with no members really does mean, and the two must not collapse.
--
-- It exists because the per-row form of the same question is what several
-- statements were spending their time on. `app.in_channel` is two EXISTS
-- queries, and asked once per member it cost 3.6 seconds to count the people
-- in a private channel on a 50,000-member server. The list is the channel's
-- membership, which is small whatever the server is.
CREATE OR REPLACE FUNCTION app.channel_audience(p_channel UUID) RETURNS UUID[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT CASE
    WHEN p_channel IS NULL THEN NULL
    WHEN NOT COALESCE((SELECT c.is_private FROM channels c WHERE c.id = p_channel), false)
      THEN NULL
    ELSE COALESCE((
      SELECT array_agg(DISTINCT e.user_id) FROM (
        SELECT cm.user_id FROM channel_members cm WHERE cm.channel_id = p_channel
        UNION
        SELECT mr.user_id FROM channel_role_access cra
          JOIN member_roles mr ON mr.role_id = cra.role_id
         WHERE cra.channel_id = p_channel
      ) e), ARRAY[]::UUID[])
  END
$$;

COMMENT ON FUNCTION app.channel_audience(UUID) IS
  'Who may open this private channel, as one array; NULL when the channel is '
  'public or absent, meaning no restriction. Hoisted out of the per-row '
  'membership test the member queries and the doorbell used to make.';

CREATE OR REPLACE FUNCTION app.member_in_scope(
  p_user     UUID,
  p_is_bot   BOOLEAN,
  p_banned_row BOOLEAN,
  p_channel  UUID,
  p_bots     BOOLEAN,
  p_banned   BOOLEAN
) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT (p_bots   IS NULL OR p_is_bot     = p_bots)
     AND (p_banned IS NULL OR p_banned_row = p_banned)
     AND (p_channel IS NULL
          OR NOT (SELECT c.is_private FROM channels c WHERE c.id = p_channel)
          OR app.in_channel(p_channel, p_user))
$$;

-- The gate the channel-scoped queries open with. Separate from the row
-- predicate because it is asked once, not per row, and because "you cannot see
-- this channel" must return nothing rather than the whole server.
CREATE OR REPLACE FUNCTION app.member_scope_allowed(p_channel UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT p_channel IS NULL OR app.can_see_channel(p_channel)
$$;

CREATE OR REPLACE FUNCTION app.sync_permission_cache(p_user UUID) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bits BIGINT;
  v_admin BIGINT := app.perm('ADMINISTRATOR');
BEGIN
  v_bits := app.permissions_of(p_user);
  UPDATE users SET
    is_server_admin    = (v_bits & v_admin) <> 0,
    is_channel_manager = (v_bits & (v_admin | app.perm('MANAGE_CHANNELS'))) <> 0,
    can_create_tokens  = (v_bits & (v_admin | app.perm('CREATE_INVITE'))) <> 0,
    is_owner           = EXISTS (SELECT 1 FROM member_roles mr
                                   JOIN roles r ON r.id = mr.role_id
                                  WHERE mr.user_id = p_user AND r.is_owner)
   WHERE id = p_user;
END; $$;

-- ============================================================
-- Roles are an administrator's to shape
-- ============================================================
-- `MANAGE_ROLES` let anybody holding it create roles beneath their own rank,
-- edit them, and hand them out, bounded by the subset rule. Sound in theory;
-- in practice it meant a server's ladder could be reshaped by whoever had
-- been given the bit, and a moderator handing out moderator roles is a
-- server whose shape nobody chose.
--
-- Roles are an administrator's now: creating, editing, deleting and assigning
-- all ask `ADMINISTRATOR`, and nothing else opens that door. The rank rule
-- stays exactly as it was — strictly below for editing, at-or-below for an
-- administrator handing one out, and never the owner role — because it
-- is what keeps two admins from rewriting each other, not something
-- `MANAGE_ROLES` was carrying.
--
-- The bit itself is cleared everywhere and retired from the editor. A bit
-- that does nothing but sit checked on a role is a promise the server no
-- longer keeps.

CREATE OR REPLACE FUNCTION app.may_manage_role(p_position INTEGER) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.has_perm('ADMINISTRATOR') AND p_position < app.max_role_position()
$$;

CREATE OR REPLACE FUNCTION app.may_assign_role(p_role UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.has_perm('ADMINISTRATOR')
     AND EXISTS (
       SELECT 1 FROM roles r
        WHERE r.id = p_role
          AND r.server_id = app.server_id()
          AND NOT r.is_everyone
          AND NOT r.is_owner)
$$;

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

-- ============================================================
-- 2. The two rows that answer for everybody
-- ============================================================

CREATE OR REPLACE FUNCTION app.unread_thresholds(
  p_channel UUID,
  p_before  BIGINT,
  OUT o_newest       BIGINT,   -- m1: the newest message before p_before
  OUT o_newest_by    UUID,     -- who sent it
  OUT o_newest_other BIGINT    -- m2: the newest before it from anybody else
) RETURNS RECORD
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_top BIGINT;
BEGIN
  -- `max(id) WHERE channel_id = …` rather than `ORDER BY id DESC LIMIT 1`,
  -- and the difference is not style. Written as an ordered read, the planner
  -- is free to satisfy the sort with the **primary key**: walk ids downwards
  -- from `p_before` and discard everything that is not this channel's. That
  -- costs one row when this is the channel everybody is talking in, and a
  -- scan of every message written since when it is not — 777 ms on a channel
  -- whose newest message was four million rows ago, measured on 5,000,000.
  -- `max()` over the same predicate becomes an InitPlan on
  -- `idx_messages_channel (channel_id, id)`, which is this channel's own
  -- newest id and nothing else's: 0.2 ms on the same data, whatever the
  -- channel. The planner cannot be talked out of the first plan, because with
  -- `channel_id` fixed by equality `ORDER BY channel_id, id DESC` reduces to
  -- `ORDER BY id DESC` and the primary key serves it again.
  --
  -- This runs on every insert into `messages`, so that scan sat on the path
  -- of every message anybody sent.
  -- The channel's own newest id, and nothing else's. Asked with no bound on
  -- `id` at all, which is what lets it become an index-only scan backwards
  -- along `idx_messages_channel` that stops on the first row: add `id <
  -- p_before` here and the planner takes the primary key instead, because a
  -- range on `id` is something the primary key can serve and a channel is
  -- not. That is the whole trap.
  SELECT max(x.id) INTO v_top FROM messages x WHERE x.channel_id = p_channel;
  IF v_top IS NULL THEN
    RETURN;   -- nothing has ever been said here
  END IF;

  -- Now the ordered read can have its range, because the range starts at this
  -- channel's own newest message rather than at the top of the table. What it
  -- walks past is whatever this channel put after `p_before` plus any button
  -- presses, not every message every other channel has received since.
  SELECT m.id, m.sender_id INTO o_newest, o_newest_by
    FROM messages m
   WHERE m.channel_id = p_channel
     AND m.id <= LEAST(v_top, p_before - 1)
     AND NOT m.is_interaction
   ORDER BY m.id DESC LIMIT 1;

  IF o_newest IS NULL THEN
    RETURN;   -- nothing came before: nobody can have unread mail here
  END IF;

  -- Bounded by `o_newest` rather than by `p_before`, and that is the whole
  -- point of doing it second. The newest message from anybody else is by
  -- definition older than the newest message, so the two are the same
  -- question — but `p_before` is the id of the message being inserted, which
  -- is the top of the whole table, while `o_newest` is this channel's own.
  -- Written against `p_before` this walked the primary key back over every
  -- message any other channel had received in the meantime, which left the
  -- fix above buying nothing: 762 ms, unchanged.
  --
  -- What remains is a walk back over however many messages that one member
  -- sent in a row, which is a handful and not a history.
  SELECT max(m.id) INTO o_newest_other
    FROM (
      -- Ids only, and that is what keeps this on `idx_messages_channel`. The
      -- index holds `(channel_id, id)`, so a query wanting nothing else is
      -- answered without touching the heap and costs a hundred index entries;
      -- ask for `sender_id` in the same breath and every row needs a heap
      -- fetch, the planner prices that above walking the primary key
      -- downwards instead, and we are back to reading every message the
      -- server has received since this channel last spoke. 813 ms against
      -- 0.4 ms, measured on 5,000,000.
      SELECT x.id FROM messages x
       WHERE x.channel_id = p_channel AND x.id < o_newest
       ORDER BY x.id DESC
       -- A hundred is "how many messages in a row can one person have sent
       -- and still be the reason nobody else is rung". Past that this comes
       -- back NULL, which the doorbell already has a meaning for — nobody
       -- else has spoken here — and that meaning errs the safe way: the one
       -- member it concerns is treated as caught up and therefore rung. The
       -- cost of being wrong is a doorbell somebody did not need, never a
       -- message nobody was told about.
       LIMIT 100
    ) t
    JOIN messages m ON m.id = t.id
   WHERE NOT m.is_interaction
     AND m.sender_id IS DISTINCT FROM o_newest_by;
END $$;

COMMENT ON FUNCTION app.unread_thresholds(UUID, BIGINT) IS
  'The two message ids that decide, for every member at once, whether they '
  'had unread mail in this channel before a given message: the newest one, '
  'and the newest one from somebody other than its sender.';

-- ============================================================
-- A policy asks once, not once per row
-- ============================================================
-- A row-level policy runs for every row the statement touches. When the
-- policy calls a function, that function runs for every row too — and most
-- of the questions these policies ask do not depend on the row at all.
-- `app.server_id()` is "which server is the caller in", `auth.uid()` is "who
-- is asking", `app.is_bot()` is "are they a bot": one answer per statement,
-- asked once per row.
--
-- Where the answer *does* depend on the row it is nearly always the channel,
-- and a server has tens of channels and millions of messages. Asking "can I
-- see this channel" once per message is the same waste wearing a hat.
--
-- Measured on 50,000 members, 50 channels, 5,000,000 messages and 2,000,000
-- keyring rows. Same queries, same data, only the policies differ:
--
--   a page of 50 messages ................    2.34 ms  →  0.82 ms
--   a capped unread count (100) ..........    4.69 ms  →  0.98 ms
--   unread_counts() over 50 channels .....  230 ms     → 24.5 ms
--   one channel's keyring ................ 2,140 ms    →  6.25 ms
--   count the members ....................  420 ms     →  5.9 ms
--   the member sidebar, page 20 ..........  134 ms     → 15.5 ms
--   role chips for 50 members ............ 1,100 ms    → 31 ms
--
-- Nothing here changes who may read what. Every rewrite below is the same
-- predicate rearranged so the planner can hoist it, and `policies_test.sql`
-- is the check that it still refuses what it refused before.
--
-- ---------- the two shapes ----------
--
-- **A question with no row in it** is wrapped in a scalar subquery:
-- `auth.uid()` becomes `(SELECT auth.uid())`. Postgres turns that into an
-- InitPlan, evaluated once for the statement and then treated as a constant.
-- Written bare it is a function call per row, and `auth.uid()` in particular
-- parses JSON out of a setting every single time.
--
-- **A question about the row's channel** becomes set membership:
-- `app.can_see_channel(channel_id)` becomes
-- `channel_id IN (SELECT unnest(app.visible_channels()))`. The set is built
-- once — it is the caller's channels, and there are tens of them — and the
-- per-row test is a hash lookup.
--
-- One policy is deliberately *not* rewritten. `message_reactions_select`
-- asks about a message id rather than a channel, so there is no small set to
-- hoist into; rewriting it as an EXISTS measured slower than what it
-- replaced (16 ms against 8.8 ms for a page of tallies), so it stays.

-- ============================================================
-- 1. The sets, built once
-- ============================================================

-- Every channel the caller may read: the same rule `app.can_see_channel`
-- applies, gathered rather than asked one channel at a time.
CREATE OR REPLACE FUNCTION app.visible_channels() RETURNS UUID[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(array_agg(c.id), '{}'::uuid[])
    FROM channels c
   WHERE c.server_id = app.server_id()
     AND (NOT c.is_private OR app.in_channel(c.id, auth.uid()))
$$;

COMMENT ON FUNCTION app.visible_channels() IS
  'The caller''s readable channels as one array, so a policy can test '
  'membership instead of calling app.can_see_channel for every row.';

-- The channels a bot was granted, which is `app.bot_reads_channel` gathered
-- the same way. Empty for everybody who is not a bot.
CREATE OR REPLACE FUNCTION app.bot_channels() RETURNS UUID[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(array_agg(g.channel_id), '{}'::uuid[])
    FROM bot_channel_keys g WHERE g.bot_id = auth.uid()
$$;

COMMENT ON FUNCTION app.bot_channels() IS
  'The channels this bot holds a key for, as one array. Empty for a person.';

-- The caller's own server's roles. `member_roles_select` used to reach for
-- `users` to decide whether a role assignment was in scope, which made every
-- read of it a scan of the whole membership; a role belongs to exactly one
-- server and `member_roles_insert` will not let the two sides differ, so the
-- twelve-row table answers the same question.
CREATE OR REPLACE FUNCTION app.server_roles() RETURNS UUID[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(array_agg(r.id), '{}'::uuid[])
    FROM roles r WHERE r.server_id = app.server_id()
$$;

COMMENT ON FUNCTION app.server_roles() IS
  'The roles of the caller''s server, as one array.';

-- ============================================================
-- 3b. One page of a channel, as ids
-- ============================================================
-- The same trap `app.unread_thresholds` fell into, in the read everybody
-- makes most: `WHERE channel_id = … ORDER BY id DESC LIMIT 51`.
--
-- Messages from every channel share one table and one sequence, so the
-- primary key is already in `id` order and can serve that sort on its own —
-- walk ids downwards from the newest message on the server and discard
-- everything belonging to another channel. The planner prices that at 255
-- rows, because it assumes `channel_id` is spread evenly through the id
-- range. It is not: ids are handed out in arrival order, so a channel's
-- messages sit where that channel was last busy. Opening a channel that is
-- not the server's most recent writer — `#rules`, `#announcements`, every
-- channel a community has stopped using — crossed four million rows and took
-- 4.4 seconds on 5,000,000 messages. `idx_messages_channel (channel_id, id)`
-- answers it in 0.17 ms and was never touched, and no amount of ANALYZE
-- changes that: there is no statistic that says "this column's values are
-- clustered against the table's own ordering".
--
-- What tips the choice is asking for **ids and nothing else**. Then the
-- index holds the whole answer, the scan is index-only, and its cost (3.24)
-- comes in under the primary key's estimate (22.52). Ask for `ciphertext`
-- in the same breath — or let a policy ask for `ephemeral_for` — and every
-- row needs the heap, the estimate goes back over, and so does the plan.
--
-- Which is why this is SECURITY DEFINER and returns ids: under RLS the
-- policy's own columns would be fetched here and the fix would undo itself.
-- `channel_messages` in 003 does the visible half, joining these ids back to
-- `messages` by primary key with the policy in force. So the only thing this
-- function decides is whether you may open the channel at all — the same
-- question `messages_select` asks first — and the only thing it discloses
-- beyond what that policy would is that an id exists: an ephemeral bot reply
-- to somebody else, a button press of theirs. Never a row, never a byte of
-- one, and only inside a channel the caller is already in.
--
-- Deliberately not a copy of `messages_select`'s other three clauses. Two
-- statements of one access rule drift, and the direction they drift in is
-- silent over-exposure; a page that comes back short because the policy
-- dropped a row from it is a page that comes back short.
CREATE OR REPLACE FUNCTION app.channel_page_ids(
  p_channel UUID,
  p_before  BIGINT,
  p_after   BIGINT,
  p_limit   INTEGER
) RETURNS SETOF BIGINT
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- Asked once, not per row, and it is the whole of the access check.
  -- An outsider gets no rows, which is what the policy gives them too.
  IF NOT app.can_see_channel(p_channel) THEN RETURN; END IF;

  -- Branched rather than `p_before IS NULL OR x.id < p_before`, for the
  -- reason the member pages are branched: a disjunction is never an index
  -- condition, and the index is the entire point of this function.
  IF p_after IS NOT NULL THEN
    RETURN QUERY
    SELECT x.id FROM messages x
     WHERE x.channel_id = p_channel AND x.id > p_after
     ORDER BY x.id LIMIT p_limit;
  ELSIF p_before IS NOT NULL THEN
    RETURN QUERY
    SELECT x.id FROM messages x
     WHERE x.channel_id = p_channel AND x.id < p_before
     ORDER BY x.id DESC LIMIT p_limit;
  ELSE
    RETURN QUERY
    SELECT x.id FROM messages x
     WHERE x.channel_id = p_channel
     ORDER BY x.id DESC LIMIT p_limit;
  END IF;
END $$;

COMMENT ON FUNCTION app.channel_page_ids(UUID, BIGINT, BIGINT, INTEGER) IS
  'One page of a channel''s message ids, newest first, or oldest first when '
  'p_after is given. Nothing but ids, so the read stays on '
  'idx_messages_channel; `channel_messages` turns them into rows under RLS.';

-- ============================================================
-- 4. Telling anyone how full it is
-- ============================================================
-- Not a secret, and useful before it matters: a composer can say the server
-- is nearly full before somebody picks a file, which is kinder than
-- refusing them after they have.

CREATE OR REPLACE FUNCTION server_storage_used() RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(
    (SELECT u.bytes FROM app.bucket_usage u
      WHERE u.bucket_id = 'chat-' || app.server_id()::TEXT), 0)
$$;

COMMENT ON FUNCTION server_storage_used() IS
  'Bytes of attachments the caller''s server is holding. 0 for a banned '
  'member, who has no server.';

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

-- ============================================================
-- What the key sweep needs to know
-- ============================================================
-- "Who may read this channel" lives in the database, but four things outside
-- it ask that question — `sweep_channel_keys`, `get_channel_key`,
-- `voice_roster` and `get_channel_token` — and all four run as the service
-- role, which is to say with row-level security switched off.
--
-- So the policies protect none of them. Each would have to filter for itself,
-- and four hand-written filters is four places for the answer to drift. This
-- is the answer, written once, in the same place the policies read it from.
-- The bot grant below is the same shape for the same reason.

-- ============================================================
-- 1. Who may hold a key, and from which version
-- ============================================================
-- One row per (channel, person) that a key may legitimately be wrapped for,
-- carrying the floor that person's access starts at. The sweep's
-- `eligibleFor(channel, version)` is this view with one `<=`.
--
-- The floor is 1 for a member, because a member joining a public channel is
-- offered the current key and reads back as far as it goes. For a bot it is the
-- grant's `from_key_version`, which is what makes a moderation grant
-- forward-only (BOTS.md §6).

CREATE OR REPLACE VIEW channel_eligible_members AS
  SELECT c.id AS channel_id,
         u.id AS user_id,
         u.chat_public_key,
         u.is_bot,
         CASE WHEN u.is_bot THEN g.from_key_version ELSE 1 END AS from_key_version
    FROM channels c
    JOIN users u ON u.server_id = c.server_id
    LEFT JOIN bot_channel_keys g ON g.channel_id = c.id AND g.bot_id = u.id
   WHERE NOT u.is_banned
     -- Sealing to somebody who has published no chat key is a message nobody
     -- can ever open, so they are not "missing" an entry — they are not ready
     -- for one.
     AND u.chat_public_key IS NOT NULL
     AND CASE WHEN u.is_bot
              -- A bot is keyed only where somebody said so, never by the sweep
              -- being helpful.
              THEN g.bot_id IS NOT NULL
              ELSE (NOT c.is_private OR app.in_channel(c.id, u.id))
         END;

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
-- 3. What a client draws them from
-- ============================================================
-- The sibling of `voice_listeners`, and the same reasoning: the table is
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

-- ============================================================
-- Asking about members without holding the roster
-- ============================================================
-- A paged member directory, reaction tallies, and DM conversation paging.
-- All three replace 'fetch everything and filter on the client'.
--
-- ============================================================

-- ============================================================
-- Asking for members a page at a time
-- ============================================================
-- Every client read of the roster was `SELECT … FROM users` with no limit, and
-- PostgREST is configured with `PGRST_DB_MAX_ROWS=1000`. So a server's 1001st
-- member did not fail to load — they were silently absent, and everything
-- built on the roster inherited that: the member sidebar, the `@` menu, the
-- `/` menu, mention resolution on send, "start a DM with…", the private
-- channel member picker. A member who sorts last by username simply stopped
-- existing, and the client had no way to know a row had been dropped.
--
-- The ceiling is the visible half of the problem. The other half is that the
-- roster was *whole-table*: `ServerMembersCubit` refetched every user, every
-- role and every role assignment on each `users` row event — a rename, an
-- avatar change, a mute, a join. Three full-table reads per keystroke somebody
-- else made. Raising the ceiling would have made that worse, not better.
--
-- So this is not "the same query with a LIMIT". It is the set of questions the
-- client actually has, each answerable in bounded work:
--
--   list_members        — a page of the roster, alphabetical, keyset-paged.
--   search_members      — the best few matches for what somebody has typed.
--   members_by_ids      — resolve these ids I already hold (presence, authors).
--   members_by_usernames— resolve the @names in this message.
--   member_counts       — how many there are, for a section header.
--   member_roles_for    — the role chips for the rows on screen.
--
-- None of them can return more than `app.member_page_max` rows, so no caller
-- can accidentally ask for the whole table again.
--
-- ---------- this tells nobody anything new ----------
--
-- `users_select` already lets a member read every other member's row on their
-- server; that is what made the unbounded read possible in the first place.
-- These functions narrow that, they do not widen it. The two that take a
-- channel add `app.can_see_channel` on top, for the same reason
-- `channel_audience` does: a private channel's membership is the one thing
-- about it an outsider could otherwise learn.

-- ============================================================
-- 1. The shape of a member
-- ============================================================
-- One view, so "a member row" means the same thing to all six functions and to
-- the client that parses them. The column list is exactly what
-- `ServerUserRow.of` reads — a function returning a bespoke record type is a
-- second place for that list to drift out of step.
--
-- `security_invoker`, so `users_select` still decides who is visible. The view
-- adds no reach of its own; it only fixes the columns.

CREATE OR REPLACE VIEW member_directory
  WITH (security_invoker = true) AS
  SELECT u.id,
         u.server_id,
         u.username,
         u.display_name,
         u.avatar_path,
         u.chat_public_key,
         u.is_muted,
         u.is_deafened,
         u.is_banned,
         u.is_bot,
         u.manifest,
         u.is_server_admin,
         u.is_channel_manager,
         u.can_create_tokens,
         -- When they joined *this* server — the only tenure anybody here can
         -- vouch for, since servers do not know about each other and there is
         -- no global "member since" to show instead.
         --
         -- Last, and out of the grouping it belongs to, because that is the
         -- only place `CREATE OR REPLACE VIEW` will take a new column: this
         -- file is re-runnable and nothing in these migrations drops.
         u.created_at AS joined_at
    FROM users u;

CREATE OR REPLACE VIEW member_role_list
  WITH (security_invoker = true) AS
  SELECT mr.user_id,
         r.id AS role_id,
         r.name,
         r.color,
         r.position,
         r.permissions,
         r.is_owner
    FROM member_roles mr
    JOIN roles r ON r.id = mr.role_id;

COMMENT ON VIEW channel_eligible_members IS
  'Service-role only. Who a channel key may be wrapped for, and from which key '
  'version. Not granted to authenticated: it would list the membership of every '
  'private channel on the server.';

COMMENT ON VIEW voice_listeners IS
  'Bots that can hear each voice channel, with the name to show. '
  'security_invoker, so bot_voice_grants_select is what decides who sees it.';

COMMENT ON VIEW bot_voice_key_candidates IS
  'Bots that may speak in each voice channel, and whether they may also hear '
  'it. Read by get_channel_key so a member''s client can seal what is missing.';

COMMENT ON VIEW voice_summons IS
  'Bots asked into each voice channel, with the name to show. Unlike '
  'voice_listeners this is not a warning — a summoned bot publishes and cannot '
  'hear. It is what makes a summon whose bot never turned up visible, and '
  'therefore dismissable.';

COMMENT ON VIEW member_directory IS
  'A member as every client surface reads one — the column list behind '
  'list_members, search_members, members_by_ids and members_by_usernames. '
  'security_invoker, so users_select still decides who is visible. '
  'joined_at is this server''s own tenure and no other''s.';

COMMENT ON VIEW member_role_list IS
  'Which roles each member holds. `is_owner` marks the one role held by '
  'exactly one person (013).';

-- ============================================================
-- Which LiveKit a call goes on
-- ============================================================
-- A room lives on exactly one node — LiveKit's open-source server binds it
-- there and cross-node media is a Cloud feature — so this is never "each
-- person connects nearby". It is one decision, made once, when the room is
-- created, and everybody who joins afterwards goes where it already is.
--
-- The order is: where the call already is, then what the channel is pinned
-- to, then what the caller measured, then the default. Each step is a weaker
-- claim than the one above it, and the first is absolute because a live room
-- cannot be moved.

CREATE OR REPLACE FUNCTION app.claim_voice_node(
  p_channel   UUID,
  p_preferred UUID DEFAULT NULL
) RETURNS TABLE (id UUID, url TEXT, label TEXT)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
  v_node   UUID;
BEGIN
  SELECT c.server_id, c.livekit_node_id INTO v_server, v_node
    FROM channels c WHERE c.id = p_channel;

  IF v_server IS NULL THEN RETURN; END IF;

  -- What the caller measured, but only if it is really one of ours. The id
  -- arrives from a client, so it is a suggestion until this says otherwise.
  IF v_node IS NULL AND p_preferred IS NOT NULL THEN
    SELECT n.id INTO v_node FROM livekit_nodes n
     WHERE n.id = p_preferred AND n.server_id = v_server;
  END IF;

  IF v_node IS NULL THEN
    SELECT n.id INTO v_node FROM livekit_nodes n
     WHERE n.server_id = v_server AND n.is_default;
  END IF;

  IF v_node IS NULL THEN RETURN; END IF;

  -- First one in decides, and the conflict clause is the whole reason this is
  -- one statement rather than a read and a write: two people opening the same
  -- call in the same moment must not open it twice in two regions. The loser
  -- of the race reads the winner's row below and joins them.
  INSERT INTO voice_rooms (channel_id, node_id) VALUES (p_channel, v_node)
    ON CONFLICT (channel_id) DO NOTHING;

  RETURN QUERY
  SELECT n.id, n.url, n.label
    FROM voice_rooms vr
    JOIN livekit_nodes n ON n.id = vr.node_id
   WHERE vr.channel_id = p_channel;
END $$;

COMMENT ON FUNCTION app.claim_voice_node(UUID, UUID) IS
  'Where this channel''s call is, creating that answer if there is not one '
  'yet. Idempotent: everybody after the first gets what the first decided.';

-- The other half. Until this runs the channel keeps the node it was last
-- called on, and "automatic" would decide once in the channel's lifetime
-- rather than once per call.
--
-- Called by `voice_roster`, which is already asking every node who is in each
-- room and is therefore the only thing that finds out a call has ended. A row
-- left behind is not a broken call — it sends the next caller to a node with
-- no such room, and LiveKit makes one — so this is allowed to be late.
CREATE OR REPLACE FUNCTION app.release_voice_node(p_channels UUID[])
  RETURNS VOID
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  DELETE FROM voice_rooms
   WHERE channel_id = ANY (COALESCE(p_channels, ARRAY[]::UUID[]));
$$;

COMMENT ON FUNCTION app.release_voice_node(UUID[]) IS
  'Forget where these channels'' calls were, because they have ended. The '
  'next call on them is decided afresh.';
