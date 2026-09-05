-- ============================================================
-- Rift self-hosted server — 011: Asking about members without holding the roster
-- ============================================================
-- A paged member directory, reaction tallies, and DM conversation paging.
-- All three replace 'fetch everything and filter on the client'.
--
-- Was 3 files: 039_member_directory, 040_reaction_tallies, 041_dm_conversation_paging.
-- Merged unchanged and in the same order, so this applies exactly what
-- they applied. The sections below are those files, each still carrying
-- the reasoning it was written with.
-- ============================================================

-- ============================================================
-- Rift self-hosted server — 039: asking for members a page at a time
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
         u.can_create_tokens
    FROM users u;

COMMENT ON VIEW member_directory IS
  'A member as every client surface reads one — the column list behind '
  'list_members, search_members, members_by_ids and members_by_usernames. '
  'security_invoker, so users_select still decides who is visible.';

REVOKE ALL ON member_directory FROM anon;
GRANT SELECT ON member_directory TO authenticated;

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

-- Keyset paging wants (lower(display_name), id) in the index, and the search
-- wants prefix matches on both names. `text_pattern_ops` is what makes
-- `LIKE 'ab%'` on a lowercased column an index scan.
CREATE INDEX IF NOT EXISTS idx_users_server_sorted
  ON users (server_id, lower(display_name), id);

CREATE INDEX IF NOT EXISTS idx_users_display_prefix
  ON users (server_id, lower(display_name) text_pattern_ops);

CREATE INDEX IF NOT EXISTS idx_users_username_prefix
  ON users (server_id, lower(username) text_pattern_ops);

-- Substring search ("ali" finding "khalid") cannot use a prefix index. Trigram
-- can, and is worth having on a large server — but `pg_trgm` is not guaranteed
-- to be installable on every host this runs on, and a missing extension must
-- not take the migration down with it. Without it the substring pass is a scan
-- bounded by the page limit, which is fine into the low tens of thousands.
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pg_trgm;
  CREATE INDEX IF NOT EXISTS idx_users_name_trgm
    ON users USING gin ((lower(display_name) || ' ' || lower(username)) gin_trgm_ops);
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pg_trgm unavailable — substring member search will scan';
END $$;

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

-- ============================================================
-- 4. A page of the roster
-- ============================================================
-- Keyset rather than OFFSET. The sidebar pages while people are joining and
-- renaming themselves, and OFFSET under a shifting sort silently skips and
-- repeats rows at every page boundary. Pass the last row you were given back
-- as (p_after_name, p_after_id) and you get the next ones, whatever moved.

CREATE OR REPLACE FUNCTION list_members(
  p_channel    UUID    DEFAULT NULL,
  p_bots       BOOLEAN DEFAULT NULL,
  p_banned     BOOLEAN DEFAULT false,
  p_after_name TEXT    DEFAULT NULL,
  p_after_id   UUID    DEFAULT NULL,
  p_limit      INTEGER DEFAULT 50
) RETURNS SETOF member_directory
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT m.*
    FROM member_directory m
   WHERE app.member_scope_allowed(p_channel)
     AND m.server_id = app.server_id()
     AND app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, p_bots, p_banned)
     AND (p_after_name IS NULL
          OR (app.member_sort_key(m.display_name), m.id)
              > (app.member_sort_key(p_after_name), COALESCE(p_after_id, '00000000-0000-0000-0000-000000000000'::UUID)))
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT app.member_limit(p_limit)
$$;

COMMENT ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER) IS
  'One alphabetical page of the roster, keyset-paged on (display_name, id). '
  'Pass the last row back as p_after_name/p_after_id for the next page. '
  'p_channel restricts to members who can open that channel and returns '
  'nothing to a caller who cannot. Never returns more than '
  'app.member_page_max() rows.';

-- ============================================================
-- 5. The best few matches
-- ============================================================
-- Searching and browsing are different questions, so they are different
-- functions. A search is ranked — a name that *starts* with what you typed
-- beats one that merely contains it — and a ranked order cannot be keyset
-- paged coherently. It also does not need to be: this feeds typeaheads, which
-- show a handful of rows and narrow as you keep typing.
--
-- Matched against username and display name both, because those are two
-- different things somebody might be thinking of and neither is reliably the
-- one they know. Spaces are squashed out of the display name so `@animb` finds
-- "Anim Bot" — a mention token cannot contain a space, so somebody typing a
-- two-word name has no other way to reach them. This mirrors
-- `MentionSuggestions.suggest` on the client exactly; the client kept its copy
-- for the rows it already holds, and the two must agree or the list reorders
-- itself as the server's answer replaces the local guess.
--
-- An empty query is a browse: the first alphabetical page. That is what makes
-- a search field openable on focus without a second call.

CREATE OR REPLACE FUNCTION search_members(
  p_query   TEXT    DEFAULT NULL,
  p_channel UUID    DEFAULT NULL,
  p_bots    BOOLEAN DEFAULT NULL,
  p_banned  BOOLEAN DEFAULT false,
  p_limit   INTEGER DEFAULT 25
) RETURNS SETOF member_directory
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  WITH needle AS (
    SELECT NULLIF(lower(btrim(COALESCE(p_query, ''))), '') AS q
  )
  SELECT m.*
    FROM member_directory m, needle n
   WHERE app.member_scope_allowed(p_channel)
     AND m.server_id = app.server_id()
     AND app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, p_bots, p_banned)
     AND (n.q IS NULL
          OR lower(m.username) LIKE n.q || '%'
          OR lower(m.display_name) LIKE n.q || '%'
          OR replace(lower(m.display_name), ' ', '') LIKE n.q || '%'
          OR lower(m.username) LIKE '%' || n.q || '%'
          OR replace(lower(m.display_name), ' ', '') LIKE '%' || n.q || '%')
   ORDER BY CASE
              WHEN n.q IS NULL THEN 0
              WHEN lower(m.username) LIKE n.q || '%'
                OR lower(m.display_name) LIKE n.q || '%'
                OR replace(lower(m.display_name), ' ', '') LIKE n.q || '%' THEN 0
              ELSE 1
            END,
            app.member_sort_key(m.display_name),
            m.id
   LIMIT app.member_limit(p_limit)
$$;

COMMENT ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER) IS
  'The best matches for p_query, prefix matches first, capped. An empty query '
  'is the first alphabetical page, so a field can open on focus. Matches '
  'username and display name, with spaces squashed out of the display name so '
  '"animb" finds "Anim Bot" — the same rule MentionSuggestions.suggest '
  'applies on the client.';

-- ============================================================
-- 6. Resolving ids and names you already hold
-- ============================================================
-- The other half of dropping the whole-roster read. Once the client no longer
-- holds every member, it still has ids in hand — from Realtime presence, from
-- a message's sender, from a voice room's participants — and names in hand,
-- from the `@`s somebody just typed. Both used to be answered out of the
-- in-memory roster, which is exactly the read being removed.
--
-- Bounded by the same page cap. A caller with more ids than that pages them.

CREATE OR REPLACE FUNCTION members_by_ids(p_ids UUID[])
  RETURNS SETOF member_directory
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT m.*
    FROM member_directory m
   WHERE m.server_id = app.server_id()
     AND m.id = ANY (COALESCE(p_ids, ARRAY[]::UUID[]))
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT app.member_page_max()
$$;

COMMENT ON FUNCTION members_by_ids(UUID[]) IS
  'Resolve ids the caller already holds — presence, message senders, voice '
  'participants — without holding the whole roster. Banned members included: '
  'the caller is asking about somebody specific, and a name that renders as '
  'blank because they were banned is worse than the name.';

-- Mention resolution. Channel-scoped, because who a mention *reaches* is the
-- question being asked: `validate_message_mentions` will strip an id that
-- cannot open the channel, and a composer that resolved a name the trigger
-- then dropped would show a ping that never happened (034).
CREATE OR REPLACE FUNCTION members_by_usernames(
  p_names   TEXT[],
  p_channel UUID DEFAULT NULL
) RETURNS SETOF member_directory
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT m.*
    FROM member_directory m
   WHERE app.member_scope_allowed(p_channel)
     AND m.server_id = app.server_id()
     AND NOT m.is_banned
     AND lower(m.username) = ANY (
           SELECT lower(n) FROM unnest(COALESCE(p_names, ARRAY[]::TEXT[])) AS n)
     AND app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, false)
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT app.member_page_max()
$$;

COMMENT ON FUNCTION members_by_usernames(TEXT[], UUID) IS
  'Resolve @names to members who can actually be reached in p_channel — the '
  'same set validate_message_mentions keeps, asked for the handful of names in '
  'one message rather than as the whole audience.';

-- ============================================================
-- 7. How many, and what they wear
-- ============================================================
-- A paged list still has to say how long it is, or the sidebar header reads
-- "Offline — 50" forever and the number means "how far you have scrolled".

CREATE OR REPLACE FUNCTION member_counts(p_channel UUID DEFAULT NULL)
  RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT jsonb_build_object(
           'people', COUNT(*) FILTER (WHERE NOT m.is_bot),
           'bots',   COUNT(*) FILTER (WHERE m.is_bot))
    FROM member_directory m
   WHERE app.member_scope_allowed(p_channel)
     AND m.server_id = app.server_id()
     AND NOT m.is_banned
     AND app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, false)
$$;

COMMENT ON FUNCTION member_counts(UUID) IS
  'How many people and how many bots are in scope, so a paged list can say how '
  'long it is. Banned members are excluded, matching what the lists show.';

-- Role chips for the rows on screen. `member_role_list` is server-wide and was
-- read whole for the same reason the roster was; at one row per (member, role)
-- it hits the ceiling sooner than the roster does.
CREATE OR REPLACE FUNCTION member_roles_for(p_ids UUID[])
  RETURNS SETOF member_role_list
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT l.*
    FROM member_role_list l
   WHERE l.user_id = ANY (COALESCE(p_ids, ARRAY[]::UUID[]))
   ORDER BY l.user_id, l.position DESC
   LIMIT app.member_page_max() * 8
$$;

COMMENT ON FUNCTION member_roles_for(UUID[]) IS
  'Which roles these members hold, most senior first — the chips for the rows '
  'on screen rather than for everybody. Capped at eight roles per member of a '
  'full page; a member wearing more than that has more than a sidebar can show.';

-- ============================================================
-- 8. Privileges
-- ============================================================
-- New functions are executable by PUBLIC by default. Every one of these is
-- revoked and handed back to `authenticated` by name.

REVOKE ALL ON FUNCTION app.member_page_max() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.member_limit(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.member_sort_key(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.member_in_scope(UUID, BOOLEAN, BOOLEAN, UUID, BOOLEAN, BOOLEAN) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.member_scope_allowed(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION members_by_ids(UUID[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION members_by_usernames(TEXT[], UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION member_counts(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION member_roles_for(UUID[]) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app.member_page_max() TO authenticated;
GRANT EXECUTE ON FUNCTION app.member_limit(INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION app.member_sort_key(TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION app.member_in_scope(UUID, BOOLEAN, BOOLEAN, UUID, BOOLEAN, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION app.member_scope_allowed(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER) TO authenticated;
GRANT EXECUTE ON FUNCTION members_by_ids(UUID[]) TO authenticated;
GRANT EXECUTE ON FUNCTION members_by_usernames(TEXT[], UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION member_counts(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION member_roles_for(UUID[]) TO authenticated;

-- ============================================================
-- 9. What this replaces
-- ============================================================
-- `channel_audience` (034) asked the same question and answered it as a whole
-- set: every member who can open a channel, in one response. That was the right
-- shape for a composer holding the roster in memory and the wrong shape the
-- moment the roster stopped fitting — it is unbounded by exactly the number
-- this migration exists to stop assuming, and on a large private channel it
-- would have been cut off by the very same 1000-row ceiling.
--
-- `list_members(p_channel => …)` is that predicate asked a page at a time, and
-- `members_by_usernames(p_names, p_channel)` is it asked about the handful of
-- names in one message. Nothing calls the old function any more, and leaving a
-- granted SECURITY DEFINER function that resolves private channel membership
-- lying around unused is how a door nobody remembers stays unlocked.
DROP FUNCTION IF EXISTS channel_audience(UUID);


-- ============================================================
-- Rift self-hosted server — 040: count reactions where they are stored
-- ============================================================
-- The standalone reaction read asked for one row per person per emoji across a
-- whole page of messages, and PostgREST caps a response at 1000 rows. Fifty
-- messages is a page; twenty people reacting to each of them is a lively
-- channel, not an extreme one. At that point the response was cut off and the
-- client tallied whatever survived — so a reaction count quietly read low, or a
-- reaction of your own stopped being yours and the button un-filled.
--
-- Nothing about it looked wrong. That is the shape of every bug in this batch:
-- a limit that trims an answer instead of refusing the question.
--
-- The fix is not a bigger limit. Counting is the database's job, and doing it
-- there makes the response smaller by exactly the factor that was overflowing
-- it — one row per (message, emoji) rather than per (message, emoji, person).
-- A message with twenty reactors and three emoji goes from sixty rows to three.
--
-- Returned as one JSONB object rather than a set, for the same reason
-- `unread_counts` and `dm_conversations` are: a scalar is not row-capped, so
-- this cannot be truncated however many reactions a page collects. The shape is
-- exactly what `ReactionOps.byMessage` used to build on the client, so the
-- caller is unchanged past the fetch.
--
-- ---------- what stays on the client ----------
--
-- `ReactionOps.aggregate` is still there, and still used: a message page
-- carries its reactions with it as an embedded select, and folding *those* is
-- free. What moves here is only the standalone read — the one that asks about a
-- page of messages at once and so was the one that overflowed.

CREATE OR REPLACE FUNCTION message_reaction_tallies(
  p_scope read_scope,
  p_ids   BIGINT[]
) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_ids  BIGINT[];
  v_rows JSONB;
BEGIN
  -- A page is fifty. The cap is here so a caller that one day asks about its
  -- whole history gets an answer about the first hundred rather than a
  -- statement that runs for a minute.
  v_ids := (SELECT array_agg(id) FROM (
              SELECT unnest(COALESCE(p_ids, ARRAY[]::BIGINT[])) AS id
               LIMIT 100) capped);
  IF v_ids IS NULL THEN RETURN '{}'::jsonb; END IF;

  -- Two tables, one shape. Written as two branches rather than dynamic SQL:
  -- the scope is an enum, so there is nothing to interpolate and nothing to
  -- get wrong. `security_invoker` throughout, so the reaction policies decide
  -- what is visible exactly as they do for a direct read.
  IF p_scope = 'channel' THEN
    SELECT jsonb_object_agg(message_id::TEXT, entries) INTO v_rows
      FROM (
        SELECT r.message_id,
               jsonb_agg(jsonb_build_object(
                 'emoji', r.emoji,
                 'count', r.n,
                 'mine',  r.mine) ORDER BY r.emoji) AS entries
          FROM (
            SELECT m.message_id,
                   m.emoji,
                   count(*)                                   AS n,
                   bool_or(m.user_id = auth.uid())             AS mine
              FROM message_reactions m
             WHERE m.message_id = ANY (v_ids)
             GROUP BY m.message_id, m.emoji
          ) r
         GROUP BY r.message_id
      ) grouped;
  ELSE
    SELECT jsonb_object_agg(message_id::TEXT, entries) INTO v_rows
      FROM (
        SELECT r.message_id,
               jsonb_agg(jsonb_build_object(
                 'emoji', r.emoji,
                 'count', r.n,
                 'mine',  r.mine) ORDER BY r.emoji) AS entries
          FROM (
            SELECT m.message_id,
                   m.emoji,
                   count(*)                                   AS n,
                   bool_or(m.user_id = auth.uid())             AS mine
              FROM dm_message_reactions m
             WHERE m.message_id = ANY (v_ids)
             GROUP BY m.message_id, m.emoji
          ) r
         GROUP BY r.message_id
      ) grouped;
  END IF;

  RETURN COALESCE(v_rows, '{}'::jsonb);
END; $$;

COMMENT ON FUNCTION message_reaction_tallies(read_scope, BIGINT[]) IS
  'Reaction counts for a page of messages, as {message_id: [{emoji, count, '
  'mine}]}. One row per (message, emoji) instead of per person, and returned '
  'as a scalar rather than a set, so a lively page cannot overflow the 1000-row '
  'response cap and silently read low. Ordered by emoji so two clients drawing '
  'the same message draw it the same way.';

REVOKE ALL ON FUNCTION message_reaction_tallies(read_scope, BIGINT[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION message_reaction_tallies(read_scope, BIGINT[]) TO authenticated;


-- ============================================================
-- Rift self-hosted server — 041: the DM conversation list, a page at a time
-- ============================================================
-- `dm_conversations()` from 003 returned every peer you have ever exchanged a
-- message with, in one answer, with no way to ask for fewer. Central had the
-- same shape and lost it in migration 013; this is the same change, made here.
--
-- It could not truncate — a JSONB scalar is not subject to the 1000-row
-- response cap, which is why 003 built it that way — so nothing was silently
-- missing. What it did instead was grow: the list is refetched on every server
-- switch and on every incoming DM, and each row carries an envelope the client
-- decrypts to draw a preview. A member who has spoken to two hundred people
-- pays two hundred decryptions to render the dozen tiles that fit on screen,
-- and pays them again the next time somebody says hello.
--
-- Bounded by how many people you have talked to rather than by how much was
-- said, so it was the slowest of the reads to become a problem and the last one
-- left. That is the only reason it is a migration of its own.
--
-- ---------- what does not change ----------
--
-- The row. Same keys, same envelope, same `DISTINCT ON (peer)` — a caller that
-- reads a conversation out of the answer needs no edit. What changes is the
-- envelope around them: an array becomes `{conversations, has_more}`, because a
-- page that cannot say whether it is the last one leaves the client guessing
-- from whether it came back full, and a full last page then offers a "load
-- more" that fetches nothing.
--
-- SECURITY INVOKER, still. `dm_messages_select` (002) is already
-- `auth.uid() IN (sender_id, recipient_id)`, so the rows this can reach are the
-- caller's own conversations and nothing else — the pairing below has no filter
-- of its own because it does not need one. Central's version is DEFINER for a
-- reason that does not exist here: it has a `blocks` table, and it must name a
-- blocked peer's handle in order to leave them out.

DROP FUNCTION IF EXISTS dm_conversations();

CREATE OR REPLACE FUNCTION dm_conversations(
  p_limit  INTEGER DEFAULT 30,
  p_before BIGINT  DEFAULT NULL
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  WITH newest AS (
    SELECT DISTINCT ON (peer) *
      FROM (
        SELECT d.*,
               CASE WHEN d.sender_id = auth.uid()
                    THEN d.recipient_id ELSE d.sender_id END AS peer
          FROM dm_messages d
      ) paired
     ORDER BY peer, id DESC
  ),
  -- One row past the page, so "there is more" is proved rather than guessed
  -- from a full page. Same trick the message history and central use.
  page AS (
    SELECT * FROM newest
     WHERE p_before IS NULL OR id < p_before
     ORDER BY id DESC
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100) + 1
  ),
  kept AS (
    SELECT * FROM page
     ORDER BY id DESC
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100)
  ),
  rows AS (
    SELECT jsonb_build_object(
             'peer_id',               u.id,
             'peer_name',             u.display_name,
             'peer_username',         u.username,
             'peer_avatar_path',      u.avatar_path,
             'peer_chat_public_key',  u.chat_public_key,
             'peer_public_key',       u.public_key,
             'last_message', jsonb_build_object(
               'id',           k.id,
               'created_at',   k.created_at,
               'sender_id',    k.sender_id,
               'recipient_id', k.recipient_id,
               'ciphertext',   k.ciphertext,
               'nonce',        k.nonce,
               'signature',    k.signature,
               'key_version',  k.key_version,
               'edited_at',    k.edited_at
             )
           ) AS row,
           k.id AS sort_id
      FROM kept k
      JOIN users u ON u.id = k.peer
  )
  SELECT jsonb_build_object(
           'conversations',
           COALESCE((SELECT jsonb_agg(row ORDER BY sort_id DESC) FROM rows),
                    '[]'::jsonb),
           'has_more',
           (SELECT count(*) FROM page) > (SELECT count(*) FROM kept));
$$;

COMMENT ON FUNCTION dm_conversations(INTEGER, BIGINT) IS
  'A page of DM conversations, newest activity first, as {conversations, '
  'has_more}. Keyset-paged on the newest message id: pass the last row''s '
  'message id as p_before for the next page. Ordering by id rather than by a '
  'timestamp is what makes the cursor exact — the list reorders itself every '
  'time somebody speaks, and an offset into it means something different a '
  'second later.';

REVOKE ALL ON FUNCTION dm_conversations(INTEGER, BIGINT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dm_conversations(INTEGER, BIGINT) TO authenticated;
