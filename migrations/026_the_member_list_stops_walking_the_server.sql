-- ============================================================
-- Rift self-hosted server — 026: the member list stops walking the server
-- ============================================================
-- 025 stopped the policies re-asking the same question per row. What is left
-- is the five queries behind the member sidebar, and every one of them read
-- the whole membership to answer a question about a handful of people.
--
-- Measured on 50,000 members, after 025:
--
--   resolve 50 ids (members_by_ids) .....   8.96 ms  →  0.7 ms
--   role chips for 50 (member_roles_for)   32.6  ms  →  0.8 ms
--   count the members (member_counts) ...  160   ms  →  5.9 ms
--   typeahead, no match (search_members)   120   ms  →  0.5 ms
--   the sidebar, page 20 (list_members) .   15.6 ms  →  0.2 ms
--
-- There are three separate causes and they need three separate fixes.
--
-- ---------- 1. an array parameter tells the planner nothing ----------
--
-- `members_by_ids` and `member_roles_for` take `uuid[]`. The planner has no
-- idea whether that holds one id or fifty thousand, so it plans for the
-- worst: a sequential scan of `member_roles`, or a walk of the whole server
-- in name order until fifty of the wanted ids happen to turn up. Unnesting
-- the array into a materialised CTE first gives it a row count, and it joins
-- by primary key instead.
--
-- ---------- 2. a SECURITY DEFINER call is a call per row ----------
--
-- `app.member_in_scope` cannot be inlined, so it is a real function call for
-- every member considered. Two thirds of what it asks — is this a bot, is
-- this a banned account — are comparisons on columns the query already has.
-- Only the channel question needs the function, so only the channel question
-- calls it now. That was the whole of `member_counts`: 50,000 calls to
-- compare two booleans.
--
-- ---------- 3. the caller's own row, OR'd into every read ----------
--
-- This is the one worth reading carefully, because it is not obvious and it
-- was costing the most.
--
-- `users` has two SELECT policies, and Postgres ORs permissive policies
-- together, so every read of `users` carries
-- `(id = auth.uid() OR server_id = app.server_id())`. That disjunction can
-- never be an index condition — so the planner applies it as a filter, and a
-- filter it cannot index means *nothing else can be an index condition
-- either*. The keyset paging comparison, the three prefix patterns, all of
-- it falls back to a sequential scan of the membership:
--
--   the sidebar, page 20 ........ 22,214 rows walked to return 51
--   typeahead for "zzz" ......... 50,000 rows walked to return 0
--
-- The second policy is not a mistake. A banned member has no server, so
-- `app.server_id()` is null for them, and `users_select_self` is how they can
-- still read their own row and find out the ban was lifted. It has to stay.
--
-- So these five functions become SECURITY DEFINER and enforce the same scope
-- themselves, in one place, with a constant: `v_server := app.server_id()`,
-- nothing at all if that is null, and `server_id = v_server` on every query.
-- That is exactly what `users_select_members` permits — a banned caller
-- resolves to null and gets nothing either way, which is what the INVOKER
-- versions already did — and with a constant in hand the planner uses the
-- indexes that were there all along.
--
-- `member_roles_for` is the one to be careful with: it had no scope of its
-- own at all, because `member_roles_select` was doing the scoping for it.
-- Bypassing RLS means it has to say so itself, which is the `scoped` CTE.

-- ============================================================
-- 1. The two indexes the search needed
-- ============================================================
-- `replace(lower(display_name), ' ', '')` is how "JohnSmith" finds "John
-- Smith". It was already one of the match patterns and had no index, so it
-- was the one dragging the other two into a scan.

CREATE INDEX IF NOT EXISTS idx_users_display_squashed
  ON users (server_id, replace(lower(display_name), ' ', '') text_pattern_ops);

-- The prefilter for the infix fallback. Deliberately built on the *squashed*
-- display name so it is a true superset of both infix patterns: a needle
-- that spans a space in the display name is present here, and would not be
-- in a concatenation that kept the space.
--
-- Guarded exactly as 011 guards its own trigram index, and for the same
-- reason: `pg_trgm` is not installable on every host, and a missing
-- extension must not take the migration down with it. Without the index the
-- infix half is a scan bounded by the page limit — which is what it was
-- before this migration, so nothing is worse off.
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pg_trgm;
  CREATE INDEX IF NOT EXISTS idx_users_search_trgm
    ON users USING gin (
      (replace(lower(display_name), ' ', '') || ' ' || lower(username))
      gin_trgm_ops);
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pg_trgm unavailable — the infix half of member search will scan';
END $$;

-- ============================================================
-- 2. Resolving ids
-- ============================================================

CREATE OR REPLACE FUNCTION members_by_ids(p_ids UUID[])
  RETURNS SETOF member_directory
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_server UUID := app.server_id();
BEGIN
  IF v_server IS NULL THEN RETURN; END IF;
  RETURN QUERY
  WITH wanted AS MATERIALIZED (
    SELECT unnest(COALESCE(p_ids, ARRAY[]::UUID[])) AS id
  )
  SELECT m.*
    FROM member_directory m
    JOIN wanted w ON w.id = m.id
   WHERE m.server_id = v_server
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT app.member_page_max();
END $$;

COMMENT ON FUNCTION members_by_ids(UUID[]) IS
  'Members by id, for ids the caller already holds. MATERIALIZED so the '
  'planner knows how few they are and joins by key rather than sorting the '
  'whole server to find them.';

CREATE OR REPLACE FUNCTION member_roles_for(p_ids UUID[])
  RETURNS SETOF member_role_list
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_server UUID := app.server_id();
BEGIN
  IF v_server IS NULL THEN RETURN; END IF;
  RETURN QUERY
  WITH wanted AS MATERIALIZED (
    SELECT unnest(COALESCE(p_ids, ARRAY[]::UUID[])) AS id
  ),
  -- The scope `member_roles_select` used to apply. A role belongs to one
  -- server and `member_roles_insert` will not let an assignment cross
  -- servers, so the role's server is the assignment's server.
  scoped AS MATERIALIZED (
    SELECT r.id FROM roles r WHERE r.server_id = v_server
  )
  SELECT l.*
    FROM member_role_list l
    JOIN wanted w ON w.id = l.user_id
    JOIN scoped s ON s.id = l.role_id
   ORDER BY l.user_id, l.position DESC
   LIMIT app.member_page_max() * 8;
END $$;

COMMENT ON FUNCTION member_roles_for(UUID[]) IS
  'Role chips for the members on screen. SECURITY DEFINER, so it carries '
  'its own scope: the roles of the caller''s server and nobody else''s.';

-- ============================================================
-- 3. Counting
-- ============================================================

CREATE OR REPLACE FUNCTION member_counts(p_channel UUID DEFAULT NULL)
  RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
  v_people BIGINT; v_bots BIGINT;
BEGIN
  IF v_server IS NULL OR NOT app.member_scope_allowed(p_channel) THEN
    RETURN jsonb_build_object('people', 0, 'bots', 0);
  END IF;

  SELECT count(*) FILTER (WHERE NOT m.is_bot),
         count(*) FILTER (WHERE m.is_bot)
    INTO v_people, v_bots
    FROM member_directory m
   WHERE m.server_id = v_server
     AND NOT m.is_banned
     -- Only the channel half needs the function; without a channel this is
     -- a constant false and it is never called.
     AND (p_channel IS NULL
          OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL));

  RETURN jsonb_build_object('people', COALESCE(v_people, 0),
                            'bots',   COALESCE(v_bots, 0));
END $$;

COMMENT ON FUNCTION member_counts(UUID) IS
  'How many people and bots are in scope, for the sidebar header.';

-- ============================================================
-- 4. Paging
-- ============================================================
-- Branched rather than `p_after_name IS NULL OR (…)`: a disjunction is never
-- an index condition, so the one query had to become two.

CREATE OR REPLACE FUNCTION list_members(
  p_channel    UUID    DEFAULT NULL,
  p_bots       BOOLEAN DEFAULT NULL,
  p_banned     BOOLEAN DEFAULT FALSE,
  p_after_name TEXT    DEFAULT NULL,
  p_after_id   UUID    DEFAULT NULL,
  p_limit      INTEGER DEFAULT 50)
  RETURNS SETOF member_directory
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_server UUID := app.server_id();
BEGIN
  IF v_server IS NULL OR NOT app.member_scope_allowed(p_channel) THEN
    RETURN;
  END IF;

  IF p_after_name IS NULL THEN
    RETURN QUERY
    SELECT m.* FROM member_directory m
     WHERE m.server_id = v_server
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (p_channel IS NULL
            OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
     ORDER BY app.member_sort_key(m.display_name), m.id
     LIMIT app.member_limit(p_limit);
  ELSE
    RETURN QUERY
    SELECT m.* FROM member_directory m
     WHERE m.server_id = v_server
       AND (app.member_sort_key(m.display_name), m.id)
           > (app.member_sort_key(p_after_name),
              COALESCE(p_after_id, '00000000-0000-0000-0000-000000000000'::UUID))
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (p_channel IS NULL
            OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
     ORDER BY app.member_sort_key(m.display_name), m.id
     LIMIT app.member_limit(p_limit);
  END IF;
END $$;

COMMENT ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER) IS
  'One page of the member sidebar, keyset-paged by (sorted name, id).';

-- ============================================================
-- 5. Searching
-- ============================================================
-- Two phases, because the ranking already said it was two: prefix matches
-- outrank infix ones, so the infix half only runs when the prefix half did
-- not fill the page. Somebody typing the start of a name never reaches it.

CREATE OR REPLACE FUNCTION search_members(
  p_query   TEXT    DEFAULT NULL,
  p_channel UUID    DEFAULT NULL,
  p_bots    BOOLEAN DEFAULT NULL,
  p_banned  BOOLEAN DEFAULT FALSE,
  p_limit   INTEGER DEFAULT 25)
  RETURNS SETOF member_directory
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID    := app.server_id();
  v_q      TEXT    := NULLIF(lower(btrim(COALESCE(p_query, ''))), '');
  v_limit  INTEGER := app.member_limit(p_limit);
  v_found  INTEGER;
  v_seen   UUID[];
BEGIN
  IF v_server IS NULL OR NOT app.member_scope_allowed(p_channel) THEN
    RETURN;
  END IF;

  -- No needle: the first alphabetical page, which is what lets a search
  -- field open on focus without a second round trip.
  IF v_q IS NULL THEN
    RETURN QUERY
    SELECT m.* FROM member_directory m
     WHERE m.server_id = v_server
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (p_channel IS NULL
            OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
     ORDER BY app.member_sort_key(m.display_name), m.id
     LIMIT v_limit;
    RETURN;
  END IF;

  -- Phase one: what the name starts with. Three patterns, an index each,
  -- which the planner combines into one bitmap.
  RETURN QUERY
  SELECT m.* FROM member_directory m
   WHERE m.server_id = v_server
     AND (lower(m.username) LIKE v_q || '%'
          OR lower(m.display_name) LIKE v_q || '%'
          OR replace(lower(m.display_name), ' ', '') LIKE v_q || '%')
     AND (p_bots   IS NULL OR m.is_bot    = p_bots)
     AND (p_banned IS NULL OR m.is_banned = p_banned)
     AND (p_channel IS NULL
          OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT v_limit;
  GET DIAGNOSTICS v_found = ROW_COUNT;

  IF v_found >= v_limit THEN
    RETURN;   -- the page is full of prefix matches, which outrank the rest
  END IF;

  -- Which ones phase one already returned, so phase two does not repeat
  -- them. Capped: it only has to cover what was actually emitted.
  SELECT COALESCE(array_agg(t.id), '{}'::uuid[]) INTO v_seen FROM (
    SELECT m.id FROM member_directory m
     WHERE m.server_id = v_server
       AND (lower(m.username) LIKE v_q || '%'
            OR lower(m.display_name) LIKE v_q || '%'
            OR replace(lower(m.display_name), ' ', '') LIKE v_q || '%')
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (p_channel IS NULL
            OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
     ORDER BY app.member_sort_key(m.display_name), m.id
     LIMIT v_limit) t;

  -- Phase two: what the name merely contains. The trigram expression is a
  -- superset of both patterns under it, so it narrows without deciding.
  RETURN QUERY
  SELECT m.* FROM member_directory m
   WHERE m.server_id = v_server
     AND NOT (m.id = ANY (v_seen))
     AND (replace(lower(m.display_name), ' ', '') || ' ' || lower(m.username))
         LIKE '%' || v_q || '%'
     AND (lower(m.username) LIKE '%' || v_q || '%'
          OR replace(lower(m.display_name), ' ', '') LIKE '%' || v_q || '%')
     AND (p_bots   IS NULL OR m.is_bot    = p_bots)
     AND (p_banned IS NULL OR m.is_banned = p_banned)
     AND (p_channel IS NULL
          OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT v_limit - v_found;
END $$;

COMMENT ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER) IS
  'Members matching a needle, prefix matches first, then infix.';

-- ============================================================
-- 6. Who may call them
-- ============================================================
-- CREATE OR REPLACE keeps the existing grants, but these are SECURITY
-- DEFINER now, so the grants are restated rather than assumed: `anon` must
-- not reach a function that no longer has RLS behind it.

REVOKE ALL ON FUNCTION members_by_ids(UUID[]) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION member_roles_for(UUID[]) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION member_counts(UUID) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER)
  FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER)
  FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION members_by_ids(UUID[]) TO authenticated;
GRANT EXECUTE ON FUNCTION member_roles_for(UUID[]) TO authenticated;
GRANT EXECUTE ON FUNCTION member_counts(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER)
  TO authenticated;
GRANT EXECUTE ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER)
  TO authenticated;
