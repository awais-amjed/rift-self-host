-- ============================================================
-- Rift self-hosted server — 052: the @ menu asks a private channel who is in
-- it once
-- ============================================================
-- Found in the query review of Nov 25 2026, measured Nov 26 on a test
-- database of 50,000 members, in a private channel of 201.
--
-- `search_members` is what the composer's @ menu asks as you type. In a
-- private channel it asked `app.member_in_scope` of each member it walked
-- past, and that asks `app.in_channel`: two lookups for every member of the
-- server, in name order, until it had found 25 who were in the channel. With
-- 201 of 50,000 in it, that is most of the server: 521 ms to open the menu
-- with nothing typed, 904 ms for "a".
--
-- Now it gathers the channel's audience once (`app.channel_audience`), as
-- `list_members` has since it was written, and keeps the members in it:
-- 521 → 2 ms with nothing typed, 904 → 35 ms for "a", which is what "a" costs
-- in a public channel too, since matching the name is all that is left.
--
-- A private channel opened to a large role pays for gathering it: in one
-- opened to a role of 38,000, 4 → 14 ms with nothing typed and 37 → 48 ms for
-- "a", about 10 ms of it the list.
--
-- The answer is unchanged: the same members in the same order, compared over
-- 1,512 calls (every private channel shape on the test database, a public
-- channel and none; bots and banned filters; three callers).

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
  v_audience UUID[];
BEGIN
  IF v_server IS NULL OR NOT app.member_scope_allowed(p_channel) THEN
    RETURN;
  END IF;
  -- Who the channel is open to, gathered once rather than asked of each
  -- member walked past; NULL for a public channel or none.
  v_audience := app.channel_audience(p_channel);

  -- No needle: the first alphabetical page, which is what lets a search
  -- field open on focus without a second round trip.
  IF v_q IS NULL THEN
    RETURN QUERY
    SELECT m.* FROM member_directory m
     WHERE m.server_id = v_server
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (v_audience IS NULL OR m.id IN (SELECT unnest(v_audience)))
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
     AND (v_audience IS NULL OR m.id IN (SELECT unnest(v_audience)))
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
       AND (v_audience IS NULL OR m.id IN (SELECT unnest(v_audience)))
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
     AND (v_audience IS NULL OR m.id IN (SELECT unnest(v_audience)))
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT v_limit - v_found;
END $$;


COMMENT ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER) IS
  'Members matching a needle, prefix matches first, then infix.';

REVOKE ALL ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER)
  TO authenticated;
