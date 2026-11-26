-- ============================================================
-- Rift self-hosted server — 075: the @ menu gathers its matches before
-- sorting them
-- ============================================================
-- Found in the speed re-review, Nov 26 2026, on a test database of 50,000
-- members.
--
-- `search_members` answers every keystroke of an @ and of the member
-- searches. Its prefix pass asked for the first 25 matches in name order, so
-- the planner walked the whole membership in that order and tested each
-- member, expecting matches to turn up evenly. They do not: what one prefix
-- matches sits together, and the walk read everyone sorted before it. "a"
-- read 31,000 members to find 25, and a prefix nobody has read all 50,000 to
-- find none: 31–34 ms a keystroke.
--
--   * The prefix pass now gathers what the three name indexes match first
--     (ids and the sort key, nothing else), sorts that, and fetches the
--     page's rows after. "a": 32 → 4–7 ms; a prefix nobody has, three empty
--     index probes. The page it returns is the one it returned before, and it
--     no longer runs twice to learn what it returned.
--   * The pass for what a name merely contains now waits for the third
--     letter. Below three, the trigram index under it holds nothing to look
--     up, and the pass read every member to fill the page — 31 ms for a
--     two-letter search with few prefix matches. From the third letter on it
--     runs as before. So "ab" no longer offers Gabriel; "abr" does.

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
  -- combined into one bitmap. Gathered whole before the sort: asked for in
  -- name order instead, the planner walks the members in that order and
  -- tests each one, and a prefix's matches are all in one place.
  WITH hits AS MATERIALIZED (
    SELECT m.id, app.member_sort_key(m.display_name) AS k
      FROM member_directory m
     WHERE m.server_id = v_server
       AND (lower(m.username) LIKE v_q || '%'
            OR lower(m.display_name) LIKE v_q || '%'
            OR replace(lower(m.display_name), ' ', '') LIKE v_q || '%')
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (v_audience IS NULL OR m.id IN (SELECT unnest(v_audience)))
  )
  SELECT COALESCE(array_agg(p.id ORDER BY p.k, p.id), '{}'::uuid[]) INTO v_seen
    FROM (SELECT h.id, h.k FROM hits h ORDER BY h.k, h.id LIMIT v_limit) p;

  RETURN QUERY
  SELECT m.* FROM unnest(v_seen) WITH ORDINALITY AS s(id, n)
    JOIN member_directory m ON m.id = s.id
   ORDER BY s.n;
  v_found := cardinality(v_seen);

  -- The page is full of prefix matches, which outrank the rest. Or the
  -- needle is too short for the trigram index, and what a name contains
  -- would be asked of every member.
  IF v_found >= v_limit OR char_length(v_q) < 3 THEN
    RETURN;
  END IF;

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
  'Members matching a needle, prefix matches first, then (from three '
  'letters) those containing it.';

-- ── Grants ──────────────────────────────────────────────────
-- Unchanged by a replace; restated so this file says who may call it.
REVOKE ALL ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER)
  TO authenticated;
