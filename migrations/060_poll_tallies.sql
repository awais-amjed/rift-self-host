-- ============================================================
-- Rift self-hosted server — 060: a poll's votes are counted in one walk
-- ============================================================
-- Found in the query review of Nov 25 2026, measured Nov 26 on a test
-- database with 20 polls of 5,000 voters each, a third of them with two
-- picks.
--
-- `poll_tallies` answers for the polls on a page of messages, and every
-- member's app asks it as the page opens and again on every vote. For each
-- poll it read the votes twice — once to count each option, once more to
-- count the voters — and then the caller's own. It now counts both in one
-- walk of the poll's votes along the primary key, whose order
-- (message, voter, option) is already the one counting distinct voters
-- needs; the caller's own picks are still their own lookup by that key.
-- Same answers: 1.5 → 1.2 ms a poll, 26 → 22 ms for all twenty.
--
-- One walk per poll, on purpose: counted for every poll at once, the
-- planner read all the votes into a sort, which was slower than before.

CREATE OR REPLACE FUNCTION poll_tallies(p_ids BIGINT[]) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_ids  BIGINT[];
  v_rows JSONB;
BEGIN
  -- The same cap as reactions, for the same reason.
  v_ids := (SELECT array_agg(id) FROM (
              SELECT unnest(COALESCE(p_ids, ARRAY[]::BIGINT[])) AS id
               LIMIT 100) capped);
  IF v_ids IS NULL THEN RETURN '{}'::jsonb; END IF;

  -- SECURITY DEFINER because the votes table shows a member only their own
  -- rows, and a count has to see everybody's. Visibility is therefore asked
  -- by hand, per message, with the same question `messages_select` asks.
  WITH polls AS MATERIALIZED (
    SELECT m.id, (m.poll ->> 'options')::INT AS options
      FROM messages m
     WHERE m.id = ANY (v_ids)
       AND m.poll IS NOT NULL
       AND app.can_see_message(m.id)
  )
  SELECT jsonb_object_agg(p.id::TEXT, jsonb_build_object(
           'counts', to_jsonb(t.counts[1:p.options]),
           'voters', t.voters,
           'mine',   COALESCE((SELECT jsonb_agg(v.option ORDER BY v.option)
                                 FROM poll_votes v
                                WHERE v.message_id = p.id
                                  AND v.user_id = auth.uid()), '[]'::jsonb)))
    INTO v_rows
    FROM polls p
    -- One walk of each poll's votes, along the primary key, which is already
    -- the order `count(DISTINCT user_id)` needs. An option is 0 to 9.
    CROSS JOIN LATERAL (
      SELECT count(DISTINCT v.user_id) AS voters,
             ARRAY[count(*) FILTER (WHERE v.option = 0), count(*) FILTER (WHERE v.option = 1),
                   count(*) FILTER (WHERE v.option = 2), count(*) FILTER (WHERE v.option = 3),
                   count(*) FILTER (WHERE v.option = 4), count(*) FILTER (WHERE v.option = 5),
                   count(*) FILTER (WHERE v.option = 6), count(*) FILTER (WHERE v.option = 7),
                   count(*) FILTER (WHERE v.option = 8), count(*) FILTER (WHERE v.option = 9)]
               AS counts
        FROM poll_votes v
       WHERE v.message_id = p.id) t;

  RETURN COALESCE(v_rows, '{}'::jsonb);
END; $$;

COMMENT ON FUNCTION poll_tallies(BIGINT[]) IS
  'Results for the polls among these messages, as {message_id: {counts: '
  '[per option], voters, mine: [the caller''s options]}}. Never who voted '
  'for what.';

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION poll_tallies(BIGINT[]) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION poll_tallies(BIGINT[]) TO authenticated;
