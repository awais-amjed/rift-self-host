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
