-- ============================================================
-- Rift self-hosted server — 050: a page of messages carries its reactions
-- as counts, worked out once per message
-- ============================================================
-- Found in the query review of Nov 25 2026, measured the same day on a test
-- database whose announcements channel has 2,600 reactions on each of its
-- latest fifty messages.
--
-- The app read a page of messages with every reaction row embedded
-- (`message_reactions(user_id, emoji)`): one row per person per emoji, each
-- one checked by `message_reactions_select`. That page took 220 ms and came
-- back as 3.3 MB, all of it folded into a handful of counts by the app.
-- `message_reaction_tallies`, which the app asks when a reaction rings, ran
-- the same policy on every row it counted.
--
-- Now a message row has a computed column, `reaction_counts`, which the page
-- selects in place of the embed: `[{emoji, count, mine}]`, ordered by emoji,
-- the shape the tally has always had. It asks whether the caller may see the
-- message once (`app.can_see_message`, `app.can_see_dm` — what the reaction
-- policies mean), and then counts that message's reactions without asking
-- again for each. `message_reaction_tallies` does the same.
--
-- On that page: 220 ms and 3.3 MB → 22 ms and 45 KB. A page with no
-- reactions costs what it did (4.4 → 5.0 ms), and so does a DM page.
--
-- Who sees what is unchanged: a message the caller may not see has no counts
-- (null), as its reaction rows were invisible before.

-- ── One message's counts ────────────────────────────────────
-- The visibility rule is `app.can_see_message` (or `app.can_see_dm`), written
-- out here (`app.server_id`, `app.is_bot` and all) so the check is one query
-- rather than a nest of functions: as first written, calling it, a page with
-- no reactions at all went from 4 ms to 22 ms, nearly all of it the calls.
-- The caller is worked out once, not for each reaction row counted
-- (`auth.uid()` per row cost 1.4 ms a message at 2,600 reactions).
--
-- Granted to members: it answers only about a message the caller may see,
-- which is all the reaction policies let a member read.
CREATE OR REPLACE FUNCTION app.reaction_counts_of(p_scope read_scope, p_message BIGINT)
  RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me     UUID := auth.uid();
  v_counts JSONB;
BEGIN
  IF p_scope = 'channel' THEN
    IF NOT EXISTS (
         SELECT 1 FROM messages x
           JOIN channels c ON c.id = x.channel_id
           JOIN users u ON u.id = v_me AND NOT u.is_banned
                       AND u.server_id = c.server_id
          WHERE x.id = p_message
            AND (NOT c.is_private OR app.in_channel(c.id, v_me))
            AND (NOT u.is_bot OR v_me IN (x.to_bot, x.sender_id))) THEN
      RETURN NULL;
    END IF;
    SELECT jsonb_agg(jsonb_build_object('emoji', r.emoji, 'count', r.n,
                                        'mine', r.mine) ORDER BY r.emoji)
      INTO v_counts
      FROM (SELECT q.emoji, count(*) AS n, bool_or(q.user_id = v_me) AS mine
              FROM message_reactions q
             WHERE q.message_id = p_message
             GROUP BY q.emoji) r;
  ELSE
    IF NOT EXISTS (SELECT 1 FROM dm_messages d
                    WHERE d.id = p_message
                      AND v_me IN (d.sender_id, d.recipient_id)) THEN
      RETURN NULL;
    END IF;
    SELECT jsonb_agg(jsonb_build_object('emoji', r.emoji, 'count', r.n,
                                        'mine', r.mine) ORDER BY r.emoji)
      INTO v_counts
      FROM (SELECT q.emoji, count(*) AS n, bool_or(q.user_id = v_me) AS mine
              FROM dm_message_reactions q
             WHERE q.message_id = p_message
             GROUP BY q.emoji) r;
  END IF;
  RETURN COALESCE(v_counts, '[]'::jsonb);
END $$;

COMMENT ON FUNCTION app.reaction_counts_of(read_scope, BIGINT) IS
  'One message''s reactions as [{emoji, count, mine}], ordered by emoji; '
  'null for a message the caller may not see.';

-- ── The computed column ─────────────────────────────────────
-- PostgREST offers a function of a table's row as a column of that table, so
-- `select=…,reactions:reaction_counts` adds it to each message of a page, an
-- embedded one included. Only the row's id is used: the function can also be
-- called with a row the caller made up. Plain SQL, so the planner puts the
-- call above in its place.
CREATE OR REPLACE FUNCTION reaction_counts(m messages) RETURNS JSONB
  LANGUAGE sql STABLE AS $$
  SELECT app.reaction_counts_of('channel', m.id)
$$;

CREATE OR REPLACE FUNCTION reaction_counts(d dm_messages) RETURNS JSONB
  LANGUAGE sql STABLE AS $$
  SELECT app.reaction_counts_of('dm', d.id)
$$;

COMMENT ON FUNCTION reaction_counts(messages) IS
  'A message''s reactions as [{emoji, count, mine}], ordered by emoji; null '
  'for a message the caller may not see. Selected as a column of the page.';
COMMENT ON FUNCTION reaction_counts(dm_messages) IS
  'A DM''s reactions as [{emoji, count, mine}], ordered by emoji; null for a '
  'message the caller is not party to. Selected as a column of the page.';

-- ── The tally a reaction ring asks ──────────────────────────
-- Same answer as before: {message_id: [{emoji, count, mine}]} for the first
-- hundred ids, leaving out messages with no reactions and messages the caller
-- may not see. Materialized so each message is counted once, not once for
-- the filter and again for the answer.
CREATE OR REPLACE FUNCTION message_reaction_tallies(
  p_scope read_scope,
  p_ids   BIGINT[]
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  WITH ids AS (
    SELECT DISTINCT q.id
      FROM (SELECT unnest(COALESCE(p_ids, ARRAY[]::BIGINT[])) AS id
             LIMIT 100) q
  ), counted AS MATERIALIZED (
    SELECT ids.id, app.reaction_counts_of(p_scope, ids.id) AS counts FROM ids
  )
  SELECT COALESCE(jsonb_object_agg(c.id::TEXT, c.counts), '{}'::jsonb)
    FROM counted c
   WHERE c.counts IS NOT NULL AND c.counts <> '[]'::jsonb
$$;

COMMENT ON FUNCTION message_reaction_tallies(read_scope, BIGINT[]) IS
  'Reaction counts for up to a hundred messages, as {message_id: [{emoji, '
  'count, mine}]}, leaving out messages with none or that the caller may not '
  'see. A scalar rather than a set, so a lively page cannot overflow the '
  '1000-row response cap. Ordered by emoji so two clients draw a message the '
  'same way.';

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.reaction_counts_of(read_scope, BIGINT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION reaction_counts(messages) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION reaction_counts(dm_messages) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION app.reaction_counts_of(read_scope, BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION reaction_counts(messages) TO authenticated;
GRANT EXECUTE ON FUNCTION reaction_counts(dm_messages) TO authenticated;
