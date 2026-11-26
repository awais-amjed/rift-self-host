-- ============================================================
-- Rift self-hosted server — 076: a server's member count is kept, not
-- counted
-- ============================================================
-- Found in the speed re-review, Nov 26 2026, on a test database of 50,000
-- members.
--
-- `member_counts` counts the members who are not banned, people and bots
-- apart. Every app with the server listed asks it on every `members` ring,
-- through `members_refresh`, and on every open of the member sidebar,
-- through `member_sidebar`: an index-only scan of 48,000 entries (055),
-- 1.7–2.0 ms of a refresh's 3.9, though the number only moves when somebody
-- joins, leaves, is kicked, banned or let back, or a bot is added or taken
-- out.
--
-- `server_member_counts` now holds the two numbers for each server, kept by
-- triggers on `users` in the transaction that moves them, and
-- `member_counts` reads them wherever it would have counted the whole
-- server: no channel, or a public one. A private channel's count still
-- counts its audience, as before.
--
-- A join already waits for the one before it on the server's row
-- (`register_user` takes it for the member cap), so updating the server's
-- count in the same transaction holds nobody up who was not already held.
-- A ban, a leave or a bot added waits at most for a join to commit.
--
-- A join, a ban or a bot's removal is one row, so those triggers run once a
-- row and only when what is counted moves. Inserts and deletes of many rows
-- at once — a server deleted, a test seeding — are counted once a
-- statement.

-- ── The counts ──────────────────────────────────────────────
CREATE TABLE server_member_counts (
  server_id UUID   PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
  people    BIGINT NOT NULL DEFAULT 0,
  bots      BIGINT NOT NULL DEFAULT 0
);

COMMENT ON TABLE server_member_counts IS
  'Members not banned, people and bots apart, kept by the users_tally_* '
  'triggers; read by member_counts. Nobody reads or writes it directly.';

ALTER TABLE server_member_counts ENABLE ROW LEVEL SECURITY;

-- ── Keeping them ────────────────────────────────────────────
-- Members arriving. Ordered by server, so two statements arriving on the
-- same servers take their rows in the same order.
CREATE FUNCTION app.tally_members_in()
  RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO server_member_counts AS t (server_id, people, bots)
  SELECT n.server_id,
         count(*) FILTER (WHERE NOT n.is_bot),
         count(*) FILTER (WHERE n.is_bot)
    FROM fresh n
   WHERE NOT n.is_banned
   GROUP BY n.server_id
   ORDER BY n.server_id
  ON CONFLICT (server_id) DO UPDATE
     SET people = t.people + EXCLUDED.people,
         bots   = t.bots   + EXCLUDED.bots;
  RETURN NULL;
END $$;

-- Members gone. Only an update: with the server itself going, its count
-- goes with it (or already has).
CREATE FUNCTION app.tally_members_out()
  RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  UPDATE server_member_counts t
     SET people = t.people - g.people,
         bots   = t.bots   - g.bots
    FROM (SELECT o.server_id,
                 count(*) FILTER (WHERE NOT o.is_bot) AS people,
                 count(*) FILTER (WHERE o.is_bot)     AS bots
            FROM gone o
           WHERE NOT o.is_banned
           GROUP BY o.server_id) g
   WHERE t.server_id = g.server_id;
  RETURN NULL;
END $$;

-- A member whose counting moved: banned, let back, or (never, today) a bot
-- flag or server changed. Out of the old place, into the new.
CREATE FUNCTION app.tally_member_moved()
  RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT OLD.is_banned THEN
    UPDATE server_member_counts t
       SET people = t.people - (NOT OLD.is_bot)::int,
           bots   = t.bots   - OLD.is_bot::int
     WHERE t.server_id = OLD.server_id;
  END IF;
  IF NOT NEW.is_banned THEN
    INSERT INTO server_member_counts AS t (server_id, people, bots)
    VALUES (NEW.server_id, (NOT NEW.is_bot)::int, NEW.is_bot::int)
    ON CONFLICT (server_id) DO UPDATE
       SET people = t.people + EXCLUDED.people,
           bots   = t.bots   + EXCLUDED.bots;
  END IF;
  RETURN NULL;
END $$;

CREATE FUNCTION app.tally_members_cleared()
  RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  DELETE FROM server_member_counts;
  RETURN NULL;
END $$;

CREATE TRIGGER users_tally_in
  AFTER INSERT ON users
  REFERENCING NEW TABLE AS fresh
  FOR EACH STATEMENT EXECUTE FUNCTION app.tally_members_in();

CREATE TRIGGER users_tally_out
  AFTER DELETE ON users
  REFERENCING OLD TABLE AS gone
  FOR EACH STATEMENT EXECUTE FUNCTION app.tally_members_out();

CREATE TRIGGER users_tally_moved
  AFTER UPDATE OF is_banned, is_bot, server_id ON users
  FOR EACH ROW
  WHEN (OLD.is_banned IS DISTINCT FROM NEW.is_banned
        OR OLD.is_bot IS DISTINCT FROM NEW.is_bot
        OR OLD.server_id IS DISTINCT FROM NEW.server_id)
  EXECUTE FUNCTION app.tally_member_moved();

CREATE TRIGGER users_tally_cleared
  AFTER TRUNCATE ON users
  FOR EACH STATEMENT EXECUTE FUNCTION app.tally_members_cleared();

-- ── What is there now ───────────────────────────────────────
-- After the triggers, in the same transaction: a join that commits while
-- this runs waits for it, and is counted by one or the other, not both.
INSERT INTO server_member_counts (server_id, people, bots)
SELECT u.server_id,
       count(*) FILTER (WHERE NOT u.is_bot),
       count(*) FILTER (WHERE u.is_bot)
  FROM users u
 WHERE NOT u.is_banned
 GROUP BY u.server_id;

-- ── Reading them ────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.member_counts(p_channel UUID DEFAULT NULL)
  RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
  -- Once, not per member. Asked per row this was two EXISTS queries a head
  -- and 3.6 seconds to count a private channel's people on a 50,000-member
  -- server; as an array it is a hash lookup. NULL is "no restriction".
  v_audience UUID[] := app.channel_audience(p_channel);
  v_people BIGINT; v_bots BIGINT;
BEGIN
  IF v_server IS NULL OR NOT app.member_scope_allowed(p_channel) THEN
    RETURN jsonb_build_object('people', 0, 'bots', 0);
  END IF;

  -- The whole server: kept, not counted.
  IF v_audience IS NULL THEN
    SELECT c.people, c.bots INTO v_people, v_bots
      FROM server_member_counts c WHERE c.server_id = v_server;
    RETURN jsonb_build_object('people', COALESCE(v_people, 0),
                              'bots',   COALESCE(v_bots, 0));
  END IF;

  SELECT count(*) FILTER (WHERE NOT m.is_bot),
         count(*) FILTER (WHERE m.is_bot)
    INTO v_people, v_bots
    FROM member_directory m
   WHERE m.server_id = v_server
     AND NOT m.is_banned
     -- `IN (SELECT unnest(…))`, not `= ANY (…)`. Postgres hashes an array
     -- it can see as a constant, but this one arrives as a parameter, so the
     -- ANY form is a linear walk of two thousand ids for every one of fifty
     -- thousand members — 211 ms, worse than the per-row function it
     -- replaced. As a subquery the array is unnested once into a hash and the
     -- per-row test is a lookup: 2 ms.
     AND m.id IN (SELECT unnest(v_audience));

  RETURN jsonb_build_object('people', COALESCE(v_people, 0),
                            'bots',   COALESCE(v_bots, 0));
END $$;

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON TABLE server_member_counts FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.tally_members_in()      FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.tally_members_out()     FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.tally_member_moved()    FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.tally_members_cleared() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.member_counts(UUID)  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.member_counts(UUID) TO authenticated;
