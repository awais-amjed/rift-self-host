-- ============================================================
-- Rift self-hosted server — 024: the doorbell stops asking everybody
-- ============================================================
-- 020 moved the "is push even on?" check to the top of
-- `ring_channel_members`, which made a message free on a server with push
-- turned off. This is the other half: what it costs on a server where push
-- **is** on, which is every server anybody actually runs.
--
-- Measured on a copy of this schema carrying 50,000 members, 50 channels and
-- 5,000,000 messages — a large community server, not a toy:
--
--   insert with the doorbell disabled ......      1.0 ms
--   insert with push on, 50,000 members ..... 15,326 ms
--
-- Fifteen seconds. The roster walk asks two questions per member, and the
-- expensive one is `has_unread_before`, which is a query of its own:
--
--   the whole walk ......................... 15,133 ms
--     of which has_unread_before ........... 14,584 ms
--     of which app.channel_eligible .........   286 ms
--     the plain roster, no per-member call ..     3.9 ms
--
-- So the shape is wrong rather than the indexes: 50,000 function calls, each
-- one a correlated lookup, to answer a question about one new row.
--
-- ---------- what the question actually needs ----------
--
-- `has_unread_before(u, ch, X)` asks whether there is a message in `ch`
-- between u's read cursor and X that u did not send. Written out, the newest
-- such message is the only one that matters — if it is past the cursor there
-- is unread mail, and if it is not there is none.
--
-- And that newest message is always one of **two rows**, whoever u is:
--
--   m1  the newest message before X
--   m2  the newest message before X sent by somebody other than m1's sender
--
-- If u did not send m1, the newest message u did not send is m1. If u did
-- send m1, then everything between m2 and m1 is u's too — that is what makes
-- m2 the newest from anybody else — so it is m2. There is no third case.
--
-- Two scalars, read once per message, therefore answer for every member at
-- once. Checked against the old function over 3,000 members on the fixture:
-- 3,000 rows compared, zero disagreements.
--
-- ---------- and it inverts the scan ----------
--
-- The old walk started from the roster and asked each member whether they
-- were caught up. Almost nobody is: of 3,000 members on the fixture, 2,999
-- had unread mail and were skipped, and the whole walk existed to find the
-- one who did not.
--
-- Driving from `read_state` instead asks only about the people who could
-- possibly qualify — a member is caught up only if their cursor is at or past
-- one of those two ids — and `idx_read_state_caught_up` makes that a range
-- scan. A member with no `read_state` row at all has read nothing, so has
-- unread mail, so is not rung: exactly what the old code concluded, and now
-- without visiting them.
--
--   insert with push on, 50,000 members ..... 15,326 ms  →  4.9 ms
--
-- The one member who can be caught up without a `read_state` row is the
-- sender of every prior message in the channel, whose threshold is zero
-- because there is nothing there they did not write. That is the `m2 IS NULL`
-- branch below, and it is the case the old code got right by accident.

-- ============================================================
-- 1. The cursor index
-- ============================================================
-- `read_state_pkey` is (user_id, scope, scope_id): the right index for "what
-- has this member read", which is what every other caller wants. This is the
-- other direction — "who has read this channel up to here" — and there was no
-- index for it because until now nothing asked.

CREATE INDEX IF NOT EXISTS idx_read_state_caught_up
  ON read_state (scope, scope_id, last_read_id);

COMMENT ON INDEX idx_read_state_caught_up IS
  'Who is caught up in one scope, for the push doorbell. The primary key '
  'answers the opposite question and cannot serve this one.';

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
BEGIN
  SELECT m.id, m.sender_id INTO o_newest, o_newest_by
    FROM messages m
   WHERE m.channel_id = p_channel AND m.id < p_before
     AND NOT m.is_interaction
   ORDER BY m.id DESC LIMIT 1;

  IF o_newest IS NULL THEN
    RETURN;   -- nothing came before: nobody can have unread mail here
  END IF;

  SELECT m.id INTO o_newest_other
    FROM messages m
   WHERE m.channel_id = p_channel AND m.id < p_before
     AND NOT m.is_interaction
     AND m.sender_id IS DISTINCT FROM o_newest_by
   ORDER BY m.id DESC LIMIT 1;
END $$;

COMMENT ON FUNCTION app.unread_thresholds(UUID, BIGINT) IS
  'The two message ids that decide, for every member at once, whether they '
  'had unread mail in this channel before a given message: the newest one, '
  'and the newest one from somebody other than its sender.';

REVOKE ALL ON FUNCTION app.unread_thresholds(UUID, BIGINT)
  FROM PUBLIC, anon, authenticated;

-- ============================================================
-- 3. The doorbell
-- ============================================================

CREATE OR REPLACE FUNCTION ring_channel_members()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
  v_t         RECORD;
  v_targets   UUID[];
BEGIN
  IF NEW.is_interaction THEN RETURN NEW; END IF;

  SELECT server_id INTO v_server_id FROM channels WHERE id = NEW.channel_id;
  IF v_server_id IS NULL THEN RETURN NEW; END IF;
  IF NOT app.push_enabled(v_server_id) THEN RETURN NEW; END IF;

  v_t := app.unread_thresholds(NEW.channel_id, NEW.id);

  IF v_t.o_newest IS NULL THEN
    -- The first message in the channel. Nobody can have unread mail before
    -- it, so everybody eligible is rung — once, ever, per channel.
    SELECT array_agg(u.id) INTO v_targets
      FROM users u
     WHERE u.server_id = v_server_id
       AND u.id IS DISTINCT FROM NEW.sender_id
       AND NOT u.is_banned AND NOT u.is_bot
       AND (NEW.ephemeral_for IS NULL OR u.id = NEW.ephemeral_for)
       AND app.channel_eligible(NEW.channel_id, u.id);
  ELSE
    SELECT array_agg(c.user_id) INTO v_targets FROM (
      -- Everyone whose cursor is at or past the newest message they did not
      -- write. The first bound is the cheap one and drives the index; the
      -- second is the exact one and is checked on what it returns.
      SELECT r.user_id
        FROM read_state r
       WHERE r.scope = 'channel'
         AND r.scope_id = NEW.channel_id
         AND r.last_read_id >= COALESCE(v_t.o_newest_other, 0)
         AND r.last_read_id >= CASE
               WHEN v_t.o_newest_by IS DISTINCT FROM r.user_id THEN v_t.o_newest
               ELSE COALESCE(v_t.o_newest_other, 0) END
      UNION
      -- The one member who can be caught up with no `read_state` row at all:
      -- when nobody else has ever written here, everything before this
      -- message is theirs, so there is nothing of anybody else's to have
      -- missed. `o_newest_other IS NULL` is exactly that case.
      SELECT v_t.o_newest_by
       WHERE v_t.o_newest_other IS NULL AND v_t.o_newest_by IS NOT NULL
    ) c
    JOIN users u ON u.id = c.user_id
   WHERE u.server_id = v_server_id
     AND u.id IS DISTINCT FROM NEW.sender_id
     AND NOT u.is_banned AND NOT u.is_bot
     AND (NEW.ephemeral_for IS NULL OR u.id = NEW.ephemeral_for)
     AND app.channel_eligible(NEW.channel_id, u.id);
  END IF;

  PERFORM ring_devices(v_server_id, v_targets);
  RETURN NEW;
END $$;

COMMENT ON FUNCTION ring_channel_members() IS
  'Wake the phones of members who were caught up in this channel. Driven by '
  'read_state rather than the roster: being caught up is the rare case, and '
  'the roster is the expensive one to walk.';
