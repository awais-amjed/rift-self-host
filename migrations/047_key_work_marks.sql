-- ============================================================
-- Rift self-hosted server — 047: the key sweep looks only where something changed
-- ============================================================
-- `channel_key_work` (012, 014) found each channel's key work by comparing
-- everybody entitled to the channel with everybody sealed into its key, in
-- every channel the caller can see, on every call. Every member's app calls it
-- as it opens a server and again on each `sweep` ring. On a server of 50,000
-- members and 300 channels one call took 74 seconds; through the API it hit
-- the 8-second statement timeout and failed every time, so no work was ever
-- handed out, and 40 calls at once held every pooled connection, stalling
-- every other request for those 8 seconds (load test, Nov 25 2026).
--
-- Almost every call finds nothing: keys only need work after something
-- changed. So the changes now leave a mark, and the sweep looks only where
-- one is:
--
--   * `app.key_due_members` — one (channel, person) to look at. Left by a
--     member joining or publishing a chat key, a ban or unban, a seat or a
--     role given or taken, a bot's grant. Checking one is a few index reads.
--   * `app.key_due_channels` — a whole channel to look at. Left by a new
--     channel, a change to who may read one (private, encrypted, opened, a
--     role's access), and by a rotation, whose new version everybody needs.
--     Checking one is the old comparison, once.
--
-- A mark goes when what it points at is settled — judged the same for every
-- caller, so a member who holds no key cannot clear work only somebody else
-- could do. A daily job marks every channel, so a change no trigger saw is
-- still found within a day. And one call stops after a second and a half of
-- looking and answers `more`: a server marked all over is worked through over
-- several calls rather than timing out in one.
--
-- The answers are the same as before for the same state; only where the
-- sweep looks has changed. `channel_eligible_members` is unchanged and still
-- what `voice_roster` and `get_channel_token` ask about one person.
-- ============================================================

-- ── The marks ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS app.key_due_channels (
  channel_id UUID        PRIMARY KEY REFERENCES public.channels(id) ON DELETE CASCADE,
  marked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE app.key_due_channels IS
  'Channels whose whole key state the sweep must compare once: a new channel, '
  'a change to who may read it, a rotation. Cleared when nothing is left to do.';

-- No reference to users: a person's row going takes their keyring rows with
-- it, so a mark left behind settles at the next look.
CREATE TABLE IF NOT EXISTS app.key_due_members (
  channel_id UUID        NOT NULL REFERENCES public.channels(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL,
  marked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, user_id)
);

COMMENT ON TABLE app.key_due_members IS
  'One person in one channel whose keys the sweep must look at: they joined, '
  'published a key, were banned or unbanned, gained or lost a seat, a role or '
  'a bot grant. Cleared when that person''s keys there are settled.';

REVOKE ALL ON TABLE app.key_due_channels FROM PUBLIC, anon, authenticated;
REVOKE ALL ON TABLE app.key_due_members  FROM PUBLIC, anon, authenticated;

-- ── When each version was minted ────────────────────────────

-- A removal waits until the current version is old enough (014), and its age
-- was the oldest of its keyring rows: a second for a channel of 47,000, whose
-- rows lie all over the table. Kept here as each version's first rows land.
CREATE TABLE IF NOT EXISTS app.channel_key_minted (
  channel_id  UUID        NOT NULL REFERENCES public.channels(id) ON DELETE CASCADE,
  key_version INTEGER     NOT NULL,
  minted_at   TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (channel_id, key_version)
);

COMMENT ON TABLE app.channel_key_minted IS
  'When each channel key version''s first keyring rows were written: the age '
  'a removal''s rotation waits on.';

REVOKE ALL ON TABLE app.channel_key_minted FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION app.note_key_minted() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO app.channel_key_minted (channel_id, key_version, minted_at)
  SELECT f.channel_id, f.key_version, min(f.created_at)
    FROM fresh f
   GROUP BY f.channel_id, f.key_version
  ON CONFLICT (channel_id, key_version) DO NOTHING;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS channel_keyring_note_minted ON channel_keyring;
CREATE TRIGGER channel_keyring_note_minted AFTER INSERT ON channel_keyring
  REFERENCING NEW TABLE AS fresh
  FOR EACH STATEMENT EXECUTE FUNCTION app.note_key_minted();

-- The versions already there: one pass over the keyring, reading only.
INSERT INTO app.channel_key_minted (channel_id, key_version, minted_at)
SELECT k.channel_id, k.key_version, min(k.created_at)
  FROM channel_keyring k
 GROUP BY k.channel_id, k.key_version
ON CONFLICT (channel_id, key_version) DO NOTHING;

-- ── Who may hold a channel's key ────────────────────────────

-- `channel_eligible_members` for one channel, written so a public channel is
-- one pass over the members rather than a membership test per member. With
-- [p_full] false, only the people marked in it.
CREATE OR REPLACE FUNCTION app.key_candidates(p_channel UUID, p_full BOOLEAN)
  RETURNS TABLE (user_id UUID, chat_public_key TEXT, from_key_version INTEGER)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF p_full THEN
    RETURN QUERY
      SELECT u.id, u.chat_public_key, 1
        FROM channels c JOIN users u ON u.server_id = c.server_id
       WHERE c.id = p_channel AND NOT c.is_private
         AND NOT u.is_banned AND NOT u.is_bot AND u.chat_public_key IS NOT NULL
      UNION ALL
      SELECT u.id, u.chat_public_key, 1
        FROM users u
       WHERE u.id IN (SELECT cm.user_id FROM channel_members cm
                       WHERE cm.channel_id = p_channel
                      UNION
                      SELECT mr.user_id FROM channel_role_access cra
                        JOIN member_roles mr ON mr.role_id = cra.role_id
                       WHERE cra.channel_id = p_channel)
         AND EXISTS (SELECT 1 FROM channels c
                      WHERE c.id = p_channel AND c.is_private
                        AND c.server_id = u.server_id)
         AND NOT u.is_banned AND NOT u.is_bot AND u.chat_public_key IS NOT NULL
      UNION ALL
      SELECT u.id, u.chat_public_key, g.from_key_version
        FROM bot_channel_keys g JOIN users u ON u.id = g.bot_id
       WHERE g.channel_id = p_channel
         AND u.is_bot AND NOT u.is_banned AND u.chat_public_key IS NOT NULL;
  ELSE
    RETURN QUERY
      SELECT u.id, u.chat_public_key,
             CASE WHEN u.is_bot THEN g.from_key_version ELSE 1 END
        FROM app.key_due_members d
        JOIN channels c ON c.id = d.channel_id
        JOIN users u    ON u.id = d.user_id AND u.server_id = c.server_id
        LEFT JOIN bot_channel_keys g ON g.channel_id = c.id AND g.bot_id = u.id
       WHERE d.channel_id = p_channel
         AND NOT u.is_banned AND u.chat_public_key IS NOT NULL
         AND CASE WHEN u.is_bot THEN g.bot_id IS NOT NULL
                  ELSE (NOT c.is_private OR app.in_channel(c.id, u.id)) END;
  END IF;
END $$;

-- As `app.key_missing` (012), from the candidates above.
CREATE OR REPLACE FUNCTION app.key_missing_from(
  p_channel UUID, p_version INTEGER, p_first UUID, p_limit INTEGER, p_full BOOLEAN
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(
           jsonb_agg(jsonb_build_object('user_id', m.user_id,
                                        'chat_public_key', m.chat_public_key)
                     ORDER BY m.is_first DESC, m.user_id),
           '[]'::jsonb)
    FROM (SELECT e.user_id, e.chat_public_key, e.user_id = p_first AS is_first
            FROM app.key_candidates(p_channel, p_full) e
           WHERE e.from_key_version <= p_version
             AND NOT EXISTS (SELECT 1 FROM channel_keyring k
                              WHERE k.channel_id = p_channel
                                AND k.key_version = p_version
                                AND k.user_id = e.user_id)
           ORDER BY e.user_id = p_first DESC, e.user_id
           LIMIT GREATEST(p_limit, 0)) m
$$;

-- Somebody sealed into [p_version] who may no longer hold it.
--
-- Two plain queries rather than one CASE: inside a CASE the NOT EXISTS stays
-- a subplan run once per keyring row over every candidate, 32 seconds for a
-- channel of 47,000; at the top of a WHERE it is one hash anti-join.
CREATE OR REPLACE FUNCTION app.key_removed(
  p_channel UUID, p_version INTEGER, p_full BOOLEAN
) RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF p_full THEN
    RETURN EXISTS (
      SELECT 1 FROM channel_keyring k
       WHERE k.channel_id = p_channel AND k.key_version = p_version
         AND NOT EXISTS (SELECT 1 FROM app.key_candidates(p_channel, true) e
                          WHERE e.user_id = k.user_id
                            AND e.from_key_version <= p_version));
  END IF;
  RETURN EXISTS (
    SELECT 1 FROM app.key_due_members d
      JOIN channel_keyring k ON k.channel_id = d.channel_id
                            AND k.key_version = p_version
                            AND k.user_id = d.user_id
     WHERE d.channel_id = p_channel
       AND NOT EXISTS (SELECT 1 FROM app.key_candidates(p_channel, false) e
                        WHERE e.user_id = d.user_id
                          AND e.from_key_version <= p_version));
END $$;

-- The old versions somebody is still offered: above the channel's mark,
-- below the current one, the top of each linked stretch (013), and held by
-- somebody who could seal it on.
CREATE OR REPLACE FUNCTION app.key_open_history(
  p_channel UUID, p_current INTEGER, p_mark INTEGER
) RETURNS SETOF INTEGER
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT h
    FROM generate_series(COALESCE(p_mark, 0) + 1, p_current - 1) h
   WHERE NOT EXISTS (SELECT 1 FROM app.channel_key_links l
                      WHERE l.channel_id = p_channel AND l.key_version = h + 1)
     AND EXISTS (SELECT 1 FROM channel_keyring k
                   JOIN users u ON u.id = k.user_id
                  WHERE k.channel_id = p_channel AND k.key_version = h
                    AND NOT u.is_banned AND NOT u.is_bot)
$$;

-- ── The work, found where it is marked ──────────────────────

-- As in 015, with the comparisons above: the whole channel when it is marked
-- whole (or has no key yet), otherwise only the people marked in it. A
-- rotation's new version is always for everybody.
CREATE OR REPLACE FUNCTION app.key_jobs(
  p_channel UUID, p_user UUID, p_mark INTEGER, p_budget INTEGER,
  OUT jobs JSONB, OUT more BOOLEAN, OUT rotate_at TIMESTAMPTZ
)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current  INTEGER;
  v_mine     RECORD;
  v_left     INTEGER := p_budget;
  v_missing  JSONB;
  v_n        INTEGER;
  v_full     BOOLEAN;
  v_removed  BOOLEAN;
  v_ahead    BOOLEAN;
  v_opened   BOOLEAN;
  v_minted   TIMESTAMPTZ;
  v_version  INTEGER;
BEGIN
  jobs := '[]'::jsonb;
  more := false;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  IF v_current = 0 THEN
    v_missing := app.key_missing_from(p_channel, 1, p_user, v_left, true);
    IF jsonb_array_length(v_missing) > 0 THEN
      jobs := jsonb_build_array(jsonb_build_object(
        'channel_id', p_channel, 'key_version', 0, 'rotate', false,
        'my_key', NULL, 'members_missing', v_missing));
      more := jsonb_array_length(v_missing) >= v_left;
    END IF;
    RETURN;
  END IF;

  v_full := EXISTS (SELECT 1 FROM app.key_due_channels f WHERE f.channel_id = p_channel);

  SELECT ephemeral_public_key, ciphertext, nonce INTO v_mine
    FROM channel_keyring
   WHERE channel_id = p_channel AND key_version = v_current AND user_id = p_user;

  IF FOUND THEN
    v_removed := app.key_removed(p_channel, v_current, v_full);
    -- Only a bot's floor is ever above 1, so only grants can be ahead.
    v_ahead := EXISTS (SELECT 1 FROM bot_channel_keys g
                         JOIN users u ON u.id = g.bot_id
                        WHERE g.channel_id = p_channel
                          AND g.from_key_version = v_current + 1
                          AND u.is_bot AND NOT u.is_banned
                          AND u.chat_public_key IS NOT NULL);
    v_opened := p_mark IS NOT NULL AND v_current <= p_mark;

    IF NOT (SELECT c.is_encrypted FROM channels c WHERE c.id = p_channel) THEN
      v_removed := false;
      v_ahead := false;
      v_opened := false;
    END IF;

    IF v_removed AND NOT (v_ahead OR v_opened) THEN
      SELECT m.minted_at INTO v_minted
        FROM app.channel_key_minted m
       WHERE m.channel_id = p_channel AND m.key_version = v_current;
      IF NOT FOUND THEN
        SELECT min(created_at) INTO v_minted
          FROM channel_keyring
         WHERE channel_id = p_channel AND key_version = v_current;
      END IF;
      IF v_minted > now() - app.key_rotation_spacing() THEN
        rotate_at := v_minted + app.key_rotation_spacing();
        v_removed := false;
      END IF;
    END IF;

    IF v_removed OR v_ahead OR v_opened THEN
      v_missing := app.key_missing_from(p_channel, v_current + 1, p_user, v_left, true);
      jobs := jobs || jsonb_build_object(
        'channel_id', p_channel, 'key_version', v_current, 'rotate', true,
        'link', NOT (v_ahead OR v_opened),
        'my_key', jsonb_build_object(
          'ephemeral_public_key', v_mine.ephemeral_public_key,
          'ciphertext', v_mine.ciphertext, 'nonce', v_mine.nonce),
        'members_missing', v_missing);
      more := true;
      RETURN;
    END IF;

    v_missing := app.key_missing_from(p_channel, v_current, p_user, v_left, v_full);
    v_n := jsonb_array_length(v_missing);
    IF v_n > 0 THEN
      jobs := jobs || jsonb_build_object(
        'channel_id', p_channel, 'key_version', v_current, 'rotate', false,
        'my_key', jsonb_build_object(
          'ephemeral_public_key', v_mine.ephemeral_public_key,
          'ciphertext', v_mine.ciphertext, 'nonce', v_mine.nonce),
        'members_missing', v_missing);
      v_left := v_left - v_n;
      IF v_left <= 0 THEN more := true; RETURN; END IF;
    END IF;
  END IF;

  FOR v_version IN
    SELECT * FROM app.key_history_versions(p_channel, p_user, v_current, p_mark)
  LOOP
    v_missing := app.key_missing_from(p_channel, v_version, p_user, v_left, v_full);
    v_n := jsonb_array_length(v_missing);
    CONTINUE WHEN v_n = 0;
    SELECT ephemeral_public_key, ciphertext, nonce INTO v_mine
      FROM channel_keyring
     WHERE channel_id = p_channel AND key_version = v_version AND user_id = p_user;
    jobs := jobs || jsonb_build_object(
      'channel_id', p_channel, 'key_version', v_version, 'rotate', false,
      'my_key', jsonb_build_object(
        'ephemeral_public_key', v_mine.ephemeral_public_key,
        'ciphertext', v_mine.ciphertext, 'nonce', v_mine.nonce),
      'members_missing', v_missing);
    v_left := v_left - v_n;
    IF v_left <= 0 THEN more := true; RETURN; END IF;
  END LOOP;
END $$;

-- ── When a mark may go ──────────────────────────────────────

-- Drops the people marked in [p_channel] whose keys there are settled, for
-- whoever asks: entitled and holding the current version and every old one
-- still offered (or, in an unencrypted channel, a version a grant has not
-- reached yet, which will never be minted for it); or not entitled and not
-- holding the current version, or the channel writes nothing under its key.
CREATE OR REPLACE FUNCTION app.settle_key_members(p_channel UUID)
  RETURNS VOID
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current   INTEGER;
  v_mark      INTEGER;
  v_encrypted BOOLEAN;
BEGIN
  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;
  SELECT c.rotate_from_key_version, c.is_encrypted INTO v_mark, v_encrypted
    FROM channels c WHERE c.id = p_channel;

  WITH e AS MATERIALIZED (
    SELECT * FROM app.key_candidates(p_channel, false)
  ),
  hist AS MATERIALIZED (
    SELECT h FROM app.key_open_history(p_channel, v_current, v_mark) h
  )
  DELETE FROM app.key_due_members d
   WHERE d.channel_id = p_channel
     AND CASE
       WHEN EXISTS (SELECT 1 FROM e WHERE e.user_id = d.user_id) THEN
         (NOT v_encrypted AND EXISTS (SELECT 1 FROM e WHERE e.user_id = d.user_id
                                        AND e.from_key_version > v_current))
         OR (v_current > 0
             AND EXISTS (SELECT 1 FROM channel_keyring k
                          WHERE k.channel_id = p_channel AND k.key_version = v_current
                            AND k.user_id = d.user_id)
             AND NOT EXISTS (
               SELECT 1 FROM hist JOIN e ON e.user_id = d.user_id
                                         AND e.from_key_version <= hist.h
                WHERE NOT EXISTS (SELECT 1 FROM channel_keyring k
                                   WHERE k.channel_id = p_channel
                                     AND k.key_version = hist.h
                                     AND k.user_id = d.user_id)))
       ELSE
         v_current = 0 OR NOT v_encrypted
         OR NOT EXISTS (SELECT 1 FROM channel_keyring k
                         WHERE k.channel_id = p_channel AND k.key_version = v_current
                           AND k.user_id = d.user_id)
     END;
END $$;

-- True when no old version still offered in [p_channel] is missing from
-- anybody entitled to it. Asked only after a holder of the current version
-- found nothing else to do there, which already settles the rest: nothing to
-- rotate for and nobody missing the current version. What that holder could
-- not see is the old versions they do not hold themselves.
CREATE OR REPLACE FUNCTION app.key_history_settled(p_channel UUID)
  RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current INTEGER;
  v_mark    INTEGER;
  v_version INTEGER;
BEGIN
  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;
  SELECT c.rotate_from_key_version INTO v_mark FROM channels c WHERE c.id = p_channel;
  FOR v_version IN SELECT * FROM app.key_open_history(p_channel, v_current, v_mark) LOOP
    IF jsonb_array_length(app.key_missing_from(p_channel, v_version, NULL, 1, true)) > 0 THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
END $$;

-- ── The sweep's entry point ─────────────────────────────────

-- As in 014, over the marked channels only: the ones with people marked
-- first, which are cheap, then the ones marked whole. One call at a time
-- looks at a channel; a call meeting one already being looked at moves on to
-- the next, so a ring answered by every member at once spreads them across
-- the channels instead of queueing them on the first. A channel marked whole
-- is looked at only by somebody holding its current key, the only one who
-- could do its work. Stops after a second and a half and answers `more`,
-- whatever it found.
CREATE OR REPLACE FUNCTION public.channel_key_work(p_user UUID)
  RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_start   TIMESTAMPTZ := clock_timestamp();
  v_left    INTEGER := 500;
  v_work    JSONB   := '[]'::jsonb;
  v_more    BOOLEAN := false;
  v_channel RECORD;
  v_jobs    RECORD;
  v_n       INTEGER;
  v_current INTEGER;
BEGIN
  FOR v_channel IN
    SELECT c.id, c.server_id, c.rotate_from_key_version AS mark,
           EXISTS (SELECT 1 FROM app.key_due_channels f WHERE f.channel_id = c.id) AS whole
      FROM channels c
      JOIN users u ON u.id = p_user AND u.server_id = c.server_id
     WHERE NOT u.is_banned AND NOT u.is_bot
       AND u.chat_public_key IS NOT NULL
       AND (EXISTS (SELECT 1 FROM app.key_due_channels f WHERE f.channel_id = c.id)
            OR EXISTS (SELECT 1 FROM app.key_due_members d WHERE d.channel_id = c.id))
       AND (NOT c.is_private OR app.in_channel(c.id, p_user))
     ORDER BY 4, c.id
  LOOP
    CONTINUE WHEN EXISTS (
      SELECT 1 FROM app.channel_key_leases l
       WHERE l.channel_id = v_channel.id
         AND l.holder <> p_user AND l.expires_at > now());
    IF v_left <= 0 OR clock_timestamp() - v_start > interval '1.5 seconds' THEN
      v_more := true;
      EXIT;
    END IF;

    -- Somebody else's call is looking at this channel right now: skip it
    -- rather than queue behind them. Held to the end of this call.
    CONTINUE WHEN NOT pg_try_advisory_xact_lock(47047, hashtext(v_channel.id::text));

    IF v_channel.whole THEN
      SELECT COALESCE(max(key_version), 0) INTO v_current
        FROM channel_keyring WHERE channel_id = v_channel.id;
      CONTINUE WHEN v_current > 0 AND NOT EXISTS (
        SELECT 1 FROM channel_keyring k
         WHERE k.channel_id = v_channel.id AND k.key_version = v_current
           AND k.user_id = p_user);
    END IF;

    SELECT * INTO v_jobs FROM app.key_jobs(v_channel.id, p_user, v_channel.mark, v_left);

    IF v_jobs.rotate_at IS NOT NULL THEN
      INSERT INTO app.key_rotations_due (channel_id, server_id, due_at)
      VALUES (v_channel.id, v_channel.server_id, v_jobs.rotate_at)
      ON CONFLICT (channel_id) DO UPDATE SET due_at = EXCLUDED.due_at;
    END IF;

    IF jsonb_array_length(v_jobs.jobs) = 0 THEN
      DELETE FROM app.channel_key_leases
       WHERE channel_id = v_channel.id AND holder = p_user;
      IF v_jobs.rotate_at IS NULL THEN
        IF v_channel.whole THEN
          IF app.key_history_settled(v_channel.id) THEN
            DELETE FROM app.key_due_channels WHERE channel_id = v_channel.id;
            DELETE FROM app.key_due_members  WHERE channel_id = v_channel.id;
          END IF;
        ELSE
          PERFORM app.settle_key_members(v_channel.id);
        END IF;
      END IF;
      CONTINUE;
    END IF;
    CONTINUE WHEN NOT app.take_key_lease(v_channel.id, p_user);

    -- A new version, first or rotated, is for everybody: the rest of it is
    -- healed by whole-channel looks until nobody lacks it.
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(v_jobs.jobs) j
                WHERE (j ->> 'rotate')::boolean OR (j ->> 'key_version')::int = 0) THEN
      INSERT INTO app.key_due_channels (channel_id) VALUES (v_channel.id)
      ON CONFLICT (channel_id) DO NOTHING;
    END IF;

    SELECT COALESCE(sum(jsonb_array_length(j -> 'members_missing')), 0)::INTEGER
      INTO v_n FROM jsonb_array_elements(v_jobs.jobs) j;
    v_work := v_work || v_jobs.jobs;
    v_left := v_left - v_n;
    v_more := v_more OR v_jobs.more;
  END LOOP;

  RETURN jsonb_build_object('work', v_work, 'more', v_more);
END $$;

-- ── Opening a channel ───────────────────────────────────────

-- As in 013, from the marks: who lacks the current version is asked of the
-- whole channel only when it is marked whole or has no key yet.
CREATE OR REPLACE FUNCTION public.channel_key_state(p_channel UUID, p_user UUID)
  RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current INTEGER;
  v_mine    JSONB;
  v_links   JSONB;
  v_missing JSONB := '[]'::jsonb;
  v_full    BOOLEAN;
BEGIN
  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'key_version', k.key_version,
           'ephemeral_public_key', k.ephemeral_public_key,
           'ciphertext', k.ciphertext, 'nonce', k.nonce)
           ORDER BY k.key_version), '[]'::jsonb)
    INTO v_mine
    FROM channel_keyring k
   WHERE k.channel_id = p_channel AND k.user_id = p_user;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'key_version', l.key_version,
           'ciphertext', l.ciphertext, 'nonce', l.nonce)
           ORDER BY l.key_version DESC), '[]'::jsonb)
    INTO v_links
    FROM app.channel_key_links l
   WHERE l.channel_id = p_channel;

  v_full := EXISTS (SELECT 1 FROM app.key_due_channels f WHERE f.channel_id = p_channel);

  IF v_current = 0 THEN
    v_missing := app.key_missing_from(p_channel, 1, p_user, 500, true);
  ELSIF EXISTS (SELECT 1 FROM channel_keyring
                 WHERE channel_id = p_channel AND key_version = v_current
                   AND user_id = p_user) THEN
    v_missing := app.key_missing_from(p_channel, v_current, p_user, 500, v_full);
    IF jsonb_array_length(v_missing) > 0
       AND NOT app.take_key_lease(p_channel, p_user) THEN
      v_missing := '[]'::jsonb;
    END IF;
  END IF;

  RETURN jsonb_build_object('current_version', v_current,
                            'my_keys', v_mine,
                            'links', v_links,
                            'members_missing', v_missing);
END $$;

-- ── What leaves a mark ──────────────────────────────────────

CREATE OR REPLACE FUNCTION app.mark_key_channel() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_channel UUID;
BEGIN
  IF TG_TABLE_NAME = 'channels' THEN
    v_channel := NEW.id;
  ELSIF TG_OP = 'DELETE' THEN
    v_channel := OLD.channel_id;
  ELSE
    v_channel := NEW.channel_id;
  END IF;
  -- Not when the channel itself is what went.
  INSERT INTO app.key_due_channels (channel_id)
  SELECT c.id FROM channels c WHERE c.id = v_channel
  ON CONFLICT (channel_id) DO NOTHING;
  RETURN NULL;
END $$;

-- A seat or a bot grant: one person in one channel.
CREATE OR REPLACE FUNCTION app.mark_key_seat() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_channel UUID;
  v_user    UUID;
BEGIN
  -- One field per branch: an expression naming a column the row does not
  -- have fails as it is prepared, whichever branch would have been taken.
  IF TG_OP = 'DELETE' THEN
    v_channel := OLD.channel_id;
    IF TG_TABLE_NAME = 'bot_channel_keys' THEN
      v_user := OLD.bot_id;
    ELSE
      v_user := OLD.user_id;
    END IF;
  ELSE
    v_channel := NEW.channel_id;
    IF TG_TABLE_NAME = 'bot_channel_keys' THEN
      v_user := NEW.bot_id;
    ELSE
      v_user := NEW.user_id;
    END IF;
  END IF;
  INSERT INTO app.key_due_members (channel_id, user_id)
  SELECT c.id, v_user FROM channels c WHERE c.id = v_channel
  ON CONFLICT (channel_id, user_id) DO NOTHING;
  RETURN NULL;
END $$;

-- A role given or taken: that person, in every channel the role opens.
CREATE OR REPLACE FUNCTION app.mark_key_role() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_row member_roles%ROWTYPE;
BEGIN
  IF TG_OP = 'DELETE' THEN v_row := OLD; ELSE v_row := NEW; END IF;
  INSERT INTO app.key_due_members (channel_id, user_id)
  SELECT cra.channel_id, v_row.user_id
    FROM channel_role_access cra
   WHERE cra.role_id = v_row.role_id
  ON CONFLICT (channel_id, user_id) DO NOTHING;
  RETURN NULL;
END $$;

-- A member arriving with a key, publishing one, banned or unbanned: that
-- person, everywhere they may read or hold a key.
CREATE OR REPLACE FUNCTION app.mark_key_person() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO app.key_due_members (channel_id, user_id)
  SELECT c.id, NEW.id
    FROM channels c
   WHERE c.server_id = NEW.server_id
     AND (NOT c.is_private
          OR app.in_channel(c.id, NEW.id)
          OR EXISTS (SELECT 1 FROM bot_channel_keys g
                      WHERE g.channel_id = c.id AND g.bot_id = NEW.id)
          OR EXISTS (SELECT 1 FROM channel_keyring k
                      WHERE k.channel_id = c.id AND k.user_id = NEW.id))
  ON CONFLICT (channel_id, user_id) DO NOTHING;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS channels_key_due_new ON channels;
CREATE TRIGGER channels_key_due_new AFTER INSERT ON channels
  FOR EACH ROW EXECUTE FUNCTION app.mark_key_channel();

DROP TRIGGER IF EXISTS channels_key_due ON channels;
CREATE TRIGGER channels_key_due
  AFTER UPDATE OF is_private, is_encrypted, rotate_from_key_version ON channels
  FOR EACH ROW
  WHEN (OLD.is_private IS DISTINCT FROM NEW.is_private
        OR OLD.is_encrypted IS DISTINCT FROM NEW.is_encrypted
        OR OLD.rotate_from_key_version IS DISTINCT FROM NEW.rotate_from_key_version)
  EXECUTE FUNCTION app.mark_key_channel();

DROP TRIGGER IF EXISTS channel_role_access_key_due ON channel_role_access;
CREATE TRIGGER channel_role_access_key_due AFTER INSERT OR DELETE ON channel_role_access
  FOR EACH ROW EXECUTE FUNCTION app.mark_key_channel();

DROP TRIGGER IF EXISTS channel_members_key_due ON channel_members;
CREATE TRIGGER channel_members_key_due AFTER INSERT OR DELETE ON channel_members
  FOR EACH ROW EXECUTE FUNCTION app.mark_key_seat();

DROP TRIGGER IF EXISTS bot_channel_keys_key_due ON bot_channel_keys;
CREATE TRIGGER bot_channel_keys_key_due AFTER INSERT OR UPDATE OR DELETE ON bot_channel_keys
  FOR EACH ROW EXECUTE FUNCTION app.mark_key_seat();

DROP TRIGGER IF EXISTS member_roles_key_due ON member_roles;
CREATE TRIGGER member_roles_key_due AFTER INSERT OR DELETE ON member_roles
  FOR EACH ROW EXECUTE FUNCTION app.mark_key_role();

DROP TRIGGER IF EXISTS users_key_due_new ON users;
CREATE TRIGGER users_key_due_new AFTER INSERT ON users
  FOR EACH ROW WHEN (NEW.chat_public_key IS NOT NULL)
  EXECUTE FUNCTION app.mark_key_person();

DROP TRIGGER IF EXISTS users_key_due ON users;
CREATE TRIGGER users_key_due AFTER UPDATE OF chat_public_key, is_banned ON users
  FOR EACH ROW
  WHEN (OLD.chat_public_key IS DISTINCT FROM NEW.chat_public_key
        OR OLD.is_banned IS DISTINCT FROM NEW.is_banned)
  EXECUTE FUNCTION app.mark_key_person();

-- ── A daily look everywhere ─────────────────────────────────

-- Whatever no trigger saw is found within a day.
CREATE OR REPLACE FUNCTION app.mark_all_key_channels() RETURNS INTEGER
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  WITH marked AS (
    INSERT INTO app.key_due_channels (channel_id)
    SELECT c.id FROM channels c
    ON CONFLICT (channel_id) DO NOTHING
    RETURNING 1
  )
  SELECT count(*)::INTEGER FROM marked
$$;

SELECT cron.unschedule('rift-key-look')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'rift-key-look');

SELECT cron.schedule('rift-key-look', '17 3 * * *', $$SELECT app.mark_all_key_channels()$$);

-- Nothing was marked before this file, so everything is looked at once.
SELECT app.mark_all_key_channels();

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION app.key_candidates(UUID, BOOLEAN) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_missing_from(UUID, INTEGER, UUID, INTEGER, BOOLEAN)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_removed(UUID, INTEGER, BOOLEAN) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_open_history(UUID, INTEGER, INTEGER)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_jobs(UUID, UUID, INTEGER, INTEGER)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.settle_key_members(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_history_settled(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.mark_key_channel() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.mark_key_seat() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.mark_key_role() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.mark_key_person() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.mark_all_key_channels() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.note_key_minted() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.channel_key_work(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.channel_key_state(UUID, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.channel_key_work(UUID) TO service_role;
GRANT EXECUTE ON FUNCTION public.channel_key_state(UUID, UUID) TO service_role;
