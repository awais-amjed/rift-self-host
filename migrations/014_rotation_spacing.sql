-- ============================================================
-- Rift self-hosted server — 014: one key change an hour for removals
-- ============================================================
-- Every ban changed every channel's key at once, and a key change is one
-- sealed entry per member: in a channel of 50,000 that bans somebody several
-- times a day, that is a minute of one member's machine each time, and 50,000
-- keyring rows each time.
--
-- A removal (a ban or kick, somebody taken out of a private channel, a bot's
-- grant revoked) now changes the key only once the current one is an hour old.
-- Several in that hour share one change. The server stops serving the person
-- removed the moment it happens, whatever the key; what the change protects
-- against is a server operator still passing them ciphertext, and an hour of
-- that is the price of not paying for every ban separately.
--
-- Additions are not held back: a grant to a bot, and a private channel opening
-- up. Both are somebody waiting to be let in, and holding the change back only
-- makes them wait longer; neither is anybody being kept out.
--
-- A member's sweep that finds a removal waiting records when it falls due, and
-- a job each minute rings the server's sweep doorbell then, so an online
-- member makes the change on time rather than whenever somebody next opens
-- the app. With nobody online there is nobody to ring, and the first sweep
-- after somebody comes back does it.
-- ============================================================

-- How long the current key must have been in use before a removal changes it.
CREATE OR REPLACE FUNCTION app.key_rotation_spacing() RETURNS INTERVAL
  LANGUAGE sql IMMUTABLE AS $$ SELECT interval '1 hour' $$;

-- Removals waiting on the spacing, and when each falls due.
CREATE TABLE IF NOT EXISTS app.key_rotations_due (
  channel_id UUID        PRIMARY KEY REFERENCES public.channels(id) ON DELETE CASCADE,
  server_id  UUID        NOT NULL REFERENCES public.servers(id) ON DELETE CASCADE,
  due_at     TIMESTAMPTZ NOT NULL
);

COMMENT ON TABLE app.key_rotations_due IS
  'A channel whose key a removal will change at due_at, held back by '
  'app.key_rotation_spacing(). Written by public.channel_key_work, rung and '
  'deleted by app.ring_due_rotations each minute.';

-- ── The sweep, holding removals back ────────────────────────

-- As in 012, plus `rotate_at`: when a removal's change is held back, the time
-- it falls due. The OUT list grows, which CREATE OR REPLACE cannot do.
DROP FUNCTION IF EXISTS app.key_jobs(UUID, UUID, INTEGER, INTEGER);

CREATE FUNCTION app.key_jobs(
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
    v_missing := app.key_missing(p_channel, 1, p_user, v_left);
    IF jsonb_array_length(v_missing) > 0 THEN
      jobs := jsonb_build_array(jsonb_build_object(
        'channel_id', p_channel, 'key_version', 0, 'rotate', false,
        'my_key', NULL, 'members_missing', v_missing));
      more := jsonb_array_length(v_missing) >= v_left;
    END IF;
    RETURN;
  END IF;

  SELECT ephemeral_public_key, ciphertext, nonce INTO v_mine
    FROM channel_keyring
   WHERE channel_id = p_channel AND key_version = v_current AND user_id = p_user;

  IF FOUND THEN
    v_removed := EXISTS (
      SELECT 1 FROM channel_keyring k
       WHERE k.channel_id = p_channel AND k.key_version = v_current
         AND NOT EXISTS (SELECT 1 FROM channel_eligible_members e
                          WHERE e.channel_id = p_channel
                            AND e.user_id = k.user_id
                            AND e.from_key_version <= v_current));
    v_ahead := EXISTS (SELECT 1 FROM channel_eligible_members e
                        WHERE e.channel_id = p_channel
                          AND e.from_key_version = v_current + 1);
    v_opened := p_mark IS NOT NULL AND v_current <= p_mark;

    -- A removal alone waits until the current key is old enough; with an
    -- addition beside it, the change the addition needs carries it too.
    IF v_removed AND NOT (v_ahead OR v_opened) THEN
      SELECT min(created_at) INTO v_minted
        FROM channel_keyring
       WHERE channel_id = p_channel AND key_version = v_current;
      IF v_minted > now() - app.key_rotation_spacing() THEN
        rotate_at := v_minted + app.key_rotation_spacing();
        v_removed := false;
      END IF;
    END IF;

    IF v_removed OR v_ahead OR v_opened THEN
      v_missing := app.key_missing(p_channel, v_current + 1, p_user, v_left);
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

    v_missing := app.key_missing(p_channel, v_current, p_user, v_left);
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
    v_missing := app.key_missing(p_channel, v_version, p_user, v_left);
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

-- As in 012, plus recording a removal held back, so it is rung when due.
CREATE OR REPLACE FUNCTION public.channel_key_work(p_user UUID)
  RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_left    INTEGER := 500;
  v_work    JSONB   := '[]'::jsonb;
  v_more    BOOLEAN := false;
  v_channel RECORD;
  v_jobs    RECORD;
  v_n       INTEGER;
BEGIN
  FOR v_channel IN
    SELECT c.id, c.server_id, c.rotate_from_key_version AS mark
      FROM channels c
      JOIN users u ON u.id = p_user AND u.server_id = c.server_id
     WHERE NOT u.is_banned AND NOT u.is_bot
       AND u.chat_public_key IS NOT NULL
       AND (NOT c.is_private OR app.in_channel(c.id, p_user))
     ORDER BY c.id
  LOOP
    CONTINUE WHEN EXISTS (
      SELECT 1 FROM app.channel_key_leases l
       WHERE l.channel_id = v_channel.id
         AND l.holder <> p_user AND l.expires_at > now());
    IF v_left <= 0 THEN
      v_more := true;
      EXIT;
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
      CONTINUE;
    END IF;
    CONTINUE WHEN NOT app.take_key_lease(v_channel.id, p_user);

    SELECT COALESCE(sum(jsonb_array_length(j -> 'members_missing')), 0)::INTEGER
      INTO v_n FROM jsonb_array_elements(v_jobs.jobs) j;
    v_work := v_work || v_jobs.jobs;
    v_left := v_left - v_n;
    v_more := v_more OR v_jobs.more;
  END LOOP;

  RETURN jsonb_build_object('work', v_work, 'more', v_more);
END $$;

-- ── Ringing when one falls due ──────────────────────────────

-- Ring the sweep doorbell of every server with a removal now due, once per
-- server, and forget them: the sweep that answers makes the change, or finds
-- it is still waiting and records it again. Answers how many servers were rung.
CREATE OR REPLACE FUNCTION app.ring_due_rotations() RETURNS INTEGER
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
  v_n      INTEGER := 0;
BEGIN
  FOR v_server IN
    WITH due AS (
      DELETE FROM app.key_rotations_due WHERE due_at <= now() RETURNING server_id
    )
    SELECT DISTINCT server_id FROM due
  LOOP
    IF app.realtime_ready() THEN
      PERFORM realtime.send('{}'::jsonb, 'sweep', 'server:' || v_server, true);
    END IF;
    v_n := v_n + 1;
  END LOOP;
  RETURN v_n;
END $$;

SELECT cron.unschedule('rift-key-rotations-due')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'rift-key-rotations-due');

SELECT cron.schedule(
  'rift-key-rotations-due',
  '* * * * *',
  $$SELECT app.ring_due_rotations()$$
);

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON TABLE app.key_rotations_due FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_rotation_spacing() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_jobs(UUID, UUID, INTEGER, INTEGER)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.channel_key_work(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.ring_due_rotations() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.channel_key_work(UUID) TO service_role;
