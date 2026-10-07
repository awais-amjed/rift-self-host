-- ============================================================
-- Rift self-hosted server — 012: key work found by the database
-- ============================================================
-- Who is missing which channel key used to be worked out in TypeScript, by
-- `sweep_channel_keys` and `get_channel_key`, from whole tables read through
-- PostgREST. That had three faults, each of which only shows on a server of
-- some size:
--
--   * PostgREST answers at most `PGRST_DB_MAX_ROWS` (1000) rows and drops the
--     rest without saying so. A server past a thousand keyring rows — eighty
--     members and thirteen key versions — was swept from part of its keyring:
--     members went unhealed, the current version could read low, and a
--     member's own key could be among the rows dropped, so their channel
--     showed every message locked while the server held their key.
--   * Every online member was handed the same work and did it, so all but one
--     sealed hundreds of entries only to lose the race for them.
--   * A rotation sealed the new key to every member in one `post_channel_keys`
--     call, which takes at most 500 entries. A channel of more than 500 could
--     not rotate at all, so a ban there never moved the key.
--
-- So the work is found here, where it costs index lookups rather than table
-- reads, and comes back as one JSON value, which no row limit applies to. It
-- comes in batches of at most 500 entries: a rotation mints the next version
-- with the first batch, the caller first so it can heal the rest. And a
-- channel's work goes to one member at a time: the first to be given some
-- holds a lease on that channel for a minute, renewed each time they ask
-- again, and everyone else is told there is nothing to do there.
--
-- Old versions are still offered to members who lack them, newest first and
-- never at or below `rotate_from_key_version`, exactly as the TypeScript did.
-- ============================================================

-- ── Who is working on a channel's keys ──────────────────────

CREATE TABLE IF NOT EXISTS app.channel_key_leases (
  channel_id UUID        PRIMARY KEY REFERENCES public.channels(id) ON DELETE CASCADE,
  holder     UUID        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);

COMMENT ON TABLE app.channel_key_leases IS
  'The member currently doing a channel''s key work, until expires_at. Taken '
  'when public.channel_key_work hands them some, renewed each time they ask '
  'again, dropped when they ask and there is none left. Expiry is what hands '
  'the work on when the holder goes quiet partway.';

-- ── Who lacks a version ─────────────────────────────────────

-- The members entitled to [p_version] of a channel's key who hold no entry for
-- it, as `{user_id, chat_public_key}` rows ready to seal to. [p_first] comes
-- first when they are on the list: whoever mints a version has to be in its
-- first batch, or they cannot heal the rest.
CREATE OR REPLACE FUNCTION app.key_missing(
  p_channel UUID, p_version INTEGER, p_first UUID, p_limit INTEGER
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(
           jsonb_agg(jsonb_build_object('user_id', m.user_id,
                                        'chat_public_key', m.chat_public_key)
                     ORDER BY m.is_first DESC, m.user_id),
           '[]'::jsonb)
    FROM (SELECT e.user_id, e.chat_public_key, e.user_id = p_first AS is_first
            FROM channel_eligible_members e
           WHERE e.channel_id = p_channel
             AND e.from_key_version <= p_version
             AND NOT EXISTS (SELECT 1 FROM channel_keyring k
                              WHERE k.channel_id = p_channel
                                AND k.key_version = p_version
                                AND k.user_id = e.user_id)
           ORDER BY e.user_id = p_first DESC, e.user_id
           LIMIT GREATEST(p_limit, 0)) m
$$;

-- The older versions a member could seal to others: ones they hold, below the
-- current one and above the channel's private stretch. Newest first, because
-- recent history is what gets read. Its own function so that a later file can
-- narrow it without restating the sweep.
CREATE OR REPLACE FUNCTION app.key_history_versions(
  p_channel UUID, p_user UUID, p_current INTEGER, p_mark INTEGER
) RETURNS SETOF INTEGER
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT k.key_version
    FROM channel_keyring k
   WHERE k.channel_id = p_channel
     AND k.user_id = p_user
     AND k.key_version < p_current
     AND k.key_version > COALESCE(p_mark, 0)
   ORDER BY k.key_version DESC
$$;

-- ── One channel's work for one member ───────────────────────

-- Every job [p_user] can do in [p_channel], at most [p_budget] entries in all,
-- and whether some was held back for lack of budget. Reads only: whether they
-- get to keep it is the lease's call, made by the caller.
CREATE OR REPLACE FUNCTION app.key_jobs(
  p_channel UUID, p_user UUID, p_mark INTEGER, p_budget INTEGER,
  OUT jobs JSONB, OUT more BOOLEAN
)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current  INTEGER;
  v_mine     RECORD;
  v_left     INTEGER := p_budget;
  v_missing  JSONB;
  v_n        INTEGER;
  v_rotate   BOOLEAN;
  v_ahead    BOOLEAN;
  v_opened   BOOLEAN;
  v_version  INTEGER;
BEGIN
  jobs := '[]'::jsonb;
  more := false;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  IF v_current = 0 THEN
    -- No key yet: the caller can mint the first one, with themselves in it.
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
    -- The three reasons to rotate, as `sweep_channel_keys` gave them: somebody
    -- holds the current version who is no longer entitled to it; somebody's
    -- entitlement starts at the next one (a grant just made); or the channel
    -- opened up and has not moved past its private stretch yet.
    v_rotate := EXISTS (
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

    IF v_rotate OR v_ahead OR v_opened THEN
      -- The next version, sealed to the first batch of everyone entitled to
      -- it; the minter heals the rest from the next pass on. `my_key` is the
      -- current version, which the minter needs only to link the two.
      v_missing := app.key_missing(p_channel, v_current + 1, p_user, v_left);
      jobs := jobs || jsonb_build_object(
        'channel_id', p_channel, 'key_version', v_current, 'rotate', true,
        'link', NOT (v_ahead OR v_opened),
        'my_key', jsonb_build_object(
          'ephemeral_public_key', v_mine.ephemeral_public_key,
          'ciphertext', v_mine.ciphertext, 'nonce', v_mine.nonce),
        'members_missing', v_missing);
      -- Nothing older is offered until the rotation lands: what it seals is
      -- what the rest of this channel's work is measured against.
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

  -- Scrollback: older versions the caller holds and somebody entitled lacks.
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

-- ── The lease ───────────────────────────────────────────────

-- Take [p_channel]'s lease for [p_user], or renew theirs. False when somebody
-- else holds one that has not run out — they are doing this work already.
CREATE OR REPLACE FUNCTION app.take_key_lease(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_taken BOOLEAN;
BEGIN
  INSERT INTO app.channel_key_leases AS l (channel_id, holder, expires_at)
  VALUES (p_channel, p_user, now() + interval '60 seconds')
  ON CONFLICT (channel_id) DO UPDATE
     SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at
   WHERE l.holder = EXCLUDED.holder OR l.expires_at <= now()
  RETURNING true INTO v_taken;
  RETURN COALESCE(v_taken, false);
END $$;

-- ── What a member is asked to do ────────────────────────────

-- The sweep: every job [p_user] may do across their server's channels, at most
-- 500 entries, as `{work, more}`. A channel somebody else holds the lease on is
-- left out, and so is one the budget ran out before. `more` says to ask again.
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
    SELECT c.id, c.rotate_from_key_version AS mark
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
    IF jsonb_array_length(v_jobs.jobs) = 0 THEN
      -- Done here. A lease of ours goes, so the next person to have work in
      -- this channel is not kept waiting for it to run out.
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

-- Opening one channel: the caller's own sealed keys, the current version, and
-- who lacks it — at most 500, and only to a caller who holds the current key
-- and can take the lease, since only they can heal anybody. A channel with no
-- key yet lists everybody entitled to the first, caller first, with no lease:
-- that race is the keyring's unique constraint's to settle.
CREATE OR REPLACE FUNCTION public.channel_key_state(p_channel UUID, p_user UUID)
  RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current INTEGER;
  v_mine    JSONB;
  v_missing JSONB := '[]'::jsonb;
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

  IF v_current = 0 THEN
    v_missing := app.key_missing(p_channel, 1, p_user, 500);
  ELSIF EXISTS (SELECT 1 FROM channel_keyring
                 WHERE channel_id = p_channel AND key_version = v_current
                   AND user_id = p_user) THEN
    v_missing := app.key_missing(p_channel, v_current, p_user, 500);
    IF jsonb_array_length(v_missing) > 0
       AND NOT app.take_key_lease(p_channel, p_user) THEN
      v_missing := '[]'::jsonb;
    END IF;
  END IF;

  RETURN jsonb_build_object('current_version', v_current,
                            'my_keys', v_mine,
                            'members_missing', v_missing);
END $$;

COMMENT ON FUNCTION public.channel_key_work(UUID) IS
  'Service-role only (sweep_channel_keys). Every key job a member may do on '
  'their server, at most 500 entries, as {work, more}; each channel''s work '
  'goes to one member at a time (app.channel_key_leases).';
COMMENT ON FUNCTION public.channel_key_state(UUID, UUID) IS
  'Service-role only (get_channel_key). A member''s sealed keys for one '
  'channel, its current version, and who lacks it (at most 500, and only to '
  'somebody who can heal them).';

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON TABLE app.channel_key_leases FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_missing(UUID, INTEGER, UUID, INTEGER)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_history_versions(UUID, UUID, INTEGER, INTEGER)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_jobs(UUID, UUID, INTEGER, INTEGER)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.take_key_lease(UUID, UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.channel_key_work(UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.channel_key_state(UUID, UUID)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.channel_key_work(UUID) TO service_role;
GRANT EXECUTE ON FUNCTION public.channel_key_state(UUID, UUID) TO service_role;
