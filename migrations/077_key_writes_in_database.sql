-- ============================================================
-- Rift self-hosted server — 077: sealed keys are stored by a database call
-- ============================================================
-- Found in the re-review of what should move to the database, Nov 26 2026.
--
-- Every sealed channel key reached the keyring through `post_channel_keys`,
-- an edge function that asks the database seven to nine times and nothing
-- else: no secret, no outside call. A key sweep posted each channel's job on
-- its own, so a newcomer on a server with fifty channels they can see cost
-- fifty function invocations and some four hundred round trips, in series,
-- and their last channel opened when the fiftieth landed.
--
--   * `store_channel_keys` is `post_channel_keys`: the same checks in the same
--     order, the same refusals by the same codes, the same answer. They are
--     now one transaction, where the version read, the hold check and the
--     insert were separate requests and only the keyring's key caught a race.
--     Two mints of a channel now take turns, and the second is told the
--     version was minted already, as it would have been told had it come
--     second; before, it learnt that only if the two batches overlapped.
--   * `store_key_work` stores a whole sweep pass: each job as
--     `store_channel_keys` would, each in its own savepoint, so a race lost on
--     one channel costs the others nothing. One answer for each job, in the
--     order sent.
--
-- The edge function stays, for apps that have not moved; neither bot SDK
-- posts keys.

-- ── One channel's batch ─────────────────────────────────────
CREATE OR REPLACE FUNCTION public.store_channel_keys(
  p_channel UUID,
  p_version INTEGER,
  p_entries JSONB,
  p_mint    BOOLEAN DEFAULT NULL,
  p_link    JSONB   DEFAULT NULL)
  RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me       UUID := auth.uid();
  v_server   UUID := app.key_caller_server();
  v_entry    JSONB;
  v_current  INTEGER;
  v_minting  BOOLEAN;
  v_hold     INTEGER;
  v_ids      UUID[];
  v_link     BOOLEAN := false;
BEGIN
  IF p_channel IS NULL THEN
    RAISE EXCEPTION 'missing_fields';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM channels c
                  WHERE c.id = p_channel AND c.server_id = v_server) THEN
    RAISE EXCEPTION 'channel_not_found';
  END IF;
  -- Not found rather than forbidden, like every refusal about a room the
  -- caller cannot see, and before the version arithmetic, whose refusals
  -- name a private channel's current version (043).
  IF NOT app.sees_channel(p_channel, v_me) THEN
    RAISE EXCEPTION 'channel_not_found';
  END IF;

  IF p_version IS NULL OR p_version < 1 THEN
    RAISE EXCEPTION 'envelope_invalid';
  END IF;
  IF p_entries IS NULL OR jsonb_typeof(p_entries) <> 'array'
     OR jsonb_array_length(p_entries) = 0
     OR jsonb_array_length(p_entries) > 500 THEN
    RAISE EXCEPTION 'missing_fields';
  END IF;
  FOR v_entry IN SELECT e FROM jsonb_array_elements(p_entries) e LOOP
    IF jsonb_typeof(v_entry) <> 'object'
       OR jsonb_typeof(v_entry -> 'user_id') IS DISTINCT FROM 'string'
       OR (v_entry ->> 'user_id')
          !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       OR jsonb_typeof(v_entry -> 'ciphertext') IS DISTINCT FROM 'string'
       OR char_length(v_entry ->> 'ciphertext') NOT BETWEEN 1 AND 16384
       OR jsonb_typeof(v_entry -> 'nonce') IS DISTINCT FROM 'string'
       OR char_length(v_entry ->> 'nonce') NOT BETWEEN 1 AND 64
       OR jsonb_typeof(v_entry -> 'ephemeral_public_key') IS DISTINCT FROM 'string'
       OR char_length(v_entry ->> 'ephemeral_public_key') NOT BETWEEN 1 AND 64 THEN
      RAISE EXCEPTION 'envelope_invalid';
    END IF;
  END LOOP;

  -- A mint waits for any other mint of this channel to settle, so it reads
  -- the version that one left. Released when the caller's transaction ends.
  IF p_mint IS NOT FALSE THEN
    PERFORM pg_advisory_xact_lock(77077, hashtext(p_channel::text));
  END IF;

  SELECT COALESCE(max(k.key_version), 0) INTO v_current
    FROM channel_keyring k WHERE k.channel_id = p_channel;
  IF p_version > v_current + 1 THEN
    RAISE EXCEPTION 'keyring_conflict';
  END IF;
  -- Minting is the race: exactly the next version. Healing fills gaps in a
  -- version that exists. Neither said is an app older than 012, which keeps
  -- the all-or-nothing insert.
  IF p_mint IS TRUE AND p_version <> v_current + 1 THEN
    RAISE EXCEPTION 'keyring_conflict';
  END IF;
  IF p_mint IS FALSE AND p_version > v_current THEN
    RAISE EXCEPTION 'keyring_conflict';
  END IF;

  -- Sealing a key is only honest from somebody who has it: a heal re-seals
  -- the caller's own version, a mint is made by a holder of the one before.
  v_minting := p_mint IS TRUE OR (p_mint IS NULL AND p_version = v_current + 1);
  v_hold := CASE WHEN v_minting THEN p_version - 1 ELSE p_version END;
  IF v_hold >= 1 AND NOT EXISTS (
       SELECT 1 FROM channel_keyring k
        WHERE k.channel_id = p_channel AND k.key_version = v_hold
          AND k.user_id = v_me) THEN
    RAISE EXCEPTION 'permission_denied';
  END IF;

  -- Everyone sealed for is on this server.
  SELECT array_agg(DISTINCT (e ->> 'user_id')::uuid) INTO v_ids
    FROM jsonb_array_elements(p_entries) e;
  IF (SELECT count(*) FROM users u
       WHERE u.id = ANY (v_ids) AND u.server_id = v_server)
     <> cardinality(v_ids) THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;

  -- A bot only under its grant, from the version the grant names. The
  -- keyring's own check says the same, but by a reason of its own; this
  -- refuses as the edge function did, before anything is written.
  IF EXISTS (
    SELECT 1 FROM users u
      LEFT JOIN bot_channel_keys g
        ON g.channel_id = p_channel AND g.bot_id = u.id
     WHERE u.id = ANY (v_ids) AND u.is_bot
       AND (g.bot_id IS NULL OR p_version < g.from_key_version)) THEN
    RAISE EXCEPTION 'permission_denied';
  END IF;

  -- In member order, so two batches healing the same people take their
  -- places in the key in the same order and never wait on each other in a
  -- circle.
  BEGIN
    IF p_mint IS FALSE THEN
      INSERT INTO channel_keyring
             (channel_id, key_version, user_id, wrapped_by,
              ephemeral_public_key, ciphertext, nonce)
      SELECT p_channel, p_version, (e ->> 'user_id')::uuid, v_me,
             e ->> 'ephemeral_public_key', e ->> 'ciphertext', e ->> 'nonce'
        FROM jsonb_array_elements(p_entries) e
       ORDER BY (e ->> 'user_id')::uuid
      ON CONFLICT (channel_id, key_version, user_id) DO NOTHING;
    ELSE
      INSERT INTO channel_keyring
             (channel_id, key_version, user_id, wrapped_by,
              ephemeral_public_key, ciphertext, nonce)
      SELECT p_channel, p_version, (e ->> 'user_id')::uuid, v_me,
             e ->> 'ephemeral_public_key', e ->> 'ciphertext', e ->> 'nonce'
        FROM jsonb_array_elements(p_entries) e
       ORDER BY (e ->> 'user_id')::uuid;
    END IF;
  EXCEPTION WHEN unique_violation THEN
    -- Somebody else's entries are there already: refetch and re-wrap.
    RAISE EXCEPTION 'keyring_conflict';
  END;

  -- The version before, sealed under the one just won (013). Best-effort,
  -- as it was: a rotation without its link still works.
  IF p_mint IS TRUE AND p_version >= 2
     AND jsonb_typeof(p_link -> 'ciphertext') = 'string'
     AND jsonb_typeof(p_link -> 'nonce') = 'string' THEN
    BEGIN
      v_link := COALESCE(public.store_channel_key_link(
        p_channel, p_version, v_me,
        p_link ->> 'ciphertext', p_link ->> 'nonce'), false);
    EXCEPTION WHEN OTHERS THEN
      v_link := false;
    END;
  END IF;

  RETURN jsonb_build_object(
    'channel_id', p_channel,
    'key_version', p_version,
    'entries_stored', jsonb_array_length(p_entries),
    'link_stored', v_link);
END $$;

COMMENT ON FUNCTION public.store_channel_keys(UUID, INTEGER, JSONB, BOOLEAN, JSONB) IS
  'Stores keys the caller sealed for one channel: a new version when '
  'p_mint, otherwise the gaps in one they hold. As post_channel_keys, '
  'with its checks and refusals, in one transaction.';

-- ── A sweep pass ────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.store_key_work(p_jobs JSONB)
  RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_job     RECORD;
  v_answers JSONB[] := '{}';
  v_answer  JSONB;
  v_code    TEXT;
  v_total   BIGINT;
BEGIN
  -- Who is asking is refused once for the whole pass, so a sign-in the
  -- server no longer takes comes back as itself.
  PERFORM app.key_caller_server();

  IF p_jobs IS NULL OR jsonb_typeof(p_jobs) <> 'array'
     OR jsonb_array_length(p_jobs) = 0 THEN
    RAISE EXCEPTION 'missing_fields';
  END IF;
  -- A pass is what `my_key_work` hands out: 500 entries at most.
  SELECT sum(CASE WHEN jsonb_typeof(j -> 'entries') = 'array'
                  THEN jsonb_array_length(j -> 'entries') ELSE 0 END)
    INTO v_total
    FROM jsonb_array_elements(p_jobs) j;
  IF jsonb_array_length(p_jobs) > 500 OR v_total > 500 THEN
    RAISE EXCEPTION 'missing_fields';
  END IF;
  v_answers := array_fill(NULL::jsonb, ARRAY[jsonb_array_length(p_jobs)]);

  -- In channel order, so two passes minting the same channels take their
  -- turns in the same order. Answered in the order sent.
  FOR v_job IN
    SELECT j.n, j.v,
           CASE WHEN jsonb_typeof(j.v -> 'channel_id') = 'string'
                 AND (j.v ->> 'channel_id')
                     ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                THEN (j.v ->> 'channel_id')::uuid END AS channel,
           CASE WHEN jsonb_typeof(j.v -> 'key_version') = 'number'
                 AND (j.v ->> 'key_version') ~ '^[0-9]{1,9}$'
                THEN (j.v ->> 'key_version')::integer END AS version
      FROM jsonb_array_elements(p_jobs) WITH ORDINALITY AS j(v, n)
     ORDER BY 3 NULLS LAST, 1
  LOOP
    BEGIN
      IF jsonb_typeof(v_job.v) <> 'object' THEN
        RAISE EXCEPTION 'missing_fields';
      END IF;
      v_answer := public.store_channel_keys(
        v_job.channel, v_job.version, v_job.v -> 'entries',
        CASE jsonb_typeof(v_job.v -> 'mint')
          WHEN 'boolean' THEN (v_job.v ->> 'mint')::boolean END,
        v_job.v -> 'link')
        || jsonb_build_object('success', true);
    EXCEPTION WHEN OTHERS THEN
      -- The migrations raise bare codes; anything else is the database's.
      v_code := CASE WHEN SQLSTATE = 'P0001'
                      AND SQLERRM ~ '^[a-z][a-z0-9_]{2,40}$'
                     THEN SQLERRM ELSE 'db_error' END;
      v_answer := jsonb_build_object(
        'channel_id', v_job.channel,
        'key_version', v_job.version,
        'success', false,
        'code', v_code);
    END;
    v_answers[v_job.n] := v_answer;
  END LOOP;

  RETURN jsonb_build_object('results', to_jsonb(v_answers));
END $$;

COMMENT ON FUNCTION public.store_key_work(JSONB) IS
  'Stores a sweep pass: each job {channel_id, key_version, entries, mint, '
  'link} as store_channel_keys would, each on its own. One answer a job, in '
  'the order sent.';

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION public.store_channel_keys(UUID, INTEGER, JSONB, BOOLEAN, JSONB)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.store_key_work(JSONB) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.store_channel_keys(UUID, INTEGER, JSONB, BOOLEAN, JSONB)
  TO authenticated;
GRANT EXECUTE ON FUNCTION public.store_key_work(JSONB) TO authenticated;
