-- ============================================================
-- Rift self-hosted server — 057: deleting a server is a mark, and the rows
-- go afterwards
-- ============================================================
-- Found while measuring 056, Nov 26 2026, on a test database of 50,000
-- members, 5,000,000 messages and 12,800,000 keyring rows.
--
-- `delete_server` deleted the server row and let the cascade take the rest,
-- in the owner's own request. That request runs as `authenticated`, which
-- may spend 8 s on a statement, and even with 056's indexes the cascade costs
-- about 12 ms a member: a server past some 600 active members could not be
-- deleted at all, and the owner was told only that it had failed.
--
-- So deleting is now two things.
--
-- `delete_server` marks the server (`servers.deleting_since`) and returns at
-- once. From that moment nobody is a member of it: `app.server_id()`, which
-- every policy and RPC asks, answers nothing for a server being deleted, as
-- it does for a banned member, and the edge functions' sign-in check refuses
-- one too. The ways in from outside go with the mark — its invites, webhooks
-- and listing tokens — and one `channels` event on the server's topic sends
-- every member's app to re-read the server, which now answers "gone", so the
-- app forgets it as it did when the cascade took their row. What a member
-- still reaches until the purge gets to them is less than a banned member
-- does: their own DMs, read marks and settings, and nothing they could say
-- to anybody else.
--
-- `purge_deleted_servers` then deletes the rows, in pieces and for a set
-- time: the messages channel by channel, then the members a few hundred at
-- a time — what each of them still holds goes with them along 056's
-- indexes — then the server row, which takes what is left. Measured on that
-- database: 37,000 messages a second, and 2.2 ms a member once the messages
-- are gone, so that server is some four minutes of work. It runs
-- every minute for up to 25 s (`rift-server-purge`), and the
-- `delete_server` edge function runs it once for 4 s straight after the
-- mark, so a small server is gone before the owner's request returns, as
-- before.
--
-- Nothing a purge deletes is announced: the members have already been told,
-- and each deleted row ringing its topic would be a broadcast per row to
-- nobody. `app.realtime_ready()` answers false while a purge runs, which
-- quiets every announcing trigger at once, and `rift.retention` is on, which
-- quiets the two that check it.

-- ── The mark ────────────────────────────────────────────────

ALTER TABLE servers ADD COLUMN IF NOT EXISTS deleting_since TIMESTAMPTZ;

COMMENT ON COLUMN servers.deleting_since IS
  'Set by delete_server: nobody is a member from then on, and '
  'purge_deleted_servers deletes the rows. NULL for a server in use.';

-- Not a member of a server being deleted. One more lookup, by primary key,
-- in a helper that every policy already calls once a statement.
CREATE OR REPLACE FUNCTION app.server_id() RETURNS UUID
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT u.server_id FROM users u
    JOIN servers s ON s.id = u.server_id
   WHERE u.id = auth.uid() AND NOT u.is_banned AND s.deleting_since IS NULL
$$;

-- A member's own row, which a banned member still reads (it is how the app
-- shows the ban), is hidden too: `get_server_details` then answers nothing,
-- which is how the app knows to forget the server, as it did when the
-- cascade took the row. An initplan, so once a statement.
CREATE OR REPLACE FUNCTION app.my_server_in_use() RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT NOT EXISTS (SELECT 1 FROM users u JOIN servers s ON s.id = u.server_id
                      WHERE u.id = auth.uid() AND s.deleting_since IS NOT NULL)
$$;

DROP POLICY IF EXISTS users_select_self ON users;
CREATE POLICY users_select_self ON users FOR SELECT TO authenticated
  USING (id = (SELECT auth.uid()) AND (SELECT app.my_server_in_use()));

-- Quiet while a purge runs (see the header).
CREATE OR REPLACE FUNCTION app.realtime_ready() RETURNS BOOLEAN
  LANGUAGE sql STABLE AS $$
  SELECT to_regprocedure('realtime.send(jsonb,text,text,boolean)') IS NOT NULL
     AND current_setting('rift.purge', true) IS DISTINCT FROM 'on'
$$;

-- ── Deleting ────────────────────────────────────────────────
-- The gate is unchanged: the owner, of their own server. What the database
-- cannot reach — the LiveKit rooms and the storage buckets — the edge
-- function still clears with the service role after this has said yes.

CREATE OR REPLACE FUNCTION delete_server() RETURNS UUID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
BEGIN
  IF v_server IS NULL OR NOT EXISTS (
       SELECT 1 FROM member_roles mr
         JOIN roles r ON r.id = mr.role_id
        WHERE mr.user_id = auth.uid() AND r.is_owner AND r.server_id = v_server) THEN
    RAISE EXCEPTION 'not_owner';
  END IF;

  UPDATE servers SET deleting_since = now() WHERE id = v_server;

  -- The ways in that are not a member's sign-in.
  DELETE FROM invites        WHERE server_id = v_server;
  DELETE FROM webhooks       WHERE server_id = v_server;
  DELETE FROM listing_tokens WHERE server_id = v_server;

  -- Every member's app re-reads the server on this and finds it gone.
  IF app.realtime_ready() THEN
    PERFORM realtime.send('{}'::jsonb, 'channels', 'server:' || v_server, true);
  END IF;
  RETURN v_server;
END; $$;

-- ── Purging ─────────────────────────────────────────────────
-- Oldest mark first, for at most `p_seconds`, and one run at a time: the
-- minute's job and the edge function's first pass can meet. Returns how many
-- servers are still waiting, or NULL when another run holds the lock. Time
-- is checked between statements, each a fraction of a second.
--
-- Each delete names its rows by id from an array, so it is a walk of the
-- primary key, and each walk starts after the last row it took: rows this
-- transaction deleted are still in the index, and starting from the bottom
-- every time read them all again.

CREATE OR REPLACE FUNCTION purge_deleted_servers(p_seconds REAL DEFAULT 25)
  RETURNS INTEGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_until  TIMESTAMPTZ := clock_timestamp() + make_interval(secs => p_seconds);
  v_server UUID;
  v_owner  UUID;
  v_chan   UUID;
  v_last   BIGINT;
  v_lastu  UUID;
  v_n      INTEGER;
BEGIN
  IF NOT pg_try_advisory_xact_lock(hashtext('rift.purge_deleted_servers')) THEN
    RETURN NULL;
  END IF;
  PERFORM set_config('rift.purge', 'on', true);
  PERFORM set_config('rift.retention', 'on', true);

  <<work>>
  BEGIN
    FOR v_server IN
      SELECT s.id FROM servers s
       WHERE s.deleting_since IS NOT NULL
       ORDER BY s.deleting_since, s.id
    LOOP
      -- ---------- messages, a channel at a time ----------
      FOR v_chan IN
        SELECT c.id FROM channels c WHERE c.server_id = v_server ORDER BY c.id
      LOOP
        v_last := 0;
        LOOP
          IF clock_timestamp() >= v_until THEN
            EXIT work;
          END IF;
          WITH gone AS (
            DELETE FROM messages WHERE id = ANY (ARRAY(
              SELECT m.id FROM messages m
               WHERE m.channel_id = v_chan AND m.id > v_last
               ORDER BY m.id LIMIT 5000))
            RETURNING id)
          SELECT count(*), max(id) INTO v_n, v_last FROM gone;
          EXIT WHEN v_n = 0;
        END LOOP;
      END LOOP;

      -- ---------- the members, all but the owner ----------
      -- The owner's row may not go while the server stands
      -- (`refuse_owner_leaving`); the server row takes it.
      SELECT mr.user_id INTO v_owner
        FROM member_roles mr JOIN roles r ON r.id = mr.role_id
       WHERE r.server_id = v_server AND r.is_owner
       LIMIT 1;
      -- The nil uuid is below every id there is, and no member's.
      v_lastu := '00000000-0000-0000-0000-000000000000';
      LOOP
        IF clock_timestamp() >= v_until THEN
          EXIT work;
        END IF;
        WITH gone AS (
          DELETE FROM users WHERE id = ANY (ARRAY(
            SELECT u.id FROM users u
             WHERE u.server_id = v_server
               AND u.id > v_lastu
               AND u.id IS DISTINCT FROM v_owner
             ORDER BY u.id LIMIT 200))
          RETURNING id)
        -- No max() for a uuid.
        SELECT count(*), (array_agg(id ORDER BY id DESC))[1] INTO v_n, v_lastu
          FROM gone;
        EXIT WHEN v_n = 0;
      END LOOP;

      -- ---------- the rest ----------
      IF clock_timestamp() >= v_until THEN
        EXIT work;
      END IF;
      DELETE FROM servers WHERE id = v_server;
      -- The edge function emptied and dropped the bucket; files of the
      -- messages deleted above have nothing left to sweep.
      DELETE FROM attachment_trash WHERE bucket = 'chat-' || v_server::TEXT;
    END LOOP;
  END work;

  -- Said for the transaction; the rest of it, if the caller has more to do
  -- in it, announces as usual.
  PERFORM set_config('rift.purge', '', true);
  PERFORM set_config('rift.retention', '', true);
  RETURN (SELECT count(*) FROM servers WHERE deleting_since IS NOT NULL);
END; $$;

COMMENT ON FUNCTION purge_deleted_servers(REAL) IS
  'Deletes the rows of servers delete_server marked, for at most p_seconds. '
  'Returns how many are still waiting; NULL if another run is going.';

-- Every minute, and quiet when there is nothing to do: one read of `servers`.
SELECT cron.unschedule('rift-server-purge')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'rift-server-purge');
SELECT cron.schedule(
  'rift-server-purge',
  '* * * * *',
  $$SELECT purge_deleted_servers(25)$$
);

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.my_server_in_use() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION app.my_server_in_use() TO authenticated;
REVOKE ALL ON FUNCTION purge_deleted_servers(REAL) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION purge_deleted_servers(REAL) TO service_role;
