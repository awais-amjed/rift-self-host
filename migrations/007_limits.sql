-- ============================================================
-- Rift self-hosted server — 007: operator limits
-- ============================================================
-- Central imposes three limits because it pays for central: a daily send
-- quota, a 30-day TTL, and a per-conversation history cap. A self-hosted
-- server imposed none, on the reasoning that it is somebody's own disk and
-- therefore their own call.
--
-- That reasoning was right about *whose* call it is and wrong about there being
-- nothing to decide. An operator running a server for a few friends still may
-- not want one member filling the disk with 200 MB videos, and had no way to
-- say so. So the limits exist here too — but every one of them is a column the
-- admin sets, and **every one defaults to off**. A server that is upgraded and
-- never touched behaves exactly as it did before this file.
--
-- The convention throughout: 0 means "no limit". It is the default, it is what
-- an operator who never opens the settings dialog gets, and it is why none of
-- the enforcement below costs anything on a server that hasn't opted in — the
-- triggers return on their first branch and the cron job's WHERE clauses match
-- no rows.

-- ============================================================
-- 1. The settings themselves
-- ============================================================
-- On `servers` rather than a settings table: there is exactly one row per
-- server, members already select it for the name and icon, and the client
-- needs to *read* the attachment cap to reject an oversized file before
-- uploading it. `servers_select` already scopes reads to your own server and
-- there is no client-reachable UPDATE grant, so admins change these through
-- the `update_server` edge function like the name and the LiveKit URL.

ALTER TABLE servers
  ADD COLUMN IF NOT EXISTS max_attachment_bytes        BIGINT  NOT NULL DEFAULT 26214400,
  ADD COLUMN IF NOT EXISTS default_channel_daily_quota INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS dm_daily_quota              INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS message_retention_days      INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS message_history_cap         INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN servers.max_attachment_bytes IS
  'Per-file attachment cap. Mirrored onto the chat-attachments bucket''s '
  'file_size_limit by update_server — that mirror is the enforcement, this '
  'column is what the client reads to refuse a file before uploading it.';
COMMENT ON COLUMN servers.default_channel_daily_quota IS
  'Messages per member per rolling 24h in a channel that sets no quota of its '
  'own. 0 = unlimited.';
COMMENT ON COLUMN servers.dm_daily_quota IS
  'Messages per member per rolling 24h across all of their server DMs, the '
  'same shape as central''s daily_dm_quota(). 0 = unlimited.';
COMMENT ON COLUMN servers.message_retention_days IS
  'Delete messages older than this many days. 0 = keep forever.';
COMMENT ON COLUMN servers.message_history_cap IS
  'Keep at most this many messages per channel and per DM pair, newest first. '
  '0 = no cap.';

-- The upper bound is not arbitrary: Supabase Storage caps an object at 500 MB
-- on the free plan and the mirror below would silently fail past it.
ALTER TABLE servers DROP CONSTRAINT IF EXISTS servers_limits_sane;
ALTER TABLE servers ADD CONSTRAINT servers_limits_sane CHECK (
  max_attachment_bytes BETWEEN 1 AND 524288000
  AND default_channel_daily_quota >= 0
  AND dm_daily_quota              >= 0
  AND message_retention_days      >= 0
  AND message_history_cap         >= 0
);

-- Per-channel override. NULL is not "unlimited" — it is "inherit", which is
-- why this column is nullable when every other limit here is NOT NULL with a
-- 0 default. An announcements channel can be tightened to 5/day while the rest
-- of the server keeps the default, and a channel can opt out of a server-wide
-- quota entirely by setting 0.
ALTER TABLE channels ADD COLUMN IF NOT EXISTS daily_quota INTEGER;

COMMENT ON COLUMN channels.daily_quota IS
  'Per-member messages per rolling 24h in this channel. NULL inherits '
  'servers.default_channel_daily_quota; 0 explicitly means unlimited.';

ALTER TABLE channels DROP CONSTRAINT IF EXISTS channels_daily_quota_sane;
ALTER TABLE channels ADD CONSTRAINT channels_daily_quota_sane
  CHECK (daily_quota IS NULL OR daily_quota >= 0);

-- Additive to the UPDATE (name) grant in 002. Who may write it is still
-- decided by `channels_update_managers` — this only widens which columns a
-- channel manager's UPDATE is allowed to name.
GRANT UPDATE (daily_quota) ON channels TO authenticated;

-- ============================================================
-- 2. Resolving a quota
-- ============================================================
-- In `app` with the other policy helpers, for the same two reasons: PostgREST
-- cannot expose that schema as RPCs, and SECURITY DEFINER means resolving a
-- quota never depends on the caller being able to read `servers` or `channels`
-- through RLS.

CREATE OR REPLACE FUNCTION app.channel_daily_quota(p_channel UUID) RETURNS INTEGER
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(c.daily_quota, s.default_channel_daily_quota)
    FROM channels c JOIN servers s ON s.id = c.server_id
   WHERE c.id = p_channel
$$;

CREATE OR REPLACE FUNCTION app.dm_daily_quota(p_user UUID) RETURNS INTEGER
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT s.dm_daily_quota
    FROM users u JOIN servers s ON s.id = u.server_id
   WHERE u.id = p_user
$$;

-- ============================================================
-- 3. Enforcement
-- ============================================================
-- A trigger rather than a send RPC, which is the one interesting choice in
-- this file.
--
-- Central enforces its quota inside `send_dm()` because a daily counter is not
-- a row predicate — the check is over *other* rows and has to happen in the
-- same statement as the insert, or two clients race past the limit. All of
-- that is equally true here, but self-hosted messages are a direct PostgREST
-- insert under `messages_insert`, and wrapping them in an RPC would mean a new
-- transport for every surface, a second write path to keep in step with the
-- first, and re-teaching the client something it already knows how to do.
--
-- A BEFORE INSERT trigger buys the same guarantee without any of that: it runs
-- inside the inserting statement, so the count it takes is as atomic as the
-- one in central's RPC, and it is invisible to the client until it fires.
--
-- Two details it depends on:
--   * It must fire *after* `attest_message()`, which is what stamps
--     `sender_id` from auth.uid() — before that the row's sender is whatever
--     the client claimed. Postgres runs same-timing triggers in name order, so
--     `attest_*` sorting before `enforce_*` is load-bearing, not incidental.
--   * Service-role writes (registration, maintenance, seeding) have no
--     auth.uid() and are skipped, exactly as attestation skips them.

CREATE OR REPLACE FUNCTION enforce_message_quota() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_quota INTEGER;
  v_sent  INTEGER;
BEGIN
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;

  IF TG_TABLE_NAME = 'messages' THEN
    v_quota := app.channel_daily_quota(NEW.channel_id);
  ELSE
    v_quota := app.dm_daily_quota(NEW.sender_id);
  END IF;

  -- The opt-out fast path: nothing configured, nothing counted.
  IF COALESCE(v_quota, 0) <= 0 THEN
    RETURN NEW;
  END IF;

  IF TG_TABLE_NAME = 'messages' THEN
    SELECT count(*) INTO v_sent FROM messages
     WHERE channel_id = NEW.channel_id
       AND sender_id  = NEW.sender_id
       AND created_at > now() - interval '24 hours';
  ELSE
    SELECT count(*) INTO v_sent FROM dm_messages
     WHERE sender_id  = NEW.sender_id
       AND created_at > now() - interval '24 hours';
  END IF;

  IF v_sent >= v_quota THEN
    RAISE EXCEPTION 'quota_exceeded';
  END IF;

  RETURN NEW;
END; $$;

-- INSERT only. An edit is not a new message and must not cost quota — the same
-- rule central states by having `editDm` bypass `send_dm()`.
DROP TRIGGER IF EXISTS enforce_messages_quota ON messages;
CREATE TRIGGER enforce_messages_quota BEFORE INSERT ON messages
  FOR EACH ROW EXECUTE FUNCTION enforce_message_quota();

DROP TRIGGER IF EXISTS enforce_dm_messages_quota ON dm_messages;
CREATE TRIGGER enforce_dm_messages_quota BEFORE INSERT ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION enforce_message_quota();

-- ============================================================
-- 4. The meter
-- ============================================================
-- What the composer footer reads. Passing NULL asks about DMs, a channel id
-- asks about that channel — one function so the client asks both surfaces the
-- same question, the way central's `dm_quota()` answers for its one surface.
--
-- `remaining` is NULL when unlimited rather than 0. A quota of 0 meaning "no
-- limit" and a remaining of 0 meaning "you are out" are one keystroke apart in
-- a UI, and returning the same number for both is how that gets confused.

CREATE OR REPLACE FUNCTION chat_quota(p_channel_id UUID DEFAULT NULL) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_quota INTEGER;
  v_sent  INTEGER;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  IF p_channel_id IS NULL THEN
    v_quota := app.dm_daily_quota(auth.uid());
    SELECT count(*) INTO v_sent FROM dm_messages
     WHERE sender_id = auth.uid() AND created_at > now() - interval '24 hours';
  ELSE
    -- Asking about someone else's server would otherwise leak that server's
    -- quota setting to any authenticated caller.
    IF app.channel_server_id(p_channel_id) IS DISTINCT FROM app.server_id() THEN
      RAISE EXCEPTION 'not_a_member';
    END IF;
    v_quota := app.channel_daily_quota(p_channel_id);
    SELECT count(*) INTO v_sent FROM messages
     WHERE channel_id = p_channel_id
       AND sender_id  = auth.uid()
       AND created_at > now() - interval '24 hours';
  END IF;

  v_quota := COALESCE(v_quota, 0);
  RETURN jsonb_build_object(
    'quota',     v_quota,
    'remaining', CASE WHEN v_quota <= 0 THEN NULL
                      ELSE greatest(v_quota - v_sent, 0) END
  );
END; $$;

REVOKE ALL ON FUNCTION chat_quota(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION chat_quota(UUID) TO authenticated;

-- ============================================================
-- 5. Retention
-- ============================================================
-- 006 says messages are never swept, because a self-hosted server is somebody
-- else's hardware and their own retention policy. That still holds — this is
-- how they express it. Both knobs default to 0, so the job below runs nightly
-- and deletes nothing until an operator asks for it.
--
-- In `app`, not `public`: this returns VOID, which means PostgREST would have
-- happily exposed it as an RPC any member could call to wipe the server's
-- history. pg_cron runs as the database owner and reaches it regardless.
--
-- Known consequence, stated rather than hidden: deleting a message does not
-- delete the attachment blobs it referenced, so a server with retention on
-- accumulates unreferenced objects in `chat-attachments`. The blobs are
-- undecryptable once the message carrying their key is gone — they are wasted
-- bytes, not exposed content — but they are still bytes. Central's retention
-- job has had the same gap since it shipped. Sweeping them needs a reverse
-- index from blob to message that no schema here keeps yet.

CREATE OR REPLACE FUNCTION app.enforce_retention() RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- ---------- age ----------
  DELETE FROM messages m
   USING channels c, servers s
   WHERE m.channel_id = c.id
     AND c.server_id  = s.id
     AND s.message_retention_days > 0
     AND m.created_at < now() - make_interval(days => s.message_retention_days);

  -- A DM's server is its sender's; the CHECK on `dm_messages` and
  -- `can_receive_dm` both keep a pair inside one server, so either end answers.
  DELETE FROM dm_messages d
   USING users u, servers s
   WHERE d.sender_id  = u.id
     AND u.server_id  = s.id
     AND s.message_retention_days > 0
     AND d.created_at < now() - make_interval(days => s.message_retention_days);

  -- ---------- history cap ----------
  DELETE FROM messages WHERE id IN (
    SELECT id FROM (
      SELECT m.id,
             row_number() OVER (PARTITION BY m.channel_id ORDER BY m.id DESC) AS rn,
             s.message_history_cap AS cap
        FROM messages m
        JOIN channels c ON c.id = m.channel_id
        JOIN servers  s ON s.id = c.server_id
       WHERE s.message_history_cap > 0
    ) ranked WHERE rn > cap
  );

  -- Order-independent pair, matching `idx_dm_messages_pair` and central's
  -- equivalent sweep: a conversation is one bucket seen from either side.
  DELETE FROM dm_messages WHERE id IN (
    SELECT id FROM (
      SELECT d.id,
             row_number() OVER (
               PARTITION BY LEAST(d.sender_id, d.recipient_id),
                            GREATEST(d.sender_id, d.recipient_id)
               ORDER BY d.id DESC
             ) AS rn,
             s.message_history_cap AS cap
        FROM dm_messages d
        JOIN users   u ON u.id = d.sender_id
        JOIN servers s ON s.id = u.server_id
       WHERE s.message_history_cap > 0
    ) ranked WHERE rn > cap
  );
END; $$;

REVOKE ALL ON FUNCTION app.enforce_retention() FROM PUBLIC, anon, authenticated;

CREATE EXTENSION IF NOT EXISTS pg_cron;

SELECT cron.unschedule('rift-message-retention')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'rift-message-retention');

SELECT cron.schedule(
  'rift-message-retention',
  '23 4 * * *',
  $$SELECT app.enforce_retention()$$
);
