-- ============================================================
-- Rift self-hosted server — 002: Operator limits and per-server storage
-- ============================================================
-- How much a server will hold: retention, upload caps, a bucket per server
-- rather than one shared one, and the same questions asked of DMs.
--
-- Was 3 files: 007_limits, 008_per_server_buckets, 009_dm_limits.
-- Merged unchanged and in the same order, so this applies exactly what
-- they applied. The sections below are those files, each still carrying
-- the reasoning it was written with.
-- ============================================================

-- ============================================================
-- Rift self-hosted server — 007: operator limits
-- ============================================================
-- Central imposes three limits because central pays for central: a daily send
-- quota, a 30-day TTL, and a per-conversation history cap. A self-hosted server
-- imposed none, on the reasoning that it is somebody's own disk and therefore
-- their own call.
--
-- That reasoning was right about *whose* call it is and wrong about there being
-- nothing to decide. An operator running a server for a few friends still may
-- not want two of them filling the disk, and had no way to say so. So the
-- limits exist here too — but every one of them is a column the admin sets, and
-- **every one defaults to off**. A server that is upgraded and never touched
-- behaves exactly as it did before this file.
--
-- What is deliberately *not* here is a daily message quota. A quota is a rate
-- limit, not a storage bound: N messages a day, forever, is still unbounded —
-- it only takes longer to get there. The thing an operator is actually worried
-- about is the disk, and the instruments for that are a ceiling on how much
-- history is kept and a ceiling on how big one file may be. Those are what this
-- file provides.
--
-- The convention throughout: 0 means "no limit". It is the default, and it is
-- why none of this costs anything on a server that hasn't opted in — the sweep's
-- WHERE clauses match no rows.
--
-- Supersedes an earlier draft of this same migration that added per-channel and
-- per-DM daily quotas; the drops below exist so a database that ran that draft
-- converges. On a fresh database they are no-ops.

-- ============================================================
-- 0. Undo the earlier draft
-- ============================================================

DROP TRIGGER IF EXISTS enforce_messages_quota    ON messages;
DROP TRIGGER IF EXISTS enforce_dm_messages_quota ON dm_messages;
DROP FUNCTION IF EXISTS enforce_message_quota();
DROP FUNCTION IF EXISTS chat_quota(UUID);
DROP FUNCTION IF EXISTS app.channel_daily_quota(UUID);
DROP FUNCTION IF EXISTS app.dm_daily_quota(UUID);

ALTER TABLE servers  DROP CONSTRAINT IF EXISTS servers_limits_sane;
ALTER TABLE channels DROP CONSTRAINT IF EXISTS channels_daily_quota_sane;

ALTER TABLE servers  DROP COLUMN IF EXISTS default_channel_daily_quota;
ALTER TABLE servers  DROP COLUMN IF EXISTS dm_daily_quota;
ALTER TABLE channels DROP COLUMN IF EXISTS daily_quota;

-- ============================================================
-- 1. The settings
-- ============================================================
-- On `servers` rather than a settings table: there is exactly one row per
-- server, members already select it for the name and icon, and the client needs
-- to *read* the attachment cap to reject an oversized file before uploading it.
-- `servers_select` already scopes reads to your own server and there is no
-- client-reachable UPDATE grant, so admins change these through the
-- `update_server` edge function like the name and the LiveKit URL.

ALTER TABLE servers
  ADD COLUMN IF NOT EXISTS max_attachment_bytes   BIGINT  NOT NULL DEFAULT 26214400,
  ADD COLUMN IF NOT EXISTS message_retention_days INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS message_history_cap    INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN servers.max_attachment_bytes IS
  'Per-file attachment cap. Mirrored onto the chat-attachments bucket''s '
  'file_size_limit by update_server — that mirror is the enforcement, this '
  'column is what the client reads to refuse a file before uploading it.';
COMMENT ON COLUMN servers.message_retention_days IS
  'Server-wide default: delete messages older than this many days. 0 = keep '
  'forever. A channel may override it.';
COMMENT ON COLUMN servers.message_history_cap IS
  'Server-wide default: keep at most this many messages per channel and per DM '
  'pair, newest first. 0 = no cap. A channel may override it.';

-- The upper bound is not arbitrary: Supabase Storage caps an object at 500 MB
-- on the free plan and the mirror would silently fail past it.
ALTER TABLE servers ADD CONSTRAINT servers_limits_sane CHECK (
  max_attachment_bytes BETWEEN 1 AND 524288000
  AND message_retention_days >= 0
  AND message_history_cap    >= 0
);

-- Per-channel overrides. NULL is not "unlimited" — it is "inherit", which is
-- why these are nullable when the server's are NOT NULL with a 0 default. A
-- busy #random can be trimmed to 500 messages while #announcements keeps
-- everything, and a channel opts out of a server-wide sweep with 0.
--
-- Voice channels carry these columns and ignore them; they have no messages.
ALTER TABLE channels
  ADD COLUMN IF NOT EXISTS retention_days INTEGER,
  ADD COLUMN IF NOT EXISTS history_cap    INTEGER;

COMMENT ON COLUMN channels.retention_days IS
  'Delete messages in this channel older than this many days. NULL inherits '
  'servers.message_retention_days; 0 explicitly means keep forever.';
COMMENT ON COLUMN channels.history_cap IS
  'Keep at most this many messages in this channel. NULL inherits '
  'servers.message_history_cap; 0 explicitly means no cap.';

ALTER TABLE channels DROP CONSTRAINT IF EXISTS channels_limits_sane;
ALTER TABLE channels ADD CONSTRAINT channels_limits_sane CHECK (
  (retention_days IS NULL OR retention_days >= 0)
  AND (history_cap IS NULL OR history_cap >= 0)
);

-- Additive to the UPDATE (name) grant in 002. Who may write is still decided by
-- `channels_update_managers`; this only widens which columns their UPDATE may
-- name.
GRANT UPDATE (retention_days, history_cap) ON channels TO authenticated;

-- ============================================================
-- 2. Retention
-- ============================================================
-- 006 says messages are never swept, because a self-hosted server is somebody
-- else's hardware and their own retention policy. That still holds — this is
-- how they express it. Both knobs default to 0, so the job below runs nightly
-- and deletes nothing until an operator asks for it.
--
-- In `app`, not `public`: this returns VOID, which means PostgREST would have
-- happily exposed it as an RPC any member could call to wipe the server's
-- history. pg_cron runs as the database owner and reaches it regardless.

CREATE OR REPLACE FUNCTION app.enforce_retention() RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- ---------- channel messages, by age ----------
  -- COALESCE is the inherit rule: the channel's number when it set one, the
  -- server's when it didn't.
  DELETE FROM messages m
   USING channels c, servers s
   WHERE m.channel_id = c.id
     AND c.server_id  = s.id
     AND COALESCE(c.retention_days, s.message_retention_days) > 0
     AND m.created_at < now() - make_interval(
           days => COALESCE(c.retention_days, s.message_retention_days));

  -- ---------- DM messages, by age ----------
  -- A DM's server is its sender's; the CHECK on `dm_messages` and
  -- `can_receive_dm` both keep a pair inside one server, so either end answers.
  -- DMs have no per-channel equivalent to inherit from, so the server's number
  -- is the only one.
  DELETE FROM dm_messages d
   USING users u, servers s
   WHERE d.sender_id  = u.id
     AND u.server_id  = s.id
     AND s.message_retention_days > 0
     AND d.created_at < now() - make_interval(days => s.message_retention_days);

  -- ---------- channel messages, by count ----------
  DELETE FROM messages WHERE id IN (
    SELECT id FROM (
      SELECT m.id,
             row_number() OVER (PARTITION BY m.channel_id ORDER BY m.id DESC) AS rn,
             COALESCE(c.history_cap, s.message_history_cap) AS cap
        FROM messages m
        JOIN channels c ON c.id = m.channel_id
        JOIN servers  s ON s.id = c.server_id
       WHERE COALESCE(c.history_cap, s.message_history_cap) > 0
    ) ranked WHERE rn > cap
  );

  -- ---------- DM messages, by count ----------
  -- Order-independent pair, matching `idx_dm_messages_pair` and central's
  -- equivalent sweep: a conversation is one bucket seen from either side, and
  -- the cap counts both people's messages together.
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

-- ============================================================
-- 3. Attachments the messages left behind
-- ============================================================
-- Deleting a message row frees almost nothing. `ciphertext` is capped at 16 KB,
-- so a thousand messages is a few megabytes; the disk an operator is worried
-- about is filled by *attachments*. Sweeping the rows without their blobs would
-- be a limit that looks like it works and doesn't.
--
-- The server cannot find a message's blobs by reading it: the storage paths
-- live inside the E2E-encrypted body, which is the entire point. And Postgres
-- cannot delete them anyway — `storage.protect_delete()` refuses direct DELETE
-- on `storage.objects` with "Use the Storage API instead", so an ON DELETE
-- CASCADE from a linkage table would have deleted linkage rows and freed zero
-- bytes. Such a table would have bought nothing but a metadata leak.
--
-- So the work splits in two:
--   * a client deleting a message deletes that message's blobs itself. It has
--     just decrypted the body, so it holds the paths, and the policy below lets
--     it act on them. That is the precise path, and it needs no server-side
--     link at all.
--   * this function is the fallback for everything no client will do: messages
--     the retention sweep above removed, blobs whose upload succeeded and whose
--     message insert then failed, and channels that were deleted outright.
--
-- It finds them without any linkage, using the one thing the server does know:
-- an object's name begins with the scope it was uploaded for. Anything older
-- than the oldest surviving message of its scope belonged to a message that is
-- no longer there.

CREATE OR REPLACE FUNCTION app.orphaned_attachments(p_grace INTERVAL DEFAULT '1 hour')
  RETURNS TABLE (object_name TEXT)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  WITH obj AS (
    -- The grace period is a safety rail, not a nicety: an attachment is
    -- uploaded *before* the message that references it is inserted, so without
    -- it a sweep landing in that window would delete a blob whose message is
    -- milliseconds away from existing.
    SELECT o.name, o.created_at, split_part(o.name, '/', 1) AS scope
      FROM storage.objects o
     WHERE o.bucket_id = 'chat-attachments'
       AND o.created_at < now() - p_grace
  ),
  -- A channel scope is the channel id. 'infinity' for a channel with nothing
  -- left in it means every object under it is orphaned, which is correct.
  channel_marks AS (
    SELECT c.id::TEXT AS scope,
           COALESCE(MIN(m.created_at), 'infinity'::TIMESTAMPTZ) AS keep_from
      FROM channels c
      LEFT JOIN messages m ON m.channel_id = c.id
     GROUP BY c.id
  ),
  -- A DM scope is the client's conversation context with its colons swapped
  -- for underscores: `dm_<lower uuid>_<higher uuid>`. Canonical lowercase
  -- UUIDs order the same as text and as uuid, so LEAST/GREATEST reproduce the
  -- client's sort.
  dm_marks AS (
    SELECT 'dm_' || LEAST(d.sender_id, d.recipient_id)::TEXT
                 || '_' || GREATEST(d.sender_id, d.recipient_id)::TEXT AS scope,
           MIN(d.created_at) AS keep_from
      FROM dm_messages d
     GROUP BY 1
  ),
  marks AS (
    SELECT * FROM channel_marks
    UNION ALL
    SELECT * FROM dm_marks
  )
  SELECT obj.name
    FROM obj
    LEFT JOIN marks ON marks.scope = obj.scope
   -- No scope at all: the channel was deleted, or a conversation has no
   -- messages left anywhere.
   WHERE marks.scope IS NULL
      -- The margin is the same grace, used a second time and for a sharper
      -- reason. An attachment is uploaded *before* the message that carries its
      -- key, so the blobs of the oldest surviving message are themselves older
      -- than the watermark. Comparing against a bare `keep_from` would delete
      -- the attachments of the very message it was trying to protect, on every
      -- single sweep, silently. Upload-then-insert takes seconds; an hour of
      -- slack costs nothing but one more sweep before an orphan is collected.
      OR obj.created_at < marks.keep_from - p_grace;
$$;

REVOKE ALL ON FUNCTION app.orphaned_attachments(INTERVAL)
  FROM PUBLIC, anon, authenticated;

-- The one door into the two functions above.
--
-- It has to be in `public` because PostgREST cannot see the `app` schema at
-- all, and the `sweep_attachments` edge function reaches the database through
-- PostgREST. Being in `public` is exactly why it is granted to `service_role`
-- and nothing else: that edge function holds the service key, authenticates the
-- caller as a member first, and is the only thing able to finish the job —
-- deleting a blob needs the Storage API, which no database role can call.
--
-- Capped rather than unbounded, because a server that has never swept could
-- have a very large backlog and both the JSON payload and the Storage API's
-- delete call have practical limits. Callers drain it by calling again.
CREATE OR REPLACE FUNCTION sweep_attachments(p_limit INTEGER DEFAULT 1000)
  RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_names TEXT[];
BEGIN
  PERFORM app.enforce_retention();

  SELECT COALESCE(array_agg(object_name), '{}'::TEXT[]) INTO v_names
    FROM (
      SELECT object_name FROM app.orphaned_attachments()
       ORDER BY object_name
       LIMIT GREATEST(p_limit, 0)
    ) capped;

  RETURN jsonb_build_object('orphans', to_jsonb(v_names));
END; $$;

REVOKE ALL ON FUNCTION sweep_attachments(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION sweep_attachments(INTEGER) TO service_role;

-- The client half: a member may remove an attachment they uploaded, which is
-- what makes "deleting your message deletes its files" possible. Channel
-- managers may remove anyone's, because they may delete anyone's message.
DROP POLICY IF EXISTS chat_attachments_delete ON storage.objects;
CREATE POLICY chat_attachments_delete ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'chat-attachments'
    AND (owner = auth.uid() OR app.can_manage_channels())
  );


-- ============================================================
-- Rift self-hosted server — 008: an attachment bucket per server
-- ============================================================
-- One Supabase project can host several servers (001 says so, and identity is
-- derived per (host, server_id) precisely to allow it). Attachments were still
-- landing in a single project-wide `chat-attachments` bucket, and that one
-- decision cost two things:
--
--   * **The size cap could not be exact.** `file_size_limit` is a property of a
--     bucket, so a shared bucket can only carry one number. 007 mirrored the
--     MAX across servers onto it and accepted that a stricter server's cap was
--     client-enforced only — a limit a modified client could ignore.
--   * **Members could read another server's blobs.** `chat_attachments_select`
--     was `bucket_id = 'chat-attachments'` for *any* authenticated caller. The
--     bytes are AES-256-GCM ciphertext so nothing leaked, but every other rule
--     in this schema is scoped by `app.server_id()` and this one wasn't.
--
-- A bucket per server collapses both into one equality. `chat-<server uuid>` is
-- 41 characters against Storage's 100-character limit, the bucket carries that
-- server's own cap, and the read policy becomes
-- `bucket_id = 'chat-' || app.server_id()`.
--
-- The pleasant surprise is that none of this needs an endpoint. `storage.buckets`
-- is only protected against DELETE (`protect_buckets_delete`), so plain SQL can
-- create a bucket and change its limit — which means a trigger can keep every
-- bucket in step with its server's column, and `update_server` stops needing to
-- touch storage at all.

-- ============================================================
-- 1. The bucket, and keeping it in step
-- ============================================================

CREATE OR REPLACE FUNCTION app.sync_server_bucket(
  p_server UUID,
  p_limit  BIGINT
) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_bucket TEXT := 'chat-' || p_server::TEXT;
BEGIN
  INSERT INTO storage.buckets (id, name, public, file_size_limit)
       VALUES (v_bucket, v_bucket, false, p_limit)
  ON CONFLICT (id) DO UPDATE
          SET public = false, file_size_limit = EXCLUDED.file_size_limit;
END; $$;

REVOKE ALL ON FUNCTION app.sync_server_bucket(UUID, BIGINT)
  FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION sync_server_bucket() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  PERFORM app.sync_server_bucket(NEW.id, NEW.max_attachment_bytes);
  RETURN NEW;
END; $$;

-- A new server gets its bucket the moment its row exists, so `create_server`
-- needs no extra step and can't half-succeed.
DROP TRIGGER IF EXISTS servers_bucket_insert ON servers;
CREATE TRIGGER servers_bucket_insert AFTER INSERT ON servers
  FOR EACH ROW EXECUTE FUNCTION sync_server_bucket();

-- And an admin changing the cap moves the bucket with it. This is what 007's
-- `mirrorAttachmentCap()` did from the edge function, in the one place that
-- cannot be skipped or raced — the same statement that changes the column.
DROP TRIGGER IF EXISTS servers_bucket_update ON servers;
CREATE TRIGGER servers_bucket_update AFTER UPDATE OF max_attachment_bytes ON servers
  FOR EACH ROW WHEN (OLD.max_attachment_bytes IS DISTINCT FROM NEW.max_attachment_bytes)
  EXECUTE FUNCTION sync_server_bucket();

-- Backfill: every server that already exists.
SELECT app.sync_server_bucket(s.id, s.max_attachment_bytes) FROM servers s;

-- ============================================================
-- 2. Who may touch which bucket
-- ============================================================
-- One equality per policy, and `app.server_id()` already returns null for a
-- banned member — so a ban takes their attachments with it, like everything
-- else built on that helper.
--
-- Note what is *not* here: a policy for the old shared `chat-attachments`
-- bucket. It keeps existing (Storage refuses a SQL DELETE on a bucket) but has
-- no policy at all, so nothing can read or write it. Anything left inside is
-- unreachable — acceptable because it is also undecryptable without the
-- messages that carried its keys, and because nothing is deployed. Its rows are
-- still swept by `orphaned_attachments` below, which spans every `chat-%`
-- bucket, so it drains rather than lingering forever.

DROP POLICY IF EXISTS chat_attachments_select ON storage.objects;
CREATE POLICY chat_attachments_select ON storage.objects FOR SELECT TO authenticated
  USING (bucket_id = 'chat-' || app.server_id()::TEXT);

DROP POLICY IF EXISTS chat_attachments_insert ON storage.objects;
CREATE POLICY chat_attachments_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'chat-' || app.server_id()::TEXT);

-- Your own uploads, or anyone's if you may delete their message.
DROP POLICY IF EXISTS chat_attachments_delete ON storage.objects;
CREATE POLICY chat_attachments_delete ON storage.objects FOR DELETE TO authenticated
  USING (
    bucket_id = 'chat-' || app.server_id()::TEXT
    AND (owner = auth.uid() OR app.can_manage_channels())
  );

-- ============================================================
-- 3. The sweep, across buckets
-- ============================================================
-- Same reasoning as 007 — an object is named for the scope it was uploaded to,
-- and anything older than the oldest surviving message of that scope belonged
-- to a message that is gone — but the answer now has to say *which* bucket, so
-- the caller can delete from the right one.
--
-- `chat-%` rather than a join to `servers`, so a bucket whose server row has
-- been deleted still drains.

DROP FUNCTION IF EXISTS app.orphaned_attachments(INTERVAL);

CREATE OR REPLACE FUNCTION app.orphaned_attachments(p_grace INTERVAL DEFAULT '1 hour')
  RETURNS TABLE (bucket TEXT, object_name TEXT)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  WITH obj AS (
    -- The grace period is a safety rail, not a nicety: an attachment is
    -- uploaded *before* the message that references it is inserted, so without
    -- it a sweep landing in that window would delete a blob whose message is
    -- milliseconds away from existing.
    SELECT o.bucket_id, o.name, o.created_at,
           split_part(o.name, '/', 1) AS scope
      FROM storage.objects o
     WHERE o.bucket_id LIKE 'chat-%'
       AND o.created_at < now() - p_grace
  ),
  -- A channel scope is the channel id. 'infinity' for a channel with nothing
  -- left in it means every object under it is orphaned, which is correct.
  channel_marks AS (
    SELECT c.id::TEXT AS scope,
           COALESCE(MIN(m.created_at), 'infinity'::TIMESTAMPTZ) AS keep_from
      FROM channels c
      LEFT JOIN messages m ON m.channel_id = c.id
     GROUP BY c.id
  ),
  -- A DM scope is the client's conversation context with its colons swapped
  -- for underscores: `dm_<lower uuid>_<higher uuid>`. Canonical lowercase
  -- UUIDs order the same as text and as uuid, so LEAST/GREATEST reproduce the
  -- client's sort.
  dm_marks AS (
    SELECT 'dm_' || LEAST(d.sender_id, d.recipient_id)::TEXT
                 || '_' || GREATEST(d.sender_id, d.recipient_id)::TEXT AS scope,
           MIN(d.created_at) AS keep_from
      FROM dm_messages d
     GROUP BY 1
  ),
  marks AS (
    SELECT * FROM channel_marks
    UNION ALL
    SELECT * FROM dm_marks
  )
  SELECT obj.bucket_id, obj.name
    FROM obj
    LEFT JOIN marks ON marks.scope = obj.scope
   -- No scope at all: the channel was deleted, or a conversation has no
   -- messages left anywhere.
   WHERE marks.scope IS NULL
      -- The margin is the same grace, used a second time and for a sharper
      -- reason. An attachment is uploaded *before* the message that carries its
      -- key, so the blobs of the oldest surviving message are themselves older
      -- than the watermark. Comparing against a bare `keep_from` would delete
      -- the attachments of the very message it was trying to protect, on every
      -- single sweep, silently.
      OR obj.created_at < marks.keep_from - p_grace;
$$;

REVOKE ALL ON FUNCTION app.orphaned_attachments(INTERVAL)
  FROM PUBLIC, anon, authenticated;

-- Same door as 007, now answering with bucket + name so the edge function knows
-- where to send each delete. Still `public` because PostgREST cannot see `app`,
-- and still granted to `service_role` alone — that grant is the only thing
-- between a member and a history sweep.
DROP FUNCTION IF EXISTS sweep_attachments(INTEGER);

CREATE OR REPLACE FUNCTION sweep_attachments(p_limit INTEGER DEFAULT 1000)
  RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_orphans JSONB;
BEGIN
  PERFORM app.enforce_retention();

  SELECT COALESCE(
           jsonb_agg(jsonb_build_object('bucket', bucket, 'name', object_name)),
           '[]'::JSONB)
    INTO v_orphans
    FROM (
      SELECT bucket, object_name FROM app.orphaned_attachments()
       ORDER BY bucket, object_name
       LIMIT GREATEST(p_limit, 0)
    ) capped;

  RETURN jsonb_build_object('orphans', v_orphans);
END; $$;

REVOKE ALL ON FUNCTION sweep_attachments(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION sweep_attachments(INTEGER) TO service_role;


-- ============================================================
-- Rift self-hosted server — 009: retention settings for DMs
-- ============================================================
-- 007 gave every channel its own retention override and left DMs with only the
-- server-wide numbers. That asymmetry showed up the first time an operator
-- wanted the obvious policy — trim the busy channels, keep the DMs — and found
-- it wasn't expressible: setting `message_retention_days` swept both, and
-- setting it to 0 and putting a number on each channel meant remembering to
-- repeat that on every channel created afterwards.
--
-- So DMs get the same override the channels have, with the same three-valued
-- rule: NULL inherits the server's number, 0 opts DMs out of a server-wide
-- sweep, N is DMs' own number.
--
-- Why on `servers` and not on the conversation
-- --------------------------------------------
-- A per-conversation setting has no owner. A DM belongs to two people and the
-- retention policy protects the operator's disk, so neither end of it is the
-- right person to set it — and giving one of them the power to set it would let
-- them decide how long the *other* person's messages survive. One
-- server-wide number, written by an admin through `update_server` exactly like
-- the others, keeps who-decides where it already is.
--
-- Nullable, unlike the 007 columns
-- --------------------------------
-- The channel-level columns are nullable because they override; the server-level
-- ones are NOT NULL DEFAULT 0 because they are the base case. These are
-- overrides that happen to live on `servers`, so they follow the channel rule.
-- NULL and 0 are different answers and the UI says so in as many words.

ALTER TABLE servers
  ADD COLUMN IF NOT EXISTS dm_retention_days INTEGER,
  ADD COLUMN IF NOT EXISTS dm_history_cap    INTEGER;

COMMENT ON COLUMN servers.dm_retention_days IS
  'Delete DMs older than this many days. NULL inherits '
  'message_retention_days; 0 explicitly keeps DMs forever.';
COMMENT ON COLUMN servers.dm_history_cap IS
  'Keep at most this many messages per DM conversation, counting both people. '
  'NULL inherits message_history_cap; 0 explicitly means no cap.';

ALTER TABLE servers DROP CONSTRAINT IF EXISTS servers_dm_limits_sane;
ALTER TABLE servers ADD CONSTRAINT servers_dm_limits_sane CHECK (
  (dm_retention_days IS NULL OR dm_retention_days >= 0)
  AND (dm_history_cap IS NULL OR dm_history_cap >= 0)
);

-- ============================================================
-- Retention, with the DM half now overridable
-- ============================================================
-- Replaces 007's function. The two channel blocks are unchanged; the two DM
-- blocks gain the same COALESCE the channel blocks already had, which is the
-- whole of this migration's behaviour.

CREATE OR REPLACE FUNCTION app.enforce_retention() RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- ---------- channel messages, by age ----------
  -- COALESCE is the inherit rule: the channel's number when it set one, the
  -- server's when it didn't.
  DELETE FROM messages m
   USING channels c, servers s
   WHERE m.channel_id = c.id
     AND c.server_id  = s.id
     AND COALESCE(c.retention_days, s.message_retention_days) > 0
     AND m.created_at < now() - make_interval(
           days => COALESCE(c.retention_days, s.message_retention_days));

  -- ---------- DM messages, by age ----------
  -- A DM's server is its sender's; the CHECK on `dm_messages` and
  -- `can_receive_dm` both keep a pair inside one server, so either end answers.
  -- There is no per-conversation override to consult, but there is now a
  -- per-server DM one, and it reads exactly like a channel's.
  DELETE FROM dm_messages d
   USING users u, servers s
   WHERE d.sender_id  = u.id
     AND u.server_id  = s.id
     AND COALESCE(s.dm_retention_days, s.message_retention_days) > 0
     AND d.created_at < now() - make_interval(
           days => COALESCE(s.dm_retention_days, s.message_retention_days));

  -- ---------- channel messages, by count ----------
  DELETE FROM messages WHERE id IN (
    SELECT id FROM (
      SELECT m.id,
             row_number() OVER (PARTITION BY m.channel_id ORDER BY m.id DESC) AS rn,
             COALESCE(c.history_cap, s.message_history_cap) AS cap
        FROM messages m
        JOIN channels c ON c.id = m.channel_id
        JOIN servers  s ON s.id = c.server_id
       WHERE COALESCE(c.history_cap, s.message_history_cap) > 0
    ) ranked WHERE rn > cap
  );

  -- ---------- DM messages, by count ----------
  -- Order-independent pair, matching `idx_dm_messages_pair` and central's
  -- equivalent sweep: a conversation is one bucket seen from either side, and
  -- the cap counts both people's messages together.
  DELETE FROM dm_messages WHERE id IN (
    SELECT id FROM (
      SELECT d.id,
             row_number() OVER (
               PARTITION BY LEAST(d.sender_id, d.recipient_id),
                            GREATEST(d.sender_id, d.recipient_id)
               ORDER BY d.id DESC
             ) AS rn,
             COALESCE(s.dm_history_cap, s.message_history_cap) AS cap
        FROM dm_messages d
        JOIN users   u ON u.id = d.sender_id
        JOIN servers s ON s.id = u.server_id
       WHERE COALESCE(s.dm_history_cap, s.message_history_cap) > 0
    ) ranked WHERE rn > cap
  );
END; $$;

REVOKE ALL ON FUNCTION app.enforce_retention() FROM PUBLIC, anon, authenticated;
