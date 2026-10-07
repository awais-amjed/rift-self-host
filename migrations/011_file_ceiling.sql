-- ============================================================
-- Rift self-hosted server — 011: the largest file is the operator's choice
-- ============================================================
-- Two numbers decided how big an attachment could be, and neither was one an
-- operator chose. Storage refused anything over 50 MB, because the compose
-- file fixed its FILE_SIZE_LIMIT there, so a server set to 200 MB failed every
-- upload past 50 with a 413. And `servers_limits_sane` refused a setting over
-- 500 MB, on the grounds that Supabase's free plan stops there — it stops at
-- 50, and a self-hosted server has no plan.
--
-- The console now sets storage's ceiling (a setup field, changeable from the
-- dashboard) and records it in `app.file_ceiling` through
-- `app.set_file_ceiling`, which also brings down any server set above it.
-- So the CHECK keeps only its lower bound, a server's
-- `max_attachment_bytes` must stay at or under the ceiling, and
-- `get_server_details` hands the ceiling to clients as `max_file_bytes`.
--
-- Until the console writes a row, the ceiling reads as 50 MB: what storage
-- enforced on every server before this, so nothing claims more than it did.
-- ============================================================

-- ── The cap goes ────────────────────────────────────────────

ALTER TABLE servers DROP CONSTRAINT IF EXISTS servers_limits_sane;
ALTER TABLE servers ADD CONSTRAINT servers_limits_sane CHECK (
  max_attachment_bytes >= 1
  AND message_retention_days >= 0
  AND message_history_cap    >= 0
);

COMMENT ON COLUMN servers.max_attachment_bytes IS
  'Per-file attachment cap, at most max_file_bytes(). Mirrored onto the '
  'server''s chat bucket''s file_size_limit by a trigger; this column is what '
  'the client reads to refuse a file before uploading it.';

-- ── The machine's ceiling ───────────────────────────────────

CREATE TABLE IF NOT EXISTS app.file_ceiling (
  only_row  BOOLEAN PRIMARY KEY DEFAULT true CHECK (only_row),
  max_bytes BIGINT  NOT NULL CHECK (max_bytes >= 1)
);

COMMENT ON TABLE app.file_ceiling IS
  'The largest file storage on this machine accepts (its FILE_SIZE_LIMIT), as '
  'the console last set it. One row; written only by app.set_file_ceiling.';

CREATE OR REPLACE FUNCTION public.max_file_bytes() RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((SELECT c.max_bytes FROM app.file_ceiling c), 52428800)
$$;

COMMENT ON FUNCTION max_file_bytes() IS
  'The largest file storage on this machine accepts. 50 MB until the console '
  'records otherwise, which is what storage enforced before it could.';

CREATE OR REPLACE FUNCTION app.set_file_ceiling(p_bytes BIGINT) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF p_bytes IS NULL OR p_bytes < 1 THEN
    RAISE EXCEPTION 'The file ceiling must be at least one byte';
  END IF;
  INSERT INTO app.file_ceiling (only_row, max_bytes) VALUES (true, p_bytes)
  ON CONFLICT (only_row) DO UPDATE SET max_bytes = EXCLUDED.max_bytes;
  -- A server set above the new ceiling would promise files storage now
  -- refuses. Its bucket follows through the existing trigger.
  UPDATE servers SET max_attachment_bytes = p_bytes
   WHERE max_attachment_bytes > p_bytes;
END; $$;

COMMENT ON FUNCTION app.set_file_ceiling(BIGINT) IS
  'Records the largest file storage accepts and lowers any server set above '
  'it. Called by the console after it changes storage''s FILE_SIZE_LIMIT.';

-- ── Servers stay under it ───────────────────────────────────
-- A new server takes the column default (25 MB), which a machine with a
-- smaller ceiling cannot honour, so an insert is brought down to fit. A
-- change past it is refused: that is somebody asking for a number, and
-- update_server has already told them the most they can have. A value left
-- as it was is let through, since the app saves every limit at once and a
-- server set high before the console recorded a ceiling must still be able
-- to save its others.

CREATE OR REPLACE FUNCTION app.keep_under_file_ceiling() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_ceiling BIGINT := max_file_bytes();
BEGIN
  IF NEW.max_attachment_bytes > v_ceiling THEN
    IF TG_OP = 'INSERT' THEN
      NEW.max_attachment_bytes := v_ceiling;
    ELSIF NEW.max_attachment_bytes IS DISTINCT FROM OLD.max_attachment_bytes THEN
      RAISE EXCEPTION 'max_attachment_bytes % is over this machine''s ceiling of %',
        NEW.max_attachment_bytes, v_ceiling
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS servers_under_file_ceiling ON servers;
CREATE TRIGGER servers_under_file_ceiling
  BEFORE INSERT OR UPDATE OF max_attachment_bytes ON servers
  FOR EACH ROW EXECUTE FUNCTION app.keep_under_file_ceiling();

-- ── get_server_details carries it ───────────────────────────
-- Unchanged from 010 apart from `max_file_bytes`.

CREATE OR REPLACE FUNCTION public.get_server_details()
 RETURNS jsonb
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $$
  WITH me AS (
    -- `(SELECT auth.uid())`, not `auth.uid()`, and it is worth 34 of this
    -- function's 37 milliseconds. `users` carries two permissive SELECT
    -- policies, so every read of it also carries `(id = auth.uid() OR
    -- server_id = app.server_id())` — a disjunction, which can never be one
    -- index condition. Written bare, the caller's own predicate is left as a
    -- filter and the plan becomes a bitmap of every member of the server;
    -- wrapped, it is an InitPlan and the primary key answers it. 40.8 ms →
    -- 0.04 ms on 50,000 members. A client passing its own id as a literal was
    -- always fine — this is the one place the schema asked the question of
    -- itself.
    SELECT u.* FROM users u WHERE u.id = (SELECT auth.uid())
  ),
  -- Invisible to a banned caller, which is the point: the CASE below reads
  -- "no row here" as "not for you" rather than as "gone".
  srv AS (
    SELECT s.* FROM servers s LIMIT 1
  ),
  -- Only private channels can be managed individually, and only by the
  -- members holding the seat. One read for the whole list, as before.
  managed AS (
    SELECT cm.channel_id FROM channel_members cm
     WHERE cm.user_id = auth.uid() AND cm.can_manage
  ),
  chans AS (
    SELECT jsonb_agg(jsonb_build_object(
             'id',             c.id,
             'name',           c.name,
             'channel_type',   c.channel_type,
             'retention_days', c.retention_days,
             'history_cap',    c.history_cap,
             'is_private',     c.is_private,
             -- Which LiveKit voice here is pinned to, and where a call
             -- actually is. Null and null is "automatic, nobody in it".
             'livekit_node_id', c.livekit_node_id,
             'voice_node_id',   (SELECT vr.node_id FROM voice_rooms vr
                                  WHERE vr.channel_id = c.id),
             'can_manage',     c.is_private
                                 AND EXISTS (SELECT 1 FROM managed m
                                              WHERE m.channel_id = c.id))
             ORDER BY c.channel_type, c."position", c.name) AS rows
      FROM channels c
  ),
  -- Every node this server can hold a call on. Members get the list too, not
  -- just managers: a member is shown which region they are in, and picks the
  -- nearest one to offer when they are the first to open a call.
  nodes AS (
    SELECT jsonb_agg(jsonb_build_object(
             'id',         n.id,
             'label',      n.label,
             'url',        n.url,
             'is_default', n.is_default)
             ORDER BY n.is_default DESC, n.label) AS rows
      FROM livekit_nodes n
  )
  SELECT CASE
    -- No row of our own: removed, or the server is gone. Either way there is
    -- nothing here to refresh, and the client turns a null into that answer.
    WHEN NOT EXISTS (SELECT 1 FROM me) THEN NULL
    ELSE (jsonb_build_object('user', (
      SELECT jsonb_build_object(
        'id',              me.id,
        'username',        me.username,
        'display_name',    me.display_name,
        'avatar_path',     me.avatar_path,
        'chat_public_key', me.chat_public_key,
        'is_muted',        me.is_muted,
        'is_deafened',     me.is_deafened,
        'is_banned',       me.is_banned,
        'is_kicked',       me.kicked_at IS NOT NULL,
        'is_bot',          me.is_bot,
        'manifest',        me.manifest,
        'timed_out_until', me.timed_out_until,
        'dm_policy',       me.dm_policy,
        'permissions', jsonb_build_object(
          'is_server_admin',    me.is_server_admin,
          'is_channel_manager', me.is_channel_manager,
          'can_create_tokens',  me.can_create_tokens,
          'is_owner',           me.is_owner,
          'permission_bits',    my_permissions()))
        FROM me))
      -- A banned caller stops here: their own row, and an empty list rather
      -- than the null a client would have to guard.
      || CASE WHEN (SELECT me.is_banned FROM me)
              THEN jsonb_build_object('channels', '[]'::jsonb)
              ELSE jsonb_build_object(
                'server_id',   (SELECT srv.id          FROM srv),
                'name',        (SELECT srv.name        FROM srv),
                'icon_url',    (SELECT srv.icon_url    FROM srv),
                'livekit_url', (SELECT srv.livekit_url FROM srv),
                'channels',    COALESCE((SELECT rows FROM chans), '[]'::jsonb),
                'max_attachment_bytes',
                  (SELECT srv.max_attachment_bytes   FROM srv),
                'message_retention_days',
                  (SELECT srv.message_retention_days FROM srv),
                'message_history_cap',
                  (SELECT srv.message_history_cap    FROM srv),
                'dm_retention_days',
                  (SELECT srv.dm_retention_days      FROM srv),
                'dm_history_cap',
                  (SELECT srv.dm_history_cap         FROM srv),
                -- Without these the bitrate picker reads "no cap" on every
                -- refresh and an operator's setting looks forgotten.
                'max_voice_participants',
                  (SELECT srv.max_voice_participants FROM srv),
                'max_share_mbps',
                  (SELECT srv.max_share_mbps         FROM srv),
                'max_members',
                  (SELECT srv.max_members            FROM srv),
                'max_storage_bytes',
                  (SELECT srv.max_storage_bytes      FROM srv),
                'dm_openings_per_hour',
                  (SELECT srv.dm_openings_per_hour   FROM srv),
                -- Not a limit but the thing limits are judged against, and
                -- free here: one indexed read, in the call the client already
                -- makes. It is what lets the composer say a file will not fit
                -- before somebody picks it, rather than after.
                'storage_used', server_storage_used(),
                -- The ceiling `max_attachment_bytes` is set under, so the
                -- settings dialog offers no number this machine refuses.
                'max_file_bytes', max_file_bytes(),
                'livekit_nodes', COALESCE((SELECT rows FROM nodes), '[]'::jsonb))
         END)
  END;
$$;

COMMENT ON FUNCTION get_server_details() IS
  'Everything a client needs to draw a server: its identity and limits, the '
  'channels the caller may see, and the caller''s own row with their '
  'permissions. Null when the caller has no row here. Answers the five reads '
  'that used to run one after another.';

-- ── Grants ──────────────────────────────────────────────────
-- The ceiling is no secret: every member is told it through
-- get_server_details, and update_server asks it on the service role.

REVOKE ALL ON TABLE app.file_ceiling FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.set_file_ceiling(BIGINT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.keep_under_file_ceiling() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION max_file_bytes() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION max_file_bytes() TO authenticated, service_role;
