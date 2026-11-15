-- ============================================================
-- Rift self-hosted server — 029: a console update, told to admins
-- ============================================================
-- The console asked GitHub for newer releases only when somebody opened its
-- dashboard or ran `update`, so a server nobody looked at sat on an old
-- console. From the console after 1.6.0 it asks on its own every six hours
-- and keeps the newest release it would be offered in its own table
-- (`rift_console.state`, key `update_available`, JSON `{version, url,
-- notes}`), and clears it when there is none or an update lands.
--
-- `app.console_update()` hands that to a server admin and to nobody else, and
-- `get_server_details()` carries it as `console_update`, so the app can say
-- so under the server's name without a call of its own. Telling only: the
-- update itself stays in the console.
--
-- `rift_console` is the console's, made by it rather than by a migration, and
-- out of reach of every API role. So the helper is SECURITY DEFINER, and
-- answers null where the schema is not there at all (a database the console
-- never ran on), or anything else about it is wrong. The console rings each
-- admin's own topic (`app.announce_console_update`) when the row changes.
-- ============================================================

CREATE OR REPLACE FUNCTION app.console_update() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_value TEXT;
BEGIN
  IF NOT app.is_admin() THEN
    RETURN NULL;
  END IF;
  -- Dynamic, so a database with no `rift_console` still creates this.
  EXECUTE 'SELECT value FROM rift_console.state WHERE key = ''update_available'''
    INTO v_value;
  RETURN v_value::jsonb;
EXCEPTION
  -- Optional by nature: whatever is wrong here (no console schema, a value
  -- that is not JSON, a restore that changed owners), the rest of the
  -- details still answer, and an admin's server still loads.
  WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

-- The console calls this after it writes or clears the row, so admins with
-- the app open hear it at once rather than at their next re-read: their own
-- topic's `me` makes the app read the details again. Only the console's own
-- role may call it; nobody is granted it.
CREATE OR REPLACE FUNCTION app.announce_console_update() RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_admin UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN;
  END IF;
  -- `realtime.send` directly, not `app.announce_to_member`: a stack whose
  -- earlier files ran under another role holds that one where the
  -- console's role may not call it.
  FOR v_admin IN SELECT id FROM users WHERE is_server_admin AND NOT is_banned LOOP
    PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || v_admin, true);
  END LOOP;
END;
$$;

-- Unchanged from 027 but for `console_update`.
CREATE OR REPLACE FUNCTION public.get_server_details()
 RETURNS jsonb
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $$
  WITH me AS (
    SELECT u.* FROM users u WHERE u.id = (SELECT auth.uid())
  ),
  srv AS (
    SELECT s.* FROM servers s LIMIT 1
  ),
  managed AS (
    SELECT cm.channel_id FROM channel_members cm
     WHERE cm.user_id = auth.uid() AND cm.can_manage
  ),
  -- Read once; each channel's rows are applied to it below.
  mine AS (
    SELECT my_permissions() AS bits
  ),
  chans AS (
    SELECT jsonb_agg(jsonb_build_object(
             'id',             c.id,
             'name',           c.name,
             'channel_type',   c.channel_type,
             'retention_days', c.retention_days,
             'history_cap',    c.history_cap,
             'is_private',     c.is_private,
             'is_encrypted',   c.is_encrypted,
             'livekit_node_id', c.livekit_node_id,
             'voice_node_id',   (SELECT vr.node_id FROM voice_rooms vr
                                  WHERE vr.channel_id = c.id),
             'can_manage',     c.is_private
                                 AND EXISTS (SELECT 1 FROM managed m
                                              WHERE m.channel_id = c.id),
             'my_permissions', app.apply_channel_overrides(
                                 (SELECT bits FROM mine), c.id, (SELECT auth.uid())))
             ORDER BY c.channel_type, c."position", c.name) AS rows
      FROM channels c
  ),
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
        'has_left',        me.left_at IS NOT NULL,
        'is_bot',          me.is_bot,
        'manifest',        me.manifest,
        'timed_out_until', me.timed_out_until,
        'dm_policy',       me.dm_policy,
        'permissions', jsonb_build_object(
          'is_server_admin',    me.is_server_admin,
          'is_channel_manager', me.is_channel_manager,
          'can_create_tokens',  me.can_create_tokens,
          'is_owner',           me.is_owner,
          'permission_bits',    (SELECT bits FROM mine)))
        FROM me))
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
                'storage_used', server_storage_used(),
                'max_file_bytes', max_file_bytes(),
                'livekit_nodes', COALESCE((SELECT rows FROM nodes), '[]'::jsonb),
                'console_update', app.console_update())
         END)
  END;
$$;

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION app.console_update() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_console_update() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION app.console_update() TO authenticated;
REVOKE ALL ON FUNCTION get_server_details() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION get_server_details() TO authenticated;
