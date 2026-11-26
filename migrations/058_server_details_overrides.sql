-- ============================================================
-- Rift self-hosted server — 058: the server details read each channel's
-- overrides in one pass
-- ============================================================
-- Found in the query review of Nov 25 2026, measured Nov 26 on a test
-- database of 50,000 members and 320 channels, 60 of them with overrides.
--
-- `get_server_details` is what every member's app reads on opening a server
-- and again on every `channels` event, and it works out the caller's
-- permissions in each channel. It did that with `app.apply_channel_overrides`
-- once per channel: two small lookups each, 320 times, which was some 4 ms
-- of the call's 9.5 ms. A server's every member reads it after any change to
-- a channel, so it is paid once per member each time.
--
-- `app.my_channel_overrides` now reads the caller's overrides for the whole
-- server in one grouped pass, and the details apply each channel's row to the
-- bits they already read. The rule itself — @everyone's row first, then the
-- caller's roles', and an administrator past both — is `app.override_bits`,
-- which `app.apply_channel_overrides` uses too, so the two cannot drift
-- apart. What the details answer is unchanged.

-- ── The rule ────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION app.override_bits(
  p_bits BIGINT, p_ev_allow BIGINT, p_ev_deny BIGINT,
  p_rl_allow BIGINT, p_rl_deny BIGINT
) RETURNS BIGINT
  LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN (p_bits & app.perm('ADMINISTRATOR')) <> 0 THEN app.perm_all()
    ELSE ((((p_bits & ~COALESCE(p_ev_deny, 0)) | COALESCE(p_ev_allow, 0))
            & ~COALESCE(p_rl_deny, 0)) | COALESCE(p_rl_allow, 0))
  END
$$;

-- One channel, as before.
CREATE OR REPLACE FUNCTION app.apply_channel_overrides(
  p_bits BIGINT, p_channel UUID, p_user UUID
) RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.override_bits(p_bits, ev.allow, ev.deny, rl.allow, rl.deny)
  FROM (SELECT bit_or(o.allow) AS allow, bit_or(o.deny) AS deny
          FROM channel_overrides o
          JOIN member_roles mr ON mr.role_id = o.role_id AND mr.user_id = p_user
         WHERE o.channel_id = p_channel) rl
  LEFT JOIN (SELECT o.allow, o.deny
               FROM channel_overrides o
               JOIN roles r ON r.id = o.role_id AND r.is_everyone
              WHERE o.channel_id = p_channel) ev ON true
$$;

-- Every channel of the caller's server that has an override, with
-- @everyone's row and the caller's roles' rows folded. A channel with none is
-- not here, and its bits are the caller's own. Nothing for a member who is
-- banned or whose server is being deleted (`app.server_id()`).
CREATE OR REPLACE FUNCTION app.my_channel_overrides()
  RETURNS TABLE (channel_id UUID, ev_allow BIGINT, ev_deny BIGINT,
                 rl_allow BIGINT, rl_deny BIGINT)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.channel_id,
         bit_or(o.allow) FILTER (WHERE r.is_everyone),
         bit_or(o.deny)  FILTER (WHERE r.is_everyone),
         bit_or(o.allow) FILTER (WHERE mr.role_id IS NOT NULL),
         bit_or(o.deny)  FILTER (WHERE mr.role_id IS NOT NULL)
    FROM channel_overrides o
    JOIN roles r ON r.id = o.role_id AND r.server_id = app.server_id()
    LEFT JOIN member_roles mr ON mr.role_id = o.role_id AND mr.user_id = auth.uid()
   GROUP BY o.channel_id
$$;

-- ── The details ─────────────────────────────────────────────
-- As 029 left it but for each channel's `my_permissions`, from the one pass.

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
  -- Read once; each channel's overrides are applied to it below.
  mine AS (
    SELECT my_permissions() AS bits
  ),
  ovr AS (
    SELECT * FROM app.my_channel_overrides()
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
             'my_permissions', app.override_bits(
                                 (SELECT bits FROM mine),
                                 o.ev_allow, o.ev_deny, o.rl_allow, o.rl_deny))
             ORDER BY c.channel_type, c."position", c.name) AS rows
      FROM channels c
      LEFT JOIN ovr o ON o.channel_id = c.id
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

REVOKE ALL ON FUNCTION app.override_bits(BIGINT, BIGINT, BIGINT, BIGINT, BIGINT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION app.override_bits(BIGINT, BIGINT, BIGINT, BIGINT, BIGINT)
  TO authenticated;
REVOKE ALL ON FUNCTION app.my_channel_overrides() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION app.my_channel_overrides() TO authenticated;
REVOKE ALL ON FUNCTION get_server_details() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION get_server_details() TO authenticated;
