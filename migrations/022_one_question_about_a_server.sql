-- ============================================================
-- Rift self-hosted server — 022: one question about a server
-- ============================================================
-- Opening a server, and every structural change after it, cost five or six
-- sequential round trips: the caller's own row, that row again for
-- `is_owner`, the server, the channels, sometimes `channel_members`, and
-- `my_permissions()`. Each waited on the one before it, so the channel list
-- could not paint until all of them had been and come back — about 600 ms on
-- a 100 ms link, every launch, and again for every member of the server every
-- time somebody adds a channel.
--
-- It is one question. The client wants to know what this server is, what is
-- in it, and who it is to them; it cannot draw any of that without all of it.
-- Asking it in six pieces was never a decision, it was six calls that grew.
--
-- SECURITY INVOKER, so the policies answer exactly as they did when the
-- client asked them one at a time. `channels_select` still decides which
-- channels appear, and a banned member still sees their own row and nothing
-- else — `app.server_id()` empties on a ban and every policy hanging off it
-- stops matching, which is why the `servers` half is fetched separately below
-- rather than joined: a ban must come back as "you are banned", not as
-- "no such server".
--
-- ---------- two things the old reads quietly dropped ----------
--
-- `dm_retention_days` and `dm_history_cap` were never in the select. The DM
-- settings dialog writes them through `update_server` and read them back as
-- null every time, so an operator who capped DMs saw the dialog forget it on
-- the next refresh. They are in the answer now.
--
-- `chat_public_key`, `is_bot` and `manifest` were missing from the caller's
-- own row for the same reason — the select listed columns and those three
-- were not among them, while `ServerUserRow.of` read them. They cost nothing
-- to include and the row they describe is the caller's own.

CREATE OR REPLACE FUNCTION get_server_details() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  WITH me AS (
    SELECT u.* FROM users u WHERE u.id = auth.uid()
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
             'can_manage',     c.is_private
                                 AND EXISTS (SELECT 1 FROM managed m
                                              WHERE m.channel_id = c.id))
             ORDER BY c.name) AS rows
      FROM channels c
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
        'is_bot',          me.is_bot,
        'manifest',        me.manifest,
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
                  (SELECT srv.dm_history_cap         FROM srv))
         END)
  END;
$$;

COMMENT ON FUNCTION get_server_details() IS
  'Everything a client needs to draw a server: its identity and limits, the '
  'channels the caller may see, and the caller''s own row with their '
  'permissions. Null when the caller has no row here. Answers the five reads '
  'that used to run one after another.';

REVOKE ALL ON FUNCTION get_server_details() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION get_server_details() TO authenticated;
