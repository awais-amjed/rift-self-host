-- ============================================================
-- Rift self-hosted server — 085: a kick's or a move's questions in one call
-- ============================================================
-- Found in the review of call counts, Nov 26 2026 (its #16).
--
-- `kick_user` and `move_user` asked the database eight to ten times before
-- they asked LiveKit anything: the caller's row to sign them in, the target,
-- for a move the channel they are sent to, the server's LiveKit and its
-- secrets, the regions and theirs, every channel on the server, and then
-- `channel_manageable_by` once for each room the target was found in.
--
--   * `voice_moderation_facts(p_caller, p_target, p_destination)` is all of
--     it, for a kick (`p_destination` null) or a move, with the refusals in
--     the order the functions gave them: `user_not_found` (no row, or a
--     server being deleted), `user_banned`, `not_allowed` (neither an admin
--     nor a channel manager), `self` (a kick of yourself), `target_not_found`,
--     `target_admin` (a move of yourself is let through), `channel_not_found`
--     (no such channel here, or one the caller does not manage), `not_voice`,
--     `credentials_missing`.
--   * It answers the regions with their keys, as `livekitRoomServices` built
--     them — a region with no key of its own left out — and `rooms`, the
--     channels the caller manages. A function then lists only those rooms,
--     where it listed every channel and asked about each it found the
--     target in; who is reached does not change, since it dropped every
--     other room afterwards.
--   * A move whose destination the caller does not manage is refused before
--     LiveKit is asked, with the answer it gave after.
--   * Service role only: it answers with LiveKit's keys.
--
-- The search stays a search of every room on every region: a kick ends each
-- connection the target holds, two calls from two devices included, and a
-- move moves every device, so knowing the one channel the app shows them in
-- is not enough.

CREATE OR REPLACE FUNCTION public.voice_moderation_facts(
  p_caller      UUID,
  p_target      UUID,
  p_destination UUID DEFAULT NULL
) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server   UUID;
  v_banned   BOOLEAN;
  v_staff    BOOLEAN;
  v_url      TEXT;
  v_t_admin  BOOLEAN;
  v_dest     channels%ROWTYPE;
  v_key      TEXT;
  v_secret   TEXT;
  v_manage   BOOLEAN;
  v_nodes    JSONB;
  v_rooms    JSONB;
BEGIN
  SELECT u.server_id, u.is_banned, (u.is_server_admin OR u.is_channel_manager), s.livekit_url
    INTO v_server, v_banned, v_staff, v_url
    FROM users u JOIN servers s ON s.id = u.server_id
   WHERE u.id = p_caller AND s.deleting_since IS NULL;
  IF v_server IS NULL THEN
    RETURN jsonb_build_object('reason', 'user_not_found');
  END IF;
  IF v_banned THEN
    RETURN jsonb_build_object('reason', 'user_banned');
  END IF;
  IF NOT COALESCE(v_staff, false) THEN
    RETURN jsonb_build_object('reason', 'not_allowed');
  END IF;
  IF p_destination IS NULL AND p_target = p_caller THEN
    RETURN jsonb_build_object('reason', 'self');
  END IF;

  SELECT u.is_server_admin INTO v_t_admin FROM users u
   WHERE u.id = p_target AND u.server_id = v_server;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('reason', 'target_not_found');
  END IF;
  IF v_t_admin AND (p_destination IS NULL OR p_target <> p_caller) THEN
    RETURN jsonb_build_object('reason', 'target_admin');
  END IF;

  IF p_destination IS NOT NULL THEN
    SELECT * INTO v_dest FROM channels c
     WHERE c.id = p_destination AND c.server_id = v_server;
    IF v_dest.id IS NULL THEN
      RETURN jsonb_build_object('reason', 'channel_not_found');
    END IF;
    IF v_dest.channel_type <> 'voice' THEN
      RETURN jsonb_build_object('reason', 'not_voice');
    END IF;
  END IF;

  SELECT ss.livekit_api_key, ss.livekit_secret_key INTO v_key, v_secret
    FROM server_secrets ss WHERE ss.server_id = v_server;
  IF COALESCE(v_key, '') = '' OR COALESCE(v_secret, '') = '' OR COALESCE(v_url, '') = '' THEN
    RETURN jsonb_build_object('reason', 'credentials_missing');
  END IF;

  -- Every region, default first, each with the pair it signs with: the
  -- server's for the default, its own for any other, and left out without
  -- one. A server with no node rows has the one address on `servers`.
  SELECT jsonb_agg(jsonb_build_object(
           'id', n.id, 'url', n.url, 'label', n.label, 'is_default', n.is_default,
           'api_key', CASE WHEN n.is_default THEN v_key ELSE ns.livekit_api_key END,
           'api_secret', CASE WHEN n.is_default THEN v_secret ELSE ns.livekit_secret_key END)
           ORDER BY n.is_default DESC, n.label)
    INTO v_nodes
    FROM livekit_nodes n
    LEFT JOIN livekit_node_secrets ns ON ns.node_id = n.id
   WHERE n.server_id = v_server
     AND (n.is_default OR (COALESCE(ns.livekit_api_key, '') <> ''
                           AND COALESCE(ns.livekit_secret_key, '') <> ''));
  IF NOT EXISTS (SELECT 1 FROM livekit_nodes n WHERE n.server_id = v_server) THEN
    v_nodes := jsonb_build_array(jsonb_build_object(
      'id', '', 'url', v_url, 'label', 'Default', 'is_default', true,
      'api_key', v_key, 'api_secret', v_secret));
  END IF;
  IF v_nodes IS NULL OR jsonb_array_length(v_nodes) = 0 THEN
    RETURN jsonb_build_object('reason', 'credentials_missing');
  END IF;

  -- The rooms the caller manages, by `channel_manageable_by`'s rule: a
  -- private channel answers to its own managers, a public one to
  -- MANAGE_CHANNELS, asked once.
  v_manage := user_has_permission(p_caller, 'MANAGE_CHANNELS');
  SELECT COALESCE(jsonb_agg(c.id ORDER BY c.id), '[]'::jsonb) INTO v_rooms
    FROM channels c
   WHERE c.server_id = v_server
     AND CASE WHEN c.is_private
              THEN EXISTS (SELECT 1 FROM channel_members cm
                            WHERE cm.channel_id = c.id
                              AND cm.user_id = p_caller
                              AND cm.can_manage)
              ELSE v_manage END;

  IF p_destination IS NOT NULL AND NOT v_rooms @> to_jsonb(p_destination) THEN
    RETURN jsonb_build_object('reason', 'channel_not_found');
  END IF;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'nodes', v_nodes,
    'rooms', v_rooms);
END $$;

COMMENT ON FUNCTION public.voice_moderation_facts(UUID, UUID, UUID) IS
  'Service-role only. Everything kick_user (no destination) and move_user '
  'decide from before asking LiveKit: the refusal, or the regions with their '
  'keys and the rooms the caller manages. Answers with LiveKit keys.';

REVOKE ALL ON FUNCTION public.voice_moderation_facts(UUID, UUID, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.voice_moderation_facts(UUID, UUID, UUID) TO service_role;
