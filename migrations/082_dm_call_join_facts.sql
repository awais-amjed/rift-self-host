-- ============================================================
-- Rift self-hosted server — 082: a DM call's questions in one call
-- ============================================================
-- Found in the review of call counts, Nov 26 2026 (its #17), and left open
-- when 065 did the same for a voice channel.
--
-- `get_dm_call_token` asked the database nine times for every connection to
-- a DM call: the caller's row to sign them in, then eight at once — the
-- claim, CONNECT, SCREEN_SHARE, SPEAK and USE_SOUNDBOARD (each working the
-- caller's bits out again), the caller's name, the server's LiveKit and its
-- secrets, the server's share limit — and a tenth for a region's key. The
-- answers were always the database's.
--
--   * `dm_call_join_facts(p_call, p_user, p_kind, p_preferred)` is all of
--     it, with the region claimed, and the refusals in the order the
--     function gave them: `user_not_found` (no row, or a server being
--     deleted), `user_banned`, `call_not_found` (no such call, not yours,
--     not yours yet, or over: one answer, so an id you are not on does not
--     confirm it exists), `no_connect`, `no_share`, `credentials_missing`.
--     Service role only: it answers with LiveKit's keys.
--   * A watch connection reads where the call is and claims nothing.
--   * The claim writes `dm_calls.node_id` only when it moves. Every
--     connection wrote it before, the same value each time after the first,
--     on a row it holds locked.
--
-- `claim_dm_call_room` stays for the fallback that sends a call home when
-- its region does not answer, and writes only a move too.

-- ── The claim, written only when it moves ──────────────────
CREATE OR REPLACE FUNCTION claim_dm_call_room(
  p_call UUID, p_user UUID, p_preferred UUID DEFAULT NULL,
  p_move_to_default BOOLEAN DEFAULT false
) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_call   dm_calls%ROWTYPE;
  v_server UUID;
  v_node   livekit_nodes%ROWTYPE;
BEGIN
  SELECT * INTO v_call FROM dm_calls c WHERE c.id = p_call FOR UPDATE;
  IF NOT FOUND OR v_call.ended_at IS NOT NULL
     OR NOT (p_user = v_call.caller_id
             OR (p_user = v_call.callee_id AND v_call.answered_at IS NOT NULL)) THEN
    RETURN jsonb_build_object('allowed', false);
  END IF;

  SELECT u.server_id INTO v_server FROM users u
   WHERE u.id = p_user AND NOT u.is_banned;
  IF v_server IS NULL THEN RETURN jsonb_build_object('allowed', false); END IF;

  -- Answered, the call stays where it is: somebody may be in it there.
  IF p_move_to_default AND v_call.answered_at IS NOT NULL THEN
    p_move_to_default := false;
  END IF;

  IF NOT p_move_to_default THEN
    SELECT * INTO v_node FROM livekit_nodes n
     WHERE n.id = COALESCE(v_call.node_id, p_preferred) AND n.server_id = v_server;
  END IF;
  IF v_node.id IS NULL THEN
    SELECT * INTO v_node FROM livekit_nodes n
     WHERE n.server_id = v_server AND n.is_default;
  END IF;

  IF v_call.node_id IS DISTINCT FROM v_node.id THEN
    UPDATE dm_calls c SET node_id = v_node.id WHERE c.id = p_call;
  END IF;

  RETURN jsonb_build_object(
    'allowed', true,
    'node', CASE WHEN v_node.id IS NULL THEN NULL ELSE jsonb_build_object(
              'id', v_node.id, 'url', v_node.url, 'label', v_node.label,
              'is_default', v_node.is_default) END);
END; $$;

-- ── Everything a DM call's token is decided from ───────────
-- [p_kind] is `voice`, `share` (a screen or a sound share's connection) or
-- `watch`. A DM call has no channel to override anything, so the bits are
-- the server's, as `user_has_permission` answered them.
CREATE OR REPLACE FUNCTION public.dm_call_join_facts(
  p_call      UUID,
  p_user      UUID,
  p_kind      TEXT,
  p_preferred UUID DEFAULT NULL
) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_admin   BIGINT := app.perm('ADMINISTRATOR');
  v_server  UUID;
  v_name    TEXT;
  v_banned  BOOLEAN;
  v_url     TEXT;
  v_mbps    INTEGER;
  v_call    dm_calls%ROWTYPE;
  v_bits    BIGINT;
  v_key     TEXT;
  v_secret  TEXT;
  v_node    livekit_nodes%ROWTYPE;
  v_nkey    TEXT;
  v_nsecret TEXT;
BEGIN
  SELECT u.server_id, u.display_name, u.is_banned, s.livekit_url, s.max_share_mbps
    INTO v_server, v_name, v_banned, v_url, v_mbps
    FROM users u JOIN servers s ON s.id = u.server_id
   WHERE u.id = p_user AND s.deleting_since IS NULL;
  IF v_server IS NULL THEN
    RETURN jsonb_build_object('reason', 'user_not_found');
  END IF;
  IF v_banned THEN
    RETURN jsonb_build_object('reason', 'user_banned');
  END IF;

  -- Locked only when it may be written: a watch claims nothing.
  IF p_kind = 'watch' THEN
    SELECT * INTO v_call FROM dm_calls c WHERE c.id = p_call;
  ELSE
    SELECT * INTO v_call FROM dm_calls c WHERE c.id = p_call FOR UPDATE;
  END IF;
  IF v_call.id IS NULL OR v_call.ended_at IS NOT NULL
     OR NOT (p_user = v_call.caller_id
             OR (p_user = v_call.callee_id AND v_call.answered_at IS NOT NULL)) THEN
    RETURN jsonb_build_object('reason', 'call_not_found');
  END IF;

  v_bits := app.permissions_of(p_user);
  IF (v_bits & (v_admin | app.perm('CONNECT'))) = 0 THEN
    RETURN jsonb_build_object('reason', 'no_connect');
  END IF;
  IF p_kind = 'share' AND (v_bits & (v_admin | app.perm('SCREEN_SHARE'))) = 0 THEN
    RETURN jsonb_build_object('reason', 'no_share');
  END IF;

  SELECT ss.livekit_api_key, ss.livekit_secret_key INTO v_key, v_secret
    FROM server_secrets ss WHERE ss.server_id = v_server;
  IF COALESCE(v_key, '') = '' OR COALESCE(v_secret, '') = '' OR COALESCE(v_url, '') = '' THEN
    RETURN jsonb_build_object('reason', 'credentials_missing');
  END IF;

  -- Where the call is: the node it already has, else the one the caller
  -- measured if it is this server's, else the default. A server with no node
  -- rows has none, and the call runs on its own LiveKit.
  SELECT * INTO v_node FROM livekit_nodes n
   WHERE n.id = COALESCE(v_call.node_id,
                         CASE WHEN p_kind = 'watch' THEN NULL ELSE p_preferred END)
     AND n.server_id = v_server;
  IF v_node.id IS NULL THEN
    SELECT * INTO v_node FROM livekit_nodes n
     WHERE n.server_id = v_server AND n.is_default;
  END IF;
  IF p_kind <> 'watch' AND v_call.node_id IS DISTINCT FROM v_node.id THEN
    UPDATE dm_calls c SET node_id = v_node.id WHERE c.id = p_call;
  END IF;

  -- The key belongs to the node. A region with none is unusable rather than
  -- run on the server's pair: null keys, which the function treats as a
  -- region that did not answer.
  IF v_node.id IS NOT NULL AND NOT v_node.is_default THEN
    SELECT ns.livekit_api_key, ns.livekit_secret_key INTO v_nkey, v_nsecret
      FROM livekit_node_secrets ns WHERE ns.node_id = v_node.id;
  ELSE
    v_nkey := v_key;
    v_nsecret := v_secret;
  END IF;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'display_name', v_name,
    'screen_share', (v_bits & (v_admin | app.perm('SCREEN_SHARE'))) <> 0,
    'speak', (v_bits & (v_admin | app.perm('SPEAK'))) <> 0,
    'soundboard', (v_bits & (v_admin | app.perm('USE_SOUNDBOARD'))) <> 0,
    'max_share_mbps', v_mbps,
    'credentials', jsonb_build_object('url', v_url, 'api_key', v_key, 'api_secret', v_secret),
    'node', CASE WHEN v_node.id IS NULL THEN NULL ELSE jsonb_build_object(
              'id', v_node.id, 'url', v_node.url, 'label', v_node.label,
              'is_default', v_node.is_default,
              'api_key', v_nkey, 'api_secret', v_nsecret) END);
END $$;

COMMENT ON FUNCTION public.dm_call_join_facts(UUID, UUID, TEXT, UUID) IS
  'Service-role only. Everything get_dm_call_token decides a connection from, '
  'with the call''s region claimed (not for a watch), or the first refusal as '
  '{reason}. Answers with LiveKit keys.';

REVOKE ALL ON FUNCTION public.dm_call_join_facts(UUID, UUID, TEXT, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.dm_call_join_facts(UUID, UUID, TEXT, UUID) TO service_role;
