-- ============================================================
-- Rift self-hosted server — 078: a voice token names the screen
-- ============================================================
-- Found in the security re-review, Nov 26 2026 (#4).
--
-- A member's ordinary voice connection was minted able to publish every
-- source: `SCREEN_SHARE` was asked only for a `_screenshare` connection. So a
-- member whose role or channel denied it could still share their screen on
-- the voice connection, the way phones and browsers share, and every client
-- drew it.
--
-- `voice_join_facts` now also answers `screen_share`, the channel's bit as
-- `call_rights_for` already gives it, and `get_channel_token` names the
-- screen sources in the grant only with it. Otherwise the function is as 065
-- wrote it.
-- ============================================================

CREATE OR REPLACE FUNCTION public.voice_join_facts(
  p_user      UUID,
  p_channel   UUID,
  p_kind      TEXT,
  p_preferred UUID DEFAULT NULL
) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_admin   BIGINT := app.perm('ADMINISTRATOR');
  v_server  UUID;
  v_name    TEXT;
  v_muted   BOOLEAN;
  v_deaf    BOOLEAN;
  v_bot     BOOLEAN;
  v_banned  BOOLEAN;
  v_bits    BIGINT;
  v_speak   BOOLEAN;
  v_share   BOOLEAN;
  v_board   BOOLEAN;
  v_listen  BOOLEAN := true;
  v_url     TEXT;
  v_max     INTEGER;
  v_mbps    INTEGER;
  v_key     TEXT;
  v_secret  TEXT;
  v_type    channel_type;
  v_pin     UUID;
  v_node    RECORD;
  v_nkey    TEXT;
  v_nsecret TEXT;
  v_answer  JSONB;
BEGIN
  SELECT u.server_id, u.display_name, u.is_muted, u.is_deafened, u.is_bot, u.is_banned,
         s.livekit_url, s.max_voice_participants, s.max_share_mbps
    INTO v_server, v_name, v_muted, v_deaf, v_bot, v_banned, v_url, v_max, v_mbps
    FROM users u JOIN servers s ON s.id = u.server_id
   WHERE u.id = p_user AND s.deleting_since IS NULL;
  IF v_server IS NULL THEN
    RETURN jsonb_build_object('reason', 'user_not_found');
  END IF;
  IF v_banned THEN
    RETURN jsonb_build_object('reason', 'user_banned');
  END IF;

  -- Not "forbidden": a room you cannot see should not confirm it exists.
  IF NOT channel_joinable_by(p_channel, p_user) THEN
    RETURN jsonb_build_object('reason', 'channel_not_found');
  END IF;

  -- The channel's bits, worked out once. `apply_channel_overrides` already
  -- answers every bit to an administrator.
  v_bits := app.channel_permissions_of(p_channel, p_user);
  IF (v_bits & (v_admin | app.perm('CONNECT'))) = 0 THEN
    RETURN jsonb_build_object('reason', 'no_connect');
  END IF;
  IF p_kind = 'share' AND (v_bits & (v_admin | app.perm('SCREEN_SHARE'))) = 0 THEN
    RETURN jsonb_build_object('reason', 'no_share');
  END IF;
  v_speak := (v_bits & (v_admin | app.perm('SPEAK'))) <> 0;
  -- Asked for every kind now: the voice connection shares too (phones,
  -- browsers), and its token names the screen only with this.
  v_share := (v_bits & (v_admin | app.perm('SCREEN_SHARE'))) <> 0;
  -- Only the voice connection presses clips, and a clip is sound: it needs
  -- SPEAK too.
  v_board := p_kind = 'voice' AND v_speak
             AND (v_bits & (v_admin | app.perm('USE_SOUNDBOARD'))) <> 0;

  IF v_bot THEN
    IF p_kind = 'watch' THEN
      RETURN jsonb_build_object('reason', 'bot_cannot_watch');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM bot_voice_keys k
                    WHERE k.channel_id = p_channel AND k.bot_id = p_user) THEN
      RETURN jsonb_build_object('reason', 'key_not_ready');
    END IF;
    v_listen := EXISTS (SELECT 1 FROM bot_voice_grants g
                         WHERE g.channel_id = p_channel AND g.bot_id = p_user);
  END IF;

  SELECT ss.livekit_api_key, ss.livekit_secret_key INTO v_key, v_secret
    FROM server_secrets ss WHERE ss.server_id = v_server;
  IF COALESCE(v_key, '') = '' OR COALESCE(v_secret, '') = '' OR COALESCE(v_url, '') = '' THEN
    RETURN jsonb_build_object('reason', 'credentials_missing');
  END IF;

  v_answer := jsonb_build_object(
    'reason', 'ok',
    'server_id', v_server,
    'display_name', v_name,
    'is_muted', v_muted,
    'is_deafened', v_deaf,
    'is_bot', v_bot,
    'speak', v_speak,
    'screen_share', v_share,
    'soundboard', v_board,
    'may_listen', v_listen,
    'max_voice_participants', v_max,
    'max_share_mbps', v_mbps,
    'credentials', jsonb_build_object('url', v_url, 'api_key', v_key, 'api_secret', v_secret));

  -- A watch goes where the call is, read and not claimed. Only a channel on
  -- this server and a node that is its too.
  IF p_kind = 'watch' THEN
    SELECT n.id, n.url, n.is_default INTO v_node
      FROM voice_rooms vr
      JOIN livekit_nodes n ON n.id = vr.node_id AND n.server_id = v_server
      JOIN channels c ON c.id = vr.channel_id AND c.server_id = v_server
     WHERE vr.channel_id = p_channel;
    IF v_node.id IS NULL OR v_node.is_default THEN
      -- No live call names a node: the server's own address and pair, which
      -- belong together.
      RETURN v_answer || jsonb_build_object('watch', jsonb_build_object(
        'url', COALESCE(v_node.url, v_url), 'api_key', v_key, 'api_secret', v_secret));
    END IF;
    SELECT ns.livekit_api_key, ns.livekit_secret_key INTO v_nkey, v_nsecret
      FROM livekit_node_secrets ns WHERE ns.node_id = v_node.id;
    IF v_nkey IS NULL THEN
      RETURN jsonb_build_object('reason', 'not_in_call');
    END IF;
    RETURN v_answer || jsonb_build_object('watch', jsonb_build_object(
      'url', v_node.url, 'api_key', v_nkey, 'api_secret', v_nsecret));
  END IF;

  -- A call is only ever in a voice channel.
  SELECT c.channel_type, c.livekit_node_id INTO v_type, v_pin
    FROM channels c WHERE c.id = p_channel;
  IF v_type IS DISTINCT FROM 'voice' THEN
    RETURN jsonb_build_object('reason', 'not_voice');
  END IF;

  -- Where the call is, deciding it if nobody has. A failed claim is answered,
  -- never read as "this server has no node list".
  BEGIN
    SELECT * INTO v_node FROM app.claim_voice_node(p_channel, p_preferred, false);
  EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('reason', 'claim_failed');
  END;

  IF v_node.id IS NULL THEN
    RETURN v_answer || jsonb_build_object('pinned_node_id', v_pin, 'node', NULL);
  END IF;
  -- The key belongs to the node. A region with none is unusable rather than
  -- run on the server's pair: null keys, which the function treats as a
  -- region that did not answer.
  IF v_node.is_default THEN
    v_nkey := v_key;
    v_nsecret := v_secret;
  ELSE
    SELECT ns.livekit_api_key, ns.livekit_secret_key INTO v_nkey, v_nsecret
      FROM livekit_node_secrets ns WHERE ns.node_id = v_node.id;
  END IF;
  RETURN v_answer || jsonb_build_object(
    'pinned_node_id', v_pin,
    'node', jsonb_build_object(
      'id', v_node.id, 'url', v_node.url, 'label', v_node.label,
      'is_default', v_node.is_default, 'api_key', v_nkey, 'api_secret', v_nsecret));
END $$;

COMMENT ON FUNCTION public.voice_join_facts(UUID, UUID, TEXT, UUID) IS
  'Service-role only. Everything get_channel_token decides a join from, with '
  'the region claimed (not for a watch), or the first refusal as {reason}. '
  'Answers with LiveKit keys.';

REVOKE ALL ON FUNCTION public.voice_join_facts(UUID, UUID, TEXT, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.voice_join_facts(UUID, UUID, TEXT, UUID) TO service_role;
