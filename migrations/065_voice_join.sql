-- ============================================================
-- Rift self-hosted server — 065: a call's questions in one call each
-- ============================================================
-- Found in the review of call counts, Nov 26 2026 (the first review's #11).
--
-- Joining a call asked the database eleven times from `get_channel_token`:
-- the caller's row, then eight questions at once (the door, CONNECT, SPEAK,
-- SCREEN_SHARE, USE_SOUNDBOARD, each working the caller's bits out again,
-- the caller's row once more, the server twice for its LiveKit and its
-- limits), then the channel, then the claim. LiveKit's webhook for the same
-- join asked eight more, a roster read seven, and every app in a call asked
-- once per text channel for its bots' players. The answers were always the
-- database's; the functions only carried them.
--
--   * `voice_join_facts(p_user, p_channel, p_kind, p_preferred)` is
--     everything `get_channel_token` decides from, with the region claimed,
--     and its refusals in the order the function gave them. Service role only:
--     it answers with LiveKit's keys, which only the token's signer may hold.
--   * `call_rights_for(p_channel, p_users)` is what a call holds each of
--     [p_users] to: the door, the channel's call bits, the moderation flags
--     and a bot's ears. One row each, for the webhook's join check and for
--     `refresh_calls`, `set_channel_override`, `moderate_user` and
--     `set_bot_voice_listen`, which each asked per person and per bit.
--   * `voice_roster_facts(p_user)` is what `voice_roster` reads before it asks
--     LiveKit: the caller's server, its nodes and their keys, its voice
--     channels, which of them the caller can see, and which have a call
--     claimed. Service role only, for the keys.
--   * `call_panels(p_call)` is the call's bar: its bots' players wherever
--     they were posted, and every live panel in a text channel the caller
--     reads, in one read rather than one per channel. As the reads it
--     replaces: ids from a definer, rows under `messages_select`.
--
-- And `app.claim_voice_node` reads a claim made in the last half minute
-- rather than locking its row again, so a call everybody joins at once is
-- written once.
--
-- The functions and this file ship together, so the functions use these
-- without asking first. An app asks `call_panels` and, on a server from
-- before it, reads each channel as it did.

-- ── A claim that is already fresh is read ──────────────────
-- `app.claim_voice_node` (044) always ran its upsert. When the call was
-- claimed in the last half minute the upsert changes nothing, but it still
-- locks the row, and a lock is a write the join then waits to flush: on the
-- review's test machine 15 of a join's 17 ms. Everybody joining a call that
-- has just started paid it, one after another on the same row. A claim that
-- young is now only read, which is what the upsert answered anyway; an older
-- one is renewed as before, and no claim is made as before.
CREATE OR REPLACE FUNCTION app.claim_voice_node(
  p_channel    UUID,
  p_preferred  UUID DEFAULT NULL,
  p_ignore_pin BOOLEAN DEFAULT false
) RETURNS TABLE (id UUID, url TEXT, label TEXT, is_default BOOLEAN)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
  v_node   UUID;
BEGIN
  RETURN QUERY
  SELECT n.id, n.url, n.label, n.is_default
    FROM voice_rooms vr
    JOIN livekit_nodes n ON n.id = vr.node_id
   WHERE vr.channel_id = p_channel
     AND vr.opened_at >= now() - interval '30 seconds';
  IF FOUND THEN RETURN; END IF;

  SELECT c.server_id, n.id INTO v_server, v_node
    FROM channels c
    LEFT JOIN livekit_nodes n ON n.id = c.livekit_node_id AND n.server_id = c.server_id
   WHERE c.id = p_channel;

  IF v_server IS NULL THEN RETURN; END IF;

  IF p_ignore_pin THEN v_node := NULL; END IF;

  IF v_node IS NULL AND p_preferred IS NOT NULL THEN
    SELECT n.id INTO v_node FROM livekit_nodes n
     WHERE n.id = p_preferred AND n.server_id = v_server;
  END IF;

  IF v_node IS NULL THEN
    SELECT n.id INTO v_node FROM livekit_nodes n
     WHERE n.server_id = v_server AND n.is_default;
  END IF;

  IF v_node IS NULL THEN RETURN; END IF;

  -- First one in decides; everybody after joins them, and renews the claim.
  INSERT INTO voice_rooms AS vr (channel_id, node_id) VALUES (p_channel, v_node)
    ON CONFLICT (channel_id) DO UPDATE SET opened_at = now()
     WHERE vr.opened_at < now() - interval '30 seconds';

  RETURN QUERY
  SELECT n.id, n.url, n.label, n.is_default
    FROM voice_rooms vr
    JOIN livekit_nodes n ON n.id = vr.node_id
   WHERE vr.channel_id = p_channel;
END $$;

-- ── A join ──────────────────────────────────────────────────
-- [p_kind] is `voice`, `share` (a screen or a sound share's connection) or
-- `watch`. A watch connection claims nothing: it goes where the call is, or
-- nowhere. The refusal reasons, in the order they are weighed:
--
--   user_not_found  no member row, or the server is being deleted
--   user_banned
--   channel_not_found  not one the caller may join (`channel_joinable_by`)
--   no_connect / no_share
--   bot_cannot_watch / key_not_ready  (a bot with no media key here yet)
--   credentials_missing  the server has no LiveKit
--   not_in_call      a watch with no call to go to
--   not_voice        a text channel's id
--   claim_failed     the region could not be decided
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

-- ── What a call holds each person to ────────────────────────
-- One row per member found, whatever server: a connection whose row is on
-- another server has no bits here, so it is outside and holds nothing.
-- `soundboard` already needs `speak`, as a clip is sound.
CREATE OR REPLACE FUNCTION public.call_rights_for(p_channel UUID, p_users UUID[])
RETURNS TABLE (
  user_id      UUID,
  joinable     BOOLEAN,
  connect      BOOLEAN,
  screen_share BOOLEAN,
  speak        BOOLEAN,
  soundboard   BOOLEAN,
  is_muted     BOOLEAN,
  is_deafened  BOOLEAN,
  is_bot       BOOLEAN,
  bot_listens  BOOLEAN
)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  -- Materialized, so each person's bits are worked out once and not once per
  -- column that reads them: a pulled-up subquery calls the function at every
  -- reference, which made forty people cost four times what it should.
  WITH m AS MATERIALIZED (
    SELECT app.perm('ADMINISTRATOR') AS admin, app.perm('CONNECT') AS connect,
           app.perm('SCREEN_SHARE') AS share, app.perm('SPEAK') AS speak,
           app.perm('USE_SOUNDBOARD') AS board
  ), b AS MATERIALIZED (
    SELECT u.id, u.is_muted, u.is_deafened, u.is_bot,
           app.channel_permissions_of(p_channel, u.id) AS bits,
           channel_joinable_by(p_channel, u.id) AS joinable
      FROM users u
     WHERE u.id = ANY (p_users)
  )
  SELECT b.id,
         b.joinable,
         (b.bits & (m.admin | m.connect)) <> 0,
         (b.bits & (m.admin | m.share)) <> 0,
         (b.bits & (m.admin | m.speak)) <> 0,
         (b.bits & (m.admin | m.speak)) <> 0 AND (b.bits & (m.admin | m.board)) <> 0,
         b.is_muted,
         b.is_deafened,
         b.is_bot,
         EXISTS (SELECT 1 FROM bot_voice_grants g
                  WHERE g.channel_id = p_channel AND g.bot_id = b.id)
    FROM b CROSS JOIN m
$$;

COMMENT ON FUNCTION public.call_rights_for(UUID, UUID[]) IS
  'Service-role only. For each of p_users found: whether they may be in '
  'p_channel''s call, its CONNECT, SCREEN_SHARE, SPEAK and soundboard bits '
  '(soundboard needing SPEAK), their moderation flags, and a bot''s ears.';

-- ── What a roster reads before LiveKit ──────────────────────
-- `nodes` is the server's LiveKit list, default first, each with the key it
-- signs with (the default's is the server's, and a region with none has
-- null). `voice_channels` is all of the server's, so one LiveKit sweep can
-- answer every member; `visible` is the caller's share of them.
CREATE OR REPLACE FUNCTION public.voice_roster_facts(p_user UUID) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
  v_banned BOOLEAN;
  v_url    TEXT;
  v_key    TEXT;
  v_secret TEXT;
BEGIN
  SELECT u.server_id, u.is_banned, s.livekit_url INTO v_server, v_banned, v_url
    FROM users u JOIN servers s ON s.id = u.server_id
   WHERE u.id = p_user AND s.deleting_since IS NULL;
  IF v_server IS NULL THEN
    RETURN jsonb_build_object('reason', 'user_not_found');
  END IF;
  IF v_banned THEN
    RETURN jsonb_build_object('reason', 'user_banned');
  END IF;

  SELECT ss.livekit_api_key, ss.livekit_secret_key INTO v_key, v_secret
    FROM server_secrets ss WHERE ss.server_id = v_server;
  IF COALESCE(v_key, '') = '' OR COALESCE(v_secret, '') = '' OR COALESCE(v_url, '') = '' THEN
    RETURN jsonb_build_object('reason', 'credentials_missing');
  END IF;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'server_id', v_server,
    'credentials', jsonb_build_object('url', v_url, 'api_key', v_key, 'api_secret', v_secret),
    'nodes', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
               'id', n.id, 'url', n.url, 'label', n.label, 'is_default', n.is_default,
               'api_key', CASE WHEN n.is_default THEN v_key ELSE ns.livekit_api_key END,
               'api_secret', CASE WHEN n.is_default THEN v_secret ELSE ns.livekit_secret_key END)
             ORDER BY n.is_default DESC, n.label)
        FROM livekit_nodes n
        LEFT JOIN livekit_node_secrets ns ON ns.node_id = n.id
       WHERE n.server_id = v_server), '[]'::jsonb),
    'voice_channels', COALESCE((
      SELECT jsonb_agg(c.id ORDER BY c.id) FROM channels c
       WHERE c.server_id = v_server AND c.channel_type = 'voice'), '[]'::jsonb),
    'visible', COALESCE((
      SELECT jsonb_agg(c.id ORDER BY c.id) FROM channels c
       WHERE c.server_id = v_server AND c.channel_type = 'voice'
         AND (NOT c.is_private OR app.in_channel(c.id, p_user))), '[]'::jsonb),
    'claims', COALESCE((
      SELECT jsonb_agg(jsonb_build_object('channel_id', vr.channel_id, 'node_id', vr.node_id))
        FROM voice_rooms vr JOIN channels c ON c.id = vr.channel_id
       WHERE c.server_id = v_server), '[]'::jsonb));
END $$;

COMMENT ON FUNCTION public.voice_roster_facts(UUID) IS
  'Service-role only. What voice_roster reads before it asks LiveKit: the '
  'caller''s server, its nodes with their keys, its voice channels, the ones '
  'the caller can see, and the calls claimed. Answers with LiveKit keys.';

-- ── A call's bar ────────────────────────────────────────────
-- `app.call_live_ids` (the call's players, from any channel) and, for each
-- text channel the caller reads, its newest live panels, which is the half of
-- `app.channel_live_ids` the bar keeps: it draws players, not polls.
CREATE OR REPLACE FUNCTION app.call_panel_ids(p_call UUID)
RETURNS SETOF BIGINT
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.can_see_channel(p_call) THEN RETURN; END IF;

  RETURN QUERY
  SELECT id FROM (
    SELECT x.id FROM messages x
     WHERE x.blocks ->> 'call' = p_call::TEXT
       AND x.blocks -> 'live' = 'true'::jsonb
     ORDER BY x.id DESC LIMIT 25
  ) called
  UNION
  SELECT p.id
    FROM channels c
    CROSS JOIN LATERAL (
      SELECT x.id FROM messages x
       WHERE x.channel_id = c.id AND x.blocks -> 'live' = 'true'::jsonb
       ORDER BY x.id DESC LIMIT 25
    ) p
   WHERE c.server_id = (SELECT u.server_id FROM users u WHERE u.id = auth.uid())
     AND c.channel_type = 'text'
     AND app.can_see_channel(c.id);
END $$;

COMMENT ON FUNCTION app.call_panel_ids(UUID) IS
  'Ids of what a call''s bar can hold: the call''s players and the live '
  'panels of every text channel the caller reads. Ids only; call_panels turns '
  'them into rows under RLS.';

CREATE OR REPLACE FUNCTION public.call_panels(p_call UUID)
RETURNS SETOF messages
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT m.* FROM app.call_panel_ids(p_call) AS l(id)
    JOIN messages m ON m.id = l.id
   ORDER BY m.id DESC;
$$;

COMMENT ON FUNCTION public.call_panels(UUID) IS
  'What a voice call''s bar holds: its bots'' players wherever posted, and the '
  'live panels of every text channel the caller reads, newest first. Rows are '
  'still subject to messages_select.';

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.claim_voice_node(UUID, UUID, BOOLEAN) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.voice_join_facts(UUID, UUID, TEXT, UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.call_rights_for(UUID, UUID[]) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.voice_roster_facts(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.call_panel_ids(UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.call_panels(UUID) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.voice_join_facts(UUID, UUID, TEXT, UUID) TO service_role;
GRANT EXECUTE ON FUNCTION public.call_rights_for(UUID, UUID[]) TO service_role;
GRANT EXECUTE ON FUNCTION public.voice_roster_facts(UUID) TO service_role;
GRANT EXECUTE ON FUNCTION public.call_panels(UUID) TO authenticated;
-- The definer half, which `call_panels` calls as the member.
GRANT EXECUTE ON FUNCTION app.call_panel_ids(UUID) TO authenticated;
