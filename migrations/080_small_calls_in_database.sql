-- ============================================================
-- Rift self-hosted server — 080: four small calls answer for themselves
-- ============================================================
-- Found in the re-review of what should move to the database, Nov 26 2026.
--
--   * `summon_bot_to_voice` now says whether the summon is new (`new`) and
--     whether the bot is still owed a media key at the channel's current
--     version (`needs_key`). The app asked it through `set_bot_voice_summon`,
--     an edge function that only passes a summon on, and then rang `sweep`
--     to the whole server after every summoning command, so a queue of ten
--     songs was ten server-wide rounds of key reads, nine of them for
--     nothing. The app now calls it directly and rings only when the bot
--     needs a key. The edge function stays for a dismiss, which must reach
--     LiveKit.
--   * `my_channel_key` answers, in a voice channel, `listening_bots`: the
--     bots allowed to hear it. Joining a call read them from the
--     `voice_listeners` view beside the key, and again on every rotation;
--     now the key and the grants come from one statement, so a grant revoked
--     between two requests cannot be read on either side of the rotation it
--     causes.
--   * `push_status`, `set_push_config` and `clear_push_config` are what the
--     `configure_push` edge function did: an admin's read, write and delete
--     of `push_config`. The table keeps no policy and no grant; only these
--     reach it, and none hands the secret back.
--   * `my_listing_token` is `listing_token`: an admin's one-time listing
--     token, made and digested here (pgcrypto), stored by
--     `issue_listing_token` as before. `verify_listing_token` stays where it
--     is, since central calls it with no key.
--
-- The edge functions stay, for apps that have not moved.

-- ── Who is asking, for an admin's call ─────────────────────
-- The caller's server, as `app.key_caller_server` finds it (a member, not
-- banned, the server not being deleted), and only for a server admin.
CREATE OR REPLACE FUNCTION app.admin_caller_server() RETURNS UUID
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.key_caller_server();
BEGIN
  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = auth.uid() AND u.is_server_admin) THEN
    RAISE EXCEPTION 'permission_denied';
  END IF;
  RETURN v_server;
END $$;

-- ── Summoning a bot ─────────────────────────────────────────
-- As in 027, and the answer says what changed.
CREATE OR REPLACE FUNCTION summon_bot_to_voice(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_type    TEXT;
  v_new     INTEGER;
  v_current INTEGER;
  v_needs   BOOLEAN;
BEGIN
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  IF NOT app.has_channel_perm(p_channel, 'SUMMON_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  SELECT channel_type INTO v_type FROM channels WHERE id = p_channel;
  IF v_type IS DISTINCT FROM 'voice' THEN
    RETURN jsonb_build_object('reason', 'not_a_voice_channel');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = app.server_id()) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_voice_summons (channel_id, bot_id, summoned_by)
  VALUES (p_channel, p_bot, auth.uid())
  ON CONFLICT (channel_id, bot_id) DO NOTHING;
  GET DIAGNOSTICS v_new = ROW_COUNT;

  -- Owed a key: the rule `my_channel_key` lists `bots_missing` by, for this
  -- one bot. A channel with no key yet is sealed for its bots by whoever
  -- mints it, and a bot with no chat key can be sealed nothing.
  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;
  SELECT EXISTS (
           SELECT 1 FROM bot_voice_key_candidates c
             LEFT JOIN bot_voice_keys k
               ON k.channel_id = c.channel_id AND k.bot_id = c.bot_id
              AND k.key_version = v_current
            WHERE c.channel_id = p_channel AND c.bot_id = p_bot
              AND (k.bot_id IS NULL OR k.is_channel_key <> c.may_listen))
    INTO v_needs;

  RETURN jsonb_build_object('reason', 'ok',
                            'new', v_new > 0,
                            'needs_key', v_current > 0 AND v_needs);
END; $$;

-- ── One channel's keys ──────────────────────────────────────
-- As in 063, and in a voice channel the caller can see, the bots allowed to
-- hear it: `voice_listeners`, read in the same statement as the key.
CREATE OR REPLACE FUNCTION public.my_channel_key(p_channel UUID) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me        UUID := auth.uid();
  v_server    UUID := app.key_caller_server();
  v_type      TEXT;
  v_state     JSONB;
  v_current   INTEGER;
  v_voice     JSONB;
  v_bots      JSONB := '[]'::jsonb;
  v_listening JSONB;
  v_answer    JSONB;
BEGIN
  SELECT c.channel_type INTO v_type
    FROM channels c WHERE c.id = p_channel AND c.server_id = v_server;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'channel_not_found';
  END IF;

  -- Not the caller's to see. A summoned bot is in the room without being of
  -- it, and needs the media key a member sealed for it: its newest row, and
  -- nothing about the keyring, which is what the edge function answered.
  IF NOT app.sees_channel(p_channel, v_me) THEN
    IF NOT channel_joinable_by(p_channel, v_me) THEN
      RAISE EXCEPTION 'channel_not_found';
    END IF;
    SELECT jsonb_build_object('key_version', b.key_version,
                              'is_channel_key', b.is_channel_key,
                              'ephemeral_public_key', b.ephemeral_public_key,
                              'ciphertext', b.ciphertext, 'nonce', b.nonce)
      INTO v_voice
      FROM bot_voice_keys b
     WHERE b.channel_id = p_channel AND b.bot_id = v_me
     ORDER BY b.key_version DESC
     LIMIT 1;
    RETURN jsonb_build_object('current_version', 0,
                              'my_keys', '[]'::jsonb,
                              'members_missing', '[]'::jsonb,
                              'bots_missing', '[]'::jsonb,
                              'my_voice_key', v_voice);
  END IF;

  v_state := channel_key_state(p_channel, v_me);
  v_current := COALESCE((v_state ->> 'current_version')::INTEGER, 0);

  -- Voice: the caller's own media key if it is a bot with one, and the bots
  -- that may speak here with no row at this version, or a row whose
  -- `is_channel_key` disagrees with their grant.
  IF v_type = 'voice' AND v_current > 0 THEN
    SELECT jsonb_build_object('key_version', v_current,
                              'is_channel_key', b.is_channel_key,
                              'ephemeral_public_key', b.ephemeral_public_key,
                              'ciphertext', b.ciphertext, 'nonce', b.nonce)
      INTO v_voice
      FROM bot_voice_keys b
     WHERE b.channel_id = p_channel AND b.bot_id = v_me
       AND b.key_version = v_current;

    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'bot_id', c.bot_id,
             'chat_public_key', c.chat_public_key,
             'may_listen', c.may_listen) ORDER BY c.bot_id), '[]'::jsonb)
      INTO v_bots
      FROM bot_voice_key_candidates c
      LEFT JOIN bot_voice_keys k
        ON k.channel_id = c.channel_id AND k.bot_id = c.bot_id
       AND k.key_version = v_current
     WHERE c.channel_id = p_channel
       AND (k.bot_id IS NULL OR k.is_channel_key <> c.may_listen);
  END IF;

  v_answer := jsonb_build_object(
    'current_version', v_current,
    'my_keys', COALESCE(v_state -> 'my_keys', '[]'::jsonb),
    'links', COALESCE(v_state -> 'links', '[]'::jsonb),
    'members_missing', COALESCE(v_state -> 'members_missing', '[]'::jsonb),
    'bots_missing', v_bots,
    'my_voice_key', v_voice);

  -- Who hears the call decides which key each bot in it is registered
  -- under, so a call reads it with the key rather than beside it.
  IF v_type = 'voice' THEN
    SELECT COALESCE(jsonb_agg(g.bot_id ORDER BY g.bot_id), '[]'::jsonb)
      INTO v_listening
      FROM bot_voice_grants g
      JOIN users u ON u.id = g.bot_id
     WHERE g.channel_id = p_channel AND NOT u.is_banned;
    v_answer := v_answer || jsonb_build_object('listening_bots', v_listening);
  END IF;

  RETURN v_answer;
END $$;

COMMENT ON FUNCTION public.my_channel_key(UUID) IS
  'The caller''s keys for one channel, as get_channel_key answers them: '
  'sealed rows, links, the current version, who lacks it, and in a voice '
  'channel the bots owed a media key and the bots allowed to hear it.';

-- ── Push notifications (admin) ──────────────────────────────
-- Whether push is on, and the relay id an admin needs to revoke the
-- credential on central. Never the secret: the admin held it once, in
-- transit, and re-enrolling is how it is replaced.
CREATE OR REPLACE FUNCTION public.push_status() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.admin_caller_server();
  v_relay  UUID;
BEGIN
  SELECT pc.relay_id INTO v_relay FROM push_config pc WHERE pc.server_id = v_server;
  RETURN jsonb_build_object('enabled', FOUND, 'relay_id', v_relay);
END $$;

-- A URL rather than a host: the relay's address is central's to choose.
CREATE OR REPLACE FUNCTION public.set_push_config(
  p_endpoint TEXT,
  p_relay_id UUID,
  p_secret   TEXT
) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.admin_caller_server();
BEGIN
  IF p_endpoint IS NULL OR p_endpoint !~ '^https://[^ ]+$'
     OR p_relay_id IS NULL
     OR p_secret IS NULL OR length(p_secret) < 16 THEN
    RAISE EXCEPTION 'missing_fields';
  END IF;

  INSERT INTO push_config (server_id, endpoint, relay_id, secret, updated_at)
  VALUES (v_server, p_endpoint, p_relay_id, p_secret, now())
  ON CONFLICT (server_id) DO UPDATE
    SET endpoint = EXCLUDED.endpoint,
        relay_id = EXCLUDED.relay_id,
        secret = EXCLUDED.secret,
        updated_at = EXCLUDED.updated_at;
  RETURN jsonb_build_object('enabled', true);
END $$;

-- The relay id comes back so the admin's client can revoke the credential on
-- central too; dropping the row already makes it unusable.
CREATE OR REPLACE FUNCTION public.clear_push_config() RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.admin_caller_server();
  v_relay  UUID;
BEGIN
  DELETE FROM push_config WHERE server_id = v_server RETURNING relay_id INTO v_relay;
  RETURN jsonb_build_object('enabled', false, 'relay_id', v_relay);
END $$;

-- ── A listing token (admin) ─────────────────────────────────
-- 256 bits, hex, returned once. Only its digest is stored; the token is in
-- this answer, the admin's client and central's request, never at rest.
CREATE OR REPLACE FUNCTION public.my_listing_token() RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public, extensions AS $$
DECLARE
  v_server  UUID := app.admin_caller_server();
  v_token   TEXT := encode(gen_random_bytes(32), 'hex');
  v_expires TIMESTAMPTZ;
BEGIN
  v_expires := issue_listing_token(auth.uid(), v_server,
                                   encode(digest(v_token, 'sha256'), 'hex'));
  RETURN jsonb_build_object('token', v_token,
                            'server_id', v_server,
                            'expires_at', v_expires);
END $$;

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.admin_caller_server() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.push_status() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.set_push_config(TEXT, UUID, TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.clear_push_config() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.my_listing_token() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.push_status() TO authenticated;
GRANT EXECUTE ON FUNCTION public.set_push_config(TEXT, UUID, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION public.clear_push_config() TO authenticated;
GRANT EXECUTE ON FUNCTION public.my_listing_token() TO authenticated;
