-- ============================================================
-- Rift self-hosted server — 063: a member's key reads are database calls
-- ============================================================
-- Found in the review of call counts, Nov 26 2026.
--
-- Opening a channel, joining a call and every `sweep` ring asked an edge
-- function: `get_channel_key` (five database round trips, seven in a voice
-- channel) and `sweep_channel_keys` (two). Each went through the functions
-- runtime, which loads the caller's row to check the ban, then asks the
-- database what 012 and 047 already work out there. The answer was always
-- the database's; the function only carried it.
--
--   * `my_key_work()` is `sweep_channel_keys`: the caller's key work, from
--     `channel_key_work`.
--   * `my_channel_key(p_channel)` is `get_channel_key`: the caller's keys
--     for one channel, from `channel_key_state`, and in a voice channel the
--     bots still owed a media key and, for a bot asking, its own. A summoned
--     bot that cannot see the channel gets its own sealed key and nothing
--     else, as before.
--
-- Both are definers that ask about the caller and nobody else, and refuse
-- whoever the edge functions refused: no member row, a server being deleted
-- (`user_not_found`), a ban (`user_banned`), a channel on another server or
-- out of sight (`channel_not_found`). They answer in the edge functions'
-- shape, so the app reads either. The edge functions stay, for apps and bot
-- SDKs that have not moved.

-- ── Who is asking ───────────────────────────────────────────
-- The caller's server, or the refusal the edge functions gave.
CREATE OR REPLACE FUNCTION app.key_caller_server() RETURNS UUID
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
  v_banned BOOLEAN;
BEGIN
  SELECT u.server_id, u.is_banned INTO v_server, v_banned
    FROM users u JOIN servers s ON s.id = u.server_id
   WHERE u.id = auth.uid() AND s.deleting_since IS NULL;
  IF v_server IS NULL THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;
  IF v_banned THEN
    RAISE EXCEPTION 'user_banned';
  END IF;
  RETURN v_server;
END $$;

-- ── The sweep ───────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.my_key_work() RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_answer JSONB;
BEGIN
  PERFORM app.key_caller_server();
  v_answer := channel_key_work(auth.uid());
  RETURN jsonb_build_object(
    'work', COALESCE(v_answer -> 'work', '[]'::jsonb),
    'more', COALESCE((v_answer ->> 'more')::boolean, false));
END $$;

COMMENT ON FUNCTION public.my_key_work() IS
  'The caller''s key work, as sweep_channel_keys answers it: channels to '
  'seal for, mint or rotate. Volatile: it takes the leases that spread the '
  'work across members.';

-- ── One channel's keys ──────────────────────────────────────
CREATE OR REPLACE FUNCTION public.my_channel_key(p_channel UUID) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me      UUID := auth.uid();
  v_server  UUID := app.key_caller_server();
  v_type    TEXT;
  v_state   JSONB;
  v_current INTEGER;
  v_voice   JSONB;
  v_bots    JSONB := '[]'::jsonb;
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

  RETURN jsonb_build_object(
    'current_version', v_current,
    'my_keys', COALESCE(v_state -> 'my_keys', '[]'::jsonb),
    'links', COALESCE(v_state -> 'links', '[]'::jsonb),
    'members_missing', COALESCE(v_state -> 'members_missing', '[]'::jsonb),
    'bots_missing', v_bots,
    'my_voice_key', v_voice);
END $$;

COMMENT ON FUNCTION public.my_channel_key(UUID) IS
  'The caller''s keys for one channel, as get_channel_key answers them: '
  'sealed rows, links, the current version, who lacks it, and in a voice '
  'channel the bots owed a media key.';

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.key_caller_server() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.my_key_work() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.my_channel_key(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.my_key_work() TO authenticated;
GRANT EXECUTE ON FUNCTION public.my_channel_key(UUID) TO authenticated;
