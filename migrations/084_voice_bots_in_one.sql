-- ============================================================
-- Rift self-hosted server — 084: a `voice_bots` ring is one read
-- ============================================================
-- Found in the review of call counts, Nov 26 2026 (its #13).
--
-- A `voice_bots` ring — a bot's ears granted or taken, a summon made or
-- dropped — has every online member read the server's listeners and its
-- summons again: two requests each, `voice_listeners` and `voice_summons`,
-- at the same moment, for one sidebar.
--
-- `voice_bots()` answers both, `{listeners: [...], summons: [...]}`, each
-- row `{channel_id, bot_id, bot_name}` in `bot_name` order, as the two
-- reads did. Read as the caller, so `bot_voice_grants_select` and
-- `bot_voice_summons_select` decide what is in it, as before. An app that
-- finds it missing (`PGRST202`) reads the two views as before.

CREATE OR REPLACE FUNCTION public.voice_bots()
  RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
BEGIN
  RETURN jsonb_build_object(
    'listeners', COALESCE((
      SELECT jsonb_agg(jsonb_build_object('channel_id', l.channel_id,
                                          'bot_id', l.bot_id,
                                          'bot_name', l.bot_name)
                       ORDER BY l.bot_name)
        FROM voice_listeners l), '[]'::jsonb),
    'summons', COALESCE((
      SELECT jsonb_agg(jsonb_build_object('channel_id', s.channel_id,
                                          'bot_id', s.bot_id,
                                          'bot_name', s.bot_name)
                       ORDER BY s.bot_name)
        FROM voice_summons s), '[]'::jsonb));
END $$;

COMMENT ON FUNCTION public.voice_bots() IS
  'The server''s voice listeners and summons, as voice_listeners and '
  'voice_summons answer them, in one read. Read as the caller.';

REVOKE ALL ON FUNCTION public.voice_bots() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.voice_bots() TO authenticated;
