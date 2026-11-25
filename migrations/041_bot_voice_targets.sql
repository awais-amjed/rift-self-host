-- ============================================================
-- Rift self-hosted server — 041: sending a bot away names a bot
-- ============================================================
-- Found in the app's review of voice listeners, Nov 25 2026.
--
-- `dismiss_bot_from_voice` and `revoke_bot_voice_listen` never asked whether
-- the user they were given was a bot. Each deletes a row that only a bot can
-- have, so for a person they deleted nothing and answered `ok` — and then the
-- edge function in front of them acted on LiveKit with that answer:
--
--   * `set_bot_voice_summon` (`summon: false`) removes every connection in the
--     room whose identity is that user. `dismiss_bot_from_voice` asks only that
--     the caller can see the channel, so any member could throw anybody out of
--     a call, as often as they liked, where `kick_user` needs a manager.
--   * `set_bot_voice_listen` (`listen: false`) rewrites the user's live
--     permissions: no subscribing, and the microphone as the channel's Speak
--     has it. A `MANAGE_BOTS` holder could deafen a person, and hand a mic
--     back to someone a moderator had muted.
--
-- Both now refuse `no_such_bot` unless the user is a bot of this server,
-- before anything is deleted, and the edge functions already stop on a
-- refusal before they touch LiveKit. A banned bot still counts: sending one
-- away or taking its hearing is exactly what an admin may want then.
-- `summon_bot_to_voice` and `grant_bot_voice_listen` already checked.
--
-- Also: a bot's ban or unban now rings `voice_bots`. A ban keeps its listening
-- grant and its summons, and `voice_listeners` hides a banned bot, so the
-- lists change with no row in either table changing, and nothing rang. A
-- client that read the lists during a ban showed no "can hear" marker after
-- the unban, while the bot's next token could subscribe again.

-- ── Sending a bot away ──────────────────────────────────────

CREATE OR REPLACE FUNCTION dismiss_bot_from_voice(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.can_see_channel(p_channel) AND p_bot IS DISTINCT FROM auth.uid() THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot
                    AND u.server_id = app.server_id()) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  DELETE FROM bot_voice_summons
   WHERE channel_id = p_channel AND bot_id = p_bot;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ── Taking a bot's hearing away ─────────────────────────────

CREATE OR REPLACE FUNCTION revoke_bot_voice_listen(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot
                    AND u.server_id = app.server_id()) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  DELETE FROM bot_voice_grants
   WHERE channel_id = p_channel AND bot_id = p_bot;

  -- The `set_bot_voice_listen` edge function pushes the new permission onto
  -- the bot's live connection; the row alone leaves its token hearing.
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ── A bot's ban changes who can hear ────────────────────────

CREATE OR REPLACE FUNCTION app.announce_bot_ban_voice() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF EXISTS (SELECT 1 FROM bot_voice_grants g WHERE g.bot_id = NEW.id)
     OR EXISTS (SELECT 1 FROM bot_voice_summons s WHERE s.bot_id = NEW.id) THEN
    PERFORM realtime.send('{}'::jsonb, 'voice_bots', 'server:' || NEW.server_id, true);
  END IF;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS users_bot_ban_voice ON users;
CREATE TRIGGER users_bot_ban_voice AFTER UPDATE OF is_banned ON users
  FOR EACH ROW WHEN (NEW.is_bot AND OLD.is_banned IS DISTINCT FROM NEW.is_banned)
  EXECUTE FUNCTION app.announce_bot_ban_voice();

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION dismiss_bot_from_voice(UUID, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION dismiss_bot_from_voice(UUID, UUID) TO authenticated;
REVOKE ALL ON FUNCTION revoke_bot_voice_listen(UUID, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION revoke_bot_voice_listen(UUID, UUID) TO authenticated;
REVOKE ALL ON FUNCTION app.announce_bot_ban_voice() FROM PUBLIC, anon, authenticated;
