-- ============================================================
-- Rift self-hosted server — 038: a summon outliving its reason
-- ============================================================
-- 037 gave a summon two ways to end: somebody dismisses it, or the channel or
-- the bot is deleted. Both are somebody deciding. Nothing ended one because the
-- *reason* for it had gone, and three things fall out of that.
--
--   1. **A channel made private kept its summons.** 031 already drops a
--      listening grant when a channel closes, for the obvious reason: the
--      people who granted it are not necessarily the people in the room now.
--      A summon is the same shape and was left out, so a bot summoned into a
--      public call could still take a token for it after it was closed —
--      `channel_joinable_by` reads the summon and never asks about privacy.
--      That is a privacy boundary crossed by a stale row.
--
--   2. **A summon outlived the call.** Say `/play` while the bot is down and
--      everybody goes home: the row waits. The bot cannot arrive at once,
--      because dismissing took its media key — but the next time a member is in
--      that channel their client seals a new one, and the bot turns up in a
--      conversation nobody invited it to, hours later.
--
--   3. **Nobody could see one.** "Send away" lives on the participant menu,
--      which needs the bot to be *in* the call. A summon whose bot never joined
--      was invisible and unclearable. `voice_summons` below is the view a
--      client can draw it from, the sibling of `voice_listeners`.
--
-- ---------- why an hour, and why not a disconnect hook ----------
--
-- The exact end of a call is LiveKit's to know, not this database's, and asking
-- it would mean a webhook and a new failure mode for a tidy-up. An age is worse
-- at the edges and cannot break: a summon is a request to come and play *now*,
-- so one that has sat unused for an hour has been answered by events. A bot
-- that is already connected is unaffected — dropping the row takes its right to
-- a *new* token, and it is the dismiss path that disconnects.
--
-- Riding on the same hourly job as the invite sweep for the same reason: one
-- schedule to reason about.

-- ============================================================
-- 1. Closing a channel takes its summons with it
-- ============================================================
-- Deliberately not `AFTER UPDATE OF is_private`: 020's `set_channel_private` is
-- the only writer, and matching 031's trigger shape exactly is worth more here
-- than saving a comparison.

CREATE OR REPLACE FUNCTION drop_bot_voice_summons_when_closed()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF NEW.is_private AND NOT OLD.is_private THEN
    DELETE FROM bot_voice_summons WHERE channel_id = NEW.id;
  END IF;
  RETURN NULL;
END; $$;

REVOKE ALL ON FUNCTION drop_bot_voice_summons_when_closed() FROM PUBLIC;

DROP TRIGGER IF EXISTS channels_drop_bot_voice_summons ON channels;
CREATE TRIGGER channels_drop_bot_voice_summons
  AFTER UPDATE ON channels
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_summons_when_closed();

-- ============================================================
-- 2. And so does an hour of nobody using it
-- ============================================================

CREATE OR REPLACE FUNCTION app.expire_bot_voice_summons() RETURNS VOID
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  DELETE FROM bot_voice_summons WHERE summoned_at < now() - interval '1 hour'
$$;

REVOKE ALL ON FUNCTION app.expire_bot_voice_summons() FROM PUBLIC, anon, authenticated;

SELECT cron.unschedule('expire-bot-voice-summons')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'expire-bot-voice-summons');

SELECT cron.schedule(
  'expire-bot-voice-summons',
  '0 * * * *',
  $$SELECT app.expire_bot_voice_summons()$$
);

-- ============================================================
-- 3. What a client draws them from
-- ============================================================
-- The sibling of `voice_listeners` (031), and the same reasoning: the table is
-- readable, but a marker needs a name rather than an id, and joining `users`
-- from every client that draws a channel row is a second query per channel.
--
-- `security_invoker`, so `bot_voice_summons_select` decides who sees a row —
-- the room, or the bot itself.

CREATE OR REPLACE VIEW voice_summons
  WITH (security_invoker = true) AS
  SELECT s.channel_id,
         s.bot_id,
         u.display_name AS bot_name,
         s.summoned_by,
         s.summoned_at
    FROM bot_voice_summons s
    JOIN users u ON u.id = s.bot_id
   WHERE NOT u.is_banned;

COMMENT ON VIEW voice_summons IS
  'Bots asked into each voice channel, with the name to show. Unlike '
  'voice_listeners this is not a warning — a summoned bot publishes and cannot '
  'hear. It is what makes a summon whose bot never turned up visible, and '
  'therefore dismissable.';

REVOKE ALL ON voice_summons FROM anon;
GRANT SELECT ON voice_summons TO authenticated;
