-- ============================================================
-- Rift self-hosted server — 018: a bot is told, instead of asking
-- ============================================================
-- A bot polls. Every two seconds it asks for messages addressed to it, asks
-- again for its DMs, and asks once more for each channel it watches — so a bot
-- watching two channels is about two queries a second, awake or not, and a
-- server running ten of them carries twenty. That was the only way it could
-- work: 017 gave members broadcasts, but a bot is in none of the audiences
-- those go to.
--
-- Now it is. Everything a bot may hear arrives on its own topic, `user:<bot
-- id>`, and it needs no other:
--
--   * a message addressed to it (`to_bot`), wherever it was written;
--   * an interaction — a button press — which reaches nobody else at all;
--   * every message in a channel it has been granted (`bot_channel_keys`),
--     which is what "watching" means;
--   * a DM to it, which 017's dm_messages trigger already sends.
--
-- The SDK keeps a slow poll behind this as a backstop. A broadcast is
-- best-effort by design, and a bot that misses one and waits forever for the
-- next is a bot that has quietly stopped working.

-- ---------- granted bots hear the channels they watch ----------
-- 017's version, with the grant holders added to both branches: a grant is
-- read access to a channel the bot is not a member of, and for a public
-- channel it is the only way a bot is in the audience at all.

CREATE OR REPLACE FUNCTION app.announce_to_channel(
  p_channel UUID,
  p_event   TEXT,
  p_payload JSONB
) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server  UUID;
  v_private BOOLEAN;
BEGIN
  SELECT c.server_id, c.is_private INTO v_server, v_private
    FROM channels c WHERE c.id = p_channel;
  IF v_server IS NULL THEN
    RETURN;
  END IF;

  IF NOT v_private THEN
    PERFORM realtime.send(p_payload, p_event, 'server:' || v_server, true);
  ELSE
    PERFORM realtime.send(p_payload, p_event, 'user:' || member.user_id, true)
       FROM (SELECT cm.user_id FROM channel_members cm
              WHERE cm.channel_id = p_channel
             UNION
             SELECT mr.user_id FROM channel_role_access cra
               JOIN member_roles mr ON mr.role_id = cra.role_id
              WHERE cra.channel_id = p_channel) member;
  END IF;

  -- Bots are never in the member fanout above, and do not join the server's
  -- topic: a bot hears only its own.
  PERFORM realtime.send(p_payload, p_event, 'user:' || g.bot_id, true)
     FROM bot_channel_keys g
    WHERE g.channel_id = p_channel;
END $$;

REVOKE ALL ON FUNCTION app.announce_to_channel(UUID, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated;

-- ---------- a message addressed to a bot reaches that bot ----------
-- 017's version, with the two cases a bot has that a member does not.
--
-- An interaction is a button press: `messages_select` shows it to the presser
-- and to the bot alone, so it goes to the bot alone. 017 dropped it entirely,
-- which was right while nothing listened and wrong the moment something did.
--
-- An addressed message (`to_bot`) is an ordinary message that members can see
-- too, so the channel still hears it; the bot is told as well, because being
-- addressed is not the same as being granted and a bot usually holds no grant
-- on the channel somebody summoned it in.

CREATE OR REPLACE FUNCTION app.announce_message() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_row     messages%ROWTYPE;
  v_event   TEXT;
  v_payload JSONB;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_row := OLD;
  ELSE
    v_row := NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    v_event := 'message';
    v_payload := jsonb_build_object(
      'id',           v_row.id,
      'channel_id',   v_row.channel_id,
      'sender_id',    v_row.sender_id,
      'mentions',     COALESCE(to_jsonb(v_row.mentions), '[]'::jsonb),
      'mentions_all', COALESCE(v_row.mentions_all, false));
  ELSE
    v_event := 'message_changed';
    v_payload := jsonb_build_object(
      'message_id', v_row.id,
      'channel_id', v_row.channel_id);
  END IF;

  -- Whoever it is for, and nobody else. An interaction with no bot to answer
  -- it is for nobody, and saying so to a topic called `user:` is worse than
  -- saying nothing.
  IF v_row.is_interaction OR v_row.ephemeral_for IS NOT NULL THEN
    IF COALESCE(v_row.ephemeral_for, v_row.to_bot) IS NOT NULL THEN
      PERFORM realtime.send(v_payload, v_event,
        'user:' || COALESCE(v_row.ephemeral_for, v_row.to_bot), true);
    END IF;
    RETURN NULL;
  END IF;

  PERFORM app.announce_to_channel(v_row.channel_id, v_event, v_payload);
  IF v_row.to_bot IS NOT NULL THEN
    PERFORM realtime.send(v_payload, v_event, 'user:' || v_row.to_bot, true);
  END IF;
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION app.announce_message() FROM PUBLIC, anon, authenticated;
