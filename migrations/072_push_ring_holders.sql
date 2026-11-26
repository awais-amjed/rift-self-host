-- ============================================================
-- Rift self-hosted server — 072: a push ring starts from the phones
-- ============================================================
-- Found in the speed re-review, Nov 26 2026.
--
-- With push set up, every message sent works out, inside the sender's own
-- INSERT, who to wake: `app.channel_ring_targets` lists every member caught
-- up in the channel, and `ring_devices` then keeps the few of them with a
-- phone registered. In a busy channel of a big server that list is nearly
-- everybody: 48,000 members worked out, joined to `users` and thrown away,
-- 118–150 ms on every message.
--
--   * `app.channel_ring_tokens` answers the tokens themselves, asking the
--     same questions of each member holding a device: on the server, not
--     the sender, not banned or a bot, let into a private channel, and
--     caught up (or named, or the channel's only writer). Written as a join,
--     the planner starts from whichever side is smaller. 3,000 holders:
--     11 ms; 25,000: no worse than before.
--   * `ring_channel_members` posts them through `app.push_tokens`, which
--     `ring_devices` now shares.
--   * `app.channel_ring_targets` stays, and the test suite holds the two to
--     the same answer.

-- ── The tokens to wake for one message ──────────────────────
CREATE OR REPLACE FUNCTION app.channel_ring_tokens(p_message messages)
  RETURNS TEXT[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server_id UUID;
  v_private   BOOLEAN;
  v_eligible  UUID[];
  v_t         RECORD;
  v_everyone  BOOLEAN;
  v_tokens    TEXT[];
BEGIN
  SELECT c.server_id, c.is_private INTO v_server_id, v_private
    FROM channels c WHERE c.id = p_message.channel_id;
  IF v_server_id IS NULL THEN RETURN NULL; END IF;

  IF v_private THEN
    v_eligible := app.channel_audience(p_message.channel_id);
    IF v_eligible IS NULL OR cardinality(v_eligible) = 0 THEN RETURN NULL; END IF;
  END IF;

  v_t := app.unread_thresholds(p_message.channel_id, p_message.id);
  -- The first message in the channel, or one naming everyone: everybody.
  v_everyone := v_t.o_newest IS NULL OR p_message.mentions_all;

  -- `app.channel_ring_targets`, asked of each holder. Its sender-of-the-
  -- newest needs only the newest somebody else wrote, which is never past
  -- the newest itself, so one test with that bound covers both of its
  -- cursor branches.
  SELECT array_agg(d.token) INTO v_tokens
    FROM device_tokens d
    JOIN users u ON u.id = d.user_id
   WHERE u.server_id = v_server_id
     AND u.id IS DISTINCT FROM p_message.sender_id
     AND NOT u.is_banned AND NOT u.is_bot
     AND (p_message.ephemeral_for IS NULL OR u.id = p_message.ephemeral_for)
     AND (NOT v_private OR u.id = ANY (v_eligible))
     AND (v_everyone
          OR u.id = ANY (COALESCE(p_message.mentions, '{}'))
          OR (u.id = v_t.o_newest_by AND v_t.o_newest_other IS NULL)
          OR EXISTS (SELECT 1 FROM read_state r
                      WHERE r.user_id = u.id
                        AND r.scope = 'channel'
                        AND r.scope_id = p_message.channel_id
                        AND r.last_read_id >= CASE WHEN u.id = v_t.o_newest_by
                                                   THEN COALESCE(v_t.o_newest_other, 0)
                                                   ELSE v_t.o_newest END));
  RETURN v_tokens;
END $$;

COMMENT ON FUNCTION app.channel_ring_tokens(messages) IS
  'The device tokens a message wakes: app.channel_ring_targets, asked of '
  'each member holding a device rather than of everyone caught up.';

-- ── Posting tokens to the relay ─────────────────────────────
CREATE OR REPLACE FUNCTION app.push_tokens(p_server_id UUID, p_tokens TEXT[])
  RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, extensions AS $$
DECLARE
  v_cfg push_config;
BEGIN
  IF p_tokens IS NULL OR cardinality(p_tokens) = 0 THEN RETURN; END IF;

  SELECT * INTO v_cfg FROM push_config WHERE server_id = p_server_id;
  IF v_cfg IS NULL THEN RETURN; END IF;   -- push not enabled on this server

  PERFORM net.http_post(
    url     := v_cfg.endpoint,
    headers := jsonb_build_object(
                 'Content-Type', 'application/json',
                 'x-push-secret', v_cfg.secret
               ),
    body    := jsonb_build_object(
                 'relay_id', v_cfg.relay_id,
                 'tokens',   to_jsonb(p_tokens)
               )
  );
END $$;

CREATE OR REPLACE FUNCTION public.ring_devices(p_server_id UUID, p_user_ids UUID[])
  RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, extensions AS $$
DECLARE
  v_tokens TEXT[];
BEGIN
  IF p_user_ids IS NULL OR cardinality(p_user_ids) = 0 THEN RETURN; END IF;
  SELECT array_agg(token) INTO v_tokens
    FROM device_tokens WHERE user_id = ANY (p_user_ids);
  PERFORM app.push_tokens(p_server_id, v_tokens);
END $$;

-- ── A message sent ──────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.ring_channel_members()
  RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server_id UUID;
BEGIN
  IF NEW.is_interaction THEN RETURN NEW; END IF;

  SELECT c.server_id INTO v_server_id
    FROM channels c WHERE c.id = NEW.channel_id;
  IF v_server_id IS NULL THEN RETURN NEW; END IF;
  IF NOT app.push_enabled(v_server_id) THEN RETURN NEW; END IF;

  PERFORM app.push_tokens(v_server_id, app.channel_ring_tokens(NEW));
  RETURN NEW;
END $$;

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.channel_ring_tokens(messages) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.push_tokens(UUID, TEXT[]) FROM PUBLIC, anon, authenticated;
