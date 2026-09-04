-- ============================================================
-- Rift self-hosted server — 010: push notifications
-- ============================================================
-- A phone stops running Rift the moment Android decides it has been away long
-- enough, and every local notification stops with it. Only a push wakes it.
--
-- **This server cannot send one.** An FCM registration token is scoped to the
-- Firebase project the *app* was built against, so waking a Rift install needs
-- Rift's credentials — which an operator running their own server does not
-- have and must not be given. So the ring is relayed: this server asks central
-- to forward it, over a credential the operator's admin enrolled once. What
-- central learns from that is a device token and a moment: not who sent the
-- message, not what it said, not which server or channel it was in.
--
-- The push itself carries nothing at all — see 009 on central for the whole
-- argument. It is a doorbell; the phone holds the keys and reads the message
-- itself once it is awake.

CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;

-- ---------- where a member can be reached ----------
-- A row is a device, not a person: the same account on a phone and a tablet is
-- two rows and both should ring. The token is the key because FCM hands the
-- same one back to a reinstalled app, and a device that changes hands must
-- replace the previous owner's row rather than accumulate beside it.

CREATE TABLE IF NOT EXISTS device_tokens (
  token      TEXT        PRIMARY KEY,
  user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  platform   TEXT        NOT NULL CHECK (platform IN ('android', 'ios', 'web')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_tokens_user ON device_tokens (user_id);

-- Stamped rather than accepted from the client, the same way `messages` stamps
-- its sender: a client that could name the owner could register its token
-- against somebody else's account and be woken for that person's messages.
CREATE OR REPLACE FUNCTION stamp_device_owner()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  -- The service role has no `auth.uid()` and is not a client to be constrained
  -- — the same exemption `attest_dm` makes on central, and what lets a
  -- migration or an operator seed a row at all.
  IF auth.uid() IS NOT NULL THEN
    NEW.user_id := auth.uid();
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS device_tokens_stamp ON device_tokens;
CREATE TRIGGER device_tokens_stamp BEFORE INSERT OR UPDATE ON device_tokens
  FOR EACH ROW EXECUTE FUNCTION stamp_device_owner();

ALTER TABLE device_tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS device_tokens_own ON device_tokens;
CREATE POLICY device_tokens_own ON device_tokens FOR ALL TO authenticated
  USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

REVOKE ALL ON device_tokens FROM anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON device_tokens TO authenticated;

-- ---------- the relay credential ----------
-- Per server, not per project: one Supabase project can host several servers
-- (001), and each is a separate community whose admin enrolled separately.
--
-- RLS with no policy at all is the point. The secret is what proves a forward
-- request came from this server; the triggers below reach it as SECURITY
-- DEFINER and no session ever can — not even the admin who configured it, who
-- had it once, at enrolment, and does not need it again.

CREATE TABLE IF NOT EXISTS push_config (
  server_id  UUID        PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
  endpoint   TEXT        NOT NULL,
  relay_id   UUID        NOT NULL,
  secret     TEXT        NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE push_config ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON push_config FROM anon, authenticated;

-- ---------- ringing ----------
-- `net.http_post` queues and returns immediately. The push must not be able to
-- slow down, or fail, the send that caused it: a delivered message with no
-- doorbell is a far smaller problem than a message that could not be sent
-- because a push gateway was down.
CREATE OR REPLACE FUNCTION ring_devices(p_server_id UUID, p_user_ids UUID[])
  RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_cfg    push_config;
  v_tokens TEXT[];
BEGIN
  IF p_user_ids IS NULL OR cardinality(p_user_ids) = 0 THEN RETURN; END IF;

  SELECT * INTO v_cfg FROM push_config WHERE server_id = p_server_id;
  IF v_cfg IS NULL THEN RETURN; END IF;   -- push not enabled on this server

  SELECT array_agg(token) INTO v_tokens
    FROM device_tokens WHERE user_id = ANY (p_user_ids);
  IF v_tokens IS NULL THEN RETURN; END IF;

  PERFORM net.http_post(
    url     := v_cfg.endpoint,
    headers := jsonb_build_object(
                 'Content-Type', 'application/json',
                 'x-push-secret', v_cfg.secret
               ),
    body    := jsonb_build_object(
                 'relay_id', v_cfg.relay_id,
                 'tokens',   to_jsonb(v_tokens)
               )
  );
END; $$;

-- ---------- who to ring ----------
-- Only on the transition from "nothing unread here" to "something unread
-- here", per conversation. A doorbell says *look again*; it says nothing new
-- when the badge is already lit, and the phone reads everything unread when it
-- wakes, so a second ring during a burst adds no information and costs a wake,
-- a relay call and a little of somebody's battery.
--
-- The consequence worth knowing: a member who has never opened a channel that
-- already had messages is permanently in the "unread" state there, and so is
-- never rung for it. That is the same answer their badge gives, and pushing
-- someone about a channel they have never looked at is not obviously a
-- service.

CREATE OR REPLACE FUNCTION has_unread_before(
  p_user_id UUID, p_scope read_scope, p_scope_id UUID, p_before BIGINT
) RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = public AS $$
  SELECT CASE p_scope
    WHEN 'channel' THEN EXISTS (
      SELECT 1 FROM messages m
       WHERE m.channel_id = p_scope_id
         AND m.sender_id <> p_user_id
         AND m.id < p_before
         AND m.id > COALESCE((SELECT r.last_read_id FROM read_state r
                               WHERE r.user_id = p_user_id AND r.scope = 'channel'
                                 AND r.scope_id = p_scope_id), 0))
    ELSE EXISTS (
      SELECT 1 FROM dm_messages d
       WHERE d.recipient_id = p_user_id
         AND d.sender_id = p_scope_id
         AND d.id < p_before
         AND d.id > COALESCE((SELECT r.last_read_id FROM read_state r
                               WHERE r.user_id = p_user_id AND r.scope = 'dm'
                                 AND r.scope_id = p_scope_id), 0))
  END;
$$;

CREATE OR REPLACE FUNCTION ring_dm_recipient()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
BEGIN
  IF has_unread_before(NEW.recipient_id, 'dm', NEW.sender_id, NEW.id) THEN
    RETURN NEW;
  END IF;
  SELECT server_id INTO v_server_id FROM users WHERE id = NEW.recipient_id;
  PERFORM ring_devices(v_server_id, ARRAY[NEW.recipient_id]);
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS dm_messages_ring ON dm_messages;
CREATE TRIGGER dm_messages_ring AFTER INSERT ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION ring_dm_recipient();

-- Every member of the server except the sender. There is no per-channel
-- membership table yet — a member is in every channel — so the server's roster
-- is the channel's roster, and the unread gate above is what keeps that from
-- meaning "ring everyone, every message".
CREATE OR REPLACE FUNCTION ring_channel_members()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
  v_targets   UUID[];
BEGIN
  SELECT server_id INTO v_server_id FROM channels WHERE id = NEW.channel_id;
  IF v_server_id IS NULL THEN RETURN NEW; END IF;

  SELECT array_agg(u.id) INTO v_targets
    FROM users u
   WHERE u.server_id = v_server_id
     AND u.id <> NEW.sender_id
     AND NOT u.is_banned
     AND NOT has_unread_before(u.id, 'channel', NEW.channel_id, NEW.id);

  PERFORM ring_devices(v_server_id, v_targets);
  RETURN NEW;
END; $$;

DROP TRIGGER IF EXISTS messages_ring ON messages;
CREATE TRIGGER messages_ring AFTER INSERT ON messages
  FOR EACH ROW EXECUTE FUNCTION ring_channel_members();

-- ---------- forgetting a device ----------
-- FCM tells the sender when a token is dead, but the sender here is central,
-- relaying for a database it holds no credentials for — and having it report
-- back which of a server's tokens had died would tell it which members had
-- uninstalled the app. So this side sweeps on staleness instead: the client
-- re-registers on every sign-in, so a row that has not been touched in two
-- months belongs to a device that has not opened Rift in two months.

SELECT cron.unschedule('cleanup-stale-device-tokens')
  WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'cleanup-stale-device-tokens');

SELECT cron.schedule(
  'cleanup-stale-device-tokens',
  '30 4 * * *',
  $$DELETE FROM device_tokens WHERE updated_at < now() - interval '60 days'$$
);
