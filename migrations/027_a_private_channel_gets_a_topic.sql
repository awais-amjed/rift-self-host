-- ============================================================
-- Rift self-hosted server — 027: a private channel gets a topic of its own
-- ============================================================
-- A message in an **open** channel is announced once, to `server:<id>`, and
-- Realtime fans it out to whoever is listening. A message in a **private**
-- channel was announced once *per member who could see it* — a row in
-- `realtime.messages` each, written by the transaction that sent the
-- message.
--
-- Measured on a private channel reachable by 8,750 people (500 by seat, the
-- rest through a role the channel admits):
--
--   announce to an open channel ......    0.04 ms
--   announce to that private channel .  176    ms
--
-- Four thousand times the cost, and it scales with the membership: the
-- sender's own insert pays for everybody else's notification. A private
-- channel with 50,000 members would take about a second per message, in the
-- writing transaction, holding its locks the whole time.
--
-- The fan-out itself is not the problem — Realtime does the same number of
-- deliveries either way, and does them well (measured at ~97,000 a second).
-- The problem is doing the fan-out *in Postgres*, one INSERT at a time.
--
-- So a private channel now has a topic of its own, `channel:<channel id>`,
-- and the announcement is one row again whatever the membership. That is
-- exactly what `server:<id>` already does for open channels; there was never
-- a reason for private ones to work differently, beyond `server:<id>` being
-- too wide an audience for them.
--
-- ---------- what may be said there, and by whom ----------
--
-- Read by anyone `app.can_see_channel` admits — the same rule that decides
-- whether they may read the messages being announced, so the topic cannot
-- tell them anything the table would not.
--
-- **Written by nobody.** Every other topic here is writable by the members
-- who can join it, because clients send typing indicators and doorbells on
-- them. Nothing is sent here by a client, so nothing may be: a member who
-- could write to it could forge a `message` event naming an id, and send a
-- whole private channel off to re-read the database on request.
--
-- Typing stays on `chat:<channel id>`, which clients do write to. The two
-- are deliberately separate topics rather than one: what the database
-- asserts and what a member claims should not arrive by the same door.
--
-- ---------- what still goes to a person's own topic ----------
--
-- An ephemeral reply — a bot answering one member where nobody else sees it
-- — is still sent to `user:<id>`, because its audience is one person and not
-- a channel. `app.announce_message` decides that before it gets here.

-- ============================================================
-- 1. Who may join a channel's topic
-- ============================================================

CREATE OR REPLACE FUNCTION app.can_use_topic(p_topic TEXT, p_write BOOLEAN)
  RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_kind   TEXT := split_part(p_topic, ':', 1);
  v_rest   TEXT := substr(p_topic, length(split_part(p_topic, ':', 1)) + 2);
  v_me     UUID := auth.uid();
  v_server UUID;
BEGIN
  IF v_me IS NULL THEN
    RETURN FALSE;
  END IF;

  -- Before the ban check, on purpose: a banned member still hears their own
  -- topic, because that is how they learn the ban was lifted.
  IF v_kind = 'user' AND NOT p_write THEN
    RETURN v_rest = v_me::text;
  END IF;

  v_server := app.server_id();  -- null for a banned member, or a stranger
  IF v_server IS NULL THEN
    RETURN FALSE;
  END IF;

  CASE v_kind
    WHEN 'server', 'presence', 'voice' THEN
      RETURN v_rest = v_server::text;
    WHEN 'user' THEN
      -- Only a DM's typing indicator is sent here by a client; everything else
      -- on a user topic comes from the database.
      RETURN v_rest ~ '^[0-9a-f-]{36}$' AND app.is_co_member(v_rest::uuid);
    WHEN 'chat' THEN
      RETURN v_rest ~ '^[0-9a-f-]{36}$' AND app.can_see_channel(v_rest::uuid);
    WHEN 'channel' THEN
      -- Listening only. The database is the only thing that speaks here, and
      -- a member who could speak here could forge a message announcement to
      -- everyone in a private channel.
      RETURN NOT p_write
         AND v_rest ~ '^[0-9a-f-]{36}$'
         AND app.can_see_channel(v_rest::uuid);
    ELSE
      RETURN FALSE;
  END CASE;
END $$;

REVOKE ALL ON FUNCTION app.can_use_topic(TEXT, BOOLEAN) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.can_use_topic(TEXT, BOOLEAN) TO authenticated;

COMMENT ON FUNCTION app.can_use_topic(TEXT, BOOLEAN) IS
  'Whether the caller may join (p_write false) or send on (p_write true) a '
  'Realtime topic. `channel:<id>` is listen-only: the database speaks there.';

-- ============================================================
-- 2. Saying it once
-- ============================================================

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

  -- One row either way. An open channel reaches the whole server, a private
  -- one reaches its own topic, and Realtime does the fanning out — which is
  -- its job, and which it is much better at than a trigger is.
  IF v_private THEN
    PERFORM realtime.send(p_payload, p_event, 'channel:' || p_channel, true);
  ELSE
    PERFORM realtime.send(p_payload, p_event, 'server:' || v_server, true);
  END IF;

  -- 018's clause, unchanged. A bot joins neither of the topics above — it
  -- hears everything on its own, which is what keeps the SDK to one
  -- subscription (BOTS.md §5) — so it is still told one at a time. That
  -- fanout is bounded by the grants on this channel rather than by its
  -- membership, which is a handful, and is why it can stay a loop.
  PERFORM realtime.send(p_payload, p_event, 'user:' || g.bot_id, true)
     FROM bot_channel_keys g
    WHERE g.channel_id = p_channel;
END $$;

REVOKE ALL ON FUNCTION app.announce_to_channel(UUID, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated;

COMMENT ON FUNCTION app.announce_to_channel(UUID, TEXT, JSONB) IS
  'Announce something about a channel to whoever may read it: the server''s '
  'topic for an open channel, the channel''s own for a private one. One row '
  'in either case — the membership does not appear in the cost.';
