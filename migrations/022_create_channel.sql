-- ============================================================
-- Rift self-hosted server — 022: making a channel is one statement
-- ============================================================
-- 020 let a member create a private channel, and then made it impossible to
-- read back the one they had just made.
--
-- `INSERT ... RETURNING` applies the **SELECT** policy to the row it hands back,
-- and `channels_select` now asks whether the caller is in the channel. The
-- creator is seated by an AFTER INSERT trigger, which has not run when RETURNING
-- is evaluated — so the insert succeeded, the read of its own row did not, and
-- Postgres reported the whole thing as `new row violates row-level security
-- policy for table "channels"`. Which is true, and names the wrong policy.
--
-- Found by clicking the button.
--
-- Three fixes were possible and only one of them is honest. Widening
-- `channels_select` to include whoever created a channel would mean recording a
-- creator and then explaining why they can still see a room they were removed
-- from. Dropping the RETURNING would leave the client looking its own channel
-- up by name. So: one function that makes the channel, seats the people, and
-- hands the row back — which is what the two round trips were pretending to be
-- anyway, minus the moment in between where the channel exists and nobody is
-- in it.

CREATE OR REPLACE FUNCTION create_channel(
  p_name    TEXT,
  p_type    TEXT,
  p_private BOOLEAN DEFAULT false,
  p_members UUID[]  DEFAULT '{}'
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server  UUID := app.server_id();
  v_channel channels%ROWTYPE;
BEGIN
  IF v_server IS NULL THEN
    RAISE EXCEPTION 'not_a_member';
  END IF;

  -- The same split the policy makes, checked here so the failure has a name.
  -- A private channel is how a few people talk without asking permission;
  -- one the whole server can see is a change to the server's shape.
  IF p_private THEN
    IF NOT app.has_perm('CREATE_PRIVATE_CHANNEL') THEN
      RAISE EXCEPTION 'not_authorized';
    END IF;
  ELSIF NOT app.has_perm('MANAGE_CHANNELS') THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;

  IF length(btrim(p_name)) = 0 THEN
    RAISE EXCEPTION 'bad_name';
  END IF;
  IF p_type NOT IN ('text', 'voice') THEN
    RAISE EXCEPTION 'bad_type';
  END IF;

  INSERT INTO channels (server_id, name, channel_type, is_private)
  VALUES (v_server, btrim(p_name), p_type::channel_type, p_private)
  RETURNING * INTO v_channel;

  -- `seed_private_channel_owner` has already seated the caller by the time this
  -- runs, so the members list only has to add the others — and cannot remove
  -- the creator by omitting them, which is the mistake the two-call version was
  -- one forgotten id away from.
  IF p_private AND array_length(p_members, 1) IS NOT NULL THEN
    INSERT INTO channel_members (channel_id, user_id, added_by)
    SELECT v_channel.id, u.id, auth.uid()
      FROM users u
     WHERE u.id = ANY (p_members)
       AND u.server_id = v_server
       AND NOT u.is_banned
       -- A bot is keyed by `grant_bot_channel_key` and nothing else.
       AND NOT u.is_bot
    ON CONFLICT DO NOTHING;
  END IF;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'id', v_channel.id,
    'name', v_channel.name,
    'channel_type', v_channel.channel_type,
    'is_private', v_channel.is_private
  );
EXCEPTION WHEN unique_violation THEN
  RETURN jsonb_build_object('reason', 'name_taken');
END; $$;

REVOKE ALL ON FUNCTION create_channel(TEXT, TEXT, BOOLEAN, UUID[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION create_channel(TEXT, TEXT, BOOLEAN, UUID[]) TO authenticated;
