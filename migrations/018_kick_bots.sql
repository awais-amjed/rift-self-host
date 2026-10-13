-- ============================================================
-- Rift self-hosted server — 018: a bot can be kicked
-- ============================================================
-- `kick_member` refused a bot (`cannot_kick_bot`), on the grounds that a bot
-- is removed from the Bots page and never invited back. The Bots page never
-- had a remove, so the only way to get a bot off a server was a ban, which
-- leaves it listed as banned and has no way back short of lifting it.
-- Reported Oct 13: "I can ban it, but not remove it".
--
-- Now a bot is kicked like anybody: locked out with `kicked_at` beside the
-- ban, its roles gone. And what only a bot holds goes with it, so a bot let
-- back in starts from nothing rather than finding its old reach waiting:
--
--   * its channel keys, server-wide and per channel, exactly as
--     `revoke_bot_channel_key` takes one back: the grant, the sealed keys the
--     server would still hand out, and a line in each channel saying so. The
--     key sweep then sees a bot sealed into the current version with no
--     grant, and changes the key;
--   * hearing a call (`bot_voice_grants`) and being summoned into one
--     (`bot_voice_summons`); their triggers clear the voice keys sealed for
--     it, and `moderate_user` takes it out of any call it is in, as for a
--     ban.
--
-- The way back is a new bot invite (`register_user`), the way a kicked
-- person's is a new invite; neither kind lets the other in.
--
-- Both functions are replaced whole; their grants carry over, and are
-- restated at the end.
-- ============================================================

CREATE OR REPLACE FUNCTION kick_member(p_target UUID) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_target  users%ROWTYPE;
  v_channel UUID;
  v_by      TEXT;
BEGIN
  IF NOT app.has_perm('KICK_MEMBERS') THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;

  SELECT * INTO v_target FROM users
   WHERE id = p_target AND server_id = app.server_id();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;
  IF v_target.id = auth.uid() THEN
    RAISE EXCEPTION 'cannot_moderate_self';
  END IF;
  IF v_target.is_server_admin THEN
    RAISE EXCEPTION 'cannot_moderate_admin';
  END IF;
  IF (app.permissions_of(v_target.id)
      & (app.perm('KICK_MEMBERS') | app.perm('BAN_MEMBERS'))) <> 0 THEN
    RAISE EXCEPTION 'cannot_kick_peer';
  END IF;
  IF v_target.is_banned THEN
    RAISE EXCEPTION 'user_banned';
  END IF;

  DELETE FROM member_roles    WHERE user_id = p_target;
  DELETE FROM channel_members WHERE user_id = p_target;

  IF v_target.is_bot THEN
    SELECT display_name INTO v_by FROM users WHERE id = auth.uid();
    DELETE FROM bot_server_grants
     WHERE bot_id = p_target AND server_id = v_target.server_id;
    FOR v_channel IN
      DELETE FROM bot_channel_keys WHERE bot_id = p_target RETURNING channel_id
    LOOP
      DELETE FROM channel_keyring
       WHERE channel_id = v_channel AND user_id = p_target;
      PERFORM app.post_system_message(
        v_channel,
        COALESCE(v_by, 'An admin') || ' removed ' || v_target.display_name
          || ' from the server. It keeps what it has already read; '
          || 'everything from here is out of its reach.'
      );
    END LOOP;
    DELETE FROM bot_voice_grants  WHERE bot_id = p_target;
    DELETE FROM bot_voice_summons WHERE bot_id = p_target;
  END IF;

  UPDATE users SET is_banned = true, kicked_at = now() WHERE id = p_target;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION register_user(
  p_invite_code  TEXT,
  p_user_id      UUID,
  p_public_key   TEXT,
  p_stable_id    TEXT,
  p_username     TEXT,
  p_display_name TEXT
) RETURNS JSONB
  LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
  v_invite  invites%ROWTYPE;
  v_max     INTEGER;
  v_members INTEGER;
BEGIN
  SELECT * INTO v_invite FROM invites WHERE code = p_invite_code FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('reason', 'not_found');
  END IF;
  IF v_invite.expires_at IS NOT NULL AND v_invite.expires_at <= now() THEN
    DELETE FROM invites WHERE id = v_invite.id;
    RETURN jsonb_build_object('reason', 'expired');
  END IF;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses >= v_invite.max_uses THEN
    RETURN jsonb_build_object('reason', 'exhausted');
  END IF;

  IF EXISTS (SELECT 1 FROM users WHERE id = p_user_id) THEN
    -- A kicked member coming back. A kick is lifted by exactly this, so they
    -- are let in the way anybody arriving is: the cap applies (a kicked
    -- member holds no seat, like a banned one), the invite's role is theirs,
    -- and the invite is counted. A person comes back through a person's
    -- invite and a bot through a bot invite, never the other way round: a
    -- bot invite is minted by somebody who manages bots, and only says "this
    -- bot may come back" when that is who it was made for. Everyone else
    -- already here — a member, one who left, one who is banned — is the
    -- `register` edge function's to answer, and `already_registered` sends
    -- it there.
    IF EXISTS (
         SELECT 1 FROM users u
          WHERE u.id = p_user_id AND u.server_id = v_invite.server_id
            AND u.is_bot = v_invite.is_bot
            AND u.kicked_at IS NOT NULL) THEN
      SELECT s.max_members INTO v_max
        FROM servers s WHERE s.id = v_invite.server_id FOR UPDATE;
      IF COALESCE(v_max, 0) > 0 THEN
        SELECT count(*) INTO v_members
          FROM users u
         WHERE u.server_id = v_invite.server_id AND NOT u.is_banned;
        IF v_members >= v_max THEN
          RETURN jsonb_build_object('reason', 'server_full');
        END IF;
      END IF;

      UPDATE users SET is_banned = false, kicked_at = NULL WHERE id = p_user_id;
      INSERT INTO member_roles (user_id, role_id)
      SELECT p_user_id, r.id
        FROM roles r
       WHERE r.server_id = v_invite.server_id
         AND r.id = v_invite.role_id
         AND NOT r.is_everyone
         AND NOT r.is_owner
      ON CONFLICT DO NOTHING;

      UPDATE invites SET uses = uses + 1 WHERE id = v_invite.id;
      IF v_invite.max_uses IS NOT NULL AND v_invite.uses + 1 >= v_invite.max_uses THEN
        DELETE FROM invites WHERE id = v_invite.id;
      END IF;
      RETURN jsonb_build_object('reason', 'readmitted',
                                'server_id', v_invite.server_id);
    END IF;
    RETURN jsonb_build_object('reason', 'already_registered');
  END IF;
  IF EXISTS (SELECT 1 FROM users
              WHERE server_id = v_invite.server_id
                AND (public_key = p_public_key OR stable_id = p_stable_id)) THEN
    RETURN jsonb_build_object('reason', 'identity_taken');
  END IF;
  IF EXISTS (SELECT 1 FROM users
              WHERE server_id = v_invite.server_id AND username = p_username) THEN
    RETURN jsonb_build_object('reason', 'username_taken');
  END IF;
  -- Named rather than left to `users_username_shape`, so a caller that went
  -- round the client's field gets a reason it can show instead of a check
  -- violation it has to guess at.
  IF p_username !~ '^[A-Za-z0-9_.-]{2,32}$' THEN
    RETURN jsonb_build_object('reason', 'username_invalid');
  END IF;

  -- The operator's ceiling on members.
  --
  -- Last of the refusals on purpose: "this server is full" is a fact about
  -- the server, and the checks above are facts about the caller. Somebody
  -- with a spent invite or a taken username should hear about that rather
  -- than about the size of a place they were not getting into anyway.
  --
  -- The server row is locked, not merely read. The invite above is already
  -- locked, which serialises everyone arriving through the *same* link — but
  -- a server has more than one link, and two of them racing is exactly how a
  -- cap of fifty admits fifty-two. This is a rare enough operation to make
  -- exact, which is the difference between it and the call cap, where the
  -- count lives on the other side of an HTTP boundary and cannot be.
  --
  -- Banned members do not hold a seat. An operator who bans somebody has
  -- decided they are not part of the server, and a ban that still cost a
  -- place would be a strange kind of removal. Bots do hold one: a bot is in
  -- the member list, takes a row, and reads what everyone else reads.
  SELECT s.max_members INTO v_max
    FROM servers s WHERE s.id = v_invite.server_id FOR UPDATE;
  IF COALESCE(v_max, 0) > 0 THEN
    SELECT count(*) INTO v_members
      FROM users u
     WHERE u.server_id = v_invite.server_id AND NOT u.is_banned;
    IF v_members >= v_max THEN
      RETURN jsonb_build_object('reason', 'server_full');
    END IF;
  END IF;

  INSERT INTO users (
    id, server_id, username, display_name, public_key, stable_id, is_bot
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name,
    p_public_key, p_stable_id, v_invite.is_bot
  );

  -- The role the invite names, if any. Nothing else: the baseline is not
  -- assigned, and there is no default role.
  INSERT INTO member_roles (user_id, role_id)
  SELECT p_user_id, r.id
    FROM roles r
   WHERE r.server_id = v_invite.server_id
     AND r.id = v_invite.role_id
     AND NOT r.is_everyone
     AND NOT r.is_owner
  ON CONFLICT DO NOTHING;

  -- The first person in owns the place.
  IF NOT v_invite.is_bot AND NOT EXISTS (
       SELECT 1 FROM member_roles mr
         JOIN roles r ON r.id = mr.role_id
        WHERE r.server_id = v_invite.server_id AND r.is_owner) THEN
    INSERT INTO member_roles (user_id, role_id)
    SELECT p_user_id, r.id FROM roles r
     WHERE r.server_id = v_invite.server_id AND r.is_owner;
  END IF;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT p_user_id, 'channel', c.id,
         COALESCE((SELECT max(m.id) FROM messages m WHERE m.channel_id = c.id), 0)
    FROM channels c
   WHERE c.server_id = v_invite.server_id;

  UPDATE invites SET uses = uses + 1 WHERE id = v_invite.id;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses + 1 >= v_invite.max_uses THEN
    DELETE FROM invites WHERE id = v_invite.id;
  END IF;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'server_id', v_invite.server_id,
    'is_bot', v_invite.is_bot
  );
END; $$;

REVOKE ALL ON FUNCTION kick_member(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION kick_member(UUID) TO authenticated;
REVOKE ALL ON FUNCTION register_user(TEXT, UUID, TEXT, TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
