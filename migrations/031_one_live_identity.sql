-- ============================================================
-- Rift self-hosted server — 031: one account, one live identity
-- ============================================================
-- 030 lets a ban of one identity reach every identity of the same account
-- (`users_ban_keeps_tag`). Found in a security review on Nov 16 2026, before
-- 030 shipped: that reached people `moderate_user` refuses to ban — an
-- admin, or a holder of BAN_MEMBERS — because one account could be in twice.
-- An identity coming back through the kicked path got its tag without the
-- account's live identity leaving, as it does when a new identity joins. So
-- somebody who rejoined as a new identity, became an admin, and later
-- brought the old identity back could be banned as an admin by a moderator
-- banning the plain one.
--
--   * `register_user`: an identity coming back takes the account's live
--     identity over, as a new one does, and never the owner's
--     (`account_in_use`). The account is the pass's tag or the one the
--     identity kept, so coming back through a link that asks for none is
--     still that account, and a banned one stays out (`user_banned`).
--   * `app.ban_keeps_tag`: the ban still keeps the tag, and still reaches the
--     account's other identities, but none that `moderate_user` would refuse
--     to ban: the owner, an admin, a holder of BAN_MEMBERS. A server that
--     ran 030 could hold such a pair already.
--
-- `register_user` is replaced whole, as 030 left it plus the lines above.
-- ============================================================

-- ── The account's live identities ───────────────────────────

-- Which of an account's identities are in now, locked so a join and a ban
-- cannot cross, leaving [p_except] (the one arriving) out. NULL when one is
-- the owner's: a link must not be a way to own the server, so the owner is
-- told to restore their identity instead.
CREATE OR REPLACE FUNCTION app.account_live_identities(
  p_server UUID,
  p_tags   TEXT[],
  p_except UUID
) RETURNS UUID[]
  LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
  v_ids UUID[];
BEGIN
  SELECT COALESCE(array_agg(u.id), '{}') INTO v_ids
    FROM (SELECT u.id FROM member_account_tags t JOIN users u ON u.id = t.user_id
           WHERE t.server_id = p_server AND t.tag = ANY (p_tags)
             AND u.id <> p_except
             AND NOT u.is_banned
           FOR UPDATE OF u) u;
  IF EXISTS (SELECT 1 FROM member_roles mr JOIN roles r ON r.id = mr.role_id
              WHERE mr.user_id = ANY (v_ids) AND r.is_owner) THEN
    RETURN NULL;
  END IF;
  RETURN v_ids;
END; $$;

-- Leaving, as `leave_server` does it: a kick by their own hand. Each keeps
-- its tag row, so banning it later still reaches the account.
CREATE OR REPLACE FUNCTION app.leave_for_account(p_ids UUID[]) RETURNS VOID
  LANGUAGE plpgsql SET search_path = public AS $$
BEGIN
  IF cardinality(p_ids) = 0 THEN
    RETURN;
  END IF;
  DELETE FROM member_roles    WHERE user_id = ANY (p_ids);
  DELETE FROM channel_members WHERE user_id = ANY (p_ids);
  UPDATE users SET is_banned = true, kicked_at = now(), left_at = now()
   WHERE id = ANY (p_ids);
END; $$;

-- ── A ban keeps the tag ─────────────────────────────────────

-- As 030, but the account's other identities are banned only where
-- `moderate_user` would have let the ban through: never the owner, an
-- admin, or a holder of BAN_MEMBERS.
CREATE OR REPLACE FUNCTION app.ban_keeps_tag() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_tag TEXT;
BEGIN
  SELECT tag INTO v_tag FROM member_account_tags WHERE user_id = NEW.id;
  IF v_tag IS NULL THEN
    RETURN NULL;
  END IF;
  IF NEW.is_banned AND NEW.kicked_at IS NULL THEN
    INSERT INTO banned_tags (server_id, tag) VALUES (NEW.server_id, v_tag)
    ON CONFLICT DO NOTHING;
    UPDATE users u SET is_banned = true, kicked_at = NULL, left_at = NULL
      FROM member_account_tags t
     WHERE t.user_id = u.id AND t.server_id = NEW.server_id AND t.tag = v_tag
       AND u.id <> NEW.id
       AND NOT (u.is_banned AND u.kicked_at IS NULL)
       AND NOT u.is_server_admin
       AND (app.permissions_of(u.id) & app.perm('BAN_MEMBERS')) = 0
       AND NOT EXISTS (SELECT 1 FROM member_roles mr JOIN roles r ON r.id = mr.role_id
                        WHERE mr.user_id = u.id AND r.is_owner);
  ELSIF NOT EXISTS (
          SELECT 1 FROM member_account_tags t JOIN users u ON u.id = t.user_id
           WHERE t.server_id = NEW.server_id AND t.tag = v_tag
             AND u.is_banned AND u.kicked_at IS NULL) THEN
    DELETE FROM banned_tags WHERE server_id = NEW.server_id AND tag = v_tag;
  END IF;
  RETURN NULL;
END $$;

-- ── Joining ─────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION register_user(
  p_invite_code  TEXT,
  p_user_id      UUID,
  p_public_key   TEXT,
  p_stable_id    TEXT,
  p_username     TEXT,
  p_display_name TEXT,
  p_account_tag  TEXT DEFAULT NULL
) RETURNS JSONB
  LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
  v_invite  invites%ROWTYPE;
  v_max     INTEGER;
  v_members INTEGER;
  v_taking  UUID[] := '{}';
  v_tags    TEXT[];
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

  -- A banned account stays banned whichever identity it comes back as, and
  -- through whichever link: the tag is the account, not the link.
  IF p_account_tag IS NOT NULL AND EXISTS (
       SELECT 1 FROM banned_tags
        WHERE server_id = v_invite.server_id AND tag = p_account_tag) THEN
    RETURN jsonb_build_object('reason', 'user_banned');
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
      -- The account behind it: the pass's, and the tag it kept when it
      -- joined with one, so coming back through a link that asks for none
      -- is still that account. A banned one stays out; a live identity of
      -- it is taken over, as a new identity would take it (031): one
      -- account is never in twice, which is what let a ban of the plain
      -- one reach an admin.
      v_tags := ARRAY(
        SELECT DISTINCT x FROM unnest(
          array_append(ARRAY(SELECT t.tag FROM member_account_tags t
                              WHERE t.user_id = p_user_id), p_account_tag)) x
         WHERE x IS NOT NULL);
      IF EXISTS (SELECT 1 FROM banned_tags
                  WHERE server_id = v_invite.server_id AND tag = ANY (v_tags)) THEN
        RETURN jsonb_build_object('reason', 'user_banned');
      END IF;
      v_taking := app.account_live_identities(v_invite.server_id, v_tags, p_user_id);
      IF v_taking IS NULL THEN
        RETURN jsonb_build_object('reason', 'account_in_use');
      END IF;
      IF EXISTS (SELECT 1 FROM banned_tags
                  WHERE server_id = v_invite.server_id AND tag = ANY (v_tags)) THEN
        RETURN jsonb_build_object('reason', 'user_banned');
      END IF;

      SELECT s.max_members INTO v_max
        FROM servers s WHERE s.id = v_invite.server_id FOR UPDATE;
      IF COALESCE(v_max, 0) > 0 THEN
        SELECT count(*) INTO v_members
          FROM users u
         WHERE u.server_id = v_invite.server_id AND NOT u.is_banned;
        IF v_members - cardinality(v_taking) >= v_max THEN
          RETURN jsonb_build_object('reason', 'server_full');
        END IF;
      END IF;

      PERFORM app.leave_for_account(v_taking);
      UPDATE users SET is_banned = false, kicked_at = NULL WHERE id = p_user_id;
      -- Coming back with an account: keep its tag.
      IF p_account_tag IS NOT NULL THEN
        INSERT INTO member_account_tags (user_id, server_id, tag)
        VALUES (p_user_id, v_invite.server_id, p_account_tag)
        ON CONFLICT DO NOTHING;
      END IF;
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

  -- A link that needs a Rift account lets in only somebody central vouched
  -- for (`register` checked the pass and hands over its tag). After the
  -- members coming back, above: the switch is about who arrives, and
  -- somebody who left on their device is still a member.
  IF v_invite.needs_account AND p_account_tag IS NULL THEN
    RETURN jsonb_build_object('reason', 'account_required');
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
  -- The same account arriving with a new identity (its seed was lost and
  -- made again): that account's membership is the one holding its tag. It
  -- is taken over — the old identity leaves, and this one joins — rather
  -- than refused, which would leave the person no way back in short of an
  -- admin. Never the owner's: a public link must not be a way to own the
  -- server, so the owner is told to restore their identity instead. Found
  -- here and acted on below, after every refusal, so a join refused for
  -- any other reason leaves the old membership exactly as it was.
  IF p_account_tag IS NOT NULL THEN
    v_taking := app.account_live_identities(
      v_invite.server_id, ARRAY[p_account_tag], p_user_id);
    IF v_taking IS NULL THEN
      RETURN jsonb_build_object('reason', 'account_in_use');
    END IF;
    -- Asked again under the lock: a ban of the old identity that landed
    -- while this waited for it has banned the tag since the check above.
    IF EXISTS (SELECT 1 FROM banned_tags
                WHERE server_id = v_invite.server_id AND tag = p_account_tag) THEN
      RETURN jsonb_build_object('reason', 'user_banned');
    END IF;
  END IF;

  SELECT s.max_members INTO v_max
    FROM servers s WHERE s.id = v_invite.server_id FOR UPDATE;
  IF COALESCE(v_max, 0) > 0 THEN
    SELECT count(*) INTO v_members
      FROM users u
     WHERE u.server_id = v_invite.server_id AND NOT u.is_banned;
    -- A take-over gives the old membership's seat to the new one.
    v_members := v_members - cardinality(v_taking);
    IF v_members >= v_max THEN
      RETURN jsonb_build_object('reason', 'server_full');
    END IF;
  END IF;

  -- Leaving, as `leave_server` does it: a kick by their own hand. The old
  -- identity keeps its tag row, so banning it later still reaches the
  -- account.
  PERFORM app.leave_for_account(v_taking);

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

  IF p_account_tag IS NOT NULL THEN
    INSERT INTO member_account_tags (user_id, server_id, tag)
    VALUES (p_user_id, v_invite.server_id, p_account_tag);
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

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION app.account_live_identities(UUID, TEXT[], UUID)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.leave_for_account(UUID[]) FROM PUBLIC, anon, authenticated;
-- `register_user` runs as the service role (the `register` edge function).
GRANT EXECUTE ON FUNCTION app.account_live_identities(UUID, TEXT[], UUID) TO service_role;
GRANT EXECUTE ON FUNCTION app.leave_for_account(UUID[]) TO service_role;
REVOKE ALL ON FUNCTION app.ban_keeps_tag() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION register_user(TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
