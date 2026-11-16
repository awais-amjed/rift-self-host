-- ============================================================
-- Rift self-hosted server — 030: a link that needs a Rift account
-- ============================================================
-- Anybody could join through a public link with an identity made a moment
-- before: a new seed is free, so a bot could make as many as it liked, and a
-- ban stopped one identity and none of the next. Asked Nov 16 2026: let an
-- admin require a Rift account on the public link, so a ban sticks to the
-- account.
--
-- The server cannot tell an account from an identity by itself, so central
-- vouches: the app asks central for a short-lived pass for this one server
-- and the identity joining, the `register` function checks central's
-- signature, and hands `register_user` the pass's **tag**. A tag is the same
-- for one account (its inbox, Gmail-style aliases merged) on one server and
-- different on every other, so this server never learns the email and no two
-- servers can match their members up.
--
--   * `invites.needs_account` marks a link. Only an admin marks or unmarks
--     one (the insert policy, `set_invite_needs_account`): the public link is
--     the server's. Links made by members still let anybody in.
--   * `member_account_tags` holds the tag of every identity an account has
--     joined as here, the ones it left behind included, and `banned_tags`
--     each banned one. Members can read every column of `users`, so tags live
--     apart, granted to nobody. A ban of any of an account's identities keeps
--     the tag and bans the others still in (`users_ban_keeps_tag`): the one a
--     moderator sees misbehave may be the one the account already left. A
--     kick, which the next invite lifts, keeps nothing. `banned_tags` names
--     no member row, so a ban outlives the member it was made against.
--   * `register_user` takes the tag. A banned tag is refused through any
--     link. The same account arriving with a new identity takes its old
--     membership over (the old one leaves), except the owner's
--     (`account_in_use`). Somebody already a member — one who left, on their
--     device — is let back as before, account or not: the switch is about
--     who arrives, and members already in are not touched.
--
-- `register_user` is replaced whole, as 018 left it plus the lines above; the
-- six-argument one is dropped, since the edge function is its only caller.
-- ============================================================

ALTER TABLE invites ADD COLUMN IF NOT EXISTS needs_account BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN invites.needs_account IS
  'Joining through this link needs a Rift account, vouched for by central. '
  'Set and cleared by an admin only.';

GRANT INSERT (server_id, created_by, max_uses, expires_at, is_bot, role_id, needs_account)
  ON invites TO authenticated;

DROP POLICY IF EXISTS invites_insert ON invites;
CREATE POLICY invites_insert ON invites FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND created_by = auth.uid()
    AND app.can_invite()
    AND (role_id IS NULL OR app.may_assign_role(role_id))
    AND (NOT is_bot OR app.has_perm('ADD_BOTS'))
    AND (NOT needs_account OR app.is_admin())
  );

CREATE TABLE IF NOT EXISTS member_account_tags (
  user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  server_id  UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  tag        TEXT NOT NULL
);

-- Not unique: an account that came back as a new identity keeps the old
-- one's row, so a ban of either reaches both.
CREATE INDEX IF NOT EXISTS member_account_tags_tag
  ON member_account_tags (server_id, tag);

COMMENT ON TABLE member_account_tags IS
  'The tag central vouched for when each identity joined with a Rift '
  'account. Read and written only by the service role.';

CREATE TABLE IF NOT EXISTS banned_tags (
  server_id  UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  tag        TEXT        NOT NULL,
  banned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (server_id, tag)
);

COMMENT ON TABLE banned_tags IS
  'Accounts banned from this server, by tag. No reference to the member, so '
  'the ban outlives the row.';

ALTER TABLE member_account_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE banned_tags         ENABLE ROW LEVEL SECURITY;

-- ── Marking a link ──────────────────────────────────────────

CREATE OR REPLACE FUNCTION set_invite_needs_account(p_code TEXT, p_on BOOLEAN)
  RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_server UUID;
BEGIN
  SELECT server_id INTO v_server FROM invites WHERE code = p_code;
  IF NOT FOUND OR v_server IS DISTINCT FROM app.server_id() THEN
    RETURN jsonb_build_object('reason', 'not_found');
  END IF;
  IF NOT app.is_admin() THEN
    RETURN jsonb_build_object('reason', 'not_admin');
  END IF;
  UPDATE invites SET needs_account = p_on WHERE code = p_code;
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

COMMENT ON FUNCTION set_invite_needs_account(TEXT, BOOLEAN) IS
  'Mark or unmark a link of this server as needing a Rift account. Admins only.';

-- ── A ban keeps the tag ─────────────────────────────────────

-- Banned and not kicked is a ban; anything else is not. One rule for every
-- way the two columns move (a ban, an unban, a kick turned into a ban).
--
-- A ban reaches the account: its tag is kept, and every other identity of it
-- still here is banned too (the owner's never, as nobody bans an owner). An
-- unban frees the tag only when no other identity of the account is still
-- banned, and lets nobody else back by itself.
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

DROP TRIGGER IF EXISTS users_ban_keeps_tag ON users;
CREATE TRIGGER users_ban_keeps_tag AFTER UPDATE OF is_banned, kicked_at ON users
  FOR EACH ROW
  WHEN (OLD.is_banned IS DISTINCT FROM NEW.is_banned
        OR OLD.kicked_at IS DISTINCT FROM NEW.kicked_at)
  EXECUTE FUNCTION app.ban_keeps_tag();

-- ── Joining ─────────────────────────────────────────────────

DROP FUNCTION IF EXISTS register_user(TEXT, UUID, TEXT, TEXT, TEXT, TEXT);

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
  v_holder  users%ROWTYPE;
  v_taking  UUID[] := '{}';
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
    FOR v_holder IN
      SELECT u.* FROM member_account_tags t JOIN users u ON u.id = t.user_id
       WHERE t.server_id = v_invite.server_id AND t.tag = p_account_tag
         AND NOT u.is_banned
       FOR UPDATE OF u
    LOOP
      IF EXISTS (
           SELECT 1 FROM member_roles mr JOIN roles r ON r.id = mr.role_id
            WHERE mr.user_id = v_holder.id AND r.is_owner) THEN
        RETURN jsonb_build_object('reason', 'account_in_use');
      END IF;
      v_taking := v_taking || v_holder.id;
    END LOOP;
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
  IF cardinality(v_taking) > 0 THEN
    DELETE FROM member_roles    WHERE user_id = ANY (v_taking);
    DELETE FROM channel_members WHERE user_id = ANY (v_taking);
    UPDATE users SET is_banned = true, kicked_at = now(), left_at = now()
     WHERE id = ANY (v_taking);
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

REVOKE ALL ON member_account_tags FROM PUBLIC, anon, authenticated;
REVOKE ALL ON banned_tags         FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION set_invite_needs_account(TEXT, BOOLEAN) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION set_invite_needs_account(TEXT, BOOLEAN) TO authenticated;
REVOKE ALL ON FUNCTION app.ban_keeps_tag() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION register_user(TEXT, UUID, TEXT, TEXT, TEXT, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
