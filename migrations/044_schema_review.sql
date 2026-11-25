-- ============================================================
-- Rift self-hosted server — 044: what the review of 026–043 found
-- ============================================================
-- Found in a review of the schema changes since Nov 5, on Nov 25 2026. Each
-- section below says what was wrong and what changed.
--
--   * A press on a bot's panel skipped `SEND_MESSAGES` whatever it pressed, so
--     a channel nobody may post in still took any number of hidden rows, and a
--     history cap counted them and deleted the real messages.
--   * An invite's role was asked of its maker when it was made and never
--     again, and since 032 an admin could read links for roles above their
--     own rank.
--   * A returning identity with no pass took the account's live identity
--     over; two joins of one account, or a join and a ban, could cross.
--   * A new member was handed a cursor, and so the id, of every private
--     channel.
--   * Smaller races: an override saved over another, a call's region let go
--     while somebody was opening it, two managers on old apps.
-- ============================================================

-- ── A press needs a panel to press ─────────────────────────
-- 027 let `is_interaction` through the send check, so that somebody who may
-- not post can still press a bot's buttons. Nothing asked that there was a
-- button: `reply_to` could be NULL and `to_bot` any bot. A press is seen only
-- by its sender and the bot, so a moderator could not find the rows, and a
-- history cap (`app.enforce_retention`) counted them with the messages.
--
-- So a press past the send check must name a panel of that bot in that
-- channel, one everybody sees or one shown to the presser alone. And the cap
-- counts presses apart from messages: pressing skip forty times never pushes
-- a message out of a channel, whoever pressed it.

CREATE OR REPLACE FUNCTION app.is_pressable_panel(
  p_channel UUID, p_panel BIGINT, p_bot UUID
) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM messages m
     WHERE m.id = p_panel
       AND m.channel_id = p_channel
       AND m.sender_id = p_bot
       AND m.blocks IS NOT NULL
       AND (m.ephemeral_for IS NULL OR m.ephemeral_for = auth.uid()))
$$;

COMMENT ON FUNCTION app.is_pressable_panel(UUID, BIGINT, UUID) IS
  'Whether p_panel is p_bot''s panel in p_channel that the caller may press: '
  'one shown to everybody, or to the caller alone.';

-- As in 027, with the send check passed by a press only on a real panel.
DROP POLICY IF EXISTS messages_insert ON messages;
CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    (app.can_see_channel(channel_id)
     OR (is_interaction AND app.can_press_call_panel(channel_id, reply_to, to_bot)))
    AND (app.has_channel_perm(channel_id, 'SEND_MESSAGES')
         OR (is_interaction AND app.is_pressable_panel(channel_id, reply_to, to_bot)))
    AND NOT app.timed_out()
    AND sender_id = auth.uid()
    AND webhook_id IS NULL AND origin_name IS NULL AND NOT is_system
    AND (key_version >= 1 OR to_bot IS NOT NULL OR app.is_bot()
         OR NOT app.channel_encrypted(channel_id))
    AND (to_bot IS NULL OR app.is_addressable_bot(to_bot))
    AND (to_bot IS NULL OR key_version = 0)
    AND (NOT app.is_bot() OR key_version = 0)
    AND (ephemeral_for IS NULL OR app.is_bot())
    AND (blocks IS NULL OR app.is_bot())
    AND (NOT is_interaction OR NOT app.is_bot())
    AND (poll IS NULL OR (NOT app.is_bot() AND to_bot IS NULL
                          AND app.has_channel_perm(channel_id, 'CREATE_POLLS')))
  );

-- As in 007, with two changes:
--   * the channel cap ranks presses apart from messages (above);
--   * the pass sets `rift.retention`, so `app.announce_dm` rings nobody for a
--     DM it deletes. 039 made that two broadcasts a row, and a pass deletes
--     up to `p_limit` rows of history nobody has open.
CREATE OR REPLACE FUNCTION app.enforce_retention(p_limit INTEGER DEFAULT 500000)
  RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  PERFORM set_config('rift.retention', 'on', true);

  -- ---------- channel messages, by age ----------
  IF EXISTS (SELECT 1 FROM servers s WHERE COALESCE(s.message_retention_days, 0) > 0)
     OR EXISTS (SELECT 1 FROM channels c WHERE COALESCE(c.retention_days, 0) > 0) THEN
  DELETE FROM messages WHERE id IN (
    SELECT m.id
      FROM messages m
      JOIN channels c ON c.id = m.channel_id
      JOIN servers  s ON s.id = c.server_id
     WHERE COALESCE(c.retention_days, s.message_retention_days) > 0
       AND m.created_at < now() - make_interval(
             days => COALESCE(c.retention_days, s.message_retention_days))
     ORDER BY m.id
     LIMIT p_limit);
  END IF;

  -- ---------- DM messages, by age ----------
  IF EXISTS (SELECT 1 FROM servers s
              WHERE COALESCE(s.dm_retention_days, s.message_retention_days, 0) > 0) THEN
  DELETE FROM dm_messages WHERE id IN (
    SELECT d.id
      FROM dm_messages d
      JOIN users   u ON u.id = d.sender_id
      JOIN servers s ON s.id = u.server_id
     WHERE COALESCE(s.dm_retention_days, s.message_retention_days) > 0
       AND d.created_at < now() - make_interval(
             days => COALESCE(s.dm_retention_days, s.message_retention_days))
     ORDER BY d.id
     LIMIT p_limit);
  END IF;

  -- ---------- DM calls, by age ----------
  IF EXISTS (SELECT 1 FROM servers s
              WHERE COALESCE(s.dm_retention_days, s.message_retention_days, 0) > 0) THEN
  DELETE FROM dm_calls WHERE id IN (
    SELECT c.id
      FROM dm_calls c
      JOIN users   u ON u.id = c.caller_id
      JOIN servers s ON s.id = u.server_id
     WHERE COALESCE(s.dm_retention_days, s.message_retention_days) > 0
       AND c.ended_at IS NOT NULL
       AND c.started_at < now() - make_interval(
             days => COALESCE(s.dm_retention_days, s.message_retention_days))
     ORDER BY c.started_at
     LIMIT p_limit);
  END IF;

  -- ---------- channel messages, by count ----------
  -- Presses are ranked on their own: they are never shown, so they must not
  -- push out what is.
  IF EXISTS (SELECT 1 FROM servers s WHERE COALESCE(s.message_history_cap, 0) > 0)
     OR EXISTS (SELECT 1 FROM channels c WHERE COALESCE(c.history_cap, 0) > 0) THEN
  DELETE FROM messages WHERE id IN (
    SELECT id FROM (
      SELECT m.id,
             row_number() OVER (PARTITION BY m.channel_id, m.is_interaction
                                ORDER BY m.id DESC) AS rn,
             COALESCE(c.history_cap, s.message_history_cap) AS cap
        FROM messages m
        JOIN channels c ON c.id = m.channel_id
        JOIN servers  s ON s.id = c.server_id
       WHERE COALESCE(c.history_cap, s.message_history_cap) > 0
    ) ranked WHERE rn > cap
     ORDER BY rn DESC
     LIMIT p_limit
  );
  END IF;

  -- ---------- DM messages, by count ----------
  IF EXISTS (SELECT 1 FROM servers s
              WHERE COALESCE(s.dm_history_cap, s.message_history_cap, 0) > 0) THEN
  DELETE FROM dm_messages WHERE id IN (
    SELECT id FROM (
      SELECT d.id,
             row_number() OVER (
               PARTITION BY LEAST(d.sender_id, d.recipient_id),
                            GREATEST(d.sender_id, d.recipient_id)
               ORDER BY d.id DESC
             ) AS rn,
             COALESCE(s.dm_history_cap, s.message_history_cap) AS cap
        FROM dm_messages d
        JOIN users   u ON u.id = d.sender_id
        JOIN servers s ON s.id = u.server_id
       WHERE COALESCE(s.dm_history_cap, s.message_history_cap) > 0
    ) ranked WHERE rn > cap
     ORDER BY rn DESC
     LIMIT p_limit
  );
  END IF;

  PERFORM set_config('rift.retention', '', true);
END; $$;

-- As in 039, but silent for a delete made by the retention pass.
CREATE OR REPLACE FUNCTION app.announce_dm() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' AND current_setting('rift.retention', true) = 'on' THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'INSERT' AND app.dm_is_request(NEW.sender_id, NEW.recipient_id) THEN
    PERFORM realtime.send(jsonb_build_object('sender_id', NEW.sender_id),
      'dm_requests', 'user:' || NEW.recipient_id, true);
  ELSIF TG_OP = 'INSERT' THEN
    PERFORM realtime.send(
      jsonb_build_object('id', NEW.id, 'sender_id', NEW.sender_id),
      'dm', 'user:' || NEW.recipient_id, true);
  END IF;

  IF TG_OP = 'INSERT' THEN
    PERFORM realtime.send(
      jsonb_build_object('id', NEW.id, 'recipient_id', NEW.recipient_id),
      'dm_sent', 'user:' || NEW.sender_id, true);
  ELSIF TG_OP = 'UPDATE' THEN
    PERFORM realtime.send(jsonb_build_object('message_id', NEW.id),
      'dm_changed', 'user:' || NEW.recipient_id, true);
    PERFORM realtime.send(jsonb_build_object('message_id', NEW.id),
      'dm_changed', 'user:' || NEW.sender_id, true);
  ELSE
    PERFORM realtime.send(jsonb_build_object('message_id', OLD.id),
      'dm_changed', 'user:' || OLD.recipient_id, true);
    PERFORM realtime.send(jsonb_build_object('message_id', OLD.id),
      'dm_changed', 'user:' || OLD.sender_id, true);
  END IF;
  RETURN NULL;
END $$;

-- ── An invite's role is its maker's to give when it is used ─
-- 032 asked `may_assign_role` when an invite was made. `register_user` handed
-- the role out whenever it was used, so an admin who made a link carrying
-- Admin and was then demoted could come back through it as Admin. And 032
-- showed every admin every invite, code and all: an admin could join a second
-- identity through a link the owner made for a role above theirs.
--
-- So the role is given only while its maker could still give it, as
-- `may_assign_role` asks of them now (an unbanned admin ranked at or above
-- it); a link whose maker cannot joins its people with no role. And an admin
-- sees the links for roles at or below their own rank, as they could make.

CREATE OR REPLACE FUNCTION app.may_hand_out(p_user UUID, p_role UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM users u
      JOIN roles r ON r.id = p_role AND r.server_id = u.server_id
     WHERE u.id = p_user
       AND NOT u.is_banned
       AND (app.permissions_of(u.id) & app.perm('ADMINISTRATOR')) <> 0
       AND NOT r.is_everyone
       AND NOT r.is_owner
       AND r.position <= COALESCE((
             SELECT max(r2.position) FROM member_roles mr
               JOIN roles r2 ON r2.id = mr.role_id
              WHERE mr.user_id = u.id), 0))
$$;

COMMENT ON FUNCTION app.may_hand_out(UUID, UUID) IS
  'Whether p_user may give p_role now: what app.may_assign_role asks of the '
  'caller, asked of somebody else (an invite''s maker, when it is used).';

DROP POLICY IF EXISTS invites_select_admin ON invites;
CREATE POLICY invites_select_admin ON invites FOR SELECT TO authenticated
  USING (
    server_id = app.server_id() AND (SELECT app.is_admin())
    AND (role_id IS NULL OR app.may_assign_role(role_id))
  );

-- ── One account, one live identity: locked, and only with a pass ─
-- 031 found an account's live identity, and took it over, before it locked
-- anything that a second join of the same account would wait for. Two joins
-- at once both found nobody, and the account was in twice. A ban of an
-- identity that had left locked nothing a join would wait for either, so a
-- new identity could get in beside the tag's ban.
--
--   * Every identity of the account is locked now, the ones that left too, so
--     a ban of any of them and a join wait for each other, and a join asks
--     again about the ban once it has them.
--   * The server's row is locked before the account is looked up, so two joins
--     of an account that has no identity yet wait for each other as well.
--     `FOR NO KEY UPDATE`, which the rows pointing at the server do not wait
--     on, where 031 took `FOR UPDATE`, which they do.
--
-- And an identity coming back with no pass took the live one over on the
-- strength of its seed. Somebody holding an old device's seed could come back
-- through any plain link and push out the identity the account had moved to.
-- Taking over now needs the pass, as joining with a new identity does; without
-- one, a returning identity is refused while another of its account is in
-- (`account_moved`).

CREATE OR REPLACE FUNCTION app.account_live_identities(
  p_server UUID,
  p_tags   TEXT[],
  p_except UUID
) RETURNS UUID[]
  LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
  v_ids UUID[];
BEGIN
  -- All of them, in one order, so two of these never wait on each other.
  PERFORM 1 FROM member_account_tags t JOIN users u ON u.id = t.user_id
   WHERE t.server_id = p_server AND t.tag = ANY (p_tags)
   ORDER BY u.id
     FOR UPDATE OF u;
  SELECT COALESCE(array_agg(u.id), '{}') INTO v_ids
    FROM member_account_tags t JOIN users u ON u.id = t.user_id
   WHERE t.server_id = p_server AND t.tag = ANY (p_tags)
     AND u.id <> p_except
     AND NOT u.is_banned;
  IF EXISTS (SELECT 1 FROM member_roles mr JOIN roles r ON r.id = mr.role_id
              WHERE mr.user_id = ANY (v_ids) AND r.is_owner) THEN
    RETURN NULL;
  END IF;
  RETURN v_ids;
END; $$;

-- As 031 left it, with:
--   * the server locked first, every identity of the account locked, and the
--     ban asked again after;
--   * a returning identity taking over only with a pass;
--   * the invite's role given only while its maker may give it;
--   * no cursor for a private channel;
--   * `left`, the identities taken over, so `register` can drop them from
--     their calls.
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

  -- Everybody arriving on this server waits here for whoever came before,
  -- whichever link they used: the member cap is counted under it, and so is
  -- the account (one live identity each).
  SELECT s.max_members INTO v_max
    FROM servers s WHERE s.id = v_invite.server_id FOR NO KEY UPDATE;

  -- A banned account stays banned whichever identity it comes back as, and
  -- through whichever link: the tag is the account, not the link.
  IF p_account_tag IS NOT NULL AND EXISTS (
       SELECT 1 FROM banned_tags
        WHERE server_id = v_invite.server_id AND tag = p_account_tag) THEN
    RETURN jsonb_build_object('reason', 'user_banned');
  END IF;

  IF EXISTS (SELECT 1 FROM users WHERE id = p_user_id) THEN
    -- A kicked member coming back, or one who left (`leave_server` is a kick
    -- by their own hand). The cap applies, the invite's role is theirs, and
    -- the invite is counted. A person comes back through a person's invite
    -- and a bot through a bot invite, never the other way round. A member
    -- still in, or one banned, is the `register` edge function's to answer,
    -- and `already_registered` sends it there.
    IF EXISTS (
         SELECT 1 FROM users u
          WHERE u.id = p_user_id AND u.server_id = v_invite.server_id
            AND u.is_bot = v_invite.is_bot
            AND u.kicked_at IS NOT NULL) THEN
      -- The account behind it: the pass's, and the tag it kept.
      v_tags := ARRAY(
        SELECT DISTINCT x FROM unnest(
          array_append(ARRAY(SELECT t.tag FROM member_account_tags t
                              WHERE t.user_id = p_user_id), p_account_tag)) x
         WHERE x IS NOT NULL);
      v_taking := app.account_live_identities(v_invite.server_id, v_tags, p_user_id);
      IF v_taking IS NULL THEN
        RETURN jsonb_build_object('reason', 'account_in_use');
      END IF;
      -- Asked under the lock, so a ban of any identity of the account that
      -- landed meanwhile is seen.
      IF EXISTS (SELECT 1 FROM banned_tags
                  WHERE server_id = v_invite.server_id AND tag = ANY (v_tags)) THEN
        RETURN jsonb_build_object('reason', 'user_banned');
      END IF;
      -- The seed alone is not the account: the account moved to another
      -- identity, and only its pass moves it back.
      IF p_account_tag IS NULL AND cardinality(v_taking) > 0 THEN
        RETURN jsonb_build_object('reason', 'account_moved');
      END IF;

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
         AND app.may_hand_out(v_invite.created_by, r.id)
      ON CONFLICT DO NOTHING;

      UPDATE invites SET uses = uses + 1 WHERE id = v_invite.id;
      IF v_invite.max_uses IS NOT NULL AND v_invite.uses + 1 >= v_invite.max_uses THEN
        DELETE FROM invites WHERE id = v_invite.id;
      END IF;
      RETURN jsonb_build_object('reason', 'readmitted',
                                'server_id', v_invite.server_id,
                                'left', to_jsonb(v_taking));
    END IF;
    RETURN jsonb_build_object('reason', 'already_registered');
  END IF;

  -- A link that needs a Rift account lets in only somebody central vouched
  -- for (`register` checked the pass and hands over its tag).
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
  IF p_username !~ '^[A-Za-z0-9_.-]{2,32}$' THEN
    RETURN jsonb_build_object('reason', 'username_invalid');
  END IF;

  -- The same account arriving with a new identity (its seed was lost and made
  -- again) takes its membership over: the old identity leaves and this one
  -- joins. Never the owner's (`account_in_use`). Acted on below, after every
  -- refusal, so a join refused for any other reason leaves it as it was.
  IF p_account_tag IS NOT NULL THEN
    v_taking := app.account_live_identities(
      v_invite.server_id, ARRAY[p_account_tag], p_user_id);
    IF v_taking IS NULL THEN
      RETURN jsonb_build_object('reason', 'account_in_use');
    END IF;
    IF EXISTS (SELECT 1 FROM banned_tags
                WHERE server_id = v_invite.server_id AND tag = p_account_tag) THEN
      RETURN jsonb_build_object('reason', 'user_banned');
    END IF;
  END IF;

  -- The operator's ceiling on members, last: it is a fact about the server,
  -- and everything above is about the caller. Banned members hold no seat;
  -- bots do. A take-over gives the old membership's seat to the new one.
  IF COALESCE(v_max, 0) > 0 THEN
    SELECT count(*) INTO v_members
      FROM users u
     WHERE u.server_id = v_invite.server_id AND NOT u.is_banned;
    IF v_members - cardinality(v_taking) >= v_max THEN
      RETURN jsonb_build_object('reason', 'server_full');
    END IF;
  END IF;

  PERFORM app.leave_for_account(v_taking);

  INSERT INTO users (
    id, server_id, username, display_name, public_key, stable_id, is_bot
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name,
    p_public_key, p_stable_id, v_invite.is_bot
  );

  -- The role the invite names, if its maker may still give it. Nothing else:
  -- the baseline is not assigned, and there is no default role.
  INSERT INTO member_roles (user_id, role_id)
  SELECT p_user_id, r.id
    FROM roles r
   WHERE r.server_id = v_invite.server_id
     AND r.id = v_invite.role_id
     AND app.may_hand_out(v_invite.created_by, r.id)
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

  -- Read up to now in every channel they can see. A private channel's cursor
  -- is made when they are seated in it (`app.seed_seat_cursors`).
  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT p_user_id, 'channel', c.id,
         COALESCE((SELECT max(m.id) FROM messages m WHERE m.channel_id = c.id), 0)
    FROM channels c
   WHERE c.server_id = v_invite.server_id
     AND NOT c.is_private;

  UPDATE invites SET uses = uses + 1 WHERE id = v_invite.id;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses + 1 >= v_invite.max_uses THEN
    DELETE FROM invites WHERE id = v_invite.id;
  END IF;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'server_id', v_invite.server_id,
    'is_bot', v_invite.is_bot,
    'left', to_jsonb(v_taking)
  );
END; $$;

-- ── A private channel's cursor comes with its seat ─────────
-- `register_user` wrote a read cursor for every channel of the server, the
-- private ones too, and `read_state_own` let the member read them: a list of
-- every private channel's id, and since 026 one of them broadcast with its
-- newest message id. A cursor is made now when somebody is seated, and the
-- ones already handed out for channels their holder cannot see are taken
-- back.

CREATE OR REPLACE FUNCTION app.seed_seat_cursors() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT n.user_id, 'channel', n.channel_id,
         COALESCE((SELECT max(m.id) FROM messages m WHERE m.channel_id = n.channel_id), 0)
    FROM new_rows n
  ON CONFLICT (user_id, scope, scope_id) DO NOTHING;
  RETURN NULL;
END $$;

COMMENT ON FUNCTION app.seed_seat_cursors() IS
  'A new seat in a private channel starts read up to now, as a new member '
  'does in the public ones.';

DROP TRIGGER IF EXISTS channel_members_seed_cursor ON channel_members;
CREATE TRIGGER channel_members_seed_cursor
  AFTER INSERT ON channel_members
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION app.seed_seat_cursors();

DELETE FROM read_state r
 USING channels c
 WHERE r.scope = 'channel'
   AND c.id = r.scope_id
   AND c.is_private
   AND NOT app.sees_channel(c.id, r.user_id);

-- ── One override saved over another ────────────────────────
-- `set_channel_override` read the row, asked whether the caller holds the
-- bits that differ, and wrote the whole row. A save from a stale read that
-- landed after somebody else's wrote their bits back, a deny the caller does
-- not hold included. The channel is locked first now, so the second save
-- reads the first's row.
CREATE OR REPLACE FUNCTION set_channel_override(
  p_channel UUID, p_role UUID, p_allow BIGINT, p_deny BIGINT
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_type     channel_type;
  v_server   UUID;
  v_everyone BOOLEAN;
  v_position INTEGER;
  v_old      channel_overrides%ROWTYPE;
  v_changed  BIGINT;
BEGIN
  IF app.timed_out() THEN RETURN jsonb_build_object('reason', 'forbidden'); END IF;
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  IF NOT app.can_manage_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  SELECT c.channel_type, c.server_id INTO v_type, v_server
    FROM channels c WHERE c.id = p_channel FOR NO KEY UPDATE;

  SELECT r.is_everyone, r."position" INTO v_everyone, v_position
    FROM roles r WHERE r.id = p_role AND r.server_id = v_server;
  IF NOT FOUND THEN RETURN jsonb_build_object('reason', 'no_such_role'); END IF;

  p_allow := COALESCE(p_allow, 0);
  p_deny  := COALESCE(p_deny, 0);
  IF p_allow < 0 OR p_deny < 0 OR (p_allow & p_deny) <> 0
     OR ((p_allow | p_deny) & ~app.channel_perm_mask(v_type)) <> 0 THEN
    RETURN jsonb_build_object('reason', 'invalid');
  END IF;

  IF NOT app.has_perm('ADMINISTRATOR') AND NOT v_everyone
     AND v_position >= app.max_role_position() THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  SELECT * INTO v_old FROM channel_overrides
   WHERE channel_id = p_channel AND role_id = p_role;
  v_changed := (COALESCE(v_old.allow, 0) # p_allow) | (COALESCE(v_old.deny, 0) # p_deny);
  IF NOT app.may_hold_perms(v_changed) THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF v_changed = 0 THEN RETURN jsonb_build_object('reason', 'ok'); END IF;

  IF p_allow = 0 AND p_deny = 0 THEN
    DELETE FROM channel_overrides WHERE channel_id = p_channel AND role_id = p_role;
  ELSE
    INSERT INTO channel_overrides (channel_id, role_id, allow, deny, updated_by)
    VALUES (p_channel, p_role, p_allow, p_deny, auth.uid())
    ON CONFLICT (channel_id, role_id) DO UPDATE
      SET allow = EXCLUDED.allow, deny = EXCLUDED.deny,
          updated_by = EXCLUDED.updated_by, updated_at = now();
  END IF;

  IF app.realtime_ready() THEN
    PERFORM realtime.send('{}'::jsonb, 'channels', 'server:' || v_server, true);
  END IF;
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ── Two managers, either function ──────────────────────────
-- 043 locked the channel in `change_channel_members`, so two managers
-- removing each other wait for one another. `set_channel_members`, which
-- older apps still call, had the same race and no lock. Both take the lock
-- now, and `FOR NO KEY UPDATE` rather than 043's `FOR UPDATE`: the second is
-- also waited on by every message being sent in the channel (its foreign key),
-- and the first is waited on only by another change like this one.

CREATE OR REPLACE FUNCTION set_channel_members(
  p_channel UUID,
  p_users   UUID[]
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  PERFORM 1 FROM channels WHERE id = p_channel FOR NO KEY UPDATE;
  IF NOT app.can_manage_channel(p_channel) THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM channels WHERE id = p_channel
                   AND server_id = app.server_id()) THEN
    RAISE EXCEPTION 'channel_not_found';
  END IF;

  DELETE FROM channel_members
   WHERE channel_id = p_channel AND user_id <> ALL (p_users);

  INSERT INTO channel_members (channel_id, user_id, added_by)
  SELECT p_channel, u.id, auth.uid()
    FROM users u
   WHERE u.id = ANY (p_users)
     AND u.server_id = app.server_id()
     AND NOT u.is_banned
     AND NOT u.is_bot
  ON CONFLICT (channel_id, user_id) DO NOTHING;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION change_channel_members(
  p_channel UUID,
  p_add     UUID[],
  p_remove  UUID[]
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  PERFORM 1 FROM channels WHERE id = p_channel FOR NO KEY UPDATE;
  IF NOT app.can_manage_channel(p_channel) THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM channels WHERE id = p_channel
                   AND server_id = app.server_id() AND is_private) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  -- Added first, so a list that removes everybody else and adds somebody new
  -- never passes through empty (`reassign_or_close_channel`).
  INSERT INTO channel_members (channel_id, user_id, added_by)
  SELECT p_channel, u.id, auth.uid()
    FROM users u
   WHERE u.id = ANY (COALESCE(p_add, '{}'))
     AND u.server_id = app.server_id()
     AND NOT u.is_banned
     AND NOT u.is_bot
  ON CONFLICT (channel_id, user_id) DO NOTHING;

  DELETE FROM channel_members
   WHERE channel_id = p_channel
     AND user_id = ANY (COALESCE(p_remove, '{}'))
     AND user_id <> ALL (COALESCE(p_add, '{}'));

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ── A call's region, claimed again ─────────────────────────
-- 043 keeps a `voice_rooms` row for 30 seconds after it is claimed, the time
-- between claiming a region and the room existing there. But a claim that
-- found a row already there (one `voice_roster` had not let go of yet) left
-- its old `opened_at`, so the roster could let it go while the person who
-- just claimed it was still opening the room, and the next person decided
-- the region again. A claim now renews a row older than that.
CREATE OR REPLACE FUNCTION app.claim_voice_node(
  p_channel    UUID,
  p_preferred  UUID DEFAULT NULL,
  p_ignore_pin BOOLEAN DEFAULT false
) RETURNS TABLE (id UUID, url TEXT, label TEXT, is_default BOOLEAN)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
  v_node   UUID;
BEGIN
  SELECT c.server_id, n.id INTO v_server, v_node
    FROM channels c
    LEFT JOIN livekit_nodes n ON n.id = c.livekit_node_id AND n.server_id = c.server_id
   WHERE c.id = p_channel;

  IF v_server IS NULL THEN RETURN; END IF;

  IF p_ignore_pin THEN v_node := NULL; END IF;

  IF v_node IS NULL AND p_preferred IS NOT NULL THEN
    SELECT n.id INTO v_node FROM livekit_nodes n
     WHERE n.id = p_preferred AND n.server_id = v_server;
  END IF;

  IF v_node IS NULL THEN
    SELECT n.id INTO v_node FROM livekit_nodes n
     WHERE n.server_id = v_server AND n.is_default;
  END IF;

  IF v_node IS NULL THEN RETURN; END IF;

  -- First one in decides; everybody after joins them, and renews the claim.
  INSERT INTO voice_rooms AS vr (channel_id, node_id) VALUES (p_channel, v_node)
    ON CONFLICT (channel_id) DO UPDATE SET opened_at = now()
     WHERE vr.opened_at < now() - interval '30 seconds';

  RETURN QUERY
  SELECT n.id, n.url, n.label, n.is_default
    FROM voice_rooms vr
    JOIN livekit_nodes n ON n.id = vr.node_id
   WHERE vr.channel_id = p_channel;
END $$;

-- ── A file is put where it may be read ─────────────────────
-- 027 asked a channel's `ATTACH_FILES` of whatever channel the upload's path
-- named, and did not ask whether the uploader can see it; a DM's name asked
-- nothing of who is in the DM. An upload now has to be named for a
-- conversation the uploader is in. The channel's bit still cannot be held
-- against a modified app, which can upload where files are allowed and name
-- that file in a sealed body elsewhere: the app draws a file only from its
-- own conversation's folder, and that is the rest of it.
CREATE OR REPLACE FUNCTION app.can_attach(p_name TEXT) RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_scope TEXT := split_part(p_name, '/', 1);
  v_me    TEXT := auth.uid()::TEXT;
BEGIN
  IF v_scope ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN app.can_see_channel(v_scope::UUID)
       AND app.has_channel_perm(v_scope::UUID, 'ATTACH_FILES');
  END IF;
  IF v_scope ~ '^dm_[0-9a-f-]{36}_[0-9a-f-]{36}$' THEN
    RETURN v_me IS NOT NULL
       AND v_me IN (substr(v_scope, 4, 36), substr(v_scope, 41, 36))
       AND app.has_perm('ATTACH_FILES');
  END IF;
  RETURN app.has_perm('ATTACH_FILES');
END $$;

-- ── The console's notice, to the console's server ──────────
-- 029 told every admin on the database about a newer console. A database the
-- console runs can hold other servers (`create_server`), whose admins do not
-- run it and cannot update it. The notice goes to the admins of the first
-- server made on the database, which is the one the console set up.

CREATE OR REPLACE FUNCTION app.console_server() RETURNS UUID
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT s.id FROM servers s ORDER BY s.created_at, s.id LIMIT 1
$$;

COMMENT ON FUNCTION app.console_server() IS
  'The server the console set up: the first made on this database.';

CREATE OR REPLACE FUNCTION app.console_update() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_value TEXT;
BEGIN
  IF NOT app.is_admin() OR app.server_id() IS DISTINCT FROM app.console_server() THEN
    RETURN NULL;
  END IF;
  EXECUTE 'SELECT value FROM rift_console.state WHERE key = ''update_available'''
    INTO v_value;
  RETURN v_value::jsonb;
EXCEPTION
  WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION app.announce_console_update() RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_admin UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN;
  END IF;
  FOR v_admin IN SELECT id FROM users
                  WHERE is_server_admin AND NOT is_banned
                    AND server_id = app.console_server() LOOP
    PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || v_admin, true);
  END LOOP;
END;
$$;

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION app.is_pressable_panel(UUID, BIGINT, UUID)
  FROM PUBLIC, anon, authenticated;
-- From `messages_insert`, as the member.
GRANT EXECUTE ON FUNCTION app.is_pressable_panel(UUID, BIGINT, UUID) TO authenticated;

REVOKE ALL ON FUNCTION app.may_hand_out(UUID, UUID) FROM PUBLIC, anon, authenticated;
-- From `register_user`, on the service role.
GRANT EXECUTE ON FUNCTION app.may_hand_out(UUID, UUID) TO service_role;

REVOKE ALL ON FUNCTION app.seed_seat_cursors() FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.console_server() FROM PUBLIC, anon, authenticated;
