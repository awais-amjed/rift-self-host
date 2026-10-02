-- ============================================================
-- Rift self-hosted server — 003: the RPCs
-- ============================================================
-- What a client calls. These exist for the things RLS cannot express on its
-- own: a write that has to check something first, a read that has to be
-- bounded, and an action that touches several tables and must do all of it
-- or none.
--
-- Every one of them is `SECURITY DEFINER` and every one re-checks the
-- caller's permission with a helper from 002 — being defined here is not
-- permission to run, and a function that trusted its arguments would be a
-- hole straight through 008.
-- ============================================================

-- ============================================================
-- Moderation and permissions
-- ============================================================
-- SECURITY DEFINER so the caller never needs UPDATE on someone else's row —
-- these write the moderation/permission columns and nothing else, which is
-- exactly the guarantee a policy cannot give.

CREATE OR REPLACE FUNCTION moderate_user(
  p_target   UUID,
  p_muted    BOOLEAN DEFAULT NULL,
  p_deafened BOOLEAN DEFAULT NULL,
  p_banned   BOOLEAN DEFAULT NULL
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_target users%ROWTYPE;
BEGIN
  -- Two permissions, because these are not the same act. Muting and deafening
  -- are what a channel manager is *for* — they already move and disconnect
  -- people — and gating them on admin meant the client offered buttons that
  -- always came back not_authorized. Banning is its own bit, `BAN_MEMBERS`:
  -- it ends somebody's membership, and a server that wants its moderators
  -- to act on a report without an admin awake gives them that and nothing
  -- more. Admins hold it by implication.
  IF p_banned IS NOT NULL THEN
    IF NOT app.has_perm('BAN_MEMBERS') THEN
      RAISE EXCEPTION 'not_authorized';
    END IF;
  ELSIF NOT app.can_manage_channels() THEN
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
  -- An admin is not a moderation target for another admin. Removing that
  -- standing is a permission change, and it goes through the other function.
  IF v_target.is_server_admin THEN
    RAISE EXCEPTION 'cannot_moderate_admin';
  END IF;
  -- Nor is somebody who could ban you back. Without this, two moderators
  -- holding the bit settle a disagreement by banning each other, and the
  -- first to click wins a server.
  IF p_banned IS NOT NULL
     AND (app.permissions_of(v_target.id) & app.perm('BAN_MEMBERS')) <> 0 THEN
    RAISE EXCEPTION 'cannot_ban_peer';
  END IF;

  -- A ban, or lifting one, settles the question a kick left open: banning a
  -- kicked member makes it permanent, and lifting it lets them straight back.
  UPDATE users SET
    is_muted    = COALESCE(p_muted,    is_muted),
    is_deafened = COALESCE(p_deafened, is_deafened),
    is_banned   = COALESCE(p_banned,   is_banned),
    kicked_at   = CASE WHEN p_banned IS NULL THEN kicked_at END
   WHERE id = p_target;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ============================================================
-- Kicks
-- ============================================================
-- Removal that a new invite undoes. It is a ban in every way the server
-- enforces — the same flag, so every policy, the key sweep, the call
-- teardown and the member count already treat a kicked member as gone — with
-- `kicked_at` beside it saying an invite may lift it (`register_user`).
--
-- What made them more than a newcomer goes with them: their roles and their
-- seats in private channels. They come back as what the invite grants, under
-- the same name and with the messages they wrote, because the row is theirs
-- and nobody else's identity can use it.
--
-- `KICK_MEMBERS`, and the ban's rules about who it may reach: not yourself,
-- not an admin, not a bot (removed from Bots, never invited back), and not
-- somebody who could remove you in return. A banned member cannot be kicked:
-- that would turn a ban into something any invite lifts.

CREATE OR REPLACE FUNCTION kick_member(p_target UUID) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_target users%ROWTYPE;
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
  IF v_target.is_bot THEN
    RAISE EXCEPTION 'cannot_kick_bot';
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
  UPDATE users SET is_banned = true, kicked_at = now() WHERE id = p_target;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ============================================================
-- Time-outs
-- ============================================================
-- Text's mute: no messages, DMs or reactions until the time is up. Answers to
-- `MUTE_MEMBERS`, the bit that already says "this person may be made quiet",
-- and follows the same rules as a ban about who it may reach — not yourself,
-- not an admin, not somebody who could do it back to you.
--
-- Minutes rather than a timestamp, so the clock that matters is this one and
-- not whatever the moderator's device thinks the time is. 0 lifts it. The
-- ceiling is 28 days: anything longer is a ban somebody did not want to say.

CREATE OR REPLACE FUNCTION time_out_member(p_target UUID, p_minutes INTEGER)
  RETURNS TIMESTAMPTZ
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_target users%ROWTYPE;
  v_until  TIMESTAMPTZ;
BEGIN
  IF NOT app.has_perm('MUTE_MEMBERS') THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF p_minutes IS NULL OR p_minutes < 0 OR p_minutes > 28 * 24 * 60 THEN
    RAISE EXCEPTION 'invalid_duration';
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
  IF (app.permissions_of(v_target.id) & app.perm('MUTE_MEMBERS')) <> 0 THEN
    RAISE EXCEPTION 'cannot_moderate_peer';
  END IF;

  v_until := CASE WHEN p_minutes = 0 THEN NULL
                  ELSE now() + make_interval(mins => p_minutes) END;
  UPDATE users SET timed_out_until = v_until WHERE id = p_target;
  RETURN v_until;
END; $$;

-- ============================================================
-- Reports
-- ============================================================
-- Two ways in and one way out. `report_message` and `report_member` are any
-- member's; `resolve_report` is a reviewer's. Reading the list is not a
-- function at all — `reports_select` in 008 lets a reviewer select their
-- server's rows, which is the whole of what the page needs.
--
-- Twenty open reports per reporter. It is a lot for somebody reporting in good
-- faith and a small number for somebody trying to bury the moderators, and it
-- frees up as the moderators work through them.

CREATE OR REPLACE FUNCTION app.report_room(p_reporter UUID) RETURNS VOID
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF (SELECT count(*) FROM reports r
       WHERE r.reporter_id = p_reporter AND r.outcome IS NULL) >= 20 THEN
    RAISE EXCEPTION 'too_many_reports';
  END IF;
END; $$;

-- The envelope is copied here, from the row, so the reporter supplies nothing
-- but which message and why. Anything they could see they may report, their
-- own messages and the server's notices apart.
CREATE OR REPLACE FUNCTION report_message(
  p_message BIGINT,
  p_reason  report_reason,
  p_note    TEXT DEFAULT NULL
) RETURNS BIGINT
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
  v_msg    messages%ROWTYPE;
  v_note   TEXT := NULLIF(btrim(COALESCE(p_note, '')), '');
  v_id     BIGINT;
BEGIN
  IF v_server IS NULL THEN RAISE EXCEPTION 'not_authorized'; END IF;
  IF p_reason IS NULL THEN RAISE EXCEPTION 'reason_required'; END IF;
  IF length(v_note) > 1000 THEN RAISE EXCEPTION 'note_too_long'; END IF;
  IF NOT app.can_see_message(p_message) THEN
    RAISE EXCEPTION 'message_not_found';
  END IF;

  SELECT * INTO v_msg FROM messages WHERE id = p_message;
  IF v_msg.is_system THEN RAISE EXCEPTION 'message_not_found'; END IF;
  IF v_msg.sender_id = auth.uid() THEN RAISE EXCEPTION 'cannot_report_self'; END IF;
  PERFORM app.report_room(auth.uid());

  INSERT INTO reports (server_id, reporter_id, target_id, reason, note,
                       message_id, channel_id, message_created_at, origin_name,
                       ciphertext, nonce, signature, key_version)
  VALUES (v_server, auth.uid(), v_msg.sender_id, p_reason, v_note,
          v_msg.id, v_msg.channel_id, v_msg.created_at, v_msg.origin_name,
          v_msg.ciphertext, v_msg.nonce, v_msg.signature, v_msg.key_version)
  ON CONFLICT (reporter_id, message_id) WHERE message_id IS NOT NULL
  DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN RAISE EXCEPTION 'already_reported'; END IF;
  RETURN v_id;
END; $$;

-- A person rather than a message: what somebody reports from a profile, or
-- from a DM, whose words no moderator could open (the key belongs to the
-- two of them). The note carries whatever they want to say about it.
CREATE OR REPLACE FUNCTION report_member(
  p_target UUID,
  p_reason report_reason,
  p_note   TEXT DEFAULT NULL
) RETURNS BIGINT
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
  v_note   TEXT := NULLIF(btrim(COALESCE(p_note, '')), '');
  v_id     BIGINT;
BEGIN
  IF v_server IS NULL THEN RAISE EXCEPTION 'not_authorized'; END IF;
  IF p_reason IS NULL THEN RAISE EXCEPTION 'reason_required'; END IF;
  IF length(v_note) > 1000 THEN RAISE EXCEPTION 'note_too_long'; END IF;
  IF p_target = auth.uid() THEN RAISE EXCEPTION 'cannot_report_self'; END IF;
  IF NOT app.is_co_member(p_target) THEN RAISE EXCEPTION 'user_not_found'; END IF;
  PERFORM app.report_room(auth.uid());

  INSERT INTO reports (server_id, reporter_id, target_id, reason, note)
  VALUES (v_server, auth.uid(), p_target, p_reason, v_note)
  ON CONFLICT (reporter_id, target_id)
     WHERE message_id IS NULL AND outcome IS NULL
  DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN RAISE EXCEPTION 'already_reported'; END IF;
  RETURN v_id;
END; $$;

-- Recording what was done. The action itself happens first, through the path
-- it always takes — deleting a message is the client's (it holds the blob
-- keys), a ban is `moderate_user`, a kick `kick_member`, a time-out is
-- `time_out_member` — and this checks it did, so the log cannot say "banned"
-- about somebody who is not, nor about somebody who was only kicked.
--
-- One action answers every open report it settles: deleting a message closes
-- each report about that message, and a ban or a kick closes each report
-- about that person, who is no longer there to be reported. Dismissing and
-- timing out close only the one in hand, because the next report about the
-- same person may be about something new.
--
-- Nobody closes a report about themselves, which is the same line
-- `reports_select` draws around reading one.
CREATE OR REPLACE FUNCTION resolve_report(
  p_report  BIGINT,
  p_outcome report_outcome
) RETURNS INTEGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_report reports%ROWTYPE;
  v_closed INTEGER;
BEGIN
  IF NOT app.has_perm('REVIEW_REPORTS') THEN RAISE EXCEPTION 'not_authorized'; END IF;
  IF p_outcome IS NULL THEN RAISE EXCEPTION 'outcome_required'; END IF;

  SELECT * INTO v_report FROM reports
   WHERE id = p_report AND server_id = app.server_id()
     AND target_id IS DISTINCT FROM auth.uid()
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'report_not_found'; END IF;
  IF v_report.outcome IS NOT NULL THEN RAISE EXCEPTION 'already_resolved'; END IF;

  IF p_outcome = 'deleted' AND (v_report.message_id IS NULL
       OR EXISTS (SELECT 1 FROM messages m WHERE m.id = v_report.message_id)) THEN
    RAISE EXCEPTION 'outcome_not_done';
  END IF;
  IF p_outcome = 'timed_out' AND NOT EXISTS (
       SELECT 1 FROM users u WHERE u.id = v_report.target_id
          AND u.timed_out_until > now()) THEN
    RAISE EXCEPTION 'outcome_not_done';
  END IF;
  IF p_outcome = 'banned' AND NOT EXISTS (
       SELECT 1 FROM users u WHERE u.id = v_report.target_id AND u.is_banned
          AND u.kicked_at IS NULL) THEN
    RAISE EXCEPTION 'outcome_not_done';
  END IF;
  IF p_outcome = 'kicked' AND NOT EXISTS (
       SELECT 1 FROM users u WHERE u.id = v_report.target_id AND u.is_banned
          AND u.kicked_at IS NOT NULL) THEN
    RAISE EXCEPTION 'outcome_not_done';
  END IF;

  UPDATE reports r
     SET outcome = p_outcome, resolved_by = auth.uid(), resolved_at = now()
   WHERE r.server_id = v_report.server_id
     AND r.outcome IS NULL
     AND r.target_id IS DISTINCT FROM auth.uid()
     AND (r.id = p_report
          OR (p_outcome = 'deleted' AND r.message_id = v_report.message_id)
          OR (p_outcome IN ('banned', 'kicked')
              AND r.target_id = v_report.target_id));
  GET DIAGNOSTICS v_closed = ROW_COUNT;
  RETURN v_closed;
END; $$;

-- Move a cursor forward. Never backward: two devices race on the same
-- conversation, and the one that read less must not un-read what the other
-- read. Passing 0 means "up to whatever is newest right now".
CREATE OR REPLACE FUNCTION mark_read(
  p_scope        read_scope,
  p_scope_id     UUID,
  p_last_read_id BIGINT DEFAULT 0
) RETURNS BIGINT
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_target BIGINT := p_last_read_id;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  IF v_target <= 0 THEN
    IF p_scope = 'channel' THEN
      SELECT COALESCE(max(m.id), 0) INTO v_target
        FROM messages m WHERE m.channel_id = p_scope_id;
    ELSE
      SELECT COALESCE(max(d.id), 0) INTO v_target
        FROM dm_messages d
       WHERE d.sender_id = p_scope_id AND d.recipient_id = auth.uid();
    END IF;
  END IF;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
       VALUES (auth.uid(), p_scope, p_scope_id, v_target)
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
          SET last_read_id = GREATEST(read_state.last_read_id, EXCLUDED.last_read_id),
              updated_at   = now()
    RETURNING last_read_id INTO v_target;

  RETURN v_target;
END; $$;

-- "Mark all as read" for a whole server: every channel and every conversation
-- moved to whatever is newest. One statement each rather than a round trip per
-- channel from the client.
CREATE OR REPLACE FUNCTION mark_all_read() RETURNS VOID
  LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT auth.uid(), 'channel', c.id,
         COALESCE((SELECT max(m.id) FROM messages m WHERE m.channel_id = c.id), 0)
    FROM channels c
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
     SET last_read_id = GREATEST(read_state.last_read_id, EXCLUDED.last_read_id),
         updated_at   = now();

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT auth.uid(), 'dm', d.sender_id, max(d.id)
    FROM dm_messages d
   WHERE d.recipient_id = auth.uid()
   GROUP BY d.sender_id
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
     SET last_read_id = GREATEST(read_state.last_read_id, EXCLUDED.last_read_id),
         updated_at   = now();
END; $$;

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

-- ============================================================
-- 5. Managing them
-- ============================================================

-- 32 bytes, hex. URL-safe by construction, which base64 is not, and this ends
-- up in a URL that gets pasted into CI config by hand.
CREATE OR REPLACE FUNCTION new_webhook_secret() RETURNS TEXT
  LANGUAGE sql VOLATILE SET search_path = public, extensions AS $$
  SELECT encode(gen_random_bytes(32), 'hex')
$$;

-- Returns the secret **once**. There is no way to read it back afterwards; a
-- lost URL is replaced by deleting the webhook and making another.
CREATE OR REPLACE FUNCTION create_webhook(
  p_channel_id UUID,
  p_name       TEXT
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_server_id UUID;
  v_secret    TEXT;
  v_id        UUID;
  v_count     INTEGER;
BEGIN
  IF NOT app.can_manage_channels() THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  SELECT server_id INTO v_server_id FROM channels WHERE id = p_channel_id;
  IF v_server_id IS NULL OR v_server_id <> app.server_id() THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  IF p_name IS NULL OR length(trim(p_name)) = 0 THEN
    RETURN jsonb_build_object('reason', 'bad_name');
  END IF;

  -- A ceiling per channel, so a compromised admin account cannot quietly leave
  -- a hundred ways back in.
  SELECT count(*) INTO v_count FROM webhooks WHERE channel_id = p_channel_id;
  IF v_count >= 10 THEN
    RETURN jsonb_build_object('reason', 'too_many');
  END IF;

  v_secret := new_webhook_secret();

  INSERT INTO webhooks (server_id, channel_id, created_by, name, secret_hash)
  VALUES (
    v_server_id, p_channel_id, auth.uid(), left(trim(p_name), 80),
    encode(digest(v_secret, 'sha256'), 'hex')
  )
  RETURNING id INTO v_id;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'id',     v_id,
    'secret', v_secret
  );
END; $$;

-- ============================================================
-- 6. Posting through one
-- ============================================================
-- The lookup, the rate check and the insert are one statement so a caller
-- cannot sit between them. It runs as the service role — reached only by the
-- `webhook` edge function, which is the part that can be called without a JWT.
--
-- The rule lives here rather than in the edge function for the usual reason:
-- an edge function is one way to reach a row, and the row should be able to
-- defend itself against the next one.

CREATE OR REPLACE FUNCTION post_webhook_message(
  p_secret TEXT,
  p_text   TEXT
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $$
DECLARE
  v_hook       webhooks%ROWTYPE;
  v_id         BIGINT;
  v_window     TIMESTAMPTZ := date_trunc('minute', now());
  v_per_minute CONSTANT INTEGER := 30;
BEGIN
  IF p_secret IS NULL OR length(p_secret) <> 64 THEN
    RETURN jsonb_build_object('reason', 'no_such_webhook');
  END IF;

  SELECT * INTO v_hook FROM webhooks
   WHERE secret_hash = encode(digest(p_secret, 'sha256'), 'hex')
   FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('reason', 'no_such_webhook');
  END IF;

  IF p_text IS NULL OR length(trim(p_text)) = 0 THEN
    RETURN jsonb_build_object('reason', 'empty');
  END IF;
  -- The same ceiling `ciphertext` already carries. A webhook body is plain
  -- text in that column, so the column's limit is the limit.
  IF length(p_text) > 16384 THEN
    RETURN jsonb_build_object('reason', 'too_long');
  END IF;

  IF v_hook.rate_window IS DISTINCT FROM v_window THEN
    UPDATE webhooks SET rate_window = v_window, rate_count = 0
     WHERE id = v_hook.id;
    v_hook.rate_count := 0;
  ELSIF v_hook.rate_count >= v_per_minute THEN
    RETURN jsonb_build_object('reason', 'rate_limited');
  END IF;

  INSERT INTO messages (
    channel_id, ciphertext, nonce, signature, key_version,
    webhook_id, origin_name
  ) VALUES (
    v_hook.channel_id, p_text, NULL, NULL, 0,
    v_hook.id, v_hook.name
  )
  RETURNING id INTO v_id;

  UPDATE webhooks
     SET rate_count = rate_count + 1, last_used_at = now()
   WHERE id = v_hook.id;

  RETURN jsonb_build_object(
    'reason',     'ok',
    'message_id', v_id,
    'channel_id', v_hook.channel_id,
    'server_id',  v_hook.server_id
  );
END; $$;

-- ============================================================
-- 7. Opening and closing a channel
-- ============================================================

CREATE OR REPLACE FUNCTION set_channel_private(
  p_channel UUID,
  p_private BOOLEAN
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_channel channels%ROWTYPE;
  v_current INTEGER;
BEGIN
  IF NOT app.can_manage_channel(p_channel) THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  SELECT * INTO v_channel FROM channels WHERE id = p_channel;
  IF NOT FOUND THEN RAISE EXCEPTION 'channel_not_found'; END IF;
  IF v_channel.is_private = p_private THEN
    RETURN jsonb_build_object('reason', 'ok');
  END IF;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  IF p_private THEN
    -- Closing. Whoever is in the room stays in it, and the caller can run it —
    -- otherwise a manager could close a channel and lock themselves out of the
    -- thing they now own.
    UPDATE channels SET is_private = true WHERE id = p_channel;
    INSERT INTO channel_members (channel_id, user_id, can_manage, added_by)
    SELECT p_channel, u.id, u.id = auth.uid(), auth.uid()
      FROM users u
     WHERE u.server_id = v_channel.server_id AND NOT u.is_banned AND NOT u.is_bot
    ON CONFLICT (channel_id, user_id) DO NOTHING;

    UPDATE channel_members SET can_manage = true
     WHERE channel_id = p_channel AND user_id = auth.uid();
  ELSE
    -- Opening. The flag alone would hand every arrival the key the private
    -- conversation is *still being written under*, because healing seals the
    -- current version. Nobody new is sealed until the sweep has rotated past
    -- this mark.
    UPDATE channels
       SET is_private = false,
           rotate_from_key_version = v_current
     WHERE id = p_channel;
  END IF;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- Closing a channel to everybody but a few is the common case, and doing it as
-- "make private, then remove 40 people" leaves a window where it is private and
-- everyone is still in it. One statement instead.
CREATE OR REPLACE FUNCTION set_channel_members(
  p_channel UUID,
  p_users   UUID[]
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
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
     -- A bot is keyed by `grant_bot_channel_key` and nothing else. Letting one
     -- in here would be a second door to the same room.
     AND NOT u.is_bot
  ON CONFLICT (channel_id, user_id) DO NOTHING;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION set_channel_role_access(
  p_channel UUID,
  p_role    UUID,
  p_on      BOOLEAN
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.can_manage_channel(p_channel) THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM roles r
                  WHERE r.id = p_role AND r.server_id = app.server_id()) THEN
    RAISE EXCEPTION 'role_not_found';
  END IF;

  IF p_on THEN
    INSERT INTO channel_role_access (channel_id, role_id, added_by)
    VALUES (p_channel, p_role, auth.uid())
    ON CONFLICT DO NOTHING;
  ELSE
    DELETE FROM channel_role_access
     WHERE channel_id = p_channel AND role_id = p_role;
  END IF;
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION channel_visible_to(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.sees_channel(p_channel, p_user)
$$;

CREATE OR REPLACE FUNCTION visible_channels(p_user UUID)
  RETURNS TABLE (channel_id UUID)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.id
    FROM channels c
    JOIN users u ON u.id = p_user AND u.server_id = c.server_id
   WHERE NOT u.is_banned
     AND (NOT c.is_private OR app.in_channel(c.id, p_user))
$$;

-- ============================================================
-- 3. Asking about somebody else's permissions
-- ============================================================
-- `app.has_perm` answers for `auth.uid()`, which is what a policy needs. An
-- edge function minting a LiveKit token is deciding about the person who asked
-- it, not about itself, so it needs the two-argument form.

CREATE OR REPLACE FUNCTION user_has_permission(p_user UUID, p_name TEXT)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT (app.permissions_of(p_user)
          & (app.perm('ADMINISTRATOR') | app.perm(p_name))) <> 0
$$;

-- ============================================================
-- 4. What a client is allowed to draw
-- ============================================================
-- A client reads three booleans off its own `users` row and draws its buttons
-- from them. Those columns are a cache of three bits out of twenty-two, so a
-- client that only reads them can only offer three of the twenty-two things a
-- member might be allowed to do — and `CREATE_PRIVATE_CHANNEL` is on
-- `@everyone`, which none of the three would ever say.
--
-- The bits themselves, then. `app.permissions()` is in the `app` schema, which
-- PostgREST does not expose; this is the same answer through the front door.
--
-- It only ever describes the caller. There is no argument to point somewhere
-- else, which is what keeps it safe to hand to `authenticated` — and a client
-- drawing a button it is not allowed to press is a cosmetic bug, because the
-- policy is still the thing that decides.

CREATE OR REPLACE FUNCTION my_permissions() RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.permissions()
$$;

-- ============================================================
-- Making a channel is one statement
-- ============================================================
-- A member may create a private channel, but cannot read back the one they
-- just made with a plain insert.
--
-- `INSERT ... RETURNING` applies the **SELECT** policy to the row it hands back,
-- and `channels_select` asks whether the caller is in the channel. The creator
-- is seated by an AFTER INSERT trigger, which has not run when RETURNING is
-- evaluated — so the insert succeeds, the read of its own row does not, and
-- Postgres reports the whole thing as `new row violates row-level security
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

-- ============================================================
-- Walking out of a private channel
-- ============================================================
-- `set_channel_members` needs the manage bit, which is right for deciding who
-- else is in a room and wrong for deciding whether *you* are. A member who was
-- added to a private channel and would rather not be in it could not leave;
-- they could only ask the person who added them.
--
-- So: one function that removes exactly the caller and nobody else. There is no
-- target parameter, which is what makes it safe to hand to every member.
--
-- Two things it does not do, both deliberate:
--
--   * **It does not rotate the key.** It does not have to — leaving makes the
--     caller ineligible, and the sweep's standing signal is "somebody sealed
--     into the current version who is no longer entitled to it". The next
--     member's client rotates. What the leaver already read, they keep; nobody
--     can take that back, and pretending otherwise would be the lie.
--   * **It does not delete the channel itself.** `reassign_or_close_channel`
--     already handles the last person out, and handles the manage bit moving
--     on if the leaver was holding it.

CREATE OR REPLACE FUNCTION leave_channel(p_channel UUID) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_private BOOLEAN;
BEGIN
  SELECT is_private INTO v_private FROM channels
   WHERE id = p_channel AND server_id = app.server_id();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  -- Leaving a channel everyone can see would be a no-op with a button.
  IF NOT v_private THEN
    RETURN jsonb_build_object('reason', 'not_private');
  END IF;

  -- Access granted through a role is not the caller's to give up: deleting
  -- their own row would leave them in the room and the button looking broken,
  -- and dropping the role grant would take everybody else out with them.
  IF EXISTS (SELECT 1 FROM channel_role_access cra
               JOIN member_roles mr ON mr.role_id = cra.role_id
              WHERE cra.channel_id = p_channel AND mr.user_id = auth.uid()) THEN
    RETURN jsonb_build_object('reason', 'in_by_role');
  END IF;

  DELETE FROM channel_members
   WHERE channel_id = p_channel AND user_id = auth.uid();

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ============================================================
-- 2. The grant, and the sentence it leaves behind
-- ============================================================

CREATE OR REPLACE FUNCTION grant_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current INTEGER;
  v_bot     TEXT;
  v_by      TEXT;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  -- Not "is it on my server". A private channel answers to the people in it,
  -- and an administrator standing outside one is not among them.
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  SELECT display_name INTO v_bot FROM users
   WHERE id = p_bot AND is_bot AND NOT is_banned AND server_id = app.server_id();
  IF v_bot IS NULL THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  IF EXISTS (SELECT 1 FROM bot_channel_keys
              WHERE channel_id = p_channel AND bot_id = p_bot) THEN
    RETURN jsonb_build_object('reason', 'already_granted');
  END IF;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  -- One past the current version. A channel with no key yet starts the bot at
  -- 1, which is the version its first member will bootstrap — there is no
  -- history to keep it out of.
  INSERT INTO bot_channel_keys (channel_id, bot_id, granted_by, from_key_version)
  VALUES (p_channel, p_bot, auth.uid(), GREATEST(v_current + 1, 1));

  SELECT display_name INTO v_by FROM users WHERE id = auth.uid();
  PERFORM app.post_system_message(
    p_channel,
    COALESCE(v_by, 'An admin') || ' gave ' || v_bot || ' the key to this '
      || 'channel. It can read every message sent here from now on — but '
      || 'nothing said before.'
  );

  RETURN jsonb_build_object(
    'reason', 'ok',
    'from_key_version', (SELECT from_key_version FROM bot_channel_keys
                          WHERE channel_id = p_channel AND bot_id = p_bot)
  );
END; $$;

CREATE OR REPLACE FUNCTION grant_bot_server_key(p_bot UUID) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = v_server) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_server_grants (server_id, bot_id, granted_by)
  VALUES (v_server, p_bot, auth.uid())
  ON CONFLICT (server_id, bot_id) DO NOTHING;

  PERFORM app.materialise_bot_server_grant(v_server, p_bot);
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION revoke_bot_server_key(p_bot UUID) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server  UUID := app.server_id();
  v_channel UUID;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  DELETE FROM bot_server_grants WHERE server_id = v_server AND bot_id = p_bot;

  FOR v_channel IN
    SELECT channel_id FROM bot_channel_keys g
      JOIN channels c ON c.id = g.channel_id
     WHERE c.server_id = v_server AND g.bot_id = p_bot
  LOOP
    PERFORM revoke_bot_channel_key(p_bot, v_channel);
  END LOOP;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ============================================================
-- 3. Revoking one channel downgrades the grant
-- ============================================================
-- Not an exception list. Dropping the intent row leaves every other channel's
-- materialised row exactly where it was, so the grant stops being "the whole
-- server" and becomes the set of channels it currently covers — which is what
-- the admin just said they wanted.
--
-- Written into `revoke_bot_channel_key` rather than as a trigger on
-- `bot_channel_keys`, and that distinction is the whole of it. A trigger fires
-- for *every* deletion of that row, including the one §4 does when a channel is
-- made private — so closing one channel would have cancelled the grant on all
-- the others. Downgrading is a thing a person decides, not a thing a row does.

CREATE OR REPLACE FUNCTION revoke_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bot TEXT;
  v_by  TEXT;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  SELECT u.display_name INTO v_bot
    FROM bot_channel_keys g JOIN users u ON u.id = g.bot_id
   WHERE g.channel_id = p_channel AND g.bot_id = p_bot;
  IF v_bot IS NULL THEN
    RETURN jsonb_build_object('reason', 'ok');
  END IF;

  -- Naming one channel is saying "not the whole server any more". The other
  -- channels keep the rows they already have.
  DELETE FROM bot_server_grants
   WHERE bot_id = p_bot
     AND server_id = app.channel_server_id(p_channel);

  DELETE FROM bot_channel_keys
   WHERE channel_id = p_channel AND bot_id = p_bot;
  -- Dropping the sealed keys does not take back what has been read — nothing
  -- can. It stops the server serving any more, and leaves the rotation to the
  -- sweep, which now sees a bot sealed into the current version with no grant.
  DELETE FROM channel_keyring
   WHERE channel_id = p_channel AND user_id = p_bot;

  SELECT display_name INTO v_by FROM users WHERE id = auth.uid();
  PERFORM app.post_system_message(
    p_channel,
    COALESCE(v_by, 'An admin') || ' took ' || v_bot || '’s access to this '
      || 'channel away. It keeps what it has already read; everything from '
      || 'here is out of its reach.'
  );

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ============================================================
-- 2. Granting and taking back
-- ============================================================
-- Both return a reason rather than raising, matching grant_bot_channel_key —
-- the caller is a dialog, and "forbidden" and "no such bot" are things it draws
-- differently rather than an exception it reports.
--
-- There is no system message on either. A voice channel holds no messages: it
-- carries the columns and ignores them (ARCHITECTURE.md §3), so a line in the
-- scrollback would be a line nothing renders. The notice is the standing
-- marker in the channel and the bot's own page, which are the two carriers of
-- §6's three that a room without a transcript can have.

CREATE OR REPLACE FUNCTION grant_bot_voice_listen(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bot TEXT;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  -- Not "is it on my server". An administrator standing outside a private
  -- voice channel is not among the people whose call this is.
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM channels
                  WHERE id = p_channel AND channel_type = 'voice') THEN
    RETURN jsonb_build_object('reason', 'not_a_voice_channel');
  END IF;

  SELECT display_name INTO v_bot FROM users
   WHERE id = p_bot AND is_bot AND NOT is_banned AND server_id = app.server_id();
  IF v_bot IS NULL THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_voice_grants (channel_id, bot_id, granted_by)
  VALUES (p_channel, p_bot, auth.uid())
  ON CONFLICT (channel_id, bot_id) DO NOTHING;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION revoke_bot_voice_listen(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  DELETE FROM bot_voice_grants
   WHERE channel_id = p_channel AND bot_id = p_bot;

  -- The row is only half of it: a bot already in the call holds a token whose
  -- grant said `canSubscribe`, and a token is good for its hour no matter what
  -- this table says afterwards. The `set_bot_voice_listen` edge function pushes
  -- the new permission onto the live connection, the same way `moderate_user`
  -- does for a mute — which is the bug that taught us the row alone is not the
  -- feature.
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ============================================================
-- 2. Who may join a voice channel
-- ============================================================
-- `channel_visible_to` answers "may this person see this channel", which is the
-- question for a person and the wrong one for a summoned bot: it is in the room
-- without being of it. Separating them keeps the summon from leaking anywhere
-- else — every other caller still asks `sees_channel` and still gets no.

CREATE OR REPLACE FUNCTION channel_joinable_by(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.sees_channel(p_channel, p_user)
      OR (EXISTS (SELECT 1 FROM users u WHERE u.id = p_user
                    AND u.is_bot AND NOT u.is_banned)
          AND app.bot_summoned_to(p_channel, p_user))
$$;

-- `app.can_manage_channel` for a named person, because an edge function on
-- the service role has no `auth.uid()` to ask it with. It is the question
-- `move_call` and `delete_channel` have to put before they touch a room, and
-- it was being answered in TypeScript as "is this an admin or a channel
-- manager" — which is the rule for a *public* channel. A private one answers
-- to its own managers and nobody else, so a server admin who is not in it
-- could move its call, learn how many were in it, or end it outright.
--
-- Written once here rather than rebuilt in each function, for the reason
-- `channel_joinable_by` is: the rule is the database's.
CREATE OR REPLACE FUNCTION channel_manageable_by(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM channels c
      JOIN users u ON u.id = p_user AND u.server_id = c.server_id
     WHERE c.id = p_channel
       AND NOT u.is_banned
       AND (CASE WHEN c.is_private
                 THEN EXISTS (SELECT 1 FROM channel_members cm
                               WHERE cm.channel_id = p_channel
                                 AND cm.user_id = p_user
                                 AND cm.can_manage)
                 ELSE user_has_permission(p_user, 'MANAGE_CHANNELS') END))
$$;

COMMENT ON FUNCTION channel_manageable_by(UUID, UUID) IS
  'Service-role only. Whether this person may manage this channel — '
  'app.can_manage_channel for somebody other than the caller. A private '
  'channel answers to its own managers, never to a server-wide permission.';

-- ============================================================
-- 3. Asking, and asking it to leave
-- ============================================================

CREATE OR REPLACE FUNCTION summon_bot_to_voice(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_type TEXT;
BEGIN
  IF NOT app.has_perm('SUMMON_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  -- The caller's own visibility, not the bot's — a summon is somebody in the
  -- room asking, and the whole point is that the bot cannot see it yet.
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  SELECT channel_type INTO v_type FROM channels WHERE id = p_channel;
  IF v_type IS DISTINCT FROM 'voice' THEN
    RETURN jsonb_build_object('reason', 'not_a_voice_channel');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = app.server_id()) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_voice_summons (channel_id, bot_id, summoned_by)
  VALUES (p_channel, p_bot, auth.uid())
  ON CONFLICT (channel_id, bot_id) DO NOTHING;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- Dismissing takes no permission beyond being able to see the room. Anybody in
-- a call may ask the music bot to stop, and needing the person who summoned it
-- — who may have left — is how a bot ends up playing to an empty room.
CREATE OR REPLACE FUNCTION dismiss_bot_from_voice(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.can_see_channel(p_channel) AND p_bot IS DISTINCT FROM auth.uid() THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  DELETE FROM bot_voice_summons
   WHERE channel_id = p_channel AND bot_id = p_bot;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- Mention resolution. Channel-scoped, because who a mention *reaches* is the
-- question being asked: `validate_message_mentions` will strip an id that
-- cannot open the channel, and a composer that resolved a name the trigger
-- then dropped would show a ping that never happened.
CREATE OR REPLACE FUNCTION members_by_usernames(
  p_names   TEXT[],
  p_channel UUID DEFAULT NULL
) RETURNS SETOF member_directory
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT m.*
    FROM member_directory m
   WHERE app.member_scope_allowed(p_channel)
     AND m.server_id = app.server_id()
     AND NOT m.is_banned
     AND lower(m.username) = ANY (
           SELECT lower(n) FROM unnest(COALESCE(p_names, ARRAY[]::TEXT[])) AS n)
     AND app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, false)
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT app.member_page_max()
$$;

COMMENT ON FUNCTION members_by_usernames(TEXT[], UUID) IS
  'Resolve @names to members who can actually be reached in p_channel — the '
  'same set validate_message_mentions keeps, asked for the handful of names in '
  'one message rather than as the whole audience.';

-- ============================================================
-- Count reactions where they are stored
-- ============================================================
-- The standalone reaction read asked for one row per person per emoji across a
-- whole page of messages, and PostgREST caps a response at 1000 rows. Fifty
-- messages is a page; twenty people reacting to each of them is a lively
-- channel, not an extreme one. At that point the response was cut off and the
-- client tallied whatever survived — so a reaction count quietly read low, or a
-- reaction of your own stopped being yours and the button un-filled.
--
-- Nothing about it looked wrong. That is the shape of every bug in this batch:
-- a limit that trims an answer instead of refusing the question.
--
-- The fix is not a bigger limit. Counting is the database's job, and doing it
-- there makes the response smaller by exactly the factor that was overflowing
-- it — one row per (message, emoji) rather than per (message, emoji, person).
-- A message with twenty reactors and three emoji goes from sixty rows to three.
--
-- Returned as one JSONB object rather than a set, for the same reason
-- `unread_counts` and `dm_conversations` are: a scalar is not row-capped, so
-- this cannot be truncated however many reactions a page collects. The shape is
-- exactly what `ReactionOps.byMessage` used to build on the client, so the
-- caller is unchanged past the fetch.
--
-- ---------- what stays on the client ----------
--
-- `ReactionOps.aggregate` is still there, and still used: a message page
-- carries its reactions with it as an embedded select, and folding *those* is
-- free. What moves here is only the standalone read — the one that asks about a
-- page of messages at once and so was the one that overflowed.

-- ============================================================
-- A page of a channel
-- ============================================================
-- What the chat list reads, and the one call this schema makes that a client
-- cannot make for itself.
--
-- `from('messages').eq('channel_id', …).order('id', desc).limit(51)` is the
-- obvious shape and it is a trap — see `app.channel_page_ids` for why the
-- planner walks the primary key instead of the index built for exactly this,
-- and why opening a channel that had gone quiet cost 4.4 seconds against
-- 5,000,000 messages. The page has to be taken as ids first, which is not
-- something PostgREST can express, so it is taken here.
--
-- SECURITY INVOKER, and that is the whole division of labour: the definer
-- half decides only whether the channel is open to the caller, and every row
-- it names is then fetched by primary key with `messages_select` in force —
-- ephemeral replies, button presses, a bot's key version, all of it decided
-- where it has always been decided. A page may therefore come back shorter
-- than `p_limit` because the policy dropped a row from it. That is correct
-- and the client already copes: `has_more` is read from the id count, and
-- the next page is asked for from the oldest id actually returned.
CREATE OR REPLACE FUNCTION channel_messages(
  p_channel UUID,
  p_before  BIGINT  DEFAULT NULL,
  p_after   BIGINT  DEFAULT NULL,
  p_limit   INTEGER DEFAULT 51
) RETURNS SETOF messages
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  -- One page, plus the row that proves there is another. The ceiling is the
  -- same clamp the member pages use and for the same reason: a client asking
  -- for five thousand has a bug, and failing its request turns that bug into
  -- an empty channel.
  v_limit INTEGER := LEAST(GREATEST(COALESCE(p_limit, 51), 1), 101);
BEGIN
  IF p_after IS NOT NULL THEN
    RETURN QUERY
    SELECT m.* FROM app.channel_page_ids(p_channel, NULL, p_after, v_limit) AS p(id)
      JOIN messages m ON m.id = p.id
     ORDER BY m.id;
  ELSE
    RETURN QUERY
    SELECT m.* FROM app.channel_page_ids(p_channel, p_before, NULL, v_limit) AS p(id)
      JOIN messages m ON m.id = p.id
     ORDER BY m.id DESC;
  END IF;
END $$;

COMMENT ON FUNCTION channel_messages(UUID, BIGINT, BIGINT, INTEGER) IS
  'One page of a channel, newest first — or oldest first from p_after, which '
  'is how a client catches up after a reconnect. Rows are still subject to '
  'messages_select, so a page can be shorter than it asked for.';

CREATE OR REPLACE FUNCTION message_reaction_tallies(
  p_scope read_scope,
  p_ids   BIGINT[]
) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_ids  BIGINT[];
  v_rows JSONB;
BEGIN
  -- A page is fifty. The cap is here so a caller that one day asks about its
  -- whole history gets an answer about the first hundred rather than a
  -- statement that runs for a minute.
  v_ids := (SELECT array_agg(id) FROM (
              SELECT unnest(COALESCE(p_ids, ARRAY[]::BIGINT[])) AS id
               LIMIT 100) capped);
  IF v_ids IS NULL THEN RETURN '{}'::jsonb; END IF;

  -- Two tables, one shape. Written as two branches rather than dynamic SQL:
  -- the scope is an enum, so there is nothing to interpolate and nothing to
  -- get wrong. `security_invoker` throughout, so the reaction policies decide
  -- what is visible exactly as they do for a direct read.
  IF p_scope = 'channel' THEN
    SELECT jsonb_object_agg(message_id::TEXT, entries) INTO v_rows
      FROM (
        SELECT r.message_id,
               jsonb_agg(jsonb_build_object(
                 'emoji', r.emoji,
                 'count', r.n,
                 'mine',  r.mine) ORDER BY r.emoji) AS entries
          FROM (
            SELECT m.message_id,
                   m.emoji,
                   count(*)                                   AS n,
                   bool_or(m.user_id = auth.uid())             AS mine
              FROM message_reactions m
             WHERE m.message_id = ANY (v_ids)
             GROUP BY m.message_id, m.emoji
          ) r
         GROUP BY r.message_id
      ) grouped;
  ELSE
    SELECT jsonb_object_agg(message_id::TEXT, entries) INTO v_rows
      FROM (
        SELECT r.message_id,
               jsonb_agg(jsonb_build_object(
                 'emoji', r.emoji,
                 'count', r.n,
                 'mine',  r.mine) ORDER BY r.emoji) AS entries
          FROM (
            SELECT m.message_id,
                   m.emoji,
                   count(*)                                   AS n,
                   bool_or(m.user_id = auth.uid())             AS mine
              FROM dm_message_reactions m
             WHERE m.message_id = ANY (v_ids)
             GROUP BY m.message_id, m.emoji
          ) r
         GROUP BY r.message_id
      ) grouped;
  END IF;

  RETURN COALESCE(v_rows, '{}'::jsonb);
END; $$;

COMMENT ON FUNCTION message_reaction_tallies(read_scope, BIGINT[]) IS
  'Reaction counts for a page of messages, as {message_id: [{emoji, count, '
  'mine}]}. One row per (message, emoji) instead of per person, and returned '
  'as a scalar rather than a set, so a lively page cannot overflow the 1000-row '
  'response cap and silently read low. Ordered by emoji so two clients drawing '
  'the same message draw it the same way.';

-- ============================================================
-- Pins
-- ============================================================
-- One call for both directions and both kinds of conversation, because the
-- client asks one question — "should this be pinned" — and the answer is the
-- same shape everywhere.
--
-- **Capped at fifty per conversation.** The list is fetched whole and every
-- row in it is a message to decrypt, so an unbounded one is a list that gets
-- slower to open the longer a channel lives. Fifty is what Discord settled on,
-- and it is a lot of messages to have decided are the important ones.
--
-- A pin names a message, never its words. What the list shows is the message
-- row itself, read through `messages_select` / `dm_messages_select` and
-- decrypted by the client like any other.

CREATE OR REPLACE FUNCTION set_pinned(
  p_scope   read_scope,
  p_message BIGINT,
  p_pinned  BOOLEAN
) RETURNS VOID
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_channel UUID;
  v_low     UUID;
  v_high    UUID;
BEGIN
  -- A pin rings the channel or the other person, so it is something said, and
  -- a time-out means saying nothing — unpinning included.
  IF app.timed_out() THEN
    RAISE EXCEPTION 'timed_out';
  END IF;

  IF p_scope = 'channel' THEN
    -- Neither a press nor a reply only one person can see: both are rows most
    -- of the channel cannot read, and a pin is a thing the whole channel sees.
    SELECT m.channel_id INTO v_channel
      FROM messages m
     WHERE m.id = p_message
       AND NOT m.is_interaction AND m.ephemeral_for IS NULL;
    IF v_channel IS NULL OR NOT app.can_see_message(p_message) THEN
      RAISE EXCEPTION 'message_not_found';
    END IF;
    IF NOT app.can_pin_in(v_channel) THEN
      RAISE EXCEPTION 'cannot_pin';
    END IF;

    IF p_pinned THEN
      IF NOT EXISTS (SELECT 1 FROM message_pins WHERE message_id = p_message)
         AND (SELECT count(*) FROM message_pins WHERE channel_id = v_channel) >= 50
      THEN
        RAISE EXCEPTION 'pin_limit';
      END IF;
      INSERT INTO message_pins (message_id, channel_id, pinned_by)
      VALUES (p_message, v_channel, auth.uid())
      ON CONFLICT (message_id) DO NOTHING;
    ELSE
      DELETE FROM message_pins WHERE message_id = p_message;
    END IF;

    IF app.realtime_ready() THEN
      PERFORM app.announce_to_channel(v_channel, 'pin',
        jsonb_build_object('message_id', p_message, 'channel_id', v_channel));
    END IF;
    RETURN;
  END IF;

  -- A DM: either of the two, and nobody else — and not a banned member, who
  -- can no longer send one either. A pin rings the other side, so without
  -- this a ban would leave a way to keep poking the people they wrote to.
  SELECT LEAST(d.sender_id, d.recipient_id), GREATEST(d.sender_id, d.recipient_id)
    INTO v_low, v_high
    FROM dm_messages d
   WHERE d.id = p_message AND auth.uid() IN (d.sender_id, d.recipient_id)
     AND app.server_id() IS NOT NULL;
  IF v_low IS NULL THEN
    RAISE EXCEPTION 'message_not_found';
  END IF;
  -- And not somebody who has blocked you, whom it would ring all the same.
  -- Refused in the DM gate's words, so it reads as a setting there too.
  IF app.blocked_by(CASE WHEN v_low = auth.uid() THEN v_high ELSE v_low END) THEN
    RAISE EXCEPTION 'dm_not_accepted';
  END IF;

  IF p_pinned THEN
    IF NOT EXISTS (SELECT 1 FROM dm_message_pins WHERE message_id = p_message)
       AND (SELECT count(*) FROM dm_message_pins
             WHERE user_low = v_low AND user_high = v_high) >= 50
    THEN
      RAISE EXCEPTION 'pin_limit';
    END IF;
    INSERT INTO dm_message_pins (message_id, user_low, user_high, pinned_by)
    VALUES (p_message, v_low, v_high, auth.uid())
    ON CONFLICT (message_id) DO NOTHING;
  ELSE
    DELETE FROM dm_message_pins WHERE message_id = p_message;
  END IF;

  -- Both sides, the pinner included: their other devices have the same list
  -- open, and a phone should not have to be told by its owner's desktop.
  IF app.realtime_ready() THEN
    PERFORM realtime.send(
      jsonb_build_object('message_id', p_message,
                         'user_low', v_low, 'user_high', v_high),
      'dm_pin', 'user:' || u, true)
      FROM unnest(ARRAY[v_low, v_high]) AS u;
  END IF;
END; $$;

COMMENT ON FUNCTION set_pinned(read_scope, BIGINT, BOOLEAN) IS
  'Pin or unpin a message. In a channel it takes PIN_MESSAGES (or managing '
  'a private channel); in a DM either of the two may. Fifty per conversation; '
  'the fifty-first raises pin_limit. Rings `pin` / `dm_pin` with the id.';

-- ============================================================
-- Polls
-- ============================================================
-- The poll is posted as a message: its words in the ciphertext, its rules in
-- `messages.poll`. What is here is everything that happens after — voting,
-- counting, and ending it early — and all three are functions rather than
-- table writes, because each has a rule a policy cannot say (is it still
-- open, is that a real option, is a second pick allowed).
--
-- **Counts, not voters.** `poll_tallies` answers how many picked each option,
-- how many people voted, and which options the *caller* picked. Nothing here
-- tells a member who somebody else voted for. Whoever runs the server can
-- still read `poll_votes`, and the client does not pretend otherwise.

CREATE OR REPLACE FUNCTION poll_tallies(p_ids BIGINT[]) RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_ids  BIGINT[];
  v_rows JSONB;
BEGIN
  -- The same cap as reactions, for the same reason.
  v_ids := (SELECT array_agg(id) FROM (
              SELECT unnest(COALESCE(p_ids, ARRAY[]::BIGINT[])) AS id
               LIMIT 100) capped);
  IF v_ids IS NULL THEN RETURN '{}'::jsonb; END IF;

  -- SECURITY DEFINER because the votes table shows a member only their own
  -- rows, and a count has to see everybody's. Visibility is therefore asked
  -- by hand, per message, with the same question `messages_select` asks.
  SELECT jsonb_object_agg(m.id::TEXT, jsonb_build_object(
           'counts', (SELECT jsonb_agg(COALESCE(c.n, 0) ORDER BY g.o)
                        FROM generate_series(0, (m.poll ->> 'options')::INT - 1) AS g(o)
                        LEFT JOIN (SELECT v.option, count(*) AS n
                                     FROM poll_votes v
                                    WHERE v.message_id = m.id
                                    GROUP BY v.option) c ON c.option = g.o),
           'voters', (SELECT count(DISTINCT v.user_id)
                        FROM poll_votes v WHERE v.message_id = m.id),
           'mine',   COALESCE((SELECT jsonb_agg(v.option ORDER BY v.option)
                                 FROM poll_votes v
                                WHERE v.message_id = m.id
                                  AND v.user_id = auth.uid()), '[]'::jsonb)))
    INTO v_rows
    FROM messages m
   WHERE m.id = ANY (v_ids)
     AND m.poll IS NOT NULL
     AND app.can_see_message(m.id);

  RETURN COALESCE(v_rows, '{}'::jsonb);
END; $$;

COMMENT ON FUNCTION poll_tallies(BIGINT[]) IS
  'Results for the polls among these messages, as {message_id: {counts: '
  '[per option], voters, mine: [the caller''s options]}}. Never who voted '
  'for what.';

CREATE OR REPLACE FUNCTION vote_poll(p_message BIGINT, p_options SMALLINT[])
  RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_poll    JSONB;
  v_channel UUID;
  v_options SMALLINT[];
BEGIN
  SELECT m.poll, m.channel_id INTO v_poll, v_channel
    FROM messages m WHERE m.id = p_message;
  IF v_poll IS NULL OR NOT app.can_see_message(p_message) THEN
    RAISE EXCEPTION 'poll_not_found';
  END IF;
  -- A bot reads what it is given; it does not get a say.
  IF app.is_bot() THEN
    RAISE EXCEPTION 'poll_not_found';
  END IF;
  IF (v_poll ->> 'closes_at')::timestamptz <= now() THEN
    RAISE EXCEPTION 'poll_closed';
  END IF;

  v_options := ARRAY(SELECT DISTINCT o
                       FROM unnest(COALESCE(p_options, ARRAY[]::SMALLINT[])) AS o
                      ORDER BY o);
  IF EXISTS (SELECT 1 FROM unnest(v_options) AS o
              WHERE o IS NULL OR o < 0 OR o >= (v_poll ->> 'options')::INT) THEN
    RAISE EXCEPTION 'poll_bad_option';
  END IF;
  IF NOT (v_poll ->> 'multiple')::BOOLEAN AND cardinality(v_options) > 1 THEN
    RAISE EXCEPTION 'poll_single_choice';
  END IF;

  -- The ballot replaces the last one, so changing a vote and taking it back
  -- (an empty array) are the same call as casting it.
  DELETE FROM poll_votes
   WHERE message_id = p_message AND user_id = auth.uid()
     AND option <> ALL (v_options);
  INSERT INTO poll_votes (message_id, user_id, option)
  SELECT p_message, auth.uid(), o FROM unnest(v_options) AS o
  ON CONFLICT DO NOTHING;

  -- Says that the count moved, not whose vote moved it.
  IF app.realtime_ready() THEN
    PERFORM app.announce_to_channel(v_channel, 'poll',
      jsonb_build_object('message_id', p_message, 'channel_id', v_channel));
  END IF;

  RETURN poll_tallies(ARRAY[p_message]) -> p_message::TEXT;
END; $$;

COMMENT ON FUNCTION vote_poll(BIGINT, SMALLINT[]) IS
  'Replace the caller''s ballot on a poll: every option they want picked, or '
  'none to take the vote back. Returns the new tally. Raises poll_closed, '
  'poll_bad_option or poll_single_choice.';

-- Ending a poll early is the author's, and it moves `closes_at` to now rather
-- than setting a second flag: "voting has stopped" is one fact, and a poll
-- that closed early and one that ran its course read the same afterwards.
-- The UPDATE rings `message_changed` through the ordinary trigger, which is
-- how every reader learns the rules changed.
CREATE OR REPLACE FUNCTION close_poll(p_message BIGINT) RETURNS VOID
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_poll   JSONB;
  v_sender UUID;
BEGIN
  SELECT m.poll, m.sender_id INTO v_poll, v_sender
    FROM messages m WHERE m.id = p_message;
  IF v_poll IS NULL OR NOT app.can_see_message(p_message) THEN
    RAISE EXCEPTION 'poll_not_found';
  END IF;
  IF v_sender IS DISTINCT FROM auth.uid() THEN
    RAISE EXCEPTION 'not_poll_author';
  END IF;
  IF (v_poll ->> 'closes_at')::timestamptz <= now() THEN
    RETURN;
  END IF;
  UPDATE messages
     SET poll = jsonb_set(poll, '{closes_at}', to_jsonb(now()))
   WHERE id = p_message;
END; $$;

COMMENT ON FUNCTION close_poll(BIGINT) IS
  'End a poll now. Its author only; closing a closed poll does nothing.';

-- ---------- issuing ----------
-- Called by the `listing_token` edge function, which has already established
-- that the caller is an admin of this server. The check is repeated here
-- anyway: a function that mints proof of administration should not be one
-- whose safety depends on its only caller remembering to ask.
--
-- The member is passed in rather than read from `auth.uid()`, and that is not
-- a preference. The edge function holds the service key — as every one of them
-- does — so inside this function there is no session and `auth.uid()` is null.
-- Written the obvious way, with `app.is_admin()`, it refused every caller
-- including the admin it was written for, and said `not_server_admin` while
-- doing it. `publish_server_as` on central takes the same shape for the same
-- reason: a verified id, passed by the only thing that could verify it.

CREATE OR REPLACE FUNCTION issue_listing_token(
  p_user_id    UUID,
  p_server_id  UUID,
  p_token_hash TEXT
) RETURNS TIMESTAMPTZ
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_expires TIMESTAMPTZ;
BEGIN
  -- An admin of *this* server, not banned, and not an admin of some other
  -- server on the same stack.
  IF NOT EXISTS (
    SELECT 1 FROM users u
     WHERE u.id = p_user_id
       AND u.server_id = p_server_id
       AND u.is_server_admin
       AND NOT u.is_banned
  ) THEN
    RAISE EXCEPTION 'not_server_admin';
  END IF;

  -- Housekeeping on the way past, so the table cannot grow without a job to
  -- trim it. Expired rows prove nothing and redeeming one is already refused.
  DELETE FROM listing_tokens WHERE expires_at < now() - INTERVAL '1 hour';

  INSERT INTO listing_tokens (token_hash, server_id)
       VALUES (p_token_hash, p_server_id)
    RETURNING expires_at INTO v_expires;

  RETURN v_expires;
END; $$;

COMMENT ON FUNCTION issue_listing_token(UUID, UUID, TEXT) IS
  'Record a one-time listing token for this server. Admin only, and it checks '
  'that itself rather than trusting its caller to have done so.';

-- ---------- redeeming ----------
-- Called by central, which holds no session here at all — see the
-- verify_listing_token function for why that is safe and what it may learn.
--
-- Redeeming is one statement so that two arrivals of the same token cannot
-- both find it unused: the UPDATE ... WHERE used_at IS NULL either matches a
-- row or does not, and only the caller that matched gets a row back.

CREATE OR REPLACE FUNCTION redeem_listing_token(p_token_hash TEXT)
RETURNS UUID
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  UPDATE listing_tokens
     SET used_at = now()
   WHERE token_hash = p_token_hash
     AND used_at IS NULL
     AND expires_at > now()
  RETURNING server_id
$$;

COMMENT ON FUNCTION redeem_listing_token(TEXT) IS
  'Burn a listing token and return the server it was issued for, or nothing. '
  'Single-use and single-statement, so a replay finds it already spent.';

-- ============================================================
-- 5. Passing it on
-- ============================================================
-- The one write that moves the owner role. Definer, because the policies
-- refuse this role in both directions and should keep doing so; the checks
-- the policies would have made are made here instead, in the order that
-- leaves the server with exactly one owner whichever line raises.

CREATE OR REPLACE FUNCTION transfer_ownership(p_user UUID) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_role   UUID;
  v_target users%ROWTYPE;
BEGIN
  SELECT r.id INTO v_role
    FROM member_roles mr
    JOIN roles r ON r.id = mr.role_id
   WHERE mr.user_id = auth.uid() AND r.is_owner;
  IF v_role IS NULL THEN
    RAISE EXCEPTION 'not_owner';
  END IF;

  SELECT * INTO v_target FROM users
   WHERE id = p_user AND server_id = app.server_id();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;
  IF v_target.id = auth.uid() THEN
    RAISE EXCEPTION 'cannot_transfer_to_self';
  END IF;
  IF v_target.is_bot THEN
    RAISE EXCEPTION 'bot_cannot_own';
  END IF;
  IF v_target.is_banned THEN
    RAISE EXCEPTION 'user_banned';
  END IF;

  DELETE FROM member_roles WHERE user_id = auth.uid() AND role_id = v_role;
  INSERT INTO member_roles (user_id, role_id, granted_by)
  VALUES (p_user, v_role, auth.uid());

  -- Stepping down from owner, not from running the place: the most senior
  -- role beneath that still carries `ADMINISTRATOR`, if the server has one.
  INSERT INTO member_roles (user_id, role_id, granted_by)
  SELECT auth.uid(), r.id, auth.uid()
    FROM roles r
   WHERE r.server_id = app.server_id()
     AND NOT r.is_owner AND NOT r.is_everyone
     AND (r.permissions & app.perm('ADMINISTRATOR')) <> 0
   ORDER BY r.position DESC
   LIMIT 1
  ON CONFLICT DO NOTHING;
END; $$;

-- ============================================================
-- 6. Ending it
-- ============================================================
-- The row delete cascades to everything the server holds. What it cannot
-- reach — the LiveKit rooms and the storage buckets — the `delete_server`
-- edge function clears with the service role, after this has said yes.
-- Authority stays here: the function is the gate, the edge function is the
-- broom.

CREATE OR REPLACE FUNCTION delete_server() RETURNS UUID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
BEGIN
  IF v_server IS NULL OR NOT EXISTS (
       SELECT 1 FROM member_roles mr
         JOIN roles r ON r.id = mr.role_id
        WHERE mr.user_id = auth.uid() AND r.is_owner AND r.server_id = v_server) THEN
    RAISE EXCEPTION 'not_owner';
  END IF;
  DELETE FROM servers WHERE id = v_server;
  RETURN v_server;
END; $$;

-- ============================================================
-- 2. Registration grants only what the invite names
-- ============================================================
-- `register_user` is defined once, further down under "Refusing the member
-- who would go over": the same function with the member cap and a kicked
-- member's readmission added. A second `CREATE OR REPLACE` of the same
-- signature in the same file replaced the one that stood here, and two bodies
-- claiming to be one function is a trap for whoever edits the first and
-- watches nothing change.

-- ============================================================
-- A badge stops reading the whole server
-- ============================================================
-- Two things every member's app does constantly, both of which read far more
-- than the answer needs. Measured on a copy of this schema carrying 200,000
-- messages and 1,000 members.
--
-- ---------- 1. the badges ----------
--
-- `unread_counts()` asked the question from the wrong end: it scanned
-- `messages` and grouped by channel. Two things follow from that, and both
-- are bad.
--
-- The policy on `messages` calls `app.can_see_channel(channel_id)`, so driving
-- from the rows means asking it **once per row** — 606,000 buffer hits for a
-- 200,000-row table. And the count itself is unbounded: a member who has never
-- opened a channel counts every message in it, forever, on every call.
--
--   caught-up member .................. 10,840 ms
--   never-opened channel, 200k unread . 11,184 ms
--
-- This asks from the channel end instead. A server has a handful of channels,
-- so the policy runs a handful of times, and each channel is a walk of
-- `idx_messages_channel` from the member's cursor forward — which is what that
-- index is for. The same two cases:
--
--   caught-up member ..................      1.3 ms
--   never-opened channel, 200k unread .      7.0 ms
--
-- The cap is what makes the second one a constant. `UnreadBadge` draws "99+"
-- above ninety-nine, and a server total is the sum of the channels under it,
-- so a channel that stops counting at a hundred draws exactly what an honest
-- count of five thousand would have drawn. A number nobody can read is not
-- worth a table scan an hour.
--
-- ---------- 2. the prefs it carries ----------
--
-- The `prefs` key has to be here. The client reads `data['prefs']`, and on a
-- null falls back to the defaults — so dropping it does not fail, it makes
-- muting a channel work until the next re-seed and then quietly stop, on
-- every device, for everyone.
--
-- ---------- 3. the doorbell nobody ordered ----------
--
-- `ring_channel_members` built the recipient list — every member of the
-- server, each one weighed by `app.channel_eligible` and `has_unread_before`
-- — and only then called `ring_devices`, which is where the question "is push
-- even turned on here?" was asked. On a server with no `push_config` row, all
-- of that work was done and thrown away on **every message**:
--
--   insert with the trigger disabled ....  8 ms
--   insert with the trigger enabled ..... 25–45 ms
--
-- Push is off until an admin turns it on, so that is the default state of
-- every server that has ever been started. The check moves to the top.

-- ============================================================
-- 1. Counting from the channel end
-- ============================================================

-- How high a badge bothers to count. The client draws "99+" past ninety-nine.
CREATE OR REPLACE FUNCTION unread_cap() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 100 $$;

COMMENT ON FUNCTION unread_cap() IS
  'The most a single scope''s unread count will report. The badge says "99+" '
  'above ninety-nine, so anything past this is a number nobody reads.';

CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_channels JSONB := '{}'::jsonb;
  v_chan     RECORD;
  v_cursor   BIGINT;
  v_first    BIGINT;
  v_n        INTEGER;
BEGIN
  -- SECURITY INVOKER, so this is the channels the caller may see and no
  -- others: `channels_select` decides, once per channel, instead of
  -- `messages_select` deciding once per message.
  FOR v_chan IN SELECT c.id FROM channels c LOOP
    SELECT r.last_read_id INTO v_cursor
      FROM read_state r
     WHERE r.user_id = auth.uid()
       AND r.scope   = 'channel'
       AND r.scope_id = v_chan.id;
    v_cursor := COALESCE(v_cursor, 0);

    -- Where this channel's unread mail actually starts, taken off
    -- `idx_messages_channel` and used as a floor below.
    --
    -- It changes nothing about the answer — nothing in this channel sits
    -- between the cursor and its own first row above it — and everything
    -- about the plan. `id > cursor ORDER BY id LIMIT cap` can be served by
    -- the primary key, which walks ids upwards from the cursor discarding
    -- every other channel's messages, and for a cursor left in a channel
    -- that has since gone quiet that is the whole server's traffic since:
    -- 714 ms and a million rows against 5,000,000. With the floor, 0.57 ms.
    --
    -- Today the policy happens to hide that: its quals make the primary-key
    -- path expensive enough per row that the planner picks the right index
    -- anyway. That is luck, not design — the same query with the policy
    -- stripped takes the bad plan — and this function runs on every app
    -- open, once per channel.
    SELECT min(m.id) INTO v_first
      FROM messages m
     WHERE m.channel_id = v_chan.id AND m.id > v_cursor;

    -- Nothing here since the cursor, which is the usual case for most
    -- channels most of the time: no badge, and no second statement either.
    IF v_first IS NULL THEN
      CONTINUE;
    END IF;

    -- A constant channel and a constant cursor, which is what lets the
    -- planner use `idx_messages_channel (channel_id, id)` as a range: start
    -- at the cursor, walk forward, stop at the cap. Written as a correlated
    -- subquery in one big statement it chose a sequential scan instead, cap
    -- and all, which is how the old shape came to cost eleven seconds.
    SELECT count(*) INTO v_n FROM (
      SELECT 1 FROM messages m
       WHERE m.channel_id = v_chan.id
         AND m.id > v_cursor
         AND m.id >= v_first
         -- IS DISTINCT FROM, not <>. A webhook's sender is NULL, and `NULL <>
         -- uid` is NULL rather than true — so every webhook message was
         -- dropped from this count in silence.
         AND m.sender_id IS DISTINCT FROM auth.uid()
         -- A press is not unread mail.
         AND NOT m.is_interaction
       ORDER BY m.id
       LIMIT unread_cap()
    ) capped;

    IF v_n > 0 THEN
      v_channels := v_channels || jsonb_build_object(v_chan.id::TEXT, v_n);
    END IF;
  END LOOP;

  RETURN jsonb_build_object(
    'channels', v_channels,
    -- DMs stay a grouped read: `idx_dm_messages_recipient (recipient_id, id)`
    -- already makes this the caller's own unread mail rather than the table,
    -- and there is no conversation list to drive the loop from.
    'dms', COALESCE((
      SELECT jsonb_object_agg(sender_id, n) FROM (
        SELECT d.sender_id, count(*) AS n
          FROM dm_messages d
          LEFT JOIN read_state r
            ON r.user_id = auth.uid()
           AND r.scope = 'dm'
           AND r.scope_id = d.sender_id
         WHERE d.recipient_id = auth.uid()
           AND d.id > COALESCE(r.last_read_id, 0)
         GROUP BY d.sender_id
      ) d
      -- A request is not mail until it is accepted. Asked per sender, after
      -- the grouping, so it is one question per conversation, not per row.
      WHERE NOT app.dm_is_request(d.sender_id, auth.uid())), '{}'::jsonb),
    -- Only what has been set: an absent key means "no opinion here, ask the
    -- next scope out".
    'prefs', jsonb_build_object(
      'servers', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'server'), '{}'::jsonb),
      'channels', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'channel'), '{}'::jsonb),
      'dms', COALESCE((
        SELECT jsonb_object_agg(p.scope_id, p.level::TEXT)
          FROM notification_prefs p
         WHERE p.user_id = auth.uid() AND p.scope = 'dm'), '{}'::jsonb)
    ));
END $$;

COMMENT ON FUNCTION unread_counts() IS
  'Badges and notification levels in one answer: {channels, dms, prefs}. '
  'Channel counts stop at unread_cap().';

-- ============================================================
-- 3. The list, read from the heads
-- ============================================================
-- Everything from `kept` down is unchanged: the same envelope, the same peer
-- identity, the same spare row proving `has_more`.
--
-- `page` reads the heads alone and the join happens under it, which is the
-- difference between a plan and a good one: asked for the join first, the
-- planner sorts every head the caller has and merges, so the cost comes back
-- with the conversation count. Reading the heads by themselves lets it walk
-- `idx_dm_conversation_heads_recent` in order and stop at thirty-one.
--
-- Nothing is lost by joining later. `dm_messages_select` admits the sender
-- and the recipient and asks nothing else — not membership, not a ban — so
-- the head of your own conversation is a row you can always read, and the
-- join can never drop one the page counted.

CREATE OR REPLACE FUNCTION dm_conversations(
  p_limit  INTEGER DEFAULT 30,
  p_before BIGINT  DEFAULT NULL
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  WITH page AS (
    SELECT h.last_message_id AS id, h.peer_id AS peer
      FROM dm_conversation_heads h
     WHERE h.user_id = auth.uid()
       AND (p_before IS NULL OR h.last_message_id < p_before)
     ORDER BY h.last_message_id DESC
     -- One row past the page, so "there is more" is proved rather than
     -- guessed from a full page. Same trick the message history and central
     -- use.
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100) + 1
  ),
  kept AS (
    SELECT d.*, p.peer
      FROM (SELECT * FROM page
             ORDER BY id DESC
             LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100)) p
      JOIN dm_messages d ON d.id = p.id
  ),
  rows AS (
    SELECT jsonb_build_object(
             'peer_id',               u.id,
             'peer_name',             u.display_name,
             'peer_username',         u.username,
             'peer_avatar_path',      u.avatar_path,
             'peer_chat_public_key',  u.chat_public_key,
             'peer_public_key',       u.public_key,
             'last_message', jsonb_build_object(
               'id',           k.id,
               'created_at',   k.created_at,
               'sender_id',    k.sender_id,
               'recipient_id', k.recipient_id,
               'ciphertext',   k.ciphertext,
               'nonce',        k.nonce,
               'signature',    k.signature,
               'key_version',  k.key_version,
               'edited_at',    k.edited_at
             )
           ) AS row,
           k.id AS sort_id
      FROM kept k
      JOIN users u ON u.id = k.peer
  )
  SELECT jsonb_build_object(
           'conversations',
           COALESCE((SELECT jsonb_agg(row ORDER BY sort_id DESC) FROM rows),
                    '[]'::jsonb),
           'has_more',
           (SELECT count(*) FROM page) > (SELECT count(*) FROM kept));
$$;

COMMENT ON FUNCTION dm_conversations(INTEGER, BIGINT) IS
  'The caller''s DM conversations, newest first, a page at a time. Read from '
  'dm_conversation_heads, so it costs a page rather than a history.';

-- ============================================================
-- Requests
-- ============================================================
-- A member set to `requests` receives a first message from somebody new as a
-- request: it does not ring, it is not in their conversation list, and the
-- sender may send nothing more until it is answered. `app.gate_dm` (004)
-- decides that on the way in; these three are how each side sees it after.

-- Where the caller stands with one other member:
--
--   none     nothing between you yet
--   open     an ordinary conversation
--   waiting  you asked and have not been answered
--   asked    they asked you
--   ignored  they asked you and you put it away
--
-- `waiting` covers the recipient having ignored it. That is the one fact this
-- function exists to keep from the sender.
CREATE OR REPLACE FUNCTION dm_link_state(p_peer UUID) RETURNS TEXT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT CASE
           WHEN l.status IS NULL          THEN 'none'
           WHEN l.status = 'open'         THEN 'open'
           WHEN l.opened_by = auth.uid()  THEN 'waiting'
           WHEN l.status = 'requested'    THEN 'asked'
           ELSE 'ignored'
         END
    FROM (SELECT 1) AS one
    LEFT JOIN dm_links l
      ON l.user_low  = LEAST(p_peer, auth.uid())
     AND l.user_high = GREATEST(p_peer, auth.uid())
   WHERE app.server_id() IS NOT NULL
$$;

-- The caller's waiting requests, newest first, each with the message that
-- opened it — the same shape `dm_conversations` gives a row, so one parser
-- reads both. Not the ignored ones, and not from anybody the caller has
-- blocked or who has since been banned.
CREATE OR REPLACE FUNCTION dm_requests() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  WITH mine AS (
    SELECT l.opened_by AS peer, l.opened_at
      FROM dm_links l
     WHERE (l.user_low = auth.uid() OR l.user_high = auth.uid())
       AND l.status = 'requested'
       AND l.opened_by <> auth.uid()
       AND app.server_id() IS NOT NULL
  )
  SELECT COALESCE(jsonb_agg(row ORDER BY opened_at DESC), '[]'::jsonb)
    FROM (
      SELECT m.opened_at, jsonb_build_object(
               'peer_id',              u.id,
               'peer_name',            u.display_name,
               'peer_username',        u.username,
               'peer_avatar_path',     u.avatar_path,
               'peer_chat_public_key', u.chat_public_key,
               'peer_public_key',      u.public_key,
               'opened_at',            m.opened_at,
               'last_message', (
                 SELECT jsonb_build_object(
                          'id',           d.id,
                          'created_at',   d.created_at,
                          'sender_id',    d.sender_id,
                          'recipient_id', d.recipient_id,
                          'ciphertext',   d.ciphertext,
                          'nonce',        d.nonce,
                          'signature',    d.signature,
                          'key_version',  d.key_version,
                          'edited_at',    d.edited_at)
                   FROM dm_messages d
                  WHERE d.sender_id = u.id AND d.recipient_id = auth.uid()
                  ORDER BY d.id DESC
                  LIMIT 1)) AS row
        FROM mine m
        JOIN users u ON u.id = m.peer
       WHERE NOT u.is_banned
         AND NOT EXISTS (SELECT 1 FROM member_blocks b
                          WHERE b.blocker_id = auth.uid() AND b.blocked_id = u.id)
       ORDER BY m.opened_at DESC
       LIMIT 100
    ) page
$$;

-- Accept or ignore. Accepting opens the conversation and puts it in the
-- caller's list, where the request's message becomes ordinary mail, and rings
-- the sender: their composer stays locked on "waiting" until they read the
-- state again. Ignoring tells nobody: the sender's side reads `waiting` either
-- way.
--
-- An ignored request can still be accepted later, and replying to one — from
-- the conversation, without pressing anything — accepts it too (004).
CREATE OR REPLACE FUNCTION answer_dm_request(p_peer UUID, p_accept BOOLEAN)
  RETURNS TEXT
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me     UUID := auth.uid();
  v_link   dm_links%ROWTYPE;
  v_newest BIGINT;
BEGIN
  IF app.server_id() IS NULL THEN RAISE EXCEPTION 'not_authorized'; END IF;
  IF p_accept IS NULL THEN RAISE EXCEPTION 'answer_required'; END IF;

  SELECT * INTO v_link FROM dm_links l
   WHERE l.user_low  = LEAST(p_peer, v_me)
     AND l.user_high = GREATEST(p_peer, v_me)
   FOR UPDATE;
  IF NOT FOUND OR v_link.status = 'open' OR v_link.opened_by = v_me THEN
    RAISE EXCEPTION 'no_request';
  END IF;

  UPDATE dm_links l
     SET status = CASE WHEN p_accept THEN 'open'::dm_link_status
                       ELSE 'ignored'::dm_link_status END,
         answered_at = now()
   WHERE l.user_low = v_link.user_low AND l.user_high = v_link.user_high;

  IF p_accept THEN
    SELECT max(d.id) INTO v_newest
      FROM dm_messages d
     WHERE LEAST(d.sender_id, d.recipient_id)    = v_link.user_low
       AND GREATEST(d.sender_id, d.recipient_id) = v_link.user_high;
    IF v_newest IS NOT NULL THEN
      INSERT INTO dm_conversation_heads (user_id, peer_id, last_message_id)
      VALUES (v_me, p_peer, v_newest)
          ON CONFLICT (user_id, peer_id) DO UPDATE
         SET last_message_id = GREATEST(dm_conversation_heads.last_message_id,
                                        EXCLUDED.last_message_id);
    END IF;
  END IF;

  PERFORM app.announce_to_member(v_me, 'dm_requests');
  IF p_accept THEN
    PERFORM app.announce_to_member(p_peer, 'dm_requests');
  END IF;
  RETURN CASE WHEN p_accept THEN 'open' ELSE 'ignored' END;
END; $$;

-- ============================================================
-- Calls
-- ============================================================
-- A call between two members is a row (`dm_calls`, 001) and a LiveKit room
-- named after it. These are the only writers of the row. The room is the
-- token function's (`get_dm_call_token`), and it will only mint for a call
-- these have let exist.
--
-- Who may call whom follows the DM rules rather than inventing its own:
--
--   * only an **open** conversation — somebody who asks first has to have
--     accepted, and somebody who takes nobody new has to already know you;
--   * a block stops calls exactly as it stops messages, and reads the same
--     (`call_not_accepted`), so it still reads as a setting;
--   * a member who is timed out cannot start one, and one who may not
--     `CONNECT` to voice cannot either;
--   * five unanswered calls to one person in an hour is the most anybody
--     rings them, because a phone that rings is harder to ignore than a badge.

-- How long a call rings before it is over. The caller's client hangs up at
-- thirty seconds; this is the server's own limit, a little longer so that an
-- answer in flight at the thirtieth second still lands.
CREATE OR REPLACE FUNCTION app.dm_call_ring_window() RETURNS INTERVAL
  LANGUAGE sql IMMUTABLE AS $$ SELECT interval '45 seconds' $$;

-- A caller who hangs up after this long hung up on somebody who had a
-- chance to answer: `missed`. Sooner is `cancelled`, which nobody is told
-- about as though they had missed something.
CREATE OR REPLACE FUNCTION app.dm_call_missed_after() RETURNS INTERVAL
  LANGUAGE sql IMMUTABLE AS $$ SELECT interval '15 seconds' $$;

-- An answered call nobody has touched for this long is over.
CREATE OR REPLACE FUNCTION app.dm_call_silence_limit() RETURNS INTERVAL
  LANGUAGE sql IMMUTABLE AS $$ SELECT interval '3 minutes' $$;

-- A call as one of its two people sees it: the row, and who is on the other
-- end — including their chat key, because the media key is derived from the
-- pair's DM key and the callee may never have opened this conversation on the
-- device that is ringing.
CREATE OR REPLACE FUNCTION app.dm_call_json(p_call dm_calls, p_me UUID)
  RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT jsonb_build_object(
           'id',                   p_call.id,
           'caller_id',            p_call.caller_id,
           'callee_id',            p_call.callee_id,
           'started_at',           p_call.started_at,
           'answered_at',          p_call.answered_at,
           'ended_at',             p_call.ended_at,
           'outcome',              p_call.outcome,
           'peer_id',              u.id,
           'peer_name',            u.display_name,
           'peer_username',        u.username,
           'peer_avatar_path',     u.avatar_path,
           'peer_chat_public_key', u.chat_public_key,
           'peer_public_key',      u.public_key)
    FROM users u
   WHERE u.id = CASE WHEN p_call.caller_id = p_me
                     THEN p_call.callee_id ELSE p_call.caller_id END
$$;

-- Close whatever between these two is past its time: a ring nobody answered
-- inside the window, or an answered call gone silent. Run before anything
-- asks whether the pair has a call going, so a stale row can never stand in
-- the way of a new one — and by the sweep (007) for every pair at once, with
-- both left NULL.
CREATE OR REPLACE FUNCTION app.close_stale_dm_calls(
  p_low UUID DEFAULT NULL, p_high UUID DEFAULT NULL
)
  RETURNS VOID
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  UPDATE dm_calls c
     SET ended_at = CASE WHEN c.answered_at IS NULL
                         THEN c.started_at + app.dm_call_ring_window()
                         ELSE c.alive_at END,
         outcome  = CASE WHEN c.answered_at IS NULL
                         THEN 'missed'::dm_call_outcome
                         ELSE 'completed'::dm_call_outcome END
   WHERE c.ended_at IS NULL
     AND (p_low IS NULL OR (LEAST(c.caller_id, c.callee_id)    = p_low
                        AND GREATEST(c.caller_id, c.callee_id) = p_high))
     AND ((c.answered_at IS NULL
           AND c.started_at < now() - app.dm_call_ring_window())
       OR (c.answered_at IS NOT NULL
           AND c.alive_at < now() - app.dm_call_silence_limit()))
$$;

-- Ring somebody. Returns the call.
--
-- If the two of them already have one ringing it is returned instead of a
-- second — and if that one is *them* ringing *you*, calling back is picking
-- up: it is answered here, so two people pressing Call at the same moment
-- end up in one call rather than each hearing the other's line busy.
--
-- One the pair already *answered* is a different matter. Pressing Call means
-- the presser is not in it — the app hides the button on a device that is —
-- so it is either dead (both apps closed, and the sweep has not got to it
-- yet) or the other person is waiting in it alone after this device dropped
-- out. Rejoining would be right for the second and silent for the first:
-- found live, the presser sat alone in a dead call and nobody was rung. So
-- the old call ends where it last showed signs of life, and this one rings.
-- Somebody still in the old one has it hung up by their app, and sees this
-- one ringing.
CREATE OR REPLACE FUNCTION start_dm_call(p_peer UUID) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me     UUID := auth.uid();
  v_server UUID := app.server_id();
  v_low    UUID := LEAST(p_peer, auth.uid());
  v_high   UUID := GREATEST(p_peer, auth.uid());
  v_call   dm_calls%ROWTYPE;
BEGIN
  IF v_server IS NULL THEN RAISE EXCEPTION 'not_authorized'; END IF;
  IF p_peer IS NULL OR p_peer = v_me THEN RAISE EXCEPTION 'user_not_found'; END IF;

  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_peer AND u.server_id = v_server
                    AND NOT u.is_banned AND NOT u.is_bot) THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;

  IF app.timed_out() THEN RAISE EXCEPTION 'timed_out'; END IF;
  IF NOT app.has_perm('CONNECT') THEN RAISE EXCEPTION 'cannot_connect'; END IF;
  -- Nor a bot, which cannot be rung either: nothing in the SDK can hold a
  -- call's key, so a bot's call is only ever a phone ringing for nothing.
  IF app.is_bot() THEN RAISE EXCEPTION 'cannot_connect'; END IF;

  -- Either direction. Being called by somebody you blocked is the thing a
  -- block is for; calling somebody you blocked is a mis-tap on a button the
  -- app does not show.
  IF EXISTS (SELECT 1 FROM member_blocks b
              WHERE (b.blocker_id = p_peer AND b.blocked_id = v_me)
                 OR (b.blocker_id = v_me   AND b.blocked_id = p_peer)) THEN
    RAISE EXCEPTION 'call_not_accepted';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM dm_links l
                  WHERE l.user_low = v_low AND l.user_high = v_high
                    AND l.status = 'open') THEN
    RAISE EXCEPTION 'call_needs_conversation';
  END IF;

  -- The same lock the DM gate takes on the pair: two calls crossing in flight
  -- must not both decide there is none.
  PERFORM pg_advisory_xact_lock(hashtextextended(v_low::TEXT || v_high::TEXT, 0));
  PERFORM app.close_stale_dm_calls(v_low, v_high);

  SELECT * INTO v_call FROM dm_calls c
   WHERE c.ended_at IS NULL
     AND LEAST(c.caller_id, c.callee_id)    = v_low
     AND GREATEST(c.caller_id, c.callee_id) = v_high;
  IF FOUND AND v_call.answered_at IS NULL THEN
    IF v_call.callee_id = v_me THEN
      UPDATE dm_calls c SET answered_at = now(), alive_at = now()
       WHERE c.id = v_call.id
      RETURNING * INTO v_call;
    END IF;
    RETURN app.dm_call_json(v_call, v_me);
  ELSIF FOUND THEN
    UPDATE dm_calls c
       SET ended_at = GREATEST(c.alive_at, c.answered_at),
           outcome  = 'completed'
     WHERE c.id = v_call.id;
  END IF;

  IF (SELECT count(*) FROM dm_calls c
       WHERE c.caller_id = v_me AND c.callee_id = p_peer
         AND c.started_at > now() - interval '1 hour'
         AND c.answered_at IS NULL) >= 5 THEN
    RAISE EXCEPTION 'call_rate_limited';
  END IF;

  INSERT INTO dm_calls (caller_id, callee_id) VALUES (v_me, p_peer)
  RETURNING * INTO v_call;
  RETURN app.dm_call_json(v_call, v_me);
END; $$;

-- Pick up. Only the person being called, only while it rings, and only once:
-- a second device answering after the first gets `call_not_ringing`, which is
-- how it learns to stop.
CREATE OR REPLACE FUNCTION answer_dm_call(p_call UUID) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me   UUID := auth.uid();
  v_call dm_calls%ROWTYPE;
BEGIN
  IF app.server_id() IS NULL THEN RAISE EXCEPTION 'not_authorized'; END IF;

  SELECT * INTO v_call FROM dm_calls c WHERE c.id = p_call FOR UPDATE;
  IF NOT FOUND OR v_call.callee_id <> v_me THEN
    RAISE EXCEPTION 'call_not_found';
  END IF;
  IF v_call.ended_at IS NOT NULL
     OR v_call.started_at < now() - app.dm_call_ring_window() THEN
    RAISE EXCEPTION 'call_ended';
  END IF;
  IF v_call.answered_at IS NOT NULL THEN
    RAISE EXCEPTION 'call_not_ringing';
  END IF;

  UPDATE dm_calls c SET answered_at = now(), alive_at = now()
   WHERE c.id = p_call
  RETURNING * INTO v_call;
  RETURN app.dm_call_json(v_call, v_me);
END; $$;

-- Hang up, from either end, in any state. What it is called depends on who
-- and when: a ring the callee refuses is `declined`, a ring the caller gives
-- up on is `missed` or `cancelled`, and anything answered is `completed`.
-- Ending one already over returns it as it is — both ends hang up at once
-- all the time.
CREATE OR REPLACE FUNCTION end_dm_call(p_call UUID) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me   UUID := auth.uid();
  v_call dm_calls%ROWTYPE;
BEGIN
  IF app.server_id() IS NULL THEN RAISE EXCEPTION 'not_authorized'; END IF;

  SELECT * INTO v_call FROM dm_calls c WHERE c.id = p_call FOR UPDATE;
  IF NOT FOUND OR v_me NOT IN (v_call.caller_id, v_call.callee_id) THEN
    RAISE EXCEPTION 'call_not_found';
  END IF;
  IF v_call.ended_at IS NOT NULL THEN
    RETURN app.dm_call_json(v_call, v_me);
  END IF;

  UPDATE dm_calls c
     SET ended_at = now(),
         outcome  = CASE
           WHEN c.answered_at IS NOT NULL THEN 'completed'::dm_call_outcome
           WHEN v_me = c.callee_id        THEN 'declined'::dm_call_outcome
           WHEN c.started_at <= now() - app.dm_call_missed_after()
                                          THEN 'missed'::dm_call_outcome
           ELSE 'cancelled'::dm_call_outcome END
   WHERE c.id = p_call
  RETURNING * INTO v_call;
  RETURN app.dm_call_json(v_call, v_me);
END; $$;

-- Still here. Sent by a client in an answered call every twenty seconds;
-- answers whether the call is still going, which is also how a client that
-- missed the hang-up doorbell finds out.
CREATE OR REPLACE FUNCTION dm_call_alive(p_call UUID) RETURNS BOOLEAN
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me UUID := auth.uid();
BEGIN
  IF app.server_id() IS NULL THEN RETURN false; END IF;
  UPDATE dm_calls c SET alive_at = now()
   WHERE c.id = p_call
     AND v_me IN (c.caller_id, c.callee_id)
     AND c.ended_at IS NULL
     AND c.answered_at IS NOT NULL;
  RETURN FOUND;
END; $$;

-- The caller's calls that are still going, from either side, plus any of
-- [p_known] however they stand — so a client that was ringing, or in a call,
-- learns how it ended without a second question. A ring past its window is
-- left out even before the sweep has closed it: it cannot be answered.
CREATE OR REPLACE FUNCTION my_dm_calls(p_known UUID[] DEFAULT '{}')
  RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(jsonb_agg(app.dm_call_json(c, auth.uid())
                            ORDER BY c.started_at DESC), '[]'::jsonb)
    FROM dm_calls c
   WHERE app.server_id() IS NOT NULL
     AND auth.uid() IN (c.caller_id, c.callee_id)
     AND ((c.ended_at IS NULL
           AND (c.answered_at IS NOT NULL
                OR c.started_at >= now() - app.dm_call_ring_window()))
          OR c.id = ANY (COALESCE(p_known, '{}')))
$$;

-- One conversation's calls since [p_since], newest first — the stretch of
-- history the client has messages loaded for. A call still ringing is not
-- history yet and is left to `my_dm_calls`.
CREATE OR REPLACE FUNCTION dm_call_log(p_peer UUID, p_since TIMESTAMPTZ)
  RETURNS JSONB
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(jsonb_agg(row ORDER BY started_at DESC), '[]'::jsonb)
    FROM (
      SELECT c.started_at, app.dm_call_json(c, auth.uid()) AS row
        FROM dm_calls c
       WHERE app.server_id() IS NOT NULL
         AND LEAST(c.caller_id, c.callee_id)    = LEAST(p_peer, auth.uid())
         AND GREATEST(c.caller_id, c.callee_id) = GREATEST(p_peer, auth.uid())
         AND c.started_at >= COALESCE(p_since, '-infinity')
         AND (c.answered_at IS NOT NULL OR c.ended_at IS NOT NULL)
       ORDER BY c.started_at DESC
       LIMIT 200
    ) page
$$;

-- For the token function: may this member have a token for this call's
-- room, and which node is it on? The caller from the first ring, so the
-- line is already open when the callee picks up; the callee once they have.
--
-- `{allowed, node}`, with `node` null on a server that has no node rows and
-- runs on `servers.livekit_url` alone. The node is claimed on the first ask
-- and kept, because a room lives on one box; a suggestion counts only if it is
-- one of this server's, as with a channel. [p_move_to_default] is for a node
-- that did not answer: the call goes to the default instead.
CREATE OR REPLACE FUNCTION claim_dm_call_room(
  p_call UUID, p_user UUID, p_preferred UUID DEFAULT NULL,
  p_move_to_default BOOLEAN DEFAULT false
) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_call   dm_calls%ROWTYPE;
  v_server UUID;
  v_node   livekit_nodes%ROWTYPE;
BEGIN
  SELECT * INTO v_call FROM dm_calls c WHERE c.id = p_call FOR UPDATE;
  IF NOT FOUND OR v_call.ended_at IS NOT NULL
     OR NOT (p_user = v_call.caller_id
             OR (p_user = v_call.callee_id AND v_call.answered_at IS NOT NULL)) THEN
    RETURN jsonb_build_object('allowed', false);
  END IF;

  SELECT u.server_id INTO v_server FROM users u
   WHERE u.id = p_user AND NOT u.is_banned;
  IF v_server IS NULL THEN RETURN jsonb_build_object('allowed', false); END IF;

  IF NOT p_move_to_default THEN
    SELECT * INTO v_node FROM livekit_nodes n
     WHERE n.id = COALESCE(v_call.node_id, p_preferred) AND n.server_id = v_server;
  END IF;
  IF v_node.id IS NULL THEN
    SELECT * INTO v_node FROM livekit_nodes n
     WHERE n.server_id = v_server AND n.is_default;
  END IF;

  UPDATE dm_calls c SET node_id = v_node.id WHERE c.id = p_call;

  RETURN jsonb_build_object(
    'allowed', true,
    'node', CASE WHEN v_node.id IS NULL THEN NULL ELSE jsonb_build_object(
              'id', v_node.id, 'url', v_node.url, 'label', v_node.label,
              'is_default', v_node.is_default) END);
END; $$;

COMMENT ON FUNCTION claim_dm_call_room(UUID, UUID, UUID, BOOLEAN) IS
  'Whether this member may join this call''s room and on which node, claiming '
  'one on the first ask. Service role only: the token function''s question.';

-- ============================================================
-- One question about a server
-- ============================================================
-- Opening a server, and every structural change after it, cost five or six
-- sequential round trips: the caller's own row, that row again for
-- `is_owner`, the server, the channels, sometimes `channel_members`, and
-- `my_permissions()`. Each waited on the one before it, so the channel list
-- could not paint until all of them had been and come back — about 600 ms on
-- a 100 ms link, every launch, and again for every member of the server every
-- time somebody adds a channel.
--
-- It is one question. The client wants to know what this server is, what is
-- in it, and who it is to them; it cannot draw any of that without all of it.
-- Asking it in six pieces was never a decision, it was six calls that grew.
--
-- SECURITY INVOKER, so the policies answer exactly as they did when the
-- client asked them one at a time. `channels_select` still decides which
-- channels appear, and a banned member still sees their own row and nothing
-- else — `app.server_id()` empties on a ban and every policy hanging off it
-- stops matching, which is why the `servers` half is fetched separately below
-- rather than joined: a ban must come back as "you are banned", not as
-- "no such server".
--
-- ---------- two things the old reads quietly dropped ----------
--
-- `dm_retention_days` and `dm_history_cap` were never in the select. The DM
-- settings dialog writes them through `update_server` and read them back as
-- null every time, so an operator who capped DMs saw the dialog forget it on
-- the next refresh. They are in the answer now.
--
-- `chat_public_key`, `is_bot` and `manifest` were missing from the caller's
-- own row for the same reason — the select listed columns and those three
-- were not among them, while `ServerUserRow.of` read them. They cost nothing
-- to include and the row they describe is the caller's own.

-- The definition itself is further down, after `register_user`: it is the
-- same function with the four operator limits and `storage_used` added, and
-- a second `CREATE OR REPLACE` of the same signature in the same file simply
-- replaced this one. Two bodies claiming to be one function is a trap for
-- whoever edits the first and watches nothing change, so only the later one
-- is kept.

-- ============================================================
-- 2. Resolving ids
-- ============================================================

CREATE OR REPLACE FUNCTION members_by_ids(p_ids UUID[])
  RETURNS SETOF member_directory
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_server UUID := app.server_id();
BEGIN
  IF v_server IS NULL THEN RETURN; END IF;
  RETURN QUERY
  WITH wanted AS MATERIALIZED (
    SELECT unnest(COALESCE(p_ids, ARRAY[]::UUID[])) AS id
  )
  SELECT m.*
    FROM member_directory m
    JOIN wanted w ON w.id = m.id
   WHERE m.server_id = v_server
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT app.member_page_max();
END $$;

COMMENT ON FUNCTION members_by_ids(UUID[]) IS
  'Members by id, for ids the caller already holds. MATERIALIZED so the '
  'planner knows how few they are and joins by key rather than sorting the '
  'whole server to find them.';

CREATE OR REPLACE FUNCTION member_roles_for(p_ids UUID[])
  RETURNS SETOF member_role_list
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_server UUID := app.server_id();
BEGIN
  IF v_server IS NULL THEN RETURN; END IF;
  RETURN QUERY
  WITH wanted AS MATERIALIZED (
    SELECT unnest(COALESCE(p_ids, ARRAY[]::UUID[])) AS id
  ),
  -- The scope `member_roles_select` used to apply. A role belongs to one
  -- server and `member_roles_insert` will not let an assignment cross
  -- servers, so the role's server is the assignment's server.
  scoped AS MATERIALIZED (
    SELECT r.id FROM roles r WHERE r.server_id = v_server
  )
  SELECT l.*
    FROM member_role_list l
    JOIN wanted w ON w.id = l.user_id
    JOIN scoped s ON s.id = l.role_id
   ORDER BY l.user_id, l.position DESC
   LIMIT app.member_page_max() * 8;
END $$;

COMMENT ON FUNCTION member_roles_for(UUID[]) IS
  'Role chips for the members on screen. SECURITY DEFINER, so it carries '
  'its own scope: the roles of the caller''s server and nobody else''s.';

-- ============================================================
-- 3. Counting
-- ============================================================

CREATE OR REPLACE FUNCTION member_counts(p_channel UUID DEFAULT NULL)
  RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
  -- Once, not per member. Asked per row this was two EXISTS queries a head
  -- and 3.6 seconds to count a private channel's people on a 50,000-member
  -- server; as an array it is a hash lookup. NULL is "no restriction".
  v_audience UUID[] := app.channel_audience(p_channel);
  v_people BIGINT; v_bots BIGINT;
BEGIN
  IF v_server IS NULL OR NOT app.member_scope_allowed(p_channel) THEN
    RETURN jsonb_build_object('people', 0, 'bots', 0);
  END IF;

  SELECT count(*) FILTER (WHERE NOT m.is_bot),
         count(*) FILTER (WHERE m.is_bot)
    INTO v_people, v_bots
    FROM member_directory m
   WHERE m.server_id = v_server
     AND NOT m.is_banned
     -- `IN (SELECT unnest(…))`, not `= ANY (…)`. Postgres hashes an array
     -- it can see as a constant, but this one arrives as a parameter, so the
     -- ANY form is a linear walk of two thousand ids for every one of fifty
     -- thousand members — 211 ms, worse than the per-row function it
     -- replaced. As a subquery the array is unnested once into a hash and the
     -- per-row test is a lookup: 2 ms.
     AND (v_audience IS NULL OR m.id IN (SELECT unnest(v_audience)));

  RETURN jsonb_build_object('people', COALESCE(v_people, 0),
                            'bots',   COALESCE(v_bots, 0));
END $$;

COMMENT ON FUNCTION member_counts(UUID) IS
  'How many people and bots are in scope, for the sidebar header.';

-- ============================================================
-- 4. Paging
-- ============================================================
-- Branched rather than `p_after_name IS NULL OR (…)`: a disjunction is never
-- an index condition, so the one query had to become two.

CREATE OR REPLACE FUNCTION list_members(
  p_channel    UUID    DEFAULT NULL,
  p_bots       BOOLEAN DEFAULT NULL,
  p_banned     BOOLEAN DEFAULT FALSE,
  p_after_name TEXT    DEFAULT NULL,
  p_after_id   UUID    DEFAULT NULL,
  p_limit      INTEGER DEFAULT 50)
  RETURNS SETOF member_directory
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
  -- See `app.channel_audience`: the channel's membership gathered once,
  -- rather than asked of each member the page walks past.
  v_audience UUID[] := app.channel_audience(p_channel);
BEGIN
  IF v_server IS NULL OR NOT app.member_scope_allowed(p_channel) THEN
    RETURN;
  END IF;

  IF p_after_name IS NULL THEN
    RETURN QUERY
    SELECT m.* FROM member_directory m
     WHERE m.server_id = v_server
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (v_audience IS NULL OR m.id IN (SELECT unnest(v_audience)))
     ORDER BY app.member_sort_key(m.display_name), m.id
     LIMIT app.member_limit(p_limit);
  ELSE
    RETURN QUERY
    SELECT m.* FROM member_directory m
     WHERE m.server_id = v_server
       AND (app.member_sort_key(m.display_name), m.id)
           > (app.member_sort_key(p_after_name),
              COALESCE(p_after_id, '00000000-0000-0000-0000-000000000000'::UUID))
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (v_audience IS NULL OR m.id IN (SELECT unnest(v_audience)))
     ORDER BY app.member_sort_key(m.display_name), m.id
     LIMIT app.member_limit(p_limit);
  END IF;
END $$;

COMMENT ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER) IS
  'One page of the member sidebar, keyset-paged by (sorted name, id).';

-- ============================================================
-- 5. Searching
-- ============================================================
-- Two phases, because the ranking already said it was two: prefix matches
-- outrank infix ones, so the infix half only runs when the prefix half did
-- not fill the page. Somebody typing the start of a name never reaches it.

CREATE OR REPLACE FUNCTION search_members(
  p_query   TEXT    DEFAULT NULL,
  p_channel UUID    DEFAULT NULL,
  p_bots    BOOLEAN DEFAULT NULL,
  p_banned  BOOLEAN DEFAULT FALSE,
  p_limit   INTEGER DEFAULT 25)
  RETURNS SETOF member_directory
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID    := app.server_id();
  v_q      TEXT    := NULLIF(lower(btrim(COALESCE(p_query, ''))), '');
  v_limit  INTEGER := app.member_limit(p_limit);
  v_found  INTEGER;
  v_seen   UUID[];
BEGIN
  IF v_server IS NULL OR NOT app.member_scope_allowed(p_channel) THEN
    RETURN;
  END IF;

  -- No needle: the first alphabetical page, which is what lets a search
  -- field open on focus without a second round trip.
  IF v_q IS NULL THEN
    RETURN QUERY
    SELECT m.* FROM member_directory m
     WHERE m.server_id = v_server
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (p_channel IS NULL
            OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
     ORDER BY app.member_sort_key(m.display_name), m.id
     LIMIT v_limit;
    RETURN;
  END IF;

  -- Phase one: what the name starts with. Three patterns, an index each,
  -- which the planner combines into one bitmap.
  RETURN QUERY
  SELECT m.* FROM member_directory m
   WHERE m.server_id = v_server
     AND (lower(m.username) LIKE v_q || '%'
          OR lower(m.display_name) LIKE v_q || '%'
          OR replace(lower(m.display_name), ' ', '') LIKE v_q || '%')
     AND (p_bots   IS NULL OR m.is_bot    = p_bots)
     AND (p_banned IS NULL OR m.is_banned = p_banned)
     AND (p_channel IS NULL
          OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT v_limit;
  GET DIAGNOSTICS v_found = ROW_COUNT;

  IF v_found >= v_limit THEN
    RETURN;   -- the page is full of prefix matches, which outrank the rest
  END IF;

  -- Which ones phase one already returned, so phase two does not repeat
  -- them. Capped: it only has to cover what was actually emitted.
  SELECT COALESCE(array_agg(t.id), '{}'::uuid[]) INTO v_seen FROM (
    SELECT m.id FROM member_directory m
     WHERE m.server_id = v_server
       AND (lower(m.username) LIKE v_q || '%'
            OR lower(m.display_name) LIKE v_q || '%'
            OR replace(lower(m.display_name), ' ', '') LIKE v_q || '%')
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (p_channel IS NULL
            OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
     ORDER BY app.member_sort_key(m.display_name), m.id
     LIMIT v_limit) t;

  -- Phase two: what the name merely contains. The trigram expression is a
  -- superset of both patterns under it, so it narrows without deciding.
  RETURN QUERY
  SELECT m.* FROM member_directory m
   WHERE m.server_id = v_server
     AND NOT (m.id = ANY (v_seen))
     AND (replace(lower(m.display_name), ' ', '') || ' ' || lower(m.username))
         LIKE '%' || v_q || '%'
     AND (lower(m.username) LIKE '%' || v_q || '%'
          OR replace(lower(m.display_name), ' ', '') LIKE '%' || v_q || '%')
     AND (p_bots   IS NULL OR m.is_bot    = p_bots)
     AND (p_banned IS NULL OR m.is_banned = p_banned)
     AND (p_channel IS NULL
          OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
   ORDER BY app.member_sort_key(m.display_name), m.id
   LIMIT v_limit - v_found;
END $$;

COMMENT ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER) IS
  'Members matching a needle, prefix matches first, then infix.';

-- ============================================================
-- 5. Refusing the member who would go over
-- ============================================================

-- Registration grants only what the invite names: the invite's role and,
-- for the first person in, the owner's.

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
    -- and the invite is counted. Everyone else already here — a member, one
    -- who left, one who is banned — is the `register` edge function's to
    -- answer, and `already_registered` sends it there.
    IF NOT v_invite.is_bot AND EXISTS (
         SELECT 1 FROM users u
          WHERE u.id = p_user_id AND u.server_id = v_invite.server_id
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

-- ============================================================
-- 6. Telling the client, in the call it already makes
-- ============================================================
-- `get_server_details` is the one question a client asks when it opens a
-- server, and it has to carry **every** limit column or that column does not
-- exist as far as the app is concerned.
--
-- That is the trap to watch when a limit is added. Teach `update_server`
-- and forget this function and the failure is quiet: an operator sets a
-- share limit, the settings dialog shows it because `update_server` replies
-- with it, and then the next launch reads this function instead and the
-- limit is gone.

CREATE OR REPLACE FUNCTION public.get_server_details()
 RETURNS jsonb
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $$
  WITH me AS (
    -- `(SELECT auth.uid())`, not `auth.uid()`, and it is worth 34 of this
    -- function's 37 milliseconds. `users` carries two permissive SELECT
    -- policies, so every read of it also carries `(id = auth.uid() OR
    -- server_id = app.server_id())` — a disjunction, which can never be one
    -- index condition. Written bare, the caller's own predicate is left as a
    -- filter and the plan becomes a bitmap of every member of the server;
    -- wrapped, it is an InitPlan and the primary key answers it. 40.8 ms →
    -- 0.04 ms on 50,000 members. A client passing its own id as a literal was
    -- always fine — this is the one place the schema asked the question of
    -- itself.
    SELECT u.* FROM users u WHERE u.id = (SELECT auth.uid())
  ),
  -- Invisible to a banned caller, which is the point: the CASE below reads
  -- "no row here" as "not for you" rather than as "gone".
  srv AS (
    SELECT s.* FROM servers s LIMIT 1
  ),
  -- Only private channels can be managed individually, and only by the
  -- members holding the seat. One read for the whole list, as before.
  managed AS (
    SELECT cm.channel_id FROM channel_members cm
     WHERE cm.user_id = auth.uid() AND cm.can_manage
  ),
  chans AS (
    SELECT jsonb_agg(jsonb_build_object(
             'id',             c.id,
             'name',           c.name,
             'channel_type',   c.channel_type,
             'retention_days', c.retention_days,
             'history_cap',    c.history_cap,
             'is_private',     c.is_private,
             -- Which LiveKit voice here is pinned to, and where a call
             -- actually is. Null and null is "automatic, nobody in it".
             'livekit_node_id', c.livekit_node_id,
             'voice_node_id',   (SELECT vr.node_id FROM voice_rooms vr
                                  WHERE vr.channel_id = c.id),
             'can_manage',     c.is_private
                                 AND EXISTS (SELECT 1 FROM managed m
                                              WHERE m.channel_id = c.id))
             ORDER BY c.name) AS rows
      FROM channels c
  ),
  -- Every node this server can hold a call on. Members get the list too, not
  -- just managers: a member is shown which region they are in, and picks the
  -- nearest one to offer when they are the first to open a call.
  nodes AS (
    SELECT jsonb_agg(jsonb_build_object(
             'id',         n.id,
             'label',      n.label,
             'url',        n.url,
             'is_default', n.is_default)
             ORDER BY n.is_default DESC, n.label) AS rows
      FROM livekit_nodes n
  )
  SELECT CASE
    -- No row of our own: removed, or the server is gone. Either way there is
    -- nothing here to refresh, and the client turns a null into that answer.
    WHEN NOT EXISTS (SELECT 1 FROM me) THEN NULL
    ELSE (jsonb_build_object('user', (
      SELECT jsonb_build_object(
        'id',              me.id,
        'username',        me.username,
        'display_name',    me.display_name,
        'avatar_path',     me.avatar_path,
        'chat_public_key', me.chat_public_key,
        'is_muted',        me.is_muted,
        'is_deafened',     me.is_deafened,
        'is_banned',       me.is_banned,
        'is_kicked',       me.kicked_at IS NOT NULL,
        'is_bot',          me.is_bot,
        'manifest',        me.manifest,
        'timed_out_until', me.timed_out_until,
        'dm_policy',       me.dm_policy,
        'permissions', jsonb_build_object(
          'is_server_admin',    me.is_server_admin,
          'is_channel_manager', me.is_channel_manager,
          'can_create_tokens',  me.can_create_tokens,
          'is_owner',           me.is_owner,
          'permission_bits',    my_permissions()))
        FROM me))
      -- A banned caller stops here: their own row, and an empty list rather
      -- than the null a client would have to guard.
      || CASE WHEN (SELECT me.is_banned FROM me)
              THEN jsonb_build_object('channels', '[]'::jsonb)
              ELSE jsonb_build_object(
                'server_id',   (SELECT srv.id          FROM srv),
                'name',        (SELECT srv.name        FROM srv),
                'icon_url',    (SELECT srv.icon_url    FROM srv),
                'livekit_url', (SELECT srv.livekit_url FROM srv),
                'channels',    COALESCE((SELECT rows FROM chans), '[]'::jsonb),
                'max_attachment_bytes',
                  (SELECT srv.max_attachment_bytes   FROM srv),
                'message_retention_days',
                  (SELECT srv.message_retention_days FROM srv),
                'message_history_cap',
                  (SELECT srv.message_history_cap    FROM srv),
                'dm_retention_days',
                  (SELECT srv.dm_retention_days      FROM srv),
                'dm_history_cap',
                  (SELECT srv.dm_history_cap         FROM srv),
                -- Without these the bitrate picker reads "no cap" on every
                -- refresh and an operator's setting looks forgotten.
                'max_voice_participants',
                  (SELECT srv.max_voice_participants FROM srv),
                'max_share_mbps',
                  (SELECT srv.max_share_mbps         FROM srv),
                'max_members',
                  (SELECT srv.max_members            FROM srv),
                'max_storage_bytes',
                  (SELECT srv.max_storage_bytes      FROM srv),
                'dm_openings_per_hour',
                  (SELECT srv.dm_openings_per_hour   FROM srv),
                -- Not a limit but the thing limits are judged against, and
                -- free here: one indexed read, in the call the client already
                -- makes. It is what lets the composer say a file will not fit
                -- before somebody picks it, rather than after.
                'storage_used', server_storage_used(),
                'livekit_nodes', COALESCE((SELECT rows FROM nodes), '[]'::jsonb))
         END)
  END;
$$;

COMMENT ON FUNCTION get_server_details() IS
  'Everything a client needs to draw a server: its identity and limits, the '
  'channels the caller may see, and the caller''s own row with their '
  'permissions. Null when the caller has no row here. Answers the five reads '
  'that used to run one after another.';

-- ============================================================
-- Regions, and the key each one holds
-- ============================================================
-- The two functions here an *administrator* calls, and they exist because the
-- table they write is one nobody may touch: `livekit_node_secrets` has no
-- policy and no grant, so the writes have to be SECURITY DEFINER functions
-- that check the caller themselves.
--
-- Adding a region is one of them because the node and its key are one act. A
-- region with no key of its own would fall back to the server's pair, which
-- is what per-region keys exist to prevent, so the two rows are written in
-- one transaction and a deferred trigger in 004 refuses the pair being split.
-- There is no clearing a key, for the same reason: the undo for a region is
-- removing it.

CREATE OR REPLACE FUNCTION add_voice_region(
  p_label   TEXT,
  p_url     TEXT,
  p_api_key TEXT,
  p_secret  TEXT
) RETURNS jsonb
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
  v_id     UUID;
BEGIN
  IF NOT app.is_admin() THEN
    RAISE EXCEPTION 'Only an administrator may add a region'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF btrim(COALESCE(p_api_key, '')) = '' OR btrim(COALESCE(p_secret, '')) = '' THEN
    RAISE EXCEPTION 'A region needs its own LiveKit API key and secret'
      USING ERRCODE = 'check_violation';
  END IF;

  INSERT INTO livekit_nodes (server_id, label, url)
  VALUES (v_server, btrim(p_label), btrim(p_url))
  RETURNING id INTO v_id;

  INSERT INTO livekit_node_secrets (node_id, livekit_api_key, livekit_secret_key)
  VALUES (v_id, btrim(p_api_key), btrim(p_secret));

  -- The row as the client would have read it back from the table, so adding a
  -- region answers with the region.
  RETURN (SELECT jsonb_build_object('id', n.id, 'label', n.label, 'url', n.url,
                                    'is_default', n.is_default)
            FROM livekit_nodes n WHERE n.id = v_id);
END; $$;

COMMENT ON FUNCTION add_voice_region(TEXT, TEXT, TEXT, TEXT) IS
  'Add a LiveKit region with the key pair it signs with. Administrators only; '
  'both halves of the key are required, because a region without one would '
  'fall back to the server''s.';

-- Dropped first: it once took two defaulted parameters, because passing
-- neither was how a region gave its key up. A replacement cannot take a
-- default away.
DROP FUNCTION IF EXISTS set_voice_region_credentials(UUID, TEXT, TEXT);

CREATE OR REPLACE FUNCTION set_voice_region_credentials(
  p_node    UUID,
  p_api_key TEXT,
  p_secret  TEXT
) RETURNS VOID
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_default BOOLEAN;
BEGIN
  -- The node has to be one of *this* server's, checked here rather than left
  -- to a policy: SECURITY DEFINER means the usual reason a stranger's node is
  -- out of reach does not apply.
  SELECT n.is_default INTO v_default
    FROM livekit_nodes n
   WHERE n.id = p_node AND n.server_id = app.server_id();

  IF NOT FOUND THEN
    RAISE EXCEPTION 'No such region on this server' USING ERRCODE = 'no_data_found';
  END IF;
  IF NOT app.is_admin() THEN
    RAISE EXCEPTION 'Only an administrator may change a region''s credentials'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF v_default THEN
    RAISE EXCEPTION 'The default region uses the server''s own LiveKit key'
      USING ERRCODE = 'check_violation';
  END IF;

  -- Both halves, always. One without the other is a half-configured node
  -- that would mint tokens nothing accepts, and neither is not a way to give
  -- a region up — there is no falling back to the server's pair.
  IF btrim(COALESCE(p_api_key, '')) = '' OR btrim(COALESCE(p_secret, '')) = '' THEN
    RAISE EXCEPTION 'A region needs both an API key and a secret'
      USING ERRCODE = 'check_violation';
  END IF;

  INSERT INTO livekit_node_secrets (node_id, livekit_api_key, livekit_secret_key)
  VALUES (p_node, btrim(p_api_key), btrim(p_secret))
  ON CONFLICT (node_id) DO UPDATE
    SET livekit_api_key    = EXCLUDED.livekit_api_key,
        livekit_secret_key = EXCLUDED.livekit_secret_key;
END; $$;

COMMENT ON FUNCTION set_voice_region_credentials(UUID, TEXT, TEXT) IS
  'Replace a region''s own LiveKit API key and secret — for a rotation, one '
  'box at a time. Administrators only; never the default region, whose key '
  'is the server''s.';

-- ============================================================
-- Voice nodes, for the service role
-- ============================================================
-- Two wrappers over the helpers in 002, and they are here in `public` for one
-- reason: PostgREST only exposes the schemas in `db_schema`, which is
-- `public, graphql_public`. An edge function cannot reach `app.` at all, so a
-- function it must call has to have a face in `public` even when no client
-- may touch it.
--
-- Neither is a member's to call — 008 revokes both from `anon` and
-- `authenticated`, leaving the service role, which is the only caller.
-- `get_channel_token` claims; `voice_roster` releases.

DROP FUNCTION IF EXISTS claim_voice_node(UUID, UUID);
DROP FUNCTION IF EXISTS claim_voice_node(UUID, UUID, BOOLEAN);

CREATE OR REPLACE FUNCTION claim_voice_node(
  p_channel    UUID,
  p_preferred  UUID DEFAULT NULL,
  p_ignore_pin BOOLEAN DEFAULT false
) RETURNS TABLE (id UUID, url TEXT, label TEXT, is_default BOOLEAN)
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT n.id, n.url, n.label, n.is_default
    FROM app.claim_voice_node(p_channel, p_preferred, p_ignore_pin) n
$$;

COMMENT ON FUNCTION claim_voice_node(UUID, UUID, BOOLEAN) IS
  'Service-role face of app.claim_voice_node: where this channel''s call is, '
  'deciding it if there is no answer yet.';

CREATE OR REPLACE FUNCTION release_voice_node(p_channels UUID[])
  RETURNS VOID
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.release_voice_node(p_channels)
$$;

COMMENT ON FUNCTION release_voice_node(UUID[]) IS
  'Service-role face of app.release_voice_node: these calls have ended, so '
  'the next one on each channel is decided afresh.';

DROP FUNCTION IF EXISTS move_voice_node(UUID, UUID);

CREATE OR REPLACE FUNCTION move_voice_node(p_channel UUID, p_node UUID)
  RETURNS TABLE (id UUID, url TEXT, label TEXT, is_default BOOLEAN)
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT n.id, n.url, n.label, n.is_default
    FROM app.move_voice_node(p_channel, p_node) n
$$;

COMMENT ON FUNCTION move_voice_node(UUID, UUID) IS
  'Service-role face of app.move_voice_node, for the endpoint that moves a '
  'live call and tells the room to reconnect.';
