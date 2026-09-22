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
  -- always came back not_authorized. Banning stays with admins: it ends
  -- somebody's membership, which is the same weight as granting a role.
  IF p_banned IS NOT NULL THEN
    IF NOT app.is_admin() THEN
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

  UPDATE users SET
    is_muted    = COALESCE(p_muted,    is_muted),
    is_deafened = COALESCE(p_deafened, is_deafened),
    is_banned   = COALESCE(p_banned,   is_banned)
   WHERE id = p_target;

  RETURN jsonb_build_object('reason', 'ok');
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
  v_invite invites%ROWTYPE;
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

    -- A constant channel and a constant cursor, which is what lets the
    -- planner use `idx_messages_channel (channel_id, id)` as a range: start
    -- at the cursor, walk forward, stop at the cap. Written as a correlated
    -- subquery in one big statement it chose a sequential scan instead, cap
    -- and all, which is how the old shape came to cost eleven seconds.
    SELECT count(*) INTO v_n FROM (
      SELECT 1 FROM messages m
       WHERE m.channel_id = v_chan.id
         AND m.id > v_cursor
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
      ) d), '{}'::jsonb),
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

CREATE OR REPLACE FUNCTION get_server_details() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  WITH me AS (
    SELECT u.* FROM users u WHERE u.id = auth.uid()
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
             'can_manage',     c.is_private
                                 AND EXISTS (SELECT 1 FROM managed m
                                              WHERE m.channel_id = c.id))
             ORDER BY c.name) AS rows
      FROM channels c
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
        'is_bot',          me.is_bot,
        'manifest',        me.manifest,
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
                  (SELECT srv.dm_history_cap         FROM srv))
         END)
  END;
$$;

COMMENT ON FUNCTION get_server_details() IS
  'Everything a client needs to draw a server: its identity and limits, the '
  'channels the caller may see, and the caller''s own row with their '
  'permissions. Null when the caller has no row here. Answers the five reads '
  'that used to run one after another.';

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
     -- Only the channel half needs the function; without a channel this is
     -- a constant false and it is never called.
     AND (p_channel IS NULL
          OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL));

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
DECLARE v_server UUID := app.server_id();
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
       AND (p_channel IS NULL
            OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
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
       AND (p_channel IS NULL
            OR app.member_in_scope(m.id, m.is_bot, m.is_banned, p_channel, NULL, NULL))
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

CREATE OR REPLACE FUNCTION public.register_user(p_invite_code text, p_user_id uuid, p_public_key text, p_stable_id text, p_username text, p_display_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SET search_path TO 'public'
AS $$
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
END; $$
;

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
    SELECT u.* FROM users u WHERE u.id = auth.uid()
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
             'can_manage',     c.is_private
                                 AND EXISTS (SELECT 1 FROM managed m
                                              WHERE m.channel_id = c.id))
             ORDER BY c.name) AS rows
      FROM channels c
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
        'is_bot',          me.is_bot,
        'manifest',        me.manifest,
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
                -- Not a limit but the thing limits are judged against, and
                -- free here: one indexed read, in the call the client already
                -- makes. It is what lets the composer say a file will not fit
                -- before somebody picks it, rather than after.
                'storage_used', server_storage_used())
         END)
  END;
$$;
