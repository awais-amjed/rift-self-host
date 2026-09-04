-- ============================================================
-- Rift self-hosted server — 003: RPCs
-- ============================================================
-- What's left after RLS. Two kinds of thing end up here:
--
--   * writes that touch columns the caller must not own (moderation flags,
--     permissions). RLS is row-level, so "an admin may ban but not rename"
--     cannot be a policy — it is a function that writes exactly those columns.
--   * reads that aren't a single table query (unread counts, the conversation
--     list), which would otherwise be an edge function doing in TypeScript what
--     one SQL statement does here.
--
-- Everything else the client needs is a plain PostgREST call against 002's
-- policies. Edge functions now exist only where a secret or a pre-membership
-- bootstrap step is genuinely involved: login, register, resolve_invite,
-- create_server, get_channel_token, is_username_available.

-- ============================================================
-- Registration (service role only — called by the `register` function)
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

  INSERT INTO users (
    id, server_id, username, display_name, public_key, stable_id,
    is_server_admin, is_channel_manager, can_create_tokens
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name,
    p_public_key, p_stable_id,
    v_invite.is_server_admin, v_invite.is_channel_manager, true
  );

  -- Start every channel's cursor at whatever is already there. Without this a
  -- new member's first sight of the server is every channel screaming with
  -- unread counts for messages sent before they arrived — which they can't
  -- decrypt anyway, since keys are only wrapped for them going forward.
  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT p_user_id, 'channel', c.id,
         COALESCE((SELECT max(m.id) FROM messages m WHERE m.channel_id = c.id), 0)
    FROM channels c
   WHERE c.server_id = v_invite.server_id;

  UPDATE invites SET uses = uses + 1 WHERE id = v_invite.id;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses + 1 >= v_invite.max_uses THEN
    DELETE FROM invites WHERE id = v_invite.id;
  END IF;

  RETURN jsonb_build_object('reason', 'ok', 'server_id', v_invite.server_id);
END; $$;

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

CREATE OR REPLACE FUNCTION set_user_permissions(
  p_target             UUID,
  p_is_server_admin    BOOLEAN DEFAULT NULL,
  p_is_channel_manager BOOLEAN DEFAULT NULL,
  p_can_create_tokens  BOOLEAN DEFAULT NULL
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- You can only grant what you hold. Admin holds everything, so in practice
  -- this is the admin check plus a guard against a manager minting admins.
  IF NOT app.is_admin() THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF p_target = auth.uid() THEN
    RAISE EXCEPTION 'cannot_change_own_permissions';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users
                  WHERE id = p_target AND server_id = app.server_id()) THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;

  UPDATE users SET
    is_server_admin    = COALESCE(p_is_server_admin,    is_server_admin),
    is_channel_manager = COALESCE(p_is_channel_manager, is_channel_manager),
    can_create_tokens  = COALESCE(p_can_create_tokens,  can_create_tokens)
   WHERE id = p_target;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ============================================================
-- Unread
-- ============================================================
-- Every badge in the app, in one round trip. SECURITY INVOKER on purpose: the
-- counts are filtered by the same policies as a direct read, so this can't
-- report on a channel the caller can't see.

CREATE OR REPLACE FUNCTION unread_counts() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT jsonb_build_object(
    'channels', COALESCE((
      SELECT jsonb_object_agg(channel_id, n) FROM (
        SELECT m.channel_id, count(*) AS n
          FROM messages m
          LEFT JOIN read_state r
            ON r.user_id = auth.uid()
           AND r.scope = 'channel'
           AND r.scope_id = m.channel_id
         WHERE m.sender_id <> auth.uid()
           AND m.id > COALESCE(r.last_read_id, 0)
         GROUP BY m.channel_id
      ) c), '{}'::jsonb),
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
      ) d), '{}'::jsonb)
  );
$$;

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

-- ============================================================
-- DM conversation list
-- ============================================================
-- The newest envelope per peer plus that peer's identity material. This was an
-- edge function that pulled a thousand rows and grouped them in TypeScript;
-- DISTINCT ON does it in the database and returns only what's shown.

CREATE OR REPLACE FUNCTION dm_conversations() RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  SELECT COALESCE(jsonb_agg(row ORDER BY (row->'last_message'->>'id')::BIGINT DESC), '[]'::jsonb)
    FROM (
      SELECT jsonb_build_object(
               'peer_id',               u.id,
               'peer_name',             u.display_name,
               'peer_username',         u.username,
               'peer_avatar_path',      u.avatar_path,
               'peer_chat_public_key',  u.chat_public_key,
               'peer_public_key',       u.public_key,
               'last_message', jsonb_build_object(
                 'id',           l.id,
                 'created_at',   l.created_at,
                 'sender_id',    l.sender_id,
                 'recipient_id', l.recipient_id,
                 'ciphertext',   l.ciphertext,
                 'nonce',        l.nonce,
                 'signature',    l.signature,
                 'key_version',  l.key_version,
                 'edited_at',    l.edited_at
               )
             ) AS row
        FROM (
          SELECT DISTINCT ON (peer) *
            FROM (
              SELECT d.*,
                     CASE WHEN d.sender_id = auth.uid()
                          THEN d.recipient_id ELSE d.sender_id END AS peer
                FROM dm_messages d
            ) paired
           ORDER BY peer, id DESC
        ) l
        JOIN users u ON u.id = l.peer
    ) rows;
$$;

-- ============================================================
-- Function privileges
-- ============================================================
-- Postgres grants EXECUTE to PUBLIC by default, which would expose
-- register_user to anyone. Same discipline as the tables: revoke everything,
-- then hand back only what a member is meant to call.

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION new_invite_code()        TO authenticated;
GRANT EXECUTE ON FUNCTION unread_counts()          TO authenticated;
GRANT EXECUTE ON FUNCTION mark_read(read_scope, UUID, BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION mark_all_read()          TO authenticated;
GRANT EXECUTE ON FUNCTION dm_conversations()       TO authenticated;
GRANT EXECUTE ON FUNCTION moderate_user(UUID, BOOLEAN, BOOLEAN, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION set_user_permissions(UUID, BOOLEAN, BOOLEAN, BOOLEAN) TO authenticated;

-- register_user is deliberately not granted: it is the service role's, called
-- by the `register` edge function, which is the only thing that has both the
-- invite code and no membership yet.
