-- Migration 010: Allow multiple servers to share one Supabase project.
--
-- The SIWS model keys identity per Supabase *host*: childSeed = HMAC(seed,
-- "<host>:<version>"), so two servers in the same project derived the SAME
-- web3 key → same auth.uid() → and since users.id = auth.uid() (migration 007),
-- the second server's register hit "already_registered". The client now folds
-- the server id into the derivation ("<host>:<serverId>:<version>"), giving each
-- (person, server) a distinct GoTrue identity even within one project.
--
-- The only server-side change that requires is scoping username uniqueness to
-- the server (public_key / stable_id were already per-server in migration 002),
-- so the same display name can exist on two servers in one project.

-- ── username: global-unique → per-server-unique ───────────────
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_key;
ALTER TABLE users
  ADD CONSTRAINT users_server_username_unique UNIQUE (server_id, username);

-- ── register_user: scope the username check to the server ─────
-- (Same body as migration 009, with the username uniqueness check restricted to
-- v_invite.server_id.)
CREATE OR REPLACE FUNCTION register_user(
  p_invite_code  text,
  p_user_id      uuid,
  p_public_key   text,
  p_stable_id    text,
  p_username     text,
  p_display_name text
)
RETURNS jsonb
LANGUAGE plpgsql AS $$
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
             WHERE server_id = v_invite.server_id AND public_key = p_public_key) THEN
    RETURN jsonb_build_object('reason', 'identity_taken');
  END IF;
  IF EXISTS (SELECT 1 FROM users
             WHERE server_id = v_invite.server_id AND stable_id = p_stable_id) THEN
    RETURN jsonb_build_object('reason', 'identity_taken');
  END IF;
  -- Username uniqueness is now scoped to the server (per migration 010).
  IF EXISTS (SELECT 1 FROM users
             WHERE server_id = v_invite.server_id AND username = p_username) THEN
    RETURN jsonb_build_object('reason', 'username_taken');
  END IF;

  INSERT INTO users (
    id, server_id, username, display_name, public_key, stable_id,
    is_server_admin, is_channel_manager, can_create_tokens
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name, p_public_key, p_stable_id,
    v_invite.is_server_admin, v_invite.is_channel_manager, true
  );

  UPDATE invites SET uses = uses + 1 WHERE id = v_invite.id;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses + 1 >= v_invite.max_uses THEN
    DELETE FROM invites WHERE id = v_invite.id;
  END IF;

  RETURN jsonb_build_object('reason', 'ok', 'server_id', v_invite.server_id);
END;
$$;

REVOKE EXECUTE ON FUNCTION register_user(text, uuid, text, text, text, text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION register_user(text, uuid, text, text, text, text) TO   service_role;
