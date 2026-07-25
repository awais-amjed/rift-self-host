-- Migration 009: Make registration atomic so a failed register never burns an
-- invite use.
--
-- register previously called claim_invite (which consumes a use) and only THEN
-- ran the username / identity uniqueness checks. A rejection at those checks —
-- e.g. "username taken" — left the invite use spent. This folds the whole thing
-- into one transactional RPC: the invite is validated under a row lock but only
-- consumed AFTER every check passes and the user row is inserted, so any early
-- return (or a rare insert race, which raises and rolls the transaction back)
-- leaves the invite untouched.
--
-- Also drops the orphaned create_user_with_token (token-era, unused since 007,
-- and now broken — it inserts into the dropped `tokens` table).

DROP FUNCTION IF EXISTS create_user_with_token(
  uuid, text, text, text, text, boolean, boolean, boolean, text, timestamptz);

-- Claims an invite and creates the caller's profile in one transaction.
-- p_user_id is the caller's auth.uid() (verified from their JWT by the edge
-- function). Returns a JSONB { reason, ... } mirroring claim_invite's style:
--   "ok"                 — success; "server_id" included
--   "not_found"          — no invite with that code
--   "expired"            — invite past its expires_at (row deleted)
--   "exhausted"          — invite out of uses
--   "already_registered" — this identity already has a profile here
--   "identity_taken"     — public_key or stable_id already registered on server
--   "username_taken"     — username already in use
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
  -- 1. Lock + validate the invite WITHOUT consuming it. The row lock serialises
  --    concurrent claims of the same invite for the life of this transaction.
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

  -- 2. Identity + username checks. Nothing has been consumed yet, so an early
  --    return here costs the invite nothing.
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
  IF EXISTS (SELECT 1 FROM users WHERE username = p_username) THEN
    RETURN jsonb_build_object('reason', 'username_taken');
  END IF;

  -- 3. Insert the profile bound to the GoTrue identity (users.id = auth.uid()).
  --    Done BEFORE consuming the invite: if a concurrent register won a race on
  --    a unique constraint, this raises and the whole transaction — including
  --    the invite — rolls back, so still no burn.
  INSERT INTO users (
    id, server_id, username, display_name, public_key, stable_id,
    is_server_admin, is_channel_manager, can_create_tokens
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name, p_public_key, p_stable_id,
    v_invite.is_server_admin, v_invite.is_channel_manager, true  -- baseline: may create invites
  );

  -- 4. Consume the invite now that success is guaranteed. Still holding the lock
  --    from step 1, so uses is current and cannot have been claimed underneath us.
  UPDATE invites SET uses = uses + 1 WHERE id = v_invite.id;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses + 1 >= v_invite.max_uses THEN
    DELETE FROM invites WHERE id = v_invite.id;  -- fully claimed
  END IF;

  RETURN jsonb_build_object('reason', 'ok', 'server_id', v_invite.server_id);
END;
$$;

-- Internal RPC — service_role (edge functions) only, never the anon/authenticated
-- roles reachable via the public anon key.
REVOKE EXECUTE ON FUNCTION register_user(text, uuid, text, text, text, text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION register_user(text, uuid, text, text, text, text) TO   service_role;
