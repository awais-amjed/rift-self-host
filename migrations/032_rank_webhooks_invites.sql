-- ============================================================
-- Rift self-hosted server — 032: rank on assigning, webhooks by their
-- own bit, and every invite an admin's to see and revoke
-- ============================================================
-- Three gaps a feature review of the app found on Nov 22 2026, each one the
-- server leaving to the app what only the server can hold.
--
--   * **One admin could take Admin off another.** `app.may_assign_role` asked
--     `ADMINISTRATOR` and nothing about rank, though the comment above it
--     promised "at-or-below for an administrator handing one out". So any
--     admin could hand out a role above their own, and take any role but the
--     owner's off anybody, a fellow admin's Admin included: the first admin to
--     act could leave every other one a plain member. Handing a role out now
--     asks that it sit at or below your own rank (so the only admin can still
--     make a second one), and taking one off somebody asks that it sit below
--     it, which `member_roles_delete` already asked of your own roles. An
--     invite that hands out a role (`invites_insert`) goes by the same rule,
--     since it asks `may_assign_role` too.
--   * **`MANAGE_WEBHOOKS` did nothing.** Webhooks asked only
--     `app.can_manage_channels()`, so the bit sat on roles in the editor and
--     taking it away stopped nobody. A webhook is a standing way to post into
--     a channel unencrypted, which is reason enough for a bit of its own:
--     `app.can_manage_webhooks()` asks both, as the app's Webhooks pages do.
--   * **Nobody could revoke another member's invite.** `invites_select_own`
--     and `invites_delete_own` match on `created_by`, which is right for a
--     member, and was the only rule there was. A link somebody posted where
--     it should not be, or one left behind by a member since kicked (whose
--     `created_by` went to NULL), kept letting people in until it expired,
--     and an admin could not even see it. Admins now see and delete every
--     invite on their server; a member still sees only their own.
-- ============================================================

-- ── Rank ────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION app.may_assign_role(p_role UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.has_perm('ADMINISTRATOR')
     AND EXISTS (
       SELECT 1 FROM roles r
        WHERE r.id = p_role
          AND r.server_id = app.server_id()
          AND NOT r.is_everyone
          AND NOT r.is_owner
          AND r.position <= app.max_role_position())
$$;

-- Strictly below for a removal, whoever holds the role: the rule that kept an
-- admin from dropping their own Admin, now keeping them from dropping
-- anybody's.
DROP POLICY IF EXISTS member_roles_delete ON member_roles;
CREATE POLICY member_roles_delete ON member_roles FOR DELETE TO authenticated
  USING (
    app.may_assign_role(role_id)
    AND EXISTS (SELECT 1 FROM users u
                 WHERE u.id = member_roles.user_id
                   AND u.server_id = app.server_id())
    AND EXISTS (SELECT 1 FROM roles r
                 WHERE r.id = member_roles.role_id
                   AND r.position < app.max_role_position())
  );

-- ── Webhooks ────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION app.can_manage_webhooks() RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.can_manage_channels() AND app.has_perm('MANAGE_WEBHOOKS')
$$;

COMMENT ON FUNCTION app.can_manage_webhooks() IS
  'Whether the caller may list, make and revoke webhooks: a channel manager '
  '(or admin) who also holds MANAGE_WEBHOOKS.';

DROP POLICY IF EXISTS webhooks_select ON webhooks;
CREATE POLICY webhooks_select ON webhooks FOR SELECT TO authenticated
  USING (server_id = app.server_id() AND (SELECT app.can_manage_webhooks()));

DROP POLICY IF EXISTS webhooks_delete ON webhooks;
CREATE POLICY webhooks_delete ON webhooks FOR DELETE TO authenticated
  USING (server_id = app.server_id() AND (SELECT app.can_manage_webhooks()));

-- As 003 left it, but asking the webhook bit.
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
  IF NOT app.can_manage_webhooks() THEN
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

-- ── Invites ─────────────────────────────────────────────────

DROP POLICY IF EXISTS invites_select_admin ON invites;
CREATE POLICY invites_select_admin ON invites FOR SELECT TO authenticated
  USING (server_id = app.server_id() AND (SELECT app.is_admin()));

DROP POLICY IF EXISTS invites_delete_admin ON invites;
CREATE POLICY invites_delete_admin ON invites FOR DELETE TO authenticated
  USING (server_id = app.server_id() AND (SELECT app.is_admin()));

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION app.can_manage_webhooks() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION app.can_manage_webhooks() TO authenticated;
REVOKE ALL ON FUNCTION create_webhook(UUID, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION create_webhook(UUID, TEXT) TO authenticated;
