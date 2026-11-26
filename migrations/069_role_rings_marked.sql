-- ============================================================
-- Rift self-hosted server — 069: a ring about roles says so
-- ============================================================
-- Found in the live test of 061–068, Nov 26 2026.
--
-- A role renamed, recoloured, moved, made, deleted, given or taken rings
-- `members` to the whole server. The member list draws roles, so it reads
-- again. The DM list does not draw them, but it hears the same ring, and an
-- empty one ("anything may have moved") could be a peer's new chat key, so
-- every member with DMs on the server read their conversations again: on a
-- server of 50,000, 50,000 reads for one role renamed.
--
--   * Every `members` ring a role change makes carries `"roles": true`
--     beside what it carried before (`{}`, or `{"ids": [...]}`). A role is
--     not a `users` row, so nothing the DM list shows (a name, an avatar, a
--     chat key) moved, and an app's DM list lets it go. The member list
--     reads as it did.
--   * An app that ignores the key behaves as before.
--
-- The bodies are 068's and 062's, with the marker.

-- ── What a role's ring carries ──────────────────────────────
CREATE OR REPLACE FUNCTION app.roles_ring(p_ids UUID[] DEFAULT NULL)
  RETURNS JSONB
  LANGUAGE sql IMMUTABLE AS $$
  SELECT app.members_ring(p_ids) || '{"roles": true}'::jsonb
$$;

COMMENT ON FUNCTION app.roles_ring(UUID[]) IS
  'A members ring about roles: what app.members_ring carries, and roles: true, '
  'so a listener that draws no roles can let it go.';

-- ── Roles given, taken or changed ───────────────────────────
CREATE OR REPLACE FUNCTION app.announce_permission_change(p_users UUID[])
  RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.realtime_ready() OR p_users IS NULL OR cardinality(p_users) = 0 THEN
    RETURN;
  END IF;
  PERFORM realtime.send(app.roles_ring(s.ids), 'members',
                        'server:' || s.server_id, true)
     FROM (SELECT u.server_id, array_agg(u.id) AS ids
             FROM users u WHERE u.id = ANY (p_users)
            GROUP BY u.server_id) s;
  PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || u.id, true)
     FROM users u WHERE u.id = ANY (p_users);
END $$;

-- ── A role made, deleted, or its bits held by nobody ────────
CREATE OR REPLACE FUNCTION sync_role_permission_cache()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_role    roles%ROWTYPE;
  v_holders UUID[];
BEGIN
  -- Branch rather than COALESCE: on DELETE there is no NEW.
  IF TG_OP = 'DELETE' THEN v_role := OLD; ELSE v_role := NEW; END IF;

  -- Who holds a deleted role is answered by its `member_roles` rows, which
  -- the delete cascades to and `member_roles_sync_cache_*` handles. What
  -- is left is a change to the bits, or a new `@everyone` (a new server,
  -- whose members, if any, hold nothing else yet).
  IF TG_OP = 'UPDATE' AND OLD.permissions IS DISTINCT FROM NEW.permissions
     OR TG_OP = 'INSERT' AND NEW.is_everyone THEN
    IF v_role.is_everyone THEN
      SELECT array_agg(u.id) INTO v_holders
        FROM users u WHERE u.server_id = v_role.server_id;
    ELSE
      SELECT array_agg(mr.user_id) INTO v_holders
        FROM member_roles mr WHERE mr.role_id = v_role.id;
    END IF;
    PERFORM app.sync_permission_caches(v_holders);
    PERFORM app.announce_permission_change(v_holders);
    IF v_holders IS NOT NULL THEN
      RETURN NULL;
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    -- A name, colour or position: rung once for the statement, below.
    RETURN NULL;
  END IF;

  -- A new role, a deleted one, or bits nobody holds: the member list draws
  -- roles, so it is told, and nobody's own permissions moved.
  IF app.realtime_ready() THEN
    PERFORM realtime.send(app.roles_ring(), 'members', 'server:' || v_role.server_id, true);
  END IF;
  RETURN NULL;
END; $$;

-- ── A role renamed, recoloured or moved ─────────────────────
CREATE OR REPLACE FUNCTION app.ring_role_drawing()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF app.realtime_ready() THEN
    PERFORM realtime.send(app.roles_ring(), 'members', 'server:' || s.server_id, true)
       FROM (SELECT DISTINCT n.server_id
               FROM changed_new n
               JOIN changed_old o ON o.id = n.id
              WHERE o.permissions IS NOT DISTINCT FROM n.permissions) s;
  END IF;
  RETURN NULL;
END; $$;

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.roles_ring(UUID[]) FROM PUBLIC, anon, authenticated;
