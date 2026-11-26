-- ============================================================
-- Rift self-hosted server — 068: moving a role is one statement
-- ============================================================
-- Found in the review of call counts, Nov 26 2026.
--
-- Moving a role up or down the ladder swapped its position with its
-- neighbour's in two updates, each followed by the app reading the server
-- again, and each ringing `members` to the whole server. Worse, the two were
-- not one change: when the second was refused (the connection dropped, or
-- somebody reshaped the ladder in between) the first had landed, and two
-- roles stood on one rung, which decides who outranks whom. The app put the
-- first back when it could.
--
--   * `swap_role_positions(p_a, p_b)` exchanges two roles' positions in one
--     UPDATE, and raises `not_swapped` unless both moved, so the ladder is
--     never left half done. It runs as the caller: `roles_update` and the
--     triggers that keep `@everyone` and the owner in place still decide, so
--     a role at or above the caller's own, or a rung they could not put a
--     role on, is refused as an update of either would be. Neither may be
--     `@everyone` or the owner's role, whose places are fixed.
--   * A role's name, colour or place rings `members` once a statement,
--     from a statement trigger, rather than once a row: the ring is empty,
--     so a second one to the same server says nothing the first did not. A
--     swap rang twice. A change to a role's bits still rings from the row
--     trigger, with its holders.
--
-- An app asks `swap_role_positions` and, on a server from before it, writes
-- the two rows itself as it did.

-- ── The swap ────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.swap_role_positions(p_a UUID, p_b UUID)
  RETURNS VOID
  LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_moved INTEGER;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  UPDATE roles r
     SET "position" = CASE WHEN r.id = p_a THEN b."position" ELSE a."position" END
    FROM roles a, roles b
   WHERE a.id = p_a AND b.id = p_b AND a.id <> b.id
     AND a.server_id = b.server_id
     AND NOT (a.is_everyone OR a.is_owner OR b.is_everyone OR b.is_owner)
     AND r.id IN (p_a, p_b);
  GET DIAGNOSTICS v_moved = ROW_COUNT;
  -- One moved and not the other is the ladder this replaces: undone with
  -- the statement.
  IF v_moved <> 2 THEN
    RAISE EXCEPTION 'not_swapped';
  END IF;
END $$;

COMMENT ON FUNCTION public.swap_role_positions(UUID, UUID) IS
  'Exchange two roles'' positions in one statement, or neither (not_swapped). '
  'Run as the caller, so roles_update decides.';

-- ── A role's ring, once a statement ─────────────────────────
-- The 049 body, except that an update leaving the bits alone is the
-- statement trigger's below.
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
    PERFORM realtime.send('{}'::jsonb, 'members', 'server:' || v_role.server_id, true);
  END IF;
  RETURN NULL;
END; $$;

-- Once for each server whose roles an update renamed, recoloured or moved
-- without touching their bits.
CREATE OR REPLACE FUNCTION app.ring_role_drawing()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF app.realtime_ready() THEN
    PERFORM realtime.send('{}'::jsonb, 'members', 'server:' || s.server_id, true)
       FROM (SELECT DISTINCT n.server_id
               FROM changed_new n
               JOIN changed_old o ON o.id = n.id
              WHERE o.permissions IS NOT DISTINCT FROM n.permissions) s;
  END IF;
  RETURN NULL;
END; $$;

DROP TRIGGER IF EXISTS roles_ring_drawing ON roles;
CREATE TRIGGER roles_ring_drawing AFTER UPDATE ON roles
  REFERENCING OLD TABLE AS changed_old NEW TABLE AS changed_new
  FOR EACH STATEMENT EXECUTE FUNCTION app.ring_role_drawing();

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION public.swap_role_positions(UUID, UUID) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.ring_role_drawing() FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.swap_role_positions(UUID, UUID) TO authenticated;
