-- ============================================================
-- Rift self-hosted server — 015: roles are an administrator's to shape
-- ============================================================
-- `MANAGE_ROLES` let anybody holding it create roles beneath their own rank,
-- edit them, and hand them out, bounded by the subset rule. Sound in theory;
-- in practice it meant a server's ladder could be reshaped by whoever had
-- been given the bit, and a moderator handing out moderator roles is a
-- server whose shape nobody chose.
--
-- Roles are an administrator's now: creating, editing, deleting and assigning
-- all ask `ADMINISTRATOR`, and nothing else opens that door. The rank rule
-- stays exactly as it was — strictly below for editing, at-or-below for an
-- administrator handing one out, and never the owner role (013) — because it
-- is what keeps two admins from rewriting each other, not something
-- `MANAGE_ROLES` was carrying.
--
-- The bit itself is cleared everywhere and retired from the editor. A bit
-- that does nothing but sit checked on a role is a promise the server no
-- longer keeps.

CREATE OR REPLACE FUNCTION app.may_manage_role(p_position INTEGER) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.has_perm('ADMINISTRATOR') AND p_position < app.max_role_position()
$$;

CREATE OR REPLACE FUNCTION app.may_assign_role(p_role UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.has_perm('ADMINISTRATOR')
     AND EXISTS (
       SELECT 1 FROM roles r
        WHERE r.id = p_role
          AND r.server_id = app.server_id()
          AND NOT r.is_everyone
          AND NOT r.is_owner)
$$;

UPDATE roles SET permissions = permissions & ~app.perm('MANAGE_ROLES')
 WHERE (permissions & app.perm('MANAGE_ROLES')) <> 0;
