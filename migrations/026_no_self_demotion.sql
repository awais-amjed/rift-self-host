-- ============================================================
-- Rift self-hosted server — 026: an admin cannot lock themselves out
-- ============================================================
-- 018 exempted `ADMINISTRATOR` from the position rule when *handing out* a
-- role, for a good reason: without it the only admin on a server could never
-- make a second one, and `set_user_permissions` had allowed exactly that since
-- 003.
--
-- The exemption was written once and applied to both directions. So an admin
-- could also take the Admin role *off* — including off themselves, leaving a
-- server with no administrator and no way to appoint one. The old RPC refused
-- that by name (`cannot_change_own_permissions`); moving to roles dropped the
-- refusal along with the function.
--
-- Found by a test that had been asserting the old function's behaviour and was
-- rewritten to assert the new model's.
--
-- The rule that replaces it: **you may not take a role off yourself unless you
-- outrank it.** Which for your own highest role you never do.
--
-- Deliberately not "you may not remove Admin". Two admins can still demote each
-- other, which is the check on a rogue one, and it is the same shape as every
-- other rule here — position, and nothing else.

DROP POLICY IF EXISTS member_roles_delete ON member_roles;
CREATE POLICY member_roles_delete ON member_roles FOR DELETE TO authenticated
  USING (
    app.may_assign_role(role_id)
    AND EXISTS (SELECT 1 FROM users u
                 WHERE u.id = member_roles.user_id
                   AND u.server_id = app.server_id())
    -- Somebody else's, or one you genuinely stand above.
    AND (member_roles.user_id <> auth.uid()
         OR EXISTS (SELECT 1 FROM roles r
                     WHERE r.id = member_roles.role_id
                       AND r.position < app.max_role_position()))
  );
