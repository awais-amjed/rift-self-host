-- ============================================================
-- Rift self-hosted server — 059: the Roles page asks for counts, not for
-- every assignment
-- ============================================================
-- Found in the query review of Nov 25 2026, measured Nov 26 on a test
-- database of 50,000 members holding 49,000 roles between them.
--
-- The Roles page shows how many members hold each role, and to count them
-- the app read `member_role_list` whole: one row per (member, role), a
-- thousand to a request, so 49 requests on that server, and again after any
-- change to a role while the page was open. It needed the rows for two
-- things only — the counts, and the viewer's own roles, which decide which
-- roles they may edit — so `role_counts` answers exactly those, in one call:
--
--   { "counts": { "<role id>": <holders>, ... },   -- roles nobody holds absent
--     "mine":   [ <member_role_list row>, ... ] }  -- most senior first
--
-- Counted as the page counted them: every assignment on the caller's
-- server, which is what `member_roles_select` let them read. NULL for
-- somebody who is no member (banned, or the server is being deleted). An app
-- that finds no `role_counts` on an older server reads the rows as before.

CREATE OR REPLACE FUNCTION role_counts() RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
BEGIN
  IF v_server IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object(
    'counts', COALESCE((
      SELECT jsonb_object_agg(t.role_id, t.holders)
        FROM (SELECT mr.role_id, count(*) AS holders
                FROM member_roles mr
                JOIN roles r ON r.id = mr.role_id AND r.server_id = v_server
               GROUP BY mr.role_id) t), '{}'::jsonb),
    'mine', COALESCE((
      SELECT jsonb_agg(to_jsonb(l) ORDER BY l.position DESC)
        FROM member_role_list l
        JOIN roles r ON r.id = l.role_id AND r.server_id = v_server
       WHERE l.user_id = auth.uid()), '[]'::jsonb));
END $$;

COMMENT ON FUNCTION role_counts() IS
  'How many members hold each role of the caller''s server, and the caller''s '
  'own roles: what the Roles page needs, in place of every assignment.';

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION role_counts() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION role_counts() TO authenticated;
