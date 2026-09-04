-- ============================================================
-- Rift self-hosted server — 033: say which role is the default one
-- ============================================================
-- `member_role_list` is what every client reads to draw the roles beside a
-- name, and it left out the one column that says whether a role means anything.
--
-- Every human member is given the default role when they register (025), so
-- every human wore a "Members" chip — on every row, next to every name, saying
-- what was true of everybody. A badge that never varies is not a badge; it is
-- furniture, and it crowded out the ones somebody should actually notice.
--
-- The column already exists on `roles`. Clients could not see it, so they could
-- not tell "the role everyone has" from "a role somebody chose to give you".

CREATE OR REPLACE VIEW member_role_list
  WITH (security_invoker = true) AS
  SELECT mr.user_id,
         r.id AS role_id,
         r.name,
         r.color,
         r.position,
         r.permissions,
         r.is_default
    FROM member_roles mr
    JOIN roles r ON r.id = mr.role_id;

COMMENT ON VIEW member_role_list IS
  'Which roles each member holds. `is_default` marks the one every member is '
  'given on registration — clients hide its chip, because a badge everybody '
  'wears distinguishes nobody.';

REVOKE ALL ON member_role_list FROM anon;
GRANT SELECT ON member_role_list TO authenticated;
