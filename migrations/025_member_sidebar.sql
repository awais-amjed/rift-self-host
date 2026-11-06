-- ============================================================
-- Rift self-hosted server — 025: the member sidebar in one call
-- ============================================================
-- Drawing the sidebar for the first time was five requests: the bots, the first
-- page of people, how many people there are, the roles, and who holds them. The
-- last needs the answers to the first two, so the fewest a member could wait was
-- two round trips of their ping, for about a millisecond of work here.
--
--   * `member_sidebar` answers all five at once, as one JSON document.
--
-- It holds no rule of its own. It runs as the caller and asks the functions and
-- the table the app asks, so a member gets exactly what those five requests
-- would give them, and a change to any of them reaches this too.
-- ============================================================

CREATE OR REPLACE FUNCTION member_sidebar(p_limit INTEGER DEFAULT 51)
  RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_bots        JSONB;
  v_people      JSONB;
  v_roles       JSONB;
  v_assignments JSONB;
  v_ids         UUID[];
BEGIN
  SELECT COALESCE(jsonb_agg(to_jsonb(m) - 'ordinality' ORDER BY m.ordinality),
                  '[]'::JSONB)
    INTO v_bots
    FROM list_members(p_bots => TRUE, p_limit => p_limit)
         WITH ORDINALITY AS m;

  SELECT COALESCE(jsonb_agg(to_jsonb(m) - 'ordinality' ORDER BY m.ordinality),
                  '[]'::JSONB)
    INTO v_people
    FROM list_members(p_bots => FALSE, p_limit => p_limit)
         WITH ORDINALITY AS m;

  -- Through `roles_select`, since this runs as the caller.
  SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.position DESC), '[]'::JSONB)
    INTO v_roles
    FROM roles r;

  SELECT array_agg((e ->> 'id')::UUID)
    INTO v_ids
    FROM jsonb_array_elements(v_bots || v_people) e;

  SELECT COALESCE(jsonb_agg(to_jsonb(a) - 'ordinality' ORDER BY a.ordinality),
                  '[]'::JSONB)
    INTO v_assignments
    FROM member_roles_for(v_ids) WITH ORDINALITY AS a;

  RETURN jsonb_build_object(
    'bots',        v_bots,
    'people',      v_people,
    'counts',      member_counts(),
    'roles',       v_roles,
    'assignments', v_assignments
  );
END $$;

COMMENT ON FUNCTION member_sidebar(INTEGER) IS
  'What the member sidebar needs for its first frame, in one call: the first '
  'page of bots and of people, the counts, the roles, and who of those holds '
  'which. Runs as the caller and adds no rule of its own.';

REVOKE ALL ON FUNCTION member_sidebar(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION member_sidebar(INTEGER) TO authenticated;
