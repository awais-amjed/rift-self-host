-- ============================================================
-- Rift self-hosted server — 062: a `members` ring says who, and one call
-- answers it
-- ============================================================
-- Found in the review of call counts, Nov 26 2026.
--
-- `members` rang with nothing in it, on any write to a `users` row and on any
-- change to who holds which role. Every app with the server on its list
-- (not only the one reading it) then read the bots, the counts, the roles,
-- every member it held by id and the role chips of all of them: five requests
-- each, all within the same quarter second, for one rename.
--
--   * The ring names the members it is about: `{"ids": [...]}`, for up to
--     100 of them. Without `ids` it means what it always meant, "anything may
--     have moved": a role's name or colour, or a change to more members than
--     that. It does not say who made the change, since every member hears it.
--     An app that ignores the payload behaves as before.
--   * It rings only when something the roster shows moved (the columns of
--     `member_directory`). The `me` ring to the member is as it was.
--   * `members_refresh` answers a ring in one call: the bots, the counts, the
--     roles, the named members and the role chips of all of them. It runs as
--     the caller and asks the functions the app asks, as `member_sidebar`
--     does, so it adds no rule of its own. An app that finds no
--     `members_refresh` on an older server makes the separate requests.

-- ── What a ring carries ─────────────────────────────────────
-- Up to `app.member_page_max()` ids, which is also what one
-- `members_refresh` resolves.
CREATE OR REPLACE FUNCTION app.members_ring(p_ids UUID[])
  RETURNS JSONB
  LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN p_ids IS NULL OR cardinality(p_ids) = 0
         OR cardinality(p_ids) > app.member_page_max() THEN '{}'::jsonb
    ELSE jsonb_build_object('ids', to_jsonb(p_ids))
  END
$$;

-- ── A member's row ──────────────────────────────────────────
-- As 049 left it, with the ring naming the member, and none for an update
-- that moved nothing `member_directory` shows.
CREATE OR REPLACE FUNCTION app.announce_member() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_row users%ROWTYPE;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'UPDATE' AND current_setting('rift.cache_sync', true) = 'on' THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_row := OLD;
  ELSE
    v_row := NEW;
  END IF;

  IF TG_OP <> 'UPDATE'
     OR ROW(OLD.server_id, OLD.username, OLD.display_name, OLD.avatar_path,
            OLD.chat_public_key, OLD.is_muted, OLD.is_deafened, OLD.is_banned,
            OLD.is_bot, OLD.manifest, OLD.is_server_admin,
            OLD.is_channel_manager, OLD.can_create_tokens, OLD.created_at,
            OLD.dm_policy, OLD.timed_out_until, OLD.kicked_at IS NOT NULL,
            OLD.left_at IS NOT NULL)
        IS DISTINCT FROM
        ROW(NEW.server_id, NEW.username, NEW.display_name, NEW.avatar_path,
            NEW.chat_public_key, NEW.is_muted, NEW.is_deafened, NEW.is_banned,
            NEW.is_bot, NEW.manifest, NEW.is_server_admin,
            NEW.is_channel_manager, NEW.can_create_tokens, NEW.created_at,
            NEW.dm_policy, NEW.timed_out_until, NEW.kicked_at IS NOT NULL,
            NEW.left_at IS NOT NULL) THEN
    PERFORM realtime.send(app.members_ring(ARRAY[v_row.id]), 'members',
                          'server:' || v_row.server_id, true);
  END IF;
  IF TG_OP <> 'INSERT' THEN
    PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || v_row.id, true);
  END IF;

  -- A ban is the sweep's first rotation signal — somebody sealed into the
  -- current version who is no longer entitled to it. Both directions: the
  -- unban heals a member back into the current version.
  IF TG_OP = 'UPDATE' AND OLD.is_banned IS DISTINCT FROM NEW.is_banned THEN
    PERFORM realtime.send('{}'::jsonb, 'sweep', 'server:' || v_row.server_id, true);
  END IF;

  -- A bot arriving, leaving or publishing a new command list.
  IF v_row.is_bot AND (TG_OP <> 'UPDATE'
                       OR OLD.manifest IS DISTINCT FROM NEW.manifest) THEN
    PERFORM realtime.send('{}'::jsonb, 'bots', 'server:' || v_row.server_id, true);
  END IF;
  RETURN NULL;
END $$;

-- ── Roles given, taken or changed ───────────────────────────
-- As 049 left it, with each server's ring naming its members.
CREATE OR REPLACE FUNCTION app.announce_permission_change(p_users UUID[])
  RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.realtime_ready() OR p_users IS NULL OR cardinality(p_users) = 0 THEN
    RETURN;
  END IF;
  PERFORM realtime.send(app.members_ring(s.ids), 'members',
                        'server:' || s.server_id, true)
     FROM (SELECT u.server_id, array_agg(u.id) AS ids
             FROM users u WHERE u.id = ANY (p_users)
            GROUP BY u.server_id) s;
  PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || u.id, true)
     FROM users u WHERE u.id = ANY (p_users);
END $$;

-- ── The re-read, in one call ────────────────────────────────
-- The bots (a first page, as `member_sidebar` reads them), how many people
-- and bots there are, the roles, the members named, and the role chips of
-- the named members and the bots. Up to `app.member_page_max()` ids, as
-- `members_by_ids` resolves.
CREATE OR REPLACE FUNCTION members_refresh(p_ids UUID[], p_limit INTEGER DEFAULT 51)
  RETURNS JSONB
  LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_bots        JSONB;
  v_members     JSONB;
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
    INTO v_members
    FROM members_by_ids(p_ids) WITH ORDINALITY AS m;

  -- Through `roles_select`, since this runs as the caller.
  SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.position DESC), '[]'::JSONB)
    INTO v_roles
    FROM roles r;

  SELECT array_agg(DISTINCT (e ->> 'id')::UUID)
    INTO v_ids
    FROM jsonb_array_elements(v_bots || v_members) e;

  SELECT COALESCE(jsonb_agg(to_jsonb(a) - 'ordinality' ORDER BY a.ordinality),
                  '[]'::JSONB)
    INTO v_assignments
    FROM member_roles_for(v_ids) WITH ORDINALITY AS a;

  RETURN jsonb_build_object(
    'bots',        v_bots,
    'members',     v_members,
    'counts',      member_counts(),
    'roles',       v_roles,
    'assignments', v_assignments
  );
END $$;

COMMENT ON FUNCTION members_refresh(UUID[], INTEGER) IS
  'What the member list re-reads when `members` rings, in one call: the bots, '
  'the counts, the roles, the members named and who of them holds which. Runs '
  'as the caller and adds no rule of its own.';

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION app.members_ring(UUID[]) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.announce_permission_change(UUID[]) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION members_refresh(UUID[], INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION members_refresh(UUID[], INTEGER) TO authenticated;
