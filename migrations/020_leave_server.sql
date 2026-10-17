-- ============================================================
-- Rift self-hosted server — 020: leaving a server
-- ============================================================
-- "Leave server" forgot the server on the device and told the server
-- nothing. Whoever left stayed a member: listed (offline) to everyone, with
-- their roles and private seats, holding a place under the member cap and
-- being sealed into every new channel key. Asked about Oct 17: "when a user
-- leaves a server, he's still shown in it?"
--
-- Now leaving is a kick by your own hand (`leave_server`): the same lock-out,
-- `is_banned` with `kicked_at` beside it, the same roles and private seats
-- taken, and the same way back, a new invite (`register_user` readmits
-- anybody kicked). What you wrote stays. Your server DMs stay too, and open
-- again when you come back as yourself.
--
-- `users.left_at` marks the kick as your own, for two readers:
--
--   * a moderator. The banned list is "the one place a ban can be lifted"
--     and is read whole on the grounds that bans are few; people who left
--     are not few and were not banned, so `list_members` leaves them out of
--     it. Search still finds them, marked, so a moderator can ban somebody
--     who left before they come back;
--   * your other devices. `get_server_details` says `has_left`, and a device
--     still holding the server drops it as it would a deleted one, which is
--     also what stops the cloud backup's copy bringing it back.
--
-- A leave never weakens a ban: somebody banned, or already kicked, who
-- leaves is told yes and nothing changes. The owner cannot leave
-- (`owner_cannot_leave`, as `refuse_owner_leaving` says on a delete), and a
-- bot is taken off by a kick, which also takes what only a bot holds.
--
-- Unlike `moderate_user` this does not reach LiveKit: the person leaving
-- hangs up their own call first. A DM call ends here, by
-- `users_ban_ends_calls`.
--
-- `member_directory`, `list_members` and `get_server_details` are replaced
-- whole, each as the latest file left it plus the lines above; their grants
-- are restated at the end.
-- ============================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS left_at TIMESTAMPTZ;

COMMENT ON COLUMN users.left_at IS
  'When this member left by their own hand. Set only beside kicked_at, '
  'and cleared whenever kicked_at is: a readmission, a ban or an unban.';

-- One rule, wherever kicked_at is cleared: by `register_user` readmitting
-- them, or by `moderate_user` turning the kick into a ban or lifting it. A
-- trigger rather than a line in each, so that neither function has to be
-- replaced again to learn a column it has no other use for.
CREATE OR REPLACE FUNCTION app.clear_left_with_kick() RETURNS TRIGGER
  LANGUAGE plpgsql SET search_path = public AS $$
BEGIN
  IF NEW.kicked_at IS NULL THEN
    NEW.left_at := NULL;
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS users_clear_left_with_kick ON users;
CREATE TRIGGER users_clear_left_with_kick BEFORE UPDATE ON users
  FOR EACH ROW WHEN (NEW.left_at IS NOT NULL AND NEW.kicked_at IS NULL)
  EXECUTE FUNCTION app.clear_left_with_kick();

-- ── Leaving ─────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION leave_server() RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me users%ROWTYPE;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;
  SELECT * INTO v_me FROM users WHERE id = auth.uid() FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'user_not_found';
  END IF;
  -- Out already. Saying yes is honest (they are not a member), and changing
  -- nothing is what keeps a ban from turning into a kick an invite lifts.
  IF v_me.is_banned THEN
    RETURN jsonb_build_object('reason', 'ok');
  END IF;
  IF v_me.is_owner THEN
    RAISE EXCEPTION 'owner_cannot_leave';
  END IF;
  IF v_me.is_bot THEN
    RAISE EXCEPTION 'bot_cannot_leave';
  END IF;

  DELETE FROM member_roles    WHERE user_id = v_me.id;
  DELETE FROM channel_members WHERE user_id = v_me.id;
  UPDATE users SET is_banned = true, kicked_at = now(), left_at = now()
   WHERE id = v_me.id;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

COMMENT ON FUNCTION leave_server() IS
  'Leave this server: a kick by your own hand, which a new invite lifts.';

-- ── The member row says who left ────────────────────────────

CREATE OR REPLACE VIEW member_directory
  WITH (security_invoker = true) AS
  SELECT u.id,
         u.server_id,
         u.username,
         u.display_name,
         u.avatar_path,
         u.chat_public_key,
         u.is_muted,
         u.is_deafened,
         u.is_banned,
         u.is_bot,
         u.manifest,
         u.is_server_admin,
         u.is_channel_manager,
         u.can_create_tokens,
         -- When they joined *this* server — the only tenure anybody here can
         -- vouch for, since servers do not know about each other and there is
         -- no global "member since" to show instead.
         --
         -- Last, and out of the grouping it belongs to, because that is the
         -- only place `CREATE OR REPLACE VIEW` will take a new column: this
         -- file is re-runnable and nothing in these migrations drops.
         u.created_at AS joined_at,
         -- Appended for the same reason. Whether a first DM will arrive, wait
         -- as a request, or be refused, which the sender's composer says
         -- before anybody types; and a time-out, which a moderator is shown.
         u.dm_policy,
         u.timed_out_until,
         -- A kicked member is banned until an invite brings them back; this
         -- lets a moderator's list say which of the two it is.
         u.kicked_at IS NOT NULL AS is_kicked,
         -- Appended, like the two above it. A member who left is kicked by
         -- their own hand; this lets a moderator's list say which.
         u.left_at IS NOT NULL AS has_left
    FROM users u;

-- ── The banned list leaves out who left ─────────────────────

CREATE OR REPLACE FUNCTION list_members(
  p_channel    UUID    DEFAULT NULL,
  p_bots       BOOLEAN DEFAULT NULL,
  p_banned     BOOLEAN DEFAULT FALSE,
  p_after_name TEXT    DEFAULT NULL,
  p_after_id   UUID    DEFAULT NULL,
  p_limit      INTEGER DEFAULT 50)
  RETURNS SETOF member_directory
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
  -- See `app.channel_audience`: the channel's membership gathered once,
  -- rather than asked of each member the page walks past.
  v_audience UUID[] := app.channel_audience(p_channel);
BEGIN
  IF v_server IS NULL OR NOT app.member_scope_allowed(p_channel) THEN
    RETURN;
  END IF;

  IF p_after_name IS NULL THEN
    RETURN QUERY
    SELECT m.* FROM member_directory m
     WHERE m.server_id = v_server
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (p_banned IS NOT TRUE OR NOT m.has_left)
       AND (v_audience IS NULL OR m.id IN (SELECT unnest(v_audience)))
     ORDER BY app.member_sort_key(m.display_name), m.id
     LIMIT app.member_limit(p_limit);
  ELSE
    RETURN QUERY
    SELECT m.* FROM member_directory m
     WHERE m.server_id = v_server
       AND (app.member_sort_key(m.display_name), m.id)
           > (app.member_sort_key(p_after_name),
              COALESCE(p_after_id, '00000000-0000-0000-0000-000000000000'::UUID))
       AND (p_bots   IS NULL OR m.is_bot    = p_bots)
       AND (p_banned IS NULL OR m.is_banned = p_banned)
       AND (p_banned IS NOT TRUE OR NOT m.has_left)
       AND (v_audience IS NULL OR m.id IN (SELECT unnest(v_audience)))
     ORDER BY app.member_sort_key(m.display_name), m.id
     LIMIT app.member_limit(p_limit);
  END IF;
END $$;

COMMENT ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER) IS
  'One page of the member sidebar, keyset-paged by (sorted name, id). The '
  'banned page leaves out members who left.';

-- ── Your own row says you left ──────────────────────────────
-- As in 015, plus `has_left`.

CREATE OR REPLACE FUNCTION public.get_server_details()
 RETURNS jsonb
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $$
  WITH me AS (
    -- `(SELECT auth.uid())`, not `auth.uid()`, and it is worth 34 of this
    -- function's 37 milliseconds. `users` carries two permissive SELECT
    -- policies, so every read of it also carries `(id = auth.uid() OR
    -- server_id = app.server_id())` — a disjunction, which can never be one
    -- index condition. Written bare, the caller's own predicate is left as a
    -- filter and the plan becomes a bitmap of every member of the server;
    -- wrapped, it is an InitPlan and the primary key answers it. 40.8 ms →
    -- 0.04 ms on 50,000 members. A client passing its own id as a literal was
    -- always fine — this is the one place the schema asked the question of
    -- itself.
    SELECT u.* FROM users u WHERE u.id = (SELECT auth.uid())
  ),
  -- Invisible to a banned caller, which is the point: the CASE below reads
  -- "no row here" as "not for you" rather than as "gone".
  srv AS (
    SELECT s.* FROM servers s LIMIT 1
  ),
  -- Only private channels can be managed individually, and only by the
  -- members holding the seat. One read for the whole list, as before.
  managed AS (
    SELECT cm.channel_id FROM channel_members cm
     WHERE cm.user_id = auth.uid() AND cm.can_manage
  ),
  chans AS (
    SELECT jsonb_agg(jsonb_build_object(
             'id',             c.id,
             'name',           c.name,
             'channel_type',   c.channel_type,
             'retention_days', c.retention_days,
             'history_cap',    c.history_cap,
             'is_private',     c.is_private,
             'is_encrypted',   c.is_encrypted,
             -- Which LiveKit voice here is pinned to, and where a call
             -- actually is. Null and null is "automatic, nobody in it".
             'livekit_node_id', c.livekit_node_id,
             'voice_node_id',   (SELECT vr.node_id FROM voice_rooms vr
                                  WHERE vr.channel_id = c.id),
             'can_manage',     c.is_private
                                 AND EXISTS (SELECT 1 FROM managed m
                                              WHERE m.channel_id = c.id))
             ORDER BY c.channel_type, c."position", c.name) AS rows
      FROM channels c
  ),
  -- Every node this server can hold a call on. Members get the list too, not
  -- just managers: a member is shown which region they are in, and picks the
  -- nearest one to offer when they are the first to open a call.
  nodes AS (
    SELECT jsonb_agg(jsonb_build_object(
             'id',         n.id,
             'label',      n.label,
             'url',        n.url,
             'is_default', n.is_default)
             ORDER BY n.is_default DESC, n.label) AS rows
      FROM livekit_nodes n
  )
  SELECT CASE
    -- No row of our own: removed, or the server is gone. Either way there is
    -- nothing here to refresh, and the client turns a null into that answer.
    WHEN NOT EXISTS (SELECT 1 FROM me) THEN NULL
    ELSE (jsonb_build_object('user', (
      SELECT jsonb_build_object(
        'id',              me.id,
        'username',        me.username,
        'display_name',    me.display_name,
        'avatar_path',     me.avatar_path,
        'chat_public_key', me.chat_public_key,
        'is_muted',        me.is_muted,
        'is_deafened',     me.is_deafened,
        'is_banned',       me.is_banned,
        'is_kicked',       me.kicked_at IS NOT NULL,
        'has_left',        me.left_at IS NOT NULL,
        'is_bot',          me.is_bot,
        'manifest',        me.manifest,
        'timed_out_until', me.timed_out_until,
        'dm_policy',       me.dm_policy,
        'permissions', jsonb_build_object(
          'is_server_admin',    me.is_server_admin,
          'is_channel_manager', me.is_channel_manager,
          'can_create_tokens',  me.can_create_tokens,
          'is_owner',           me.is_owner,
          'permission_bits',    my_permissions()))
        FROM me))
      -- A banned caller stops here: their own row, and an empty list rather
      -- than the null a client would have to guard.
      || CASE WHEN (SELECT me.is_banned FROM me)
              THEN jsonb_build_object('channels', '[]'::jsonb)
              ELSE jsonb_build_object(
                'server_id',   (SELECT srv.id          FROM srv),
                'name',        (SELECT srv.name        FROM srv),
                'icon_url',    (SELECT srv.icon_url    FROM srv),
                'livekit_url', (SELECT srv.livekit_url FROM srv),
                'channels',    COALESCE((SELECT rows FROM chans), '[]'::jsonb),
                'max_attachment_bytes',
                  (SELECT srv.max_attachment_bytes   FROM srv),
                'message_retention_days',
                  (SELECT srv.message_retention_days FROM srv),
                'message_history_cap',
                  (SELECT srv.message_history_cap    FROM srv),
                'dm_retention_days',
                  (SELECT srv.dm_retention_days      FROM srv),
                'dm_history_cap',
                  (SELECT srv.dm_history_cap         FROM srv),
                -- Without these the bitrate picker reads "no cap" on every
                -- refresh and an operator's setting looks forgotten.
                'max_voice_participants',
                  (SELECT srv.max_voice_participants FROM srv),
                'max_share_mbps',
                  (SELECT srv.max_share_mbps         FROM srv),
                'max_members',
                  (SELECT srv.max_members            FROM srv),
                'max_storage_bytes',
                  (SELECT srv.max_storage_bytes      FROM srv),
                'dm_openings_per_hour',
                  (SELECT srv.dm_openings_per_hour   FROM srv),
                -- Not a limit but the thing limits are judged against, and
                -- free here: one indexed read, in the call the client already
                -- makes. It is what lets the composer say a file will not fit
                -- before somebody picks it, rather than after.
                'storage_used', server_storage_used(),
                -- The ceiling `max_attachment_bytes` is set under, so the
                -- settings dialog offers no number this machine refuses.
                'max_file_bytes', max_file_bytes(),
                'livekit_nodes', COALESCE((SELECT rows FROM nodes), '[]'::jsonb))
         END)
  END;
$$;

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION app.clear_left_with_kick() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION leave_server() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION leave_server() TO authenticated;
REVOKE ALL ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER)
  FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER)
  TO authenticated;
REVOKE ALL ON FUNCTION get_server_details() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION get_server_details() TO authenticated;
