-- ============================================================
-- Rift self-hosted server — 071: the policy helpers keep their plans
-- ============================================================
-- Found in the speed re-review, Nov 26 2026.
--
-- Every policy, trigger and RPC asks a handful of small helpers: who the
-- caller is (`app.server_id`), which channels they see
-- (`app.visible_channels`), what they may do (`app.has_perm`). Each was
-- `LANGUAGE sql … SECURITY DEFINER SET search_path`. Postgres 17 cannot fold
-- such a function into its caller (the definer and the `SET` forbid it), and
-- keeps no plan for it from one statement to the next: every statement that
-- asked one parsed and planned its body again. A channel open asked
-- `app.server_id` 25 times and `app.in_channel` 210 times, and half its
-- time went to planning them. PL/pgSQL keeps a plan for the life of the
-- connection, and PostgREST's connections live long.
--
--   * Every such helper is now PL/pgSQL, returning the body it had, word
--     for word: same definer, same `search_path`, same answers. Each body
--     yields at most one row (an `EXISTS`, an aggregate, or a lookup by a
--     unique key), so `RETURN (…)` answers as the SQL function did.
--   * `app.visible_channels` asks for its private channels in one
--     statement rather than `app.in_channel` once each.
--   * The plain `IMMUTABLE` SQL functions with no `SET` (`app.perm`,
--     `app.member_sort_key`, `app.members_ring`, `unread_cap`) are left as
--     they are: those are folded into their callers today, and
--     `idx_users_server_sorted` matches `app.member_sort_key` only so.
--
-- Grants are kept: `CREATE OR REPLACE` keeps them, and the policies are not
-- touched.

-- ── Who the caller is, and what they see ────────────────────
CREATE OR REPLACE FUNCTION app.server_id()
  RETURNS UUID
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT u.server_id FROM users u
      JOIN servers s ON s.id = u.server_id
     WHERE u.id = auth.uid() AND NOT u.is_banned AND s.deleting_since IS NULL
  );
END $$;

CREATE OR REPLACE FUNCTION app.visible_channels()
  RETURNS UUID[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me UUID := auth.uid();
BEGIN
  -- `app.in_channel`, written into the statement: a seat, or a role let in.
  RETURN (
    SELECT COALESCE(array_agg(c.id), '{}'::uuid[])
      FROM channels c
     WHERE c.server_id = app.server_id()
       AND (NOT c.is_private
            OR EXISTS (SELECT 1 FROM channel_members cm
                        WHERE cm.channel_id = c.id AND cm.user_id = v_me)
            OR EXISTS (SELECT 1 FROM channel_role_access cra
                         JOIN member_roles mr ON mr.role_id = cra.role_id
                        WHERE cra.channel_id = c.id AND mr.user_id = v_me))
  );
END $$;

-- 070's body.
CREATE OR REPLACE FUNCTION app.bot_channels()
  RETURNS UUID[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE(array_agg(g.channel_id), '{}'::uuid[])
      FROM bot_channel_keys g
     WHERE g.bot_id = auth.uid()
       AND app.server_id() IS NOT NULL
  );
END $$;

-- ── The rest, bodies unchanged ──────────────────────────────
CREATE OR REPLACE FUNCTION app.apply_channel_overrides(p_bits bigint, p_channel uuid, p_user uuid)
  RETURNS bigint
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT app.override_bits(p_bits, ev.allow, ev.deny, rl.allow, rl.deny)
    FROM (SELECT bit_or(o.allow) AS allow, bit_or(o.deny) AS deny
            FROM channel_overrides o
            JOIN member_roles mr ON mr.role_id = o.role_id AND mr.user_id = p_user
           WHERE o.channel_id = p_channel) rl
    LEFT JOIN (SELECT o.allow, o.deny
                 FROM channel_overrides o
                 JOIN roles r ON r.id = o.role_id AND r.is_everyone
                WHERE o.channel_id = p_channel) ev ON true
  );
END $$;

CREATE OR REPLACE FUNCTION app.blocked_by(p_other uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM member_blocks b
                    WHERE b.blocker_id = p_other AND b.blocked_id = auth.uid())
  );
END $$;

CREATE OR REPLACE FUNCTION app.bot_reads_channel(p_channel uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM bot_channel_keys g
                    WHERE g.channel_id = p_channel AND g.bot_id = auth.uid())
  );
END $$;

CREATE OR REPLACE FUNCTION app.bot_reads_version(p_channel uuid, p_version integer)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM bot_channel_keys g
                    WHERE g.channel_id = p_channel AND g.bot_id = auth.uid()
                      AND p_version >= g.from_key_version)
  );
END $$;

CREATE OR REPLACE FUNCTION app.bot_summoned_to(p_channel uuid, p_bot uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM bot_voice_summons s
                    WHERE s.channel_id = p_channel AND s.bot_id = p_bot)
  );
END $$;

CREATE OR REPLACE FUNCTION app.can_invite()
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE((SELECT u.is_server_admin OR u.can_create_tokens FROM users u
                      WHERE u.id = auth.uid() AND NOT u.is_banned), false)
  );
END $$;

CREATE OR REPLACE FUNCTION app.can_manage_channel(p_channel uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (
      SELECT 1 FROM channels c
       WHERE c.id = p_channel
         AND c.server_id = app.server_id()
         AND (CASE WHEN c.is_private
                   THEN EXISTS (SELECT 1 FROM channel_members cm
                                 WHERE cm.channel_id = p_channel
                                   AND cm.user_id = auth.uid()
                                   AND cm.can_manage)
                   ELSE app.has_perm('MANAGE_CHANNELS') END))
  );
END $$;

CREATE OR REPLACE FUNCTION app.can_manage_channels()
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE((SELECT u.is_server_admin OR u.is_channel_manager FROM users u
                      WHERE u.id = auth.uid() AND NOT u.is_banned), false)
  );
END $$;

CREATE OR REPLACE FUNCTION app.can_manage_webhooks()
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT app.can_manage_channels() AND app.has_perm('MANAGE_WEBHOOKS')
  );
END $$;

CREATE OR REPLACE FUNCTION app.can_pin_in(p_channel uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT app.can_see_channel(p_channel)
       AND (app.has_channel_perm(p_channel, 'PIN_MESSAGES')
            OR EXISTS (SELECT 1 FROM channels c
                         JOIN channel_members cm ON cm.channel_id = c.id
                        WHERE c.id = p_channel AND c.is_private
                          AND cm.user_id = auth.uid() AND cm.can_manage))
  );
END $$;

CREATE OR REPLACE FUNCTION app.can_press_call_panel(p_channel uuid, p_panel bigint, p_bot uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (
      SELECT 1 FROM messages m
       WHERE m.id = p_panel
         AND m.channel_id = p_channel
         AND m.sender_id = p_bot
         AND m.ephemeral_for IS NULL
         AND app.panel_call(m.blocks) IS NOT NULL
         AND app.can_see_channel(app.panel_call(m.blocks)))
  );
END $$;

CREATE OR REPLACE FUNCTION app.can_receive_dm(p_user uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM users u
                    WHERE u.id = p_user AND NOT u.is_banned
                      AND u.chat_public_key IS NOT NULL
                      AND u.server_id = app.server_id())
  );
END $$;

CREATE OR REPLACE FUNCTION app.can_see_channel(p_channel uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (
      SELECT 1 FROM channels c
       WHERE c.id = p_channel
         AND c.server_id = app.server_id()
         AND (NOT c.is_private OR app.in_channel(p_channel, auth.uid())))
  );
END $$;

CREATE OR REPLACE FUNCTION app.can_see_dm(p_message bigint)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM dm_messages d
                    WHERE d.id = p_message
                      AND auth.uid() IN (d.sender_id, d.recipient_id))
  );
END $$;

CREATE OR REPLACE FUNCTION app.can_see_message(p_message bigint)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM messages m
                    WHERE m.id = p_message
                      AND app.can_see_channel(m.channel_id)
                      AND (NOT app.is_bot() OR m.to_bot = auth.uid()
                           OR m.sender_id = auth.uid()))
  );
END $$;

CREATE OR REPLACE FUNCTION app.channel_audience(p_channel uuid)
  RETURNS uuid[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT CASE
      WHEN p_channel IS NULL THEN NULL
      WHEN NOT COALESCE((SELECT c.is_private FROM channels c WHERE c.id = p_channel), false)
        THEN NULL
      ELSE COALESCE((
        SELECT array_agg(DISTINCT e.user_id) FROM (
          SELECT cm.user_id FROM channel_members cm WHERE cm.channel_id = p_channel
          UNION
          SELECT mr.user_id FROM channel_role_access cra
            JOIN member_roles mr ON mr.role_id = cra.role_id
           WHERE cra.channel_id = p_channel
        ) e), ARRAY[]::UUID[])
    END
  );
END $$;

CREATE OR REPLACE FUNCTION app.channel_eligible(p_channel uuid, p_user uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (
      SELECT 1
        FROM channels c
        JOIN users u ON u.id = p_user AND u.server_id = c.server_id
       WHERE c.id = p_channel
         AND NOT u.is_banned
         AND (NOT c.is_private OR app.in_channel(p_channel, p_user)))
  );
END $$;

CREATE OR REPLACE FUNCTION app.channel_encrypted(p_channel uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE((SELECT c.is_encrypted FROM channels c WHERE c.id = p_channel), true)
  );
END $$;

CREATE OR REPLACE FUNCTION app.channel_permissions_of(p_channel uuid, p_user uuid)
  RETURNS bigint
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE((
      SELECT app.apply_channel_overrides(app.permissions_of(p_user), p_channel, p_user)
        FROM users u
        JOIN channels c ON c.id = p_channel AND c.server_id = u.server_id
       WHERE u.id = p_user AND NOT u.is_banned
    ), 0)
  );
END $$;

CREATE OR REPLACE FUNCTION app.channel_server_id(p_channel uuid)
  RETURNS uuid
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT c.server_id FROM channels c WHERE c.id = p_channel
  );
END $$;

CREATE OR REPLACE FUNCTION app.console_server()
  RETURNS uuid
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT s.id FROM servers s ORDER BY s.created_at, s.id LIMIT 1
  );
END $$;

CREATE OR REPLACE FUNCTION app.dm_call_json(p_call dm_calls, p_me uuid)
  RETURNS jsonb
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT jsonb_build_object(
             'id',                   p_call.id,
             'caller_id',            p_call.caller_id,
             'callee_id',            p_call.callee_id,
             'started_at',           p_call.started_at,
             'answered_at',          p_call.answered_at,
             'ended_at',             p_call.ended_at,
             'outcome',              p_call.outcome,
             'peer_id',              u.id,
             'peer_name',            u.display_name,
             'peer_username',        u.username,
             'peer_avatar_path',     u.avatar_path,
             'peer_chat_public_key', u.chat_public_key,
             'peer_public_key',      u.public_key)
      FROM users u
     WHERE u.id = CASE WHEN p_call.caller_id = p_me
                       THEN p_call.callee_id ELSE p_call.caller_id END
  );
END $$;

CREATE OR REPLACE FUNCTION app.dm_is_request(p_sender uuid, p_recipient uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM dm_links l
                    WHERE l.user_low  = LEAST(p_sender, p_recipient)
                      AND l.user_high = GREATEST(p_sender, p_recipient)
                      AND l.opened_by = p_sender
                      AND l.status <> 'open')
  );
END $$;

CREATE OR REPLACE FUNCTION app.dm_newest_from(p_peer uuid)
  RETURNS bigint
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT max(d.id) FROM dm_messages d
     WHERE LEAST(d.sender_id, d.recipient_id)    = LEAST(auth.uid(), p_peer)
       AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(auth.uid(), p_peer)
       AND d.sender_id = p_peer
  );
END $$;

CREATE OR REPLACE FUNCTION app.dm_unread_from(p_peer uuid, p_after bigint)
  RETURNS bigint
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT count(*) FROM (
      SELECT 1 FROM dm_messages d
       WHERE LEAST(d.sender_id, d.recipient_id)    = LEAST(auth.uid(), p_peer)
         AND GREATEST(d.sender_id, d.recipient_id) = GREATEST(auth.uid(), p_peer)
         AND d.sender_id = p_peer
         AND d.id > p_after
       ORDER BY d.id
       LIMIT unread_cap()) capped
  );
END $$;

CREATE OR REPLACE FUNCTION app.has_channel_perm(p_channel uuid, p_name text)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT (app.channel_permissions_of(p_channel, auth.uid())
            & (app.perm('ADMINISTRATOR') | app.perm(p_name))) <> 0
  );
END $$;

CREATE OR REPLACE FUNCTION app.has_perm(p_name text)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT (app.permissions() & (app.perm('ADMINISTRATOR') | app.perm(p_name))) <> 0
  );
END $$;

CREATE OR REPLACE FUNCTION app.holds_room_key(p_channel uuid, p_version integer)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM channel_keyring k
                    WHERE k.channel_id = p_channel
                      AND k.key_version = p_version
                      AND k.user_id = auth.uid())
       AND NOT EXISTS (SELECT 1 FROM channel_keyring k
                        WHERE k.channel_id = p_channel
                          AND k.key_version > p_version)
  );
END $$;

CREATE OR REPLACE FUNCTION app.in_channel(p_channel uuid, p_user uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM channel_members cm
                    WHERE cm.channel_id = p_channel AND cm.user_id = p_user)
        OR EXISTS (SELECT 1 FROM channel_role_access cra
                    JOIN member_roles mr ON mr.role_id = cra.role_id
                   WHERE cra.channel_id = p_channel AND mr.user_id = p_user)
  );
END $$;

CREATE OR REPLACE FUNCTION app.is_addressable_bot(p_user uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM users u
                    WHERE u.id = p_user AND u.is_bot AND NOT u.is_banned
                      AND u.server_id = app.server_id())
  );
END $$;

CREATE OR REPLACE FUNCTION app.is_admin()
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE((SELECT u.is_server_admin FROM users u
                      WHERE u.id = auth.uid() AND NOT u.is_banned), false)
  );
END $$;

CREATE OR REPLACE FUNCTION app.is_bot()
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE((SELECT u.is_bot FROM users u WHERE u.id = auth.uid()), false)
  );
END $$;

CREATE OR REPLACE FUNCTION app.is_co_member(p_user uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM users u
                    WHERE u.id = p_user AND NOT u.is_banned
                      AND u.server_id = app.server_id())
  );
END $$;

CREATE OR REPLACE FUNCTION app.is_pressable_panel(p_channel uuid, p_panel bigint, p_bot uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (
      SELECT 1 FROM messages m
       WHERE m.id = p_panel
         AND m.channel_id = p_channel
         AND m.sender_id = p_bot
         AND m.blocks IS NOT NULL
         AND (m.ephemeral_for IS NULL OR m.ephemeral_for = auth.uid()))
  );
END $$;

CREATE OR REPLACE FUNCTION app.key_missing(p_channel uuid, p_version integer, p_first uuid, p_limit integer)
  RETURNS jsonb
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE(
             jsonb_agg(jsonb_build_object('user_id', m.user_id,
                                          'chat_public_key', m.chat_public_key)
                       ORDER BY m.is_first DESC, m.user_id),
             '[]'::jsonb)
      FROM (SELECT e.user_id, e.chat_public_key, e.user_id = p_first AS is_first
              FROM channel_eligible_members e
             WHERE e.channel_id = p_channel
               AND e.from_key_version <= p_version
               AND NOT EXISTS (SELECT 1 FROM channel_keyring k
                                WHERE k.channel_id = p_channel
                                  AND k.key_version = p_version
                                  AND k.user_id = e.user_id)
             ORDER BY e.user_id = p_first DESC, e.user_id
             LIMIT GREATEST(p_limit, 0)) m
  );
END $$;

CREATE OR REPLACE FUNCTION app.key_missing_from(p_channel uuid, p_version integer, p_first uuid, p_limit integer, p_full boolean)
  RETURNS jsonb
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE(
             jsonb_agg(jsonb_build_object('user_id', m.user_id,
                                          'chat_public_key', m.chat_public_key)
                       ORDER BY m.is_first DESC, m.user_id),
             '[]'::jsonb)
      FROM (SELECT e.user_id, e.chat_public_key, e.user_id = p_first AS is_first
              FROM app.key_candidates(p_channel, p_full) e
             WHERE e.from_key_version <= p_version
               AND NOT EXISTS (SELECT 1 FROM channel_keyring k
                                WHERE k.channel_id = p_channel
                                  AND k.key_version = p_version
                                  AND k.user_id = e.user_id)
             ORDER BY e.user_id = p_first DESC, e.user_id
             LIMIT GREATEST(p_limit, 0)) m
  );
END $$;

CREATE OR REPLACE FUNCTION app.max_role_position()
  RETURNS integer
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE((
      SELECT max(r.position)
        FROM member_roles mr
        JOIN roles r ON r.id = mr.role_id
       WHERE mr.user_id = auth.uid()
    ), 0)
  );
END $$;

CREATE OR REPLACE FUNCTION app.may_assign_role(p_role uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT app.has_perm('ADMINISTRATOR')
       AND EXISTS (
         SELECT 1 FROM roles r
          WHERE r.id = p_role
            AND r.server_id = app.server_id()
            AND NOT r.is_everyone
            AND NOT r.is_owner
            AND r.position <= app.max_role_position())
  );
END $$;

CREATE OR REPLACE FUNCTION app.may_hand_out(p_user uuid, p_role uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (
      SELECT 1 FROM users u
        JOIN roles r ON r.id = p_role AND r.server_id = u.server_id
       WHERE u.id = p_user
         AND NOT u.is_banned
         AND (app.permissions_of(u.id) & app.perm('ADMINISTRATOR')) <> 0
         AND NOT r.is_everyone
         AND NOT r.is_owner
         AND r.position <= COALESCE((
               SELECT max(r2.position) FROM member_roles mr
                 JOIN roles r2 ON r2.id = mr.role_id
                WHERE mr.user_id = u.id), 0))
  );
END $$;

CREATE OR REPLACE FUNCTION app.may_hold_perms(p_bits bigint)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT app.has_perm('ADMINISTRATOR') OR (p_bits & ~app.permissions()) = 0
  );
END $$;

CREATE OR REPLACE FUNCTION app.may_manage_role(p_position integer)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT app.has_perm('ADMINISTRATOR') AND p_position < app.max_role_position()
  );
END $$;

CREATE OR REPLACE FUNCTION app.may_write_bot_voice_key(p_channel uuid, p_bot uuid, p_channel_key boolean)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT NOT app.is_bot()
       AND app.can_see_channel(p_channel)
       AND EXISTS (SELECT 1 FROM channels c
                    WHERE c.id = p_channel AND c.channel_type = 'voice')
       AND EXISTS (SELECT 1 FROM users u
                    WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                      AND u.server_id = app.server_id())
       AND (NOT p_channel_key
            OR EXISTS (SELECT 1 FROM bot_voice_grants g
                        WHERE g.channel_id = p_channel AND g.bot_id = p_bot))
  );
END $$;

CREATE OR REPLACE FUNCTION app.member_in_scope(p_user uuid, p_is_bot boolean, p_banned_row boolean, p_channel uuid, p_bots boolean, p_banned boolean)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT (p_bots   IS NULL OR p_is_bot     = p_bots)
       AND (p_banned IS NULL OR p_banned_row = p_banned)
       AND (p_channel IS NULL
            OR NOT (SELECT c.is_private FROM channels c WHERE c.id = p_channel)
            OR app.in_channel(p_channel, p_user))
  );
END $$;

CREATE OR REPLACE FUNCTION app.member_scope_allowed(p_channel uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT p_channel IS NULL OR app.can_see_channel(p_channel)
  );
END $$;

CREATE OR REPLACE FUNCTION app.message_channel(p_message bigint)
  RETURNS uuid
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT m.channel_id FROM messages m WHERE m.id = p_message
  );
END $$;

CREATE OR REPLACE FUNCTION app.message_reaches_me(p_message bigint)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM messages m
                    WHERE m.id = p_message
                      AND (m.to_bot = auth.uid() OR m.sender_id = auth.uid()))
  );
END $$;

CREATE OR REPLACE FUNCTION app.my_server_in_use()
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT NOT EXISTS (SELECT 1 FROM users u JOIN servers s ON s.id = u.server_id
                        WHERE u.id = auth.uid() AND s.deleting_since IS NOT NULL)
  );
END $$;

CREATE OR REPLACE FUNCTION app.notify_level(p_user uuid, p_scope notify_scope, p_scope_id uuid)
  RETURNS notify_level
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE(
      -- 1. What this exact thing is set to.
      (SELECT p.level FROM notification_prefs p
        WHERE p.user_id = p_user AND p.scope = p_scope AND p.scope_id = p_scope_id),
      -- 2. Failing that, what the server it belongs to is set to. Skipped when
      --    the question already *is* about a server, which would ask itself.
      CASE WHEN p_scope = 'server' THEN NULL ELSE (
        SELECT p.level FROM notification_prefs p
         WHERE p.user_id = p_user AND p.scope = 'server'
           AND p.scope_id = CASE p_scope
                 WHEN 'channel' THEN app.channel_server_id(p_scope_id)
                 -- A DM's server is the one both people are members of, which is
                 -- the asker's own: identity is per (host, server), so a member
                 -- of two servers is two accounts and this is only ever one.
                 ELSE (SELECT u.server_id FROM users u WHERE u.id = p_user)
               END)
      END,
      -- 3. The default. A channel is a room full of people talking to each
      --    other; a DM is somebody talking to you; a server nobody has an
      --    opinion about quiets nothing.
      CASE p_scope WHEN 'channel' THEN 'mentions'::notify_level
                   ELSE 'all'::notify_level END
    )
  );
END $$;

CREATE OR REPLACE FUNCTION app.permissions()
  RETURNS bigint
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT app.permissions_of(auth.uid())
  );
END $$;

CREATE OR REPLACE FUNCTION app.permissions_of(p_user uuid)
  RETURNS bigint
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE((
      SELECT bit_or(r.permissions)
        FROM users u
        JOIN roles r ON r.server_id = u.server_id
       WHERE u.id = p_user
         AND NOT u.is_banned
         AND (r.is_everyone
              OR EXISTS (SELECT 1 FROM member_roles mr
                          WHERE mr.role_id = r.id AND mr.user_id = u.id))
    ), 0)
  );
END $$;

CREATE OR REPLACE FUNCTION app.push_enabled(p_server_id uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (SELECT 1 FROM push_config pc WHERE pc.server_id = p_server_id)
  );
END $$;

CREATE OR REPLACE FUNCTION app.sees_channel(p_channel uuid, p_user uuid)
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT EXISTS (
      SELECT 1 FROM channels c
        JOIN users u ON u.id = p_user AND u.server_id = c.server_id
       WHERE c.id = p_channel
         AND NOT u.is_banned
         AND (NOT c.is_private OR app.in_channel(p_channel, p_user)))
  );
END $$;

CREATE OR REPLACE FUNCTION app.server_roles()
  RETURNS uuid[]
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE(array_agg(r.id), '{}'::uuid[])
      FROM roles r WHERE r.server_id = app.server_id()
  );
END $$;

CREATE OR REPLACE FUNCTION app.timed_out()
  RETURNS boolean
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN (
    SELECT COALESCE((SELECT u.timed_out_until > now() FROM users u
                      WHERE u.id = auth.uid()), false)
  );
END $$;
