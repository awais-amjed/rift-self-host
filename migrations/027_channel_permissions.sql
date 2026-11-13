-- ============================================================
-- Rift self-hosted server — 027: permissions per channel
-- ============================================================
-- Every permission bit was the server's: a role that may post may post
-- everywhere. A server that wants an announcements channel only its admins
-- write in, a media channel where everyone may attach, or a stage where only
-- one role speaks had no way to say so.
--
-- Now a channel can override a role's bits — the `@everyone` role included —
-- with a row in `channel_overrides`: bits it allows and bits it denies, the
-- rest inherited from the server. What a member may do in a channel is
--
--   1. their server-wide bits (`app.permissions_of`),
--   2. with the channel's `@everyone` row applied: its denies taken away, its
--      allows added,
--   3. then every row for a role they hold, together: the denies of all of
--      them taken away, then the allows of all of them added — so between two
--      of their roles, allow wins,
--
-- and an administrator holds every bit whatever the channel says. Nothing
-- stores the answer; it is worked out where it is asked
-- (`app.channel_permissions_of`), so a role given tomorrow counts tomorrow.
--
-- Only the bits that mean something inside one channel may be overridden, and
-- only the ones for its kind (`app.channel_perm_mask`). Never `VIEW_CHANNEL`:
-- who can see and read a channel is a private channel's member list, because
-- it decides who is sealed the key, and a second way to hide a channel would
-- be a way for the two to disagree.
--
-- Where the server's bit was asked about one channel, the channel's is asked
-- now: posting, polls, reactions, attachments, pins, deleting others'
-- messages, @all, joining a call, speaking, sharing a screen and summoning a
-- bot. `get_channel_token` and `moderate_user` ask through
-- `user_has_channel_permission`. A press on a bot's panel is not posting and
-- passes the send check, so a panel in a read-only channel still works.
--
-- Written only through `set_channel_override`, by whoever may manage the
-- channel (`app.can_manage_channel`), and only with bits they hold themselves
-- (`app.may_hold_perms`, the rule roles already follow) on a role below their
-- own. Changing one rings `channels` on the server's topic, which every
-- client already answers by reading its server again.
-- ============================================================

-- ── The bits a channel may override ─────────────────────────

CREATE OR REPLACE FUNCTION app.channel_perm_mask(p_type channel_type)
  RETURNS BIGINT LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE p_type
    WHEN 'text' THEN app.perm('SEND_MESSAGES') | app.perm('ATTACH_FILES')
                   | app.perm('ADD_REACTIONS') | app.perm('MENTION_ALL')
                   | app.perm('MANAGE_MESSAGES') | app.perm('PIN_MESSAGES')
                   | app.perm('CREATE_POLLS')
    WHEN 'voice' THEN app.perm('CONNECT') | app.perm('SPEAK')
                    | app.perm('SCREEN_SHARE') | app.perm('USE_SOUNDBOARD')
                    | app.perm('SUMMON_BOTS')
    ELSE 0::BIGINT
  END
$$;

-- ── The table ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS channel_overrides (
  channel_id UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  -- The `@everyone` role for the channel's baseline row.
  role_id    UUID        NOT NULL REFERENCES roles(id)    ON DELETE CASCADE,
  allow      BIGINT      NOT NULL DEFAULT 0,
  deny       BIGINT      NOT NULL DEFAULT 0,
  updated_by UUID        REFERENCES users(id) ON DELETE SET NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, role_id),
  CONSTRAINT channel_overrides_one_answer CHECK ((allow & deny) = 0),
  CONSTRAINT channel_overrides_nonempty   CHECK ((allow | deny) <> 0)
);

COMMENT ON TABLE channel_overrides IS
  'Bits a channel allows or denies one role (or @everyone) on top of the '
  'server''s. Resolved by app.channel_permissions_of; written by '
  'set_channel_override.';

CREATE INDEX IF NOT EXISTS channel_overrides_role ON channel_overrides (role_id);

ALTER TABLE channel_overrides ENABLE ROW LEVEL SECURITY;

-- Readable by whoever can see the channel, which is who the editor is for.
-- A member learns nothing from it that the buttons they are shown do not
-- already say.
DROP POLICY IF EXISTS channel_overrides_select ON channel_overrides;
CREATE POLICY channel_overrides_select ON channel_overrides FOR SELECT TO authenticated
  USING (app.can_see_channel(channel_id));

-- ── Working it out ──────────────────────────────────────────

-- Steps 2 and 3 above, on bits already known. Split from the lookup so the
-- server details can read the caller's bits once and apply each channel's
-- rows to them, rather than reading them again per channel.
CREATE OR REPLACE FUNCTION app.apply_channel_overrides(
  p_bits BIGINT, p_channel UUID, p_user UUID
) RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT CASE
    WHEN (p_bits & app.perm('ADMINISTRATOR')) <> 0 THEN app.perm_all()
    ELSE ((((p_bits & ~COALESCE(ev.deny, 0)) | COALESCE(ev.allow, 0))
            & ~COALESCE(rl.deny, 0)) | COALESCE(rl.allow, 0))
  END
  FROM (SELECT bit_or(o.allow) AS allow, bit_or(o.deny) AS deny
          FROM channel_overrides o
          JOIN member_roles mr ON mr.role_id = o.role_id AND mr.user_id = p_user
         WHERE o.channel_id = p_channel) rl
  LEFT JOIN (SELECT o.allow, o.deny
               FROM channel_overrides o
               JOIN roles r ON r.id = o.role_id AND r.is_everyone
              WHERE o.channel_id = p_channel) ev ON true
$$;

-- Zero for anybody banned or not on the channel's server: an override that
-- allows must not hand a bit to somebody the server already holds nothing for.
CREATE OR REPLACE FUNCTION app.channel_permissions_of(p_channel UUID, p_user UUID)
  RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((
    SELECT app.apply_channel_overrides(app.permissions_of(p_user), p_channel, p_user)
      FROM users u
      JOIN channels c ON c.id = p_channel AND c.server_id = u.server_id
     WHERE u.id = p_user AND NOT u.is_banned
  ), 0)
$$;

-- `app.has_perm`, asked about one channel.
CREATE OR REPLACE FUNCTION app.has_channel_perm(p_channel UUID, p_name TEXT)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT (app.channel_permissions_of(p_channel, auth.uid())
          & (app.perm('ADMINISTRATOR') | app.perm(p_name))) <> 0
$$;

-- For an edge function on the service role, deciding about whoever asked it,
-- as `user_has_permission` is.
CREATE OR REPLACE FUNCTION user_has_channel_permission(
  p_user UUID, p_channel UUID, p_name TEXT
) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT (app.channel_permissions_of(p_channel, p_user)
          & (app.perm('ADMINISTRATOR') | app.perm(p_name))) <> 0
$$;

-- ── Writing one ─────────────────────────────────────────────
-- The whole row for one role: what it allows and what it denies. Both zero
-- removes it, which is "inherit everything". Answers `{reason}`, as the other
-- channel calls do: ok, forbidden, no_such_channel, no_such_role, invalid.
CREATE OR REPLACE FUNCTION set_channel_override(
  p_channel UUID, p_role UUID, p_allow BIGINT, p_deny BIGINT
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_type     channel_type;
  v_server   UUID;
  v_everyone BOOLEAN;
  v_position INTEGER;
  v_old      channel_overrides%ROWTYPE;
  v_changed  BIGINT;
BEGIN
  IF app.timed_out() THEN RETURN jsonb_build_object('reason', 'forbidden'); END IF;
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  IF NOT app.can_manage_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  SELECT c.channel_type, c.server_id INTO v_type, v_server
    FROM channels c WHERE c.id = p_channel;

  SELECT r.is_everyone, r."position" INTO v_everyone, v_position
    FROM roles r WHERE r.id = p_role AND r.server_id = v_server;
  IF NOT FOUND THEN RETURN jsonb_build_object('reason', 'no_such_role'); END IF;

  p_allow := COALESCE(p_allow, 0);
  p_deny  := COALESCE(p_deny, 0);
  IF p_allow < 0 OR p_deny < 0 OR (p_allow & p_deny) <> 0
     OR ((p_allow | p_deny) & ~app.channel_perm_mask(v_type)) <> 0 THEN
    RETURN jsonb_build_object('reason', 'invalid');
  END IF;

  -- A role at or above your own is not yours to shape, here as on the role
  -- itself. `@everyone` is below everybody.
  IF NOT app.has_perm('ADMINISTRATOR') AND NOT v_everyone
     AND v_position >= app.max_role_position() THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  -- Only the bits this call moves have to be yours: a row another admin left
  -- denying something you do not hold is not a reason you cannot change the
  -- rest of it.
  SELECT * INTO v_old FROM channel_overrides
   WHERE channel_id = p_channel AND role_id = p_role;
  v_changed := (COALESCE(v_old.allow, 0) # p_allow) | (COALESCE(v_old.deny, 0) # p_deny);
  IF NOT app.may_hold_perms(v_changed) THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF v_changed = 0 THEN RETURN jsonb_build_object('reason', 'ok'); END IF;

  IF p_allow = 0 AND p_deny = 0 THEN
    DELETE FROM channel_overrides WHERE channel_id = p_channel AND role_id = p_role;
  ELSE
    INSERT INTO channel_overrides (channel_id, role_id, allow, deny, updated_by)
    VALUES (p_channel, p_role, p_allow, p_deny, auth.uid())
    ON CONFLICT (channel_id, role_id) DO UPDATE
      SET allow = EXCLUDED.allow, deny = EXCLUDED.deny,
          updated_by = EXCLUDED.updated_by, updated_at = now();
  END IF;

  IF app.realtime_ready() THEN
    PERFORM realtime.send('{}'::jsonb, 'channels', 'server:' || v_server, true);
  END IF;
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ── Posting ─────────────────────────────────────────────────
-- As in 023, with `SEND_MESSAGES` and `CREATE_POLLS` asked of the channel, and
-- a panel press let through the send check.

DROP POLICY IF EXISTS messages_insert ON messages;
CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    (app.can_see_channel(channel_id)
     OR (is_interaction AND app.can_press_call_panel(channel_id, reply_to, to_bot)))
    AND (is_interaction OR app.has_channel_perm(channel_id, 'SEND_MESSAGES'))
    AND NOT app.timed_out()
    AND sender_id = auth.uid()
    AND webhook_id IS NULL AND origin_name IS NULL AND NOT is_system
    AND (key_version >= 1 OR to_bot IS NOT NULL OR app.is_bot()
         OR NOT app.channel_encrypted(channel_id))
    AND (to_bot IS NULL OR app.is_addressable_bot(to_bot))
    AND (to_bot IS NULL OR key_version = 0)
    AND (NOT app.is_bot() OR key_version = 0)
    AND (ephemeral_for IS NULL OR app.is_bot())
    AND (blocks IS NULL OR app.is_bot())
    AND (NOT is_interaction OR NOT app.is_bot())
    AND (poll IS NULL OR (NOT app.is_bot() AND to_bot IS NULL
                          AND app.has_channel_perm(channel_id, 'CREATE_POLLS')))
  );

-- `@all` is a plaintext flag beside the sealed body, so the server can hold
-- it to the bit, and it never had: anybody could ring a whole channel. As in
-- 004, plus the flag dropped (not the message refused, as with a long mention
-- list) for a sender the channel does not give `MENTION_ALL`.
CREATE OR REPLACE FUNCTION validate_message_mentions()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_clean UUID[];
BEGIN
  IF TG_OP = 'UPDATE' THEN
    NEW.mentions     := OLD.mentions;
    NEW.mentions_all := OLD.mentions_all;
    RETURN NEW;
  END IF;

  SELECT COALESCE(array_agg(DISTINCT u.id), '{}')
    INTO v_clean
    FROM unnest(COALESCE(NEW.mentions, '{}')) AS m(id)
    JOIN users u ON u.id = m.id
   WHERE u.server_id = app.channel_server_id(NEW.channel_id)
     AND NOT u.is_banned
     AND u.id <> NEW.sender_id
     AND app.channel_eligible(NEW.channel_id, u.id);

  IF cardinality(v_clean) > 50 THEN
    v_clean := v_clean[1:50];
  END IF;

  NEW.mentions := v_clean;

  -- A webhook or the system speaks for the server, not for a member.
  IF NEW.mentions_all AND NEW.sender_id IS NOT NULL
     AND NEW.webhook_id IS NULL AND NOT NEW.is_system
     AND (app.channel_permissions_of(NEW.channel_id, NEW.sender_id)
          & (app.perm('ADMINISTRATOR') | app.perm('MENTION_ALL'))) = 0 THEN
    NEW.mentions_all := false;
  END IF;
  RETURN NEW;
END; $$;

-- ── Reactions, pins, deleting others' ───────────────────────

DROP POLICY IF EXISTS message_reactions_insert ON message_reactions;
CREATE POLICY message_reactions_insert ON message_reactions FOR INSERT TO authenticated
  WITH CHECK (
    user_id = auth.uid()
    AND app.can_see_message(message_id)
    AND app.has_channel_perm(app.message_channel(message_id), 'ADD_REACTIONS')
    AND NOT app.timed_out()
  );

CREATE OR REPLACE FUNCTION app.can_pin_in(p_channel UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.can_see_channel(p_channel)
     AND (app.has_channel_perm(p_channel, 'PIN_MESSAGES')
          OR EXISTS (SELECT 1 FROM channels c
                       JOIN channel_members cm ON cm.channel_id = c.id
                      WHERE c.id = p_channel AND c.is_private
                        AND cm.user_id = auth.uid() AND cm.can_manage))
$$;

DROP POLICY IF EXISTS messages_delete ON messages;
CREATE POLICY messages_delete ON messages FOR DELETE TO authenticated
  USING (
    app.can_see_channel(channel_id)
    AND (sender_id = auth.uid()
         OR app.has_channel_perm(channel_id, 'MANAGE_MESSAGES')
         OR app.can_manage_channel(channel_id))
  );

-- ── Attachments ─────────────────────────────────────────────
-- A file is named for the conversation it is sent in (016), so the upload can
-- ask that channel. A server DM, or a name of no conversation, asks the server.

CREATE OR REPLACE FUNCTION app.can_attach(p_name TEXT) RETURNS BOOLEAN
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_scope TEXT := split_part(p_name, '/', 1);
BEGIN
  IF v_scope ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RETURN app.has_channel_perm(v_scope::UUID, 'ATTACH_FILES');
  END IF;
  RETURN app.has_perm('ATTACH_FILES');
END $$;

DROP POLICY IF EXISTS chat_attachments_insert ON storage.objects;
CREATE POLICY chat_attachments_insert ON storage.objects FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'chat-' || app.server_id()::TEXT
    AND app.can_attach(name)
  );

-- ── Summoning a bot ─────────────────────────────────────────
-- As in 003, with the channel asked. Visibility first now: the bit is the
-- channel's, and a channel the caller cannot see has no bits to report.

CREATE OR REPLACE FUNCTION summon_bot_to_voice(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_type TEXT;
BEGIN
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  IF NOT app.has_channel_perm(p_channel, 'SUMMON_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  SELECT channel_type INTO v_type FROM channels WHERE id = p_channel;
  IF v_type IS DISTINCT FROM 'voice' THEN
    RETURN jsonb_build_object('reason', 'not_a_voice_channel');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = app.server_id()) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_voice_summons (channel_id, bot_id, summoned_by)
  VALUES (p_channel, p_bot, auth.uid())
  ON CONFLICT (channel_id, bot_id) DO NOTHING;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- ── What a client draws ─────────────────────────────────────
-- As in 020, plus each channel's `my_permissions`: the caller's bits in that
-- channel, so the composer, the call controls and the menus ask the channel
-- rather than the server.

CREATE OR REPLACE FUNCTION public.get_server_details()
 RETURNS jsonb
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $$
  WITH me AS (
    SELECT u.* FROM users u WHERE u.id = (SELECT auth.uid())
  ),
  srv AS (
    SELECT s.* FROM servers s LIMIT 1
  ),
  managed AS (
    SELECT cm.channel_id FROM channel_members cm
     WHERE cm.user_id = auth.uid() AND cm.can_manage
  ),
  -- Read once; each channel's rows are applied to it below.
  mine AS (
    SELECT my_permissions() AS bits
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
             'livekit_node_id', c.livekit_node_id,
             'voice_node_id',   (SELECT vr.node_id FROM voice_rooms vr
                                  WHERE vr.channel_id = c.id),
             'can_manage',     c.is_private
                                 AND EXISTS (SELECT 1 FROM managed m
                                              WHERE m.channel_id = c.id),
             'my_permissions', app.apply_channel_overrides(
                                 (SELECT bits FROM mine), c.id, (SELECT auth.uid())))
             ORDER BY c.channel_type, c."position", c.name) AS rows
      FROM channels c
  ),
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
          'permission_bits',    (SELECT bits FROM mine)))
        FROM me))
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
                'storage_used', server_storage_used(),
                'max_file_bytes', max_file_bytes(),
                'livekit_nodes', COALESCE((SELECT rows FROM nodes), '[]'::jsonb))
         END)
  END;
$$;

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON channel_overrides FROM PUBLIC, anon, authenticated;
GRANT SELECT ON channel_overrides TO authenticated;

REVOKE ALL ON FUNCTION app.channel_perm_mask(channel_type) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.channel_perm_mask(channel_type) TO authenticated;
REVOKE ALL ON FUNCTION app.apply_channel_overrides(BIGINT, UUID, UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.apply_channel_overrides(BIGINT, UUID, UUID) TO authenticated;
REVOKE ALL ON FUNCTION app.channel_permissions_of(UUID, UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.channel_permissions_of(UUID, UUID) TO authenticated;
REVOKE ALL ON FUNCTION app.has_channel_perm(UUID, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.has_channel_perm(UUID, TEXT) TO authenticated;
REVOKE ALL ON FUNCTION app.can_attach(TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.can_attach(TEXT) TO authenticated;

REVOKE ALL ON FUNCTION user_has_channel_permission(UUID, UUID, TEXT)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION user_has_channel_permission(UUID, UUID, TEXT) TO service_role;

REVOKE ALL ON FUNCTION set_channel_override(UUID, UUID, BIGINT, BIGINT)
  FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION set_channel_override(UUID, UUID, BIGINT, BIGINT)
  TO authenticated;

REVOKE ALL ON FUNCTION get_server_details() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION get_server_details() TO authenticated;
