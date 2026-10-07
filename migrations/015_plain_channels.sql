-- ============================================================
-- Rift self-hosted server — 015: channels that are not encrypted
-- ============================================================
-- A channel of 50,000 pays for its encryption every time somebody is removed:
-- a new key sealed to every member. And a public channel anybody can join
-- protects little by being encrypted, since the people it hides messages from,
-- the server's operator included, can join it and read. So a channel manager
-- can turn encryption off for a public text channel.
--
-- What changes:
--
--   * `channels.is_encrypted`, true unless somebody turned it off, and only
--     ever false on a public text channel: private channels and voice stay
--     encrypted. Closing a channel turns its encryption back on.
--   * `set_channel_encrypted`, the only way to change it, which posts a system
--     message saying who did. A server that flipped it quietly would still be
--     telling every client, which draws the channel as not encrypted.
--   * Members may post messages that are not encrypted (`key_version = 0`) in
--     such a channel. They are still signed, so nobody can post as somebody
--     else; the client checks that as it does for a command.
--   * The key never changes there (`app.key_jobs`), which is what this saves.
--     Members are still sealed its keys, so the encrypted history before the
--     switch stays readable to whoever joins.
--
-- Bots see what they saw before: plaintext rows addressed to them, nothing
-- else (`messages_select`). A channel going unencrypted hands no bot its
-- messages.
-- ============================================================

ALTER TABLE channels ADD COLUMN IF NOT EXISTS is_encrypted BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN channels.is_encrypted IS
  'False when a channel manager turned encryption off (set_channel_encrypted): '
  'members then post messages the server can read, and the key never rotates. '
  'Only ever false on a public text channel.';

ALTER TABLE channels DROP CONSTRAINT IF EXISTS channels_plain_is_public_text;
ALTER TABLE channels ADD CONSTRAINT channels_plain_is_public_text
  CHECK (is_encrypted OR (NOT is_private AND channel_type = 'text'));

-- ── Asking ──────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION app.channel_encrypted(p_channel UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE((SELECT c.is_encrypted FROM channels c WHERE c.id = p_channel), true)
$$;

-- ── Changing it ─────────────────────────────────────────────

CREATE OR REPLACE FUNCTION set_channel_encrypted(p_channel UUID, p_on BOOLEAN)
  RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_channel channels%ROWTYPE;
  v_by      TEXT;
BEGIN
  IF NOT app.can_manage_channel(p_channel) THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  SELECT * INTO v_channel FROM channels WHERE id = p_channel;
  IF NOT FOUND THEN RAISE EXCEPTION 'channel_not_found'; END IF;
  IF v_channel.is_encrypted = p_on THEN
    RETURN jsonb_build_object('reason', 'ok');
  END IF;
  IF NOT p_on AND (v_channel.is_private OR v_channel.channel_type <> 'text') THEN
    RETURN jsonb_build_object('reason', 'not_public_text');
  END IF;

  UPDATE channels SET is_encrypted = p_on WHERE id = p_channel;

  SELECT display_name INTO v_by FROM users WHERE id = auth.uid();
  PERFORM app.post_system_message(
    p_channel,
    COALESCE(v_by, 'A channel manager') || CASE WHEN p_on
      THEN ' turned encryption back on. New messages here are end-to-end '
           || 'encrypted again.'
      ELSE ' turned encryption off. The server can read new messages here.'
    END
  );
  RETURN jsonb_build_object('reason', 'ok');
END $$;

COMMENT ON FUNCTION set_channel_encrypted(UUID, BOOLEAN) IS
  'Turn a public text channel''s encryption off or back on, for whoever may '
  'manage it, and say so in the channel. not_public_text when it cannot be '
  'turned off there.';

-- A channel closed while unencrypted is encrypted again: a private channel is
-- a list of people, and its key is what keeps it one.
CREATE OR REPLACE FUNCTION app.encrypt_closed_channel() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NEW.is_private AND NOT NEW.is_encrypted THEN
    NEW.is_encrypted := true;
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS channels_encrypt_closed ON channels;
CREATE TRIGGER channels_encrypt_closed BEFORE UPDATE OF is_private ON channels
  FOR EACH ROW EXECUTE FUNCTION app.encrypt_closed_channel();

-- ── Members may post in the clear there ─────────────────────
-- As in 008, plus the last clause of the key_version test.

DROP POLICY IF EXISTS messages_insert ON messages;
CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    app.can_see_channel(channel_id)
    AND app.has_perm('SEND_MESSAGES')
    AND NOT app.timed_out()
    AND sender_id = auth.uid()
    AND webhook_id IS NULL AND origin_name IS NULL AND NOT is_system
    AND (key_version >= 1 OR to_bot IS NOT NULL OR app.is_bot()
         OR NOT app.channel_encrypted(channel_id))
    AND (to_bot IS NULL OR app.is_addressable_bot(to_bot))
    AND (to_bot IS NULL OR key_version = 0)
    AND (NOT app.is_bot() OR key_version = 0)
    AND (ephemeral_for IS NULL OR app.is_bot())
    -- Only a bot draws a panel. A member posting blocks would be a member
    -- posting an interface, which is the thing the block set exists to prevent.
    AND (blocks IS NULL OR app.is_bot())
    -- ...and only a person presses one. A bot pressing its own button is a
    -- loop, and nothing in the design needs it.
    AND (NOT is_interaction OR NOT app.is_bot())
    -- A poll is a member asking the channel. A bot has panels for asking, and
    -- a poll addressed to one bot is a question only it could see answered.
    -- Its own bit, on `@everyone` by default, so a server can keep polls to
    -- the roles it picks without taking anybody's voice away.
    AND (poll IS NULL OR (NOT app.is_bot() AND to_bot IS NULL
                          AND app.has_perm('CREATE_POLLS')))
  );

-- ── The key stays put ───────────────────────────────────────
-- As in 014, plus the unencrypted test.

CREATE OR REPLACE FUNCTION app.key_jobs(
  p_channel UUID, p_user UUID, p_mark INTEGER, p_budget INTEGER,
  OUT jobs JSONB, OUT more BOOLEAN, OUT rotate_at TIMESTAMPTZ
)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current  INTEGER;
  v_mine     RECORD;
  v_left     INTEGER := p_budget;
  v_missing  JSONB;
  v_n        INTEGER;
  v_removed  BOOLEAN;
  v_ahead    BOOLEAN;
  v_opened   BOOLEAN;
  v_minted   TIMESTAMPTZ;
  v_version  INTEGER;
BEGIN
  jobs := '[]'::jsonb;
  more := false;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  IF v_current = 0 THEN
    v_missing := app.key_missing(p_channel, 1, p_user, v_left);
    IF jsonb_array_length(v_missing) > 0 THEN
      jobs := jsonb_build_array(jsonb_build_object(
        'channel_id', p_channel, 'key_version', 0, 'rotate', false,
        'my_key', NULL, 'members_missing', v_missing));
      more := jsonb_array_length(v_missing) >= v_left;
    END IF;
    RETURN;
  END IF;

  SELECT ephemeral_public_key, ciphertext, nonce INTO v_mine
    FROM channel_keyring
   WHERE channel_id = p_channel AND key_version = v_current AND user_id = p_user;

  IF FOUND THEN
    v_removed := EXISTS (
      SELECT 1 FROM channel_keyring k
       WHERE k.channel_id = p_channel AND k.key_version = v_current
         AND NOT EXISTS (SELECT 1 FROM channel_eligible_members e
                          WHERE e.channel_id = p_channel
                            AND e.user_id = k.user_id
                            AND e.from_key_version <= v_current));
    v_ahead := EXISTS (SELECT 1 FROM channel_eligible_members e
                        WHERE e.channel_id = p_channel
                          AND e.from_key_version = v_current + 1);
    v_opened := p_mark IS NOT NULL AND v_current <= p_mark;

    -- An unencrypted channel writes nothing under its key, so there is
    -- nothing for a change to protect: it never rotates. Healing and history
    -- go on, so the encrypted messages from before stay readable to whoever
    -- joins. Turning encryption back on brings any removal's change due at
    -- once, since the key it waited on is as old as the switch.
    IF NOT (SELECT c.is_encrypted FROM channels c WHERE c.id = p_channel) THEN
      v_removed := false;
      v_ahead := false;
      v_opened := false;
    END IF;

    -- A removal alone waits until the current key is old enough; with an
    -- addition beside it, the change the addition needs carries it too.
    IF v_removed AND NOT (v_ahead OR v_opened) THEN
      SELECT min(created_at) INTO v_minted
        FROM channel_keyring
       WHERE channel_id = p_channel AND key_version = v_current;
      IF v_minted > now() - app.key_rotation_spacing() THEN
        rotate_at := v_minted + app.key_rotation_spacing();
        v_removed := false;
      END IF;
    END IF;

    IF v_removed OR v_ahead OR v_opened THEN
      v_missing := app.key_missing(p_channel, v_current + 1, p_user, v_left);
      jobs := jobs || jsonb_build_object(
        'channel_id', p_channel, 'key_version', v_current, 'rotate', true,
        'link', NOT (v_ahead OR v_opened),
        'my_key', jsonb_build_object(
          'ephemeral_public_key', v_mine.ephemeral_public_key,
          'ciphertext', v_mine.ciphertext, 'nonce', v_mine.nonce),
        'members_missing', v_missing);
      more := true;
      RETURN;
    END IF;

    v_missing := app.key_missing(p_channel, v_current, p_user, v_left);
    v_n := jsonb_array_length(v_missing);
    IF v_n > 0 THEN
      jobs := jobs || jsonb_build_object(
        'channel_id', p_channel, 'key_version', v_current, 'rotate', false,
        'my_key', jsonb_build_object(
          'ephemeral_public_key', v_mine.ephemeral_public_key,
          'ciphertext', v_mine.ciphertext, 'nonce', v_mine.nonce),
        'members_missing', v_missing);
      v_left := v_left - v_n;
      IF v_left <= 0 THEN more := true; RETURN; END IF;
    END IF;
  END IF;

  FOR v_version IN
    SELECT * FROM app.key_history_versions(p_channel, p_user, v_current, p_mark)
  LOOP
    v_missing := app.key_missing(p_channel, v_version, p_user, v_left);
    v_n := jsonb_array_length(v_missing);
    CONTINUE WHEN v_n = 0;
    SELECT ephemeral_public_key, ciphertext, nonce INTO v_mine
      FROM channel_keyring
     WHERE channel_id = p_channel AND key_version = v_version AND user_id = p_user;
    jobs := jobs || jsonb_build_object(
      'channel_id', p_channel, 'key_version', v_version, 'rotate', false,
      'my_key', jsonb_build_object(
        'ephemeral_public_key', v_mine.ephemeral_public_key,
        'ciphertext', v_mine.ciphertext, 'nonce', v_mine.nonce),
      'members_missing', v_missing);
    v_left := v_left - v_n;
    IF v_left <= 0 THEN more := true; RETURN; END IF;
  END LOOP;
END $$;

-- ── Clients are told ────────────────────────────────────────
-- As in 011, plus `is_encrypted` on each channel.

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

REVOKE ALL ON FUNCTION app.channel_encrypted(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.channel_encrypted(UUID) TO authenticated;
REVOKE ALL ON FUNCTION set_channel_encrypted(UUID, BOOLEAN) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION set_channel_encrypted(UUID, BOOLEAN) TO authenticated;
REVOKE ALL ON FUNCTION app.encrypt_closed_channel() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_jobs(UUID, UUID, INTEGER, INTEGER)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION get_server_details() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION get_server_details() TO authenticated;
