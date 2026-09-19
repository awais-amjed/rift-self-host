-- ============================================================
-- Rift self-hosted server — 029: how many people, and how much disk
-- ============================================================
-- 028 gave a server a say in what a *call* costs it. This is the other two
-- an operator asked for: how many members the place holds, and how much of
-- the disk their attachments may take.
--
-- Same shape as everything in 002 and 028 — a column, 0 means off, and a
-- server that upgrades and is never touched behaves exactly as it did.
--
-- Unlike the share bitrate in 028, **both of these are real walls**. There
-- is one way to become a member (`register_user`) and one way for bytes to
-- arrive (an INSERT into `storage.objects`), and both are in the database
-- where the count is. Nothing has to be taken on trust from a client.
--
-- ---------- the disk, without counting it every time ----------
--
-- The obvious way to enforce a storage cap is to SUM the bucket on each
-- upload. That is a scan of every object the server has ever kept, per
-- upload, and it gets slower exactly as the thing it is protecting fills
-- up — the shape of problem migrations 024-026 spent their whole length
-- removing from this schema.
--
-- So the total is *kept* rather than computed: one row per bucket, moved by
-- the same statement that adds or removes the object. The check then reads
-- one row by primary key whatever the server holds.
--
-- It cannot drift, because every path that changes `storage.objects`
-- changes it through a row trigger on that table — the REST API, the
-- attachment sweep, a moderator deleting a message, a service-role script.
-- There is no fourth way in.
--
-- `metadata->>'size'` is there at INSERT: Storage writes the row once, with
-- the size already in it, and does not come back to fill it in. Checked
-- against the running stack rather than assumed, because the whole design
-- rests on it.
-- ============================================================

-- ============================================================
-- 1. The two columns
-- ============================================================

ALTER TABLE servers
  ADD COLUMN IF NOT EXISTS max_members       INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS max_storage_bytes BIGINT  NOT NULL DEFAULT 0;

ALTER TABLE servers DROP CONSTRAINT IF EXISTS servers_size_limits_sane;
ALTER TABLE servers
  ADD CONSTRAINT servers_size_limits_sane
  CHECK (max_members >= 0 AND max_storage_bytes >= 0);

COMMENT ON COLUMN servers.max_members IS
  'How many members the server holds; 0 is no limit. Counts bots, which are '
  'members, and not banned members, who are not. Enforced by register_user.';

COMMENT ON COLUMN servers.max_storage_bytes IS
  'How many bytes of attachments the server keeps; 0 is no limit. Enforced '
  'by a trigger on storage.objects against a running total, never a SUM.';

-- ============================================================
-- 2. What each bucket is holding
-- ============================================================

CREATE TABLE IF NOT EXISTS app.bucket_usage (
  bucket_id TEXT PRIMARY KEY,
  bytes     BIGINT NOT NULL DEFAULT 0 CHECK (bytes >= 0)
);

-- Internal bookkeeping. Nothing outside the triggers and `server_storage_used`
-- has any business reading it, and a new table arrives more permissive than
-- that unless it is said.
REVOKE ALL ON app.bucket_usage FROM PUBLIC, anon, authenticated;

COMMENT ON TABLE app.bucket_usage IS
  'Bytes held per chat bucket, kept current by a trigger on storage.objects '
  'so a storage cap costs one indexed read instead of a SUM of the bucket.';

CREATE OR REPLACE FUNCTION app.track_bucket_usage() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_old BIGINT := 0;
  v_new BIGINT := 0;
BEGIN
  -- The two sides are handled separately rather than as a delta, because an
  -- UPDATE can move an object between buckets as well as change its size.
  IF TG_OP IN ('UPDATE', 'DELETE') AND OLD.bucket_id LIKE 'chat-%' THEN
    v_old := COALESCE((OLD.metadata->>'size')::BIGINT, 0);
    UPDATE app.bucket_usage
       SET bytes = GREATEST(bytes - v_old, 0)
     WHERE bucket_id = OLD.bucket_id;
  END IF;

  IF TG_OP IN ('UPDATE', 'INSERT') AND NEW.bucket_id LIKE 'chat-%' THEN
    v_new := COALESCE((NEW.metadata->>'size')::BIGINT, 0);
    INSERT INTO app.bucket_usage (bucket_id, bytes)
    VALUES (NEW.bucket_id, v_new)
    ON CONFLICT (bucket_id)
      DO UPDATE SET bytes = app.bucket_usage.bytes + v_new;
  END IF;

  RETURN NULL;  -- AFTER trigger
END $$;

-- `rift_` prefixed: Storage keeps its own triggers on this table and runs its
-- own migrations over it.
DROP TRIGGER IF EXISTS rift_track_bucket_usage ON storage.objects;
CREATE TRIGGER rift_track_bucket_usage
  AFTER INSERT OR UPDATE OR DELETE ON storage.objects
  FOR EACH ROW EXECUTE FUNCTION app.track_bucket_usage();

-- Whatever is already there. Re-runnable: the migration may be applied to a
-- server that has been collecting attachments for a year.
INSERT INTO app.bucket_usage (bucket_id, bytes)
SELECT o.bucket_id, COALESCE(SUM((o.metadata->>'size')::BIGINT), 0)
  FROM storage.objects o
 WHERE o.bucket_id LIKE 'chat-%'
 GROUP BY o.bucket_id
ON CONFLICT (bucket_id) DO UPDATE SET bytes = EXCLUDED.bytes;

-- ============================================================
-- 3. Refusing the upload that would go over
-- ============================================================

CREATE OR REPLACE FUNCTION app.enforce_storage_cap() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
  v_cap    BIGINT;
  v_used   BIGINT;
  v_size   BIGINT;
BEGIN
  -- Buckets are named `chat-<server id>`; anything else is not a server's
  -- attachments and is not this limit's business.
  IF NEW.bucket_id !~ '^chat-[0-9a-f-]{36}$' THEN
    RETURN NEW;
  END IF;
  v_server := substr(NEW.bucket_id, 6)::UUID;

  SELECT s.max_storage_bytes INTO v_cap FROM servers s WHERE s.id = v_server;
  IF COALESCE(v_cap, 0) = 0 THEN
    RETURN NEW;
  END IF;

  v_size := COALESCE((NEW.metadata->>'size')::BIGINT, 0);
  SELECT COALESCE(u.bytes, 0) INTO v_used
    FROM app.bucket_usage u WHERE u.bucket_id = NEW.bucket_id;

  IF COALESCE(v_used, 0) + v_size > v_cap THEN
    -- A named condition rather than a bare string: Storage passes the
    -- message through to the client, and the uploader deserves a sentence
    -- rather than a constraint name.
    RAISE EXCEPTION
      'This server has no room left for attachments (% of % bytes used)',
      v_used, v_cap
      USING ERRCODE = 'disk_full';
  END IF;

  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS rift_enforce_storage_cap ON storage.objects;
CREATE TRIGGER rift_enforce_storage_cap
  BEFORE INSERT ON storage.objects
  FOR EACH ROW EXECUTE FUNCTION app.enforce_storage_cap();

-- ============================================================
-- 4. Telling anyone how full it is
-- ============================================================
-- Not a secret, and useful before it matters: a composer can say the server
-- is nearly full before somebody picks a file, which is kinder than
-- refusing them after they have.

CREATE OR REPLACE FUNCTION server_storage_used() RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(
    (SELECT u.bytes FROM app.bucket_usage u
      WHERE u.bucket_id = 'chat-' || app.server_id()::TEXT), 0)
$$;

REVOKE ALL ON FUNCTION server_storage_used() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION server_storage_used() TO authenticated;

COMMENT ON FUNCTION server_storage_used() IS
  'Bytes of attachments the caller''s server is holding. 0 for a banned '
  'member, who has no server.';

-- ============================================================
-- 5. Refusing the member who would go over
-- ============================================================

CREATE OR REPLACE FUNCTION public.register_user(p_invite_code text, p_user_id uuid, p_public_key text, p_stable_id text, p_username text, p_display_name text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SET search_path TO 'public'
AS $$
DECLARE
  v_invite  invites%ROWTYPE;
  v_max     INTEGER;
  v_members INTEGER;
BEGIN
  SELECT * INTO v_invite FROM invites WHERE code = p_invite_code FOR UPDATE;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('reason', 'not_found');
  END IF;
  IF v_invite.expires_at IS NOT NULL AND v_invite.expires_at <= now() THEN
    DELETE FROM invites WHERE id = v_invite.id;
    RETURN jsonb_build_object('reason', 'expired');
  END IF;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses >= v_invite.max_uses THEN
    RETURN jsonb_build_object('reason', 'exhausted');
  END IF;

  IF EXISTS (SELECT 1 FROM users WHERE id = p_user_id) THEN
    RETURN jsonb_build_object('reason', 'already_registered');
  END IF;
  IF EXISTS (SELECT 1 FROM users
              WHERE server_id = v_invite.server_id
                AND (public_key = p_public_key OR stable_id = p_stable_id)) THEN
    RETURN jsonb_build_object('reason', 'identity_taken');
  END IF;
  IF EXISTS (SELECT 1 FROM users
              WHERE server_id = v_invite.server_id AND username = p_username) THEN
    RETURN jsonb_build_object('reason', 'username_taken');
  END IF;

  -- The operator's ceiling on members (migration 029).
  --
  -- Last of the refusals on purpose: "this server is full" is a fact about
  -- the server, and the checks above are facts about the caller. Somebody
  -- with a spent invite or a taken username should hear about that rather
  -- than about the size of a place they were not getting into anyway.
  --
  -- The server row is locked, not merely read. The invite above is already
  -- locked, which serialises everyone arriving through the *same* link — but
  -- a server has more than one link, and two of them racing is exactly how a
  -- cap of fifty admits fifty-two. This is a rare enough operation to make
  -- exact, which is the difference between it and the call cap in 028, where
  -- the count lives on the other side of an HTTP boundary and cannot be.
  --
  -- Banned members do not hold a seat. An operator who bans somebody has
  -- decided they are not part of the server, and a ban that still cost a
  -- place would be a strange kind of removal. Bots do hold one: a bot is in
  -- the member list, takes a row, and reads what everyone else reads.
  SELECT s.max_members INTO v_max
    FROM servers s WHERE s.id = v_invite.server_id FOR UPDATE;
  IF COALESCE(v_max, 0) > 0 THEN
    SELECT count(*) INTO v_members
      FROM users u
     WHERE u.server_id = v_invite.server_id AND NOT u.is_banned;
    IF v_members >= v_max THEN
      RETURN jsonb_build_object('reason', 'server_full');
    END IF;
  END IF;

  INSERT INTO users (
    id, server_id, username, display_name, public_key, stable_id, is_bot
  ) VALUES (
    p_user_id, v_invite.server_id, p_username, p_display_name,
    p_public_key, p_stable_id, v_invite.is_bot
  );

  -- The role the invite names, if any. Nothing else: the baseline is not
  -- assigned, and there is no default role any more (016).
  INSERT INTO member_roles (user_id, role_id)
  SELECT p_user_id, r.id
    FROM roles r
   WHERE r.server_id = v_invite.server_id
     AND r.id = v_invite.role_id
     AND NOT r.is_everyone
     AND NOT r.is_owner
  ON CONFLICT DO NOTHING;

  -- The first person in owns the place (013).
  IF NOT v_invite.is_bot AND NOT EXISTS (
       SELECT 1 FROM member_roles mr
         JOIN roles r ON r.id = mr.role_id
        WHERE r.server_id = v_invite.server_id AND r.is_owner) THEN
    INSERT INTO member_roles (user_id, role_id)
    SELECT p_user_id, r.id FROM roles r
     WHERE r.server_id = v_invite.server_id AND r.is_owner;
  END IF;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT p_user_id, 'channel', c.id,
         COALESCE((SELECT max(m.id) FROM messages m WHERE m.channel_id = c.id), 0)
    FROM channels c
   WHERE c.server_id = v_invite.server_id;

  UPDATE invites SET uses = uses + 1 WHERE id = v_invite.id;
  IF v_invite.max_uses IS NOT NULL AND v_invite.uses + 1 >= v_invite.max_uses THEN
    DELETE FROM invites WHERE id = v_invite.id;
  END IF;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'server_id', v_invite.server_id,
    'is_bot', v_invite.is_bot
  );
END; $$
;

-- ============================================================
-- 6. Telling the client, in the call it already makes
-- ============================================================
-- `get_server_details` is the one question a client asks when it opens a
-- server (022), and it has to carry the new columns or they do not exist as
-- far as the app is concerned.
--
-- It also carries 028's two, which were added to `update_server` and not to
-- here. The effect was quiet and would have been annoying to find: an
-- operator sets a share limit, the settings dialog shows it because
-- `update_server` replies with it, and then the next launch reads this
-- function instead and the limit is gone. Fixed here rather than in a
-- migration of its own, since this is the function 029 has to touch anyway.

CREATE OR REPLACE FUNCTION public.get_server_details()
 RETURNS jsonb
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $$
  WITH me AS (
    SELECT u.* FROM users u WHERE u.id = auth.uid()
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
             'can_manage',     c.is_private
                                 AND EXISTS (SELECT 1 FROM managed m
                                              WHERE m.channel_id = c.id))
             ORDER BY c.name) AS rows
      FROM channels c
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
        'is_bot',          me.is_bot,
        'manifest',        me.manifest,
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
                -- 028's two, which this function was never taught. Without
                -- them the bitrate picker reads "no cap" on every refresh and
                -- an operator's setting appears to have been forgotten — it
                -- was only ever coming back in `update_server`'s own reply.
                'max_voice_participants',
                  (SELECT srv.max_voice_participants FROM srv),
                'max_share_mbps',
                  (SELECT srv.max_share_mbps         FROM srv),
                -- and 029's.
                'max_members',
                  (SELECT srv.max_members            FROM srv),
                'max_storage_bytes',
                  (SELECT srv.max_storage_bytes      FROM srv),
                -- Not a limit but the thing limits are judged against, and
                -- free here: one indexed read, in the call the client already
                -- makes. It is what lets the composer say a file will not fit
                -- before somebody picks it, rather than after.
                'storage_used', server_storage_used())
         END)
  END;
$$;
