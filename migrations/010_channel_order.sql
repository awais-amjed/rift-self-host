-- ============================================================
-- Rift self-hosted server — 010: channels keep the order they are put in
-- ============================================================
-- The sidebar listed each section's channels by name, because nothing else
-- was stored: a server could not put #rules above #general, or its busiest
-- voice room first. This adds that order, and the one way to change it.
--
-- `channels.position` is the place within the channel's own section (text or
-- voice); ties, which the backfill never makes but two channels created at
-- once can, fall back to the name. Existing channels are numbered by name, so
-- every sidebar looks the same until somebody moves something. A new channel
-- goes at the end of its section, as it does in every other chat app.
--
-- Only `reorder_channels` writes it — the column is not granted — because a
-- manager cannot see the private channels they are not in, and an order
-- written row by row from what they *can* see would collide with those. The
-- function moves only the channels it is given, among the places those
-- channels already hold, so everything the caller could not see stays put.
--
-- Moving one channel renumbers several, and `channels_announce` rang the
-- server's topic once per row it touched: every member would re-read the
-- server for each. An update that changes only the position is now quiet, and
-- `reorder_channels` rings once for the lot.
-- ============================================================

-- ── The quiet update, before anything below renumbers ───────

CREATE OR REPLACE FUNCTION app.announce_channels() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  -- A reorder rings once, from `reorder_channels`, not once per row.
  IF TG_OP = 'UPDATE'
     AND to_jsonb(NEW) - 'position' = to_jsonb(OLD) - 'position' THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_server := OLD.server_id;
  ELSE
    v_server := NEW.server_id;
  END IF;
  PERFORM realtime.send('{}'::jsonb, 'channels', 'server:' || v_server, true);
  RETURN NULL;
END $$;

-- ── The column ──────────────────────────────────────────────

ALTER TABLE channels
  ADD COLUMN IF NOT EXISTS "position" INTEGER NOT NULL DEFAULT 0
    CHECK ("position" >= 0);

COMMENT ON COLUMN channels."position" IS
  'Place within the channel''s section (its channel_type), from 0; ties sort '
  'by name. Written only by reorder_channels and, for a new channel, by '
  'place_new_channel.';

-- Today's order, which was the name's.
UPDATE channels c
   SET "position" = n.slot
  FROM (SELECT id,
               row_number() OVER (PARTITION BY server_id, channel_type
                                  ORDER BY name, id) - 1 AS slot
          FROM channels) n
 WHERE c.id = n.id;

CREATE INDEX IF NOT EXISTS channels_order
  ON channels (server_id, channel_type, "position");

-- ── A new channel goes last in its section ──────────────────
-- SECURITY DEFINER: the end of the section includes the private channels the
-- creator cannot see, or a new one would land among them.

CREATE OR REPLACE FUNCTION app.place_new_channel() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  NEW."position" := COALESCE((SELECT max(c."position") + 1 FROM channels c
                               WHERE c.server_id = NEW.server_id
                                 AND c.channel_type = NEW.channel_type), 0);
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS channels_place_new ON channels;
CREATE TRIGGER channels_place_new
  BEFORE INSERT ON channels
  FOR EACH ROW EXECUTE FUNCTION app.place_new_channel();

-- ── Moving them ─────────────────────────────────────────────
-- `p_channels` is channels in the order wanted, normally one whole section as
-- the caller sees it. They are dealt back into the places they held between
-- them, per section, and every other channel keeps its own, so a private
-- channel the caller cannot see neither moves nor gets in the way. Positions
-- come out numbered 0, 1, 2… per section whatever they were before.

CREATE OR REPLACE FUNCTION reorder_channels(p_channels UUID[]) RETURNS VOID
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
  v_count  INTEGER := COALESCE(cardinality(p_channels), 0);
BEGIN
  IF v_server IS NULL THEN
    RAISE EXCEPTION 'not_a_member';
  END IF;
  IF NOT app.has_perm('MANAGE_CHANNELS') THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF v_count = 0 THEN
    RETURN;
  END IF;
  IF (SELECT count(DISTINCT x) FROM unnest(p_channels) x) <> v_count THEN
    RAISE EXCEPTION 'duplicate_channel';
  END IF;
  -- Every one of them this server's and visible to the caller: SECURITY
  -- DEFINER means the policy that would have hidden the rest is not asked.
  IF (SELECT count(*) FROM channels c
       WHERE c.id = ANY (p_channels)
         AND c.server_id = v_server
         AND c.id = ANY (app.visible_channels())) <> v_count THEN
    RAISE EXCEPTION 'channel_not_found';
  END IF;

  WITH ranked AS (
    SELECT c.id, c.channel_type,
           row_number() OVER (PARTITION BY c.channel_type
                              ORDER BY c."position", c.name, c.id) - 1 AS slot,
           c.id = ANY (p_channels) AS moving
      FROM channels c
     WHERE c.server_id = v_server
  ),
  -- The places the moving channels hold, in order…
  freed AS (
    SELECT r.channel_type, r.slot,
           row_number() OVER (PARTITION BY r.channel_type ORDER BY r.slot) AS k
      FROM ranked r
     WHERE r.moving
  ),
  -- …and the moving channels in the order asked.
  wanted AS (
    SELECT r.id, r.channel_type,
           row_number() OVER (PARTITION BY r.channel_type ORDER BY t.ord) AS k
      FROM unnest(p_channels) WITH ORDINALITY AS t(id, ord)
      JOIN ranked r ON r.id = t.id
  ),
  placed AS (
    SELECT r.id, r.slot FROM ranked r WHERE NOT r.moving
    UNION ALL
    SELECT w.id, f.slot FROM wanted w JOIN freed f USING (channel_type, k)
  )
  UPDATE channels c
     SET "position" = p.slot
    FROM placed p
   WHERE c.id = p.id
     AND c."position" IS DISTINCT FROM p.slot;

  IF app.realtime_ready() THEN
    PERFORM realtime.send('{}'::jsonb, 'channels', 'server:' || v_server, true);
  END IF;
END $$;

COMMENT ON FUNCTION reorder_channels(UUID[]) IS
  'Put channels in the order given, within the places they already hold in '
  'their sections. MANAGE_CHANNELS; every channel must be this server''s and '
  'visible to the caller. Rings `channels` once.';

-- ── get_server_details lists by that order ──────────────────
-- Unchanged from 003 apart from the channel list's ORDER BY.

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
                'livekit_nodes', COALESCE((SELECT rows FROM nodes), '[]'::jsonb))
         END)
  END;
$$;

COMMENT ON FUNCTION get_server_details() IS
  'Everything a client needs to draw a server: its identity and limits, the '
  'channels the caller may see, and the caller''s own row with their '
  'permissions. Null when the caller has no row here. Answers the five reads '
  'that used to run one after another.';

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION app.place_new_channel() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION reorder_channels(UUID[]) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION reorder_channels(UUID[]) TO authenticated;
