-- ============================================================
-- Rift self-hosted server — 043: the keyring is written only through its function
-- ============================================================
-- Found in the review of the edge functions, Nov 25 2026.
--
-- Members held INSERT on `channel_keyring`, behind `channel_keyring_insert`,
-- which asks only that the writer is in the channel and the key is for
-- somebody who is. Every rule about *versions* lived in `post_channel_keys`:
-- a new version is exactly one past the current, the first batch to land wins
-- it, a heal only fills gaps. A member writing over PostgREST skipped all of
-- it, so they could:
--
--   * insert version 2147483647, after which no rotation can ever be minted
--     (the next one would overflow), so a banned member keeps every key from
--     then on;
--   * seal garbage to a new member before an honest client healed them, and
--     since an entry is never replaced, that member never opens that version.
--
-- No client writes the keyring directly: the app and both bot SDKs only read
-- it, and every write goes through `post_channel_keys`. So the grant goes, and
-- with it the policy that only guarded it. The function now also asks that
-- whoever heals a version holds it, and that whoever mints one held the
-- version before.

REVOKE INSERT ON channel_keyring FROM authenticated;
DROP POLICY IF EXISTS channel_keyring_insert ON channel_keyring;

-- ── A call's region is let go only once it has ended ───────
-- `voice_roster` forgets where a call was when it sees no room for it. It
-- read a node that did not answer, a room whose people did not answer, and a
-- room opened a moment ago all as ended, and a forgotten call is decided
-- again by the next person in: on a server with several regions, a second
-- room on another node, and the call split in two. The function now lets a
-- call go only when the node it was claimed on answered without it; this
-- keeps any row claimed in the last half minute too, which is the time
-- between claiming a region and its room existing.
-- `release_voice_node` stays as it was for `get_channel_token`, which lets go
-- of a claim it just made on a region that did not answer.

CREATE OR REPLACE FUNCTION release_idle_voice_node(p_channels UUID[])
  RETURNS VOID
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  DELETE FROM voice_rooms
   WHERE channel_id = ANY (COALESCE(p_channels, ARRAY[]::UUID[]))
     AND opened_at < now() - interval '30 seconds';
$$;

COMMENT ON FUNCTION release_idle_voice_node(UUID[]) IS
  'For voice_roster: these calls have no room on any node, so the next one on '
  'each channel is decided afresh. Keeps a row claimed in the last 30 seconds.';

REVOKE ALL ON FUNCTION release_idle_voice_node(UUID[]) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION release_idle_voice_node(UUID[]) TO service_role;

-- ── A DM call is moved home only before it is answered ─────
-- `get_dm_call_token` falls back to the default node when the call's region
-- does not answer, on the reasoning that only the caller, first in, can be
-- asked. But a caller rejoining a call already under way, or a callee whose
-- one attempt to open the room failed, asked too, and moved the call's
-- `node_id` out from under the other person: two rooms, each with half the
-- call. Moving is now only for a call nobody has answered yet.

CREATE OR REPLACE FUNCTION claim_dm_call_room(
  p_call UUID, p_user UUID, p_preferred UUID DEFAULT NULL,
  p_move_to_default BOOLEAN DEFAULT false
) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_call   dm_calls%ROWTYPE;
  v_server UUID;
  v_node   livekit_nodes%ROWTYPE;
BEGIN
  SELECT * INTO v_call FROM dm_calls c WHERE c.id = p_call FOR UPDATE;
  IF NOT FOUND OR v_call.ended_at IS NOT NULL
     OR NOT (p_user = v_call.caller_id
             OR (p_user = v_call.callee_id AND v_call.answered_at IS NOT NULL)) THEN
    RETURN jsonb_build_object('allowed', false);
  END IF;

  SELECT u.server_id INTO v_server FROM users u
   WHERE u.id = p_user AND NOT u.is_banned;
  IF v_server IS NULL THEN RETURN jsonb_build_object('allowed', false); END IF;

  -- Answered, the call stays where it is: somebody may be in it there.
  IF p_move_to_default AND v_call.answered_at IS NOT NULL THEN
    p_move_to_default := false;
  END IF;

  IF NOT p_move_to_default THEN
    SELECT * INTO v_node FROM livekit_nodes n
     WHERE n.id = COALESCE(v_call.node_id, p_preferred) AND n.server_id = v_server;
  END IF;
  IF v_node.id IS NULL THEN
    SELECT * INTO v_node FROM livekit_nodes n
     WHERE n.server_id = v_server AND n.is_default;
  END IF;

  UPDATE dm_calls c SET node_id = v_node.id WHERE c.id = p_call;

  RETURN jsonb_build_object(
    'allowed', true,
    'node', CASE WHEN v_node.id IS NULL THEN NULL ELSE jsonb_build_object(
              'id', v_node.id, 'url', v_node.url, 'label', v_node.label,
              'is_default', v_node.is_default) END);
END; $$;

-- ── The attachment sweep runs at most once a minute ────────
-- Every member's app calls `sweep_attachments` as it opens a server, and the
-- function runs the retention pass for the whole database on each call, so a
-- member who called it in a loop kept the database busy for everybody. A
-- minute apart costs nothing honest: the backlog a run leaves is picked up by
-- the next member to open a server.

CREATE TABLE IF NOT EXISTS app.attachment_sweep_runs (
  id     BOOLEAN     PRIMARY KEY DEFAULT true CHECK (id),
  last_at TIMESTAMPTZ NOT NULL
);

COMMENT ON TABLE app.attachment_sweep_runs IS
  'One row: when the attachment sweep last ran. claim_attachment_sweep spaces runs a minute apart.';

REVOKE ALL ON app.attachment_sweep_runs FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION claim_attachment_sweep()
  RETURNS BOOLEAN
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO app.attachment_sweep_runs (id, last_at) VALUES (true, now())
  ON CONFLICT (id) DO UPDATE SET last_at = now()
   WHERE app.attachment_sweep_runs.last_at < now() - interval '1 minute';
  RETURN FOUND;
END; $$;

COMMENT ON FUNCTION claim_attachment_sweep() IS
  'For the sweep_attachments edge function: true, and the run is recorded, '
  'when the last run was over a minute ago.';

REVOKE ALL ON FUNCTION claim_attachment_sweep() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION claim_attachment_sweep() TO service_role;

-- ── Two managers removing each other ───────────────────────
-- `change_channel_members` asked whether the caller runs the channel, then
-- changed the seats. Two managers removing each other at the same moment both
-- passed the question before either removal landed, so both went, and a room
-- of the two of them closed itself (`reassign_or_close_channel`). The
-- channel's row is now locked first, so the second waits for the first and
-- is then asked again, about the seats as they now are.

CREATE OR REPLACE FUNCTION change_channel_members(
  p_channel UUID,
  p_add     UUID[],
  p_remove  UUID[]
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- Before the question, so it is asked of what the last change left.
  PERFORM 1 FROM channels WHERE id = p_channel FOR UPDATE;
  IF NOT app.can_manage_channel(p_channel) THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM channels WHERE id = p_channel
                   AND server_id = app.server_id() AND is_private) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  -- Added first, so a list that removes everybody else and adds somebody new
  -- never passes through empty: the last seat going deletes the channel
  -- (`reassign_or_close_channel`).
  INSERT INTO channel_members (channel_id, user_id, added_by)
  SELECT p_channel, u.id, auth.uid()
    FROM users u
   WHERE u.id = ANY (COALESCE(p_add, '{}'))
     AND u.server_id = app.server_id()
     AND NOT u.is_banned
     -- A bot is keyed by `grant_bot_channel_key` and nothing else.
     AND NOT u.is_bot
  ON CONFLICT (channel_id, user_id) DO NOTHING;

  DELETE FROM channel_members
   WHERE channel_id = p_channel
     AND user_id = ANY (COALESCE(p_remove, '{}'))
     AND user_id <> ALL (COALESCE(p_add, '{}'));

  RETURN jsonb_build_object('reason', 'ok');
END; $$;
