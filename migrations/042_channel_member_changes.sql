-- ============================================================
-- Rift self-hosted server — 042: change a private channel's members by name
-- ============================================================
-- Found in the app's review of creating and editing channels, Nov 25 2026.
--
-- `set_channel_members` replaces a private channel's membership with exactly
-- the list it is handed: everybody not on it is removed. The app built that
-- list from a read of the members, so whatever that read got wrong, Save made
-- true:
--
--   * a read that failed was drawn as nobody, and ticking one person removed
--     everybody else;
--   * a seat whose name could not be looked up was not in the list, so Save
--     removed it, and a channel with more seats than one read returns lost
--     the rest the same way;
--   * somebody who left while the page was open was still in the list, and
--     Save seated them again.
--
-- `change_channel_members` takes the people to add and the people to remove,
-- and touches nobody else. Each is what the manager actually ticked or
-- unticked, so a seat the page never saw is never touched. The same checks as
-- `set_channel_members`: the manage bit, this server's people only, never a
-- banned member or a bot. `set_channel_members` stays for apps from before.
--
-- Removing somebody from a private voice channel does not take them out of a
-- call already running in it; the `change_channel_members` edge function in
-- front of this does that, as it does for leaving.

CREATE OR REPLACE FUNCTION change_channel_members(
  p_channel UUID,
  p_add     UUID[],
  p_remove  UUID[]
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
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

REVOKE ALL ON FUNCTION change_channel_members(UUID, UUID[], UUID[]) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION change_channel_members(UUID, UUID[], UUID[]) TO authenticated;
