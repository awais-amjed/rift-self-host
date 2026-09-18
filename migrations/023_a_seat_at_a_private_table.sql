-- ============================================================
-- Rift self-hosted server — 023: a seat at a private table is news
-- ============================================================
-- Being added to a private channel reached nobody.
--
-- 017 announces `channels` when the `channels` row moves, which covers a
-- channel created, renamed or deleted. Handing somebody a seat at one moves
-- no such row: it inserts into `channel_members`, which announced nothing at
-- all. The new member's own `users` row did not move either, so not even `me`
-- fired. They were in the channel as far as every policy was concerned, and
-- their sidebar did not know until the app was restarted or the server
-- reselected.
--
-- Measured before writing this: a member added to a private channel still had
-- no sign of it fifteen seconds later, and it appeared on the next launch.
--
-- ---------- why `me` and not a new event ----------
--
-- `me` already means "your standing on this server changed — re-read it",
-- which is how a ban, a mute and a role reach the person they happened to,
-- and the client already listens for it on its own topic. A seat at a private
-- table is the same kind of fact, so it travels the same way and no client
-- changes at all. A `channels` event would have been wrong twice over: it
-- goes to the server's topic, where everybody would re-read for one person's
-- news, and the one person it is actually for is exactly the one whose
-- previous read could not see the channel.
--
-- Both ends of the change, so losing a seat is as immediate as gaining one —
-- a private channel that lingers in the sidebar after access was taken away
-- is the worse of the two to leave.

CREATE OR REPLACE FUNCTION app.announce_channel_member() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;

  IF TG_OP = 'DELETE' THEN
    PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || OLD.user_id, true);
    RETURN NULL;
  END IF;

  -- An UPDATE that moved nothing but `can_manage` is news too: it decides
  -- whether the channel's settings are reachable at all.
  PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || NEW.user_id, true);
  IF TG_OP = 'UPDATE' AND OLD.user_id <> NEW.user_id THEN
    PERFORM realtime.send('{}'::jsonb, 'me', 'user:' || OLD.user_id, true);
  END IF;
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION app.announce_channel_member()
  FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS channel_members_announce ON channel_members;
CREATE TRIGGER channel_members_announce
  AFTER INSERT OR UPDATE OR DELETE ON channel_members
  FOR EACH ROW EXECUTE FUNCTION app.announce_channel_member();
