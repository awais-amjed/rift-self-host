-- ============================================================
-- Rift self-hosted server — 004: realtime
-- ============================================================
-- What a client may subscribe to. Realtime re-checks 002's policies per
-- subscriber for every change, so a member only ever receives rows they could
-- have selected — a message from a channel on another server in the same
-- project is never delivered.
--
-- This is what lets the `notifications` table go. Badges used to need a fanned
-- out row per recipient because that row was the only thing a client was
-- allowed to watch. Now it watches the messages themselves.
--
-- Note that a policy consulting an RLS-locked table always evaluates false
-- here, silently — which looks exactly like Realtime being broken. 002's
-- helpers are SECURITY DEFINER for that reason.

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE messages;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE dm_messages;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Reactions are watched so a tally updates live without a doorbell ping.
DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE message_reactions;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE dm_message_reactions;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Members: a rename, a new avatar, a mute or a ban reaches everyone looking at
-- the member list without polling.
DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE users;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Channels: created, renamed and deleted channels restructure the sidebar.
DO $$ BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE channels;
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
