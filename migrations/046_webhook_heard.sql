-- ============================================================
-- Rift self-hosted server — 046: when each voice node's webhook last arrived
-- ============================================================
-- LiveKit's webhook tells this server who joins and leaves its calls, and
-- `livekit_webhook` uses it to remove a watcher whose device has left and a
-- join the token gate would refuse now: a banned member back in a call, a
-- DM call that has ended. A node whose webhook does not reach this server
-- still holds calls, so nothing showed it was missing. A region set up by
-- hand, or with `MAIN_SERVER` wrong in its .env, simply never sent one.
--
-- So `livekit_webhook` stamps the node each signed event comes from, and the
-- app's region list says when a node has never been heard from. Written on
-- the service role only: `authenticated` may update `label` and `url` and
-- nothing else (`livekit_nodes_update_admins`), so no member can set it.
-- Readable by every member, like the rest of the row: it says no more than
-- the voice roster does.
-- ============================================================

ALTER TABLE livekit_nodes
  ADD COLUMN IF NOT EXISTS webhook_heard_at TIMESTAMPTZ;

COMMENT ON COLUMN livekit_nodes.webhook_heard_at IS
  'When livekit_webhook last verified an event signed by this node, at most '
  'once in ten minutes. NULL: never, so its webhook may not reach this server.';
