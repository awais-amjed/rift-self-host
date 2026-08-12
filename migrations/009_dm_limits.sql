-- ============================================================
-- Rift self-hosted server — 009: retention settings for DMs
-- ============================================================
-- 007 gave every channel its own retention override and left DMs with only the
-- server-wide numbers. That asymmetry showed up the first time an operator
-- wanted the obvious policy — trim the busy channels, keep the DMs — and found
-- it wasn't expressible: setting `message_retention_days` swept both, and
-- setting it to 0 and putting a number on each channel meant remembering to
-- repeat that on every channel created afterwards.
--
-- So DMs get the same override the channels have, with the same three-valued
-- rule: NULL inherits the server's number, 0 opts DMs out of a server-wide
-- sweep, N is DMs' own number.
--
-- Why on `servers` and not on the conversation
-- --------------------------------------------
-- A per-conversation setting has no owner. A DM belongs to two people and the
-- retention policy protects the operator's disk, so neither end of it is the
-- right person to set it — and giving one of them the power to set it would let
-- them decide how long the *other* person's messages survive. One
-- server-wide number, written by an admin through `update_server` exactly like
-- the others, keeps who-decides where it already is.
--
-- Nullable, unlike the 007 columns
-- --------------------------------
-- The channel-level columns are nullable because they override; the server-level
-- ones are NOT NULL DEFAULT 0 because they are the base case. These are
-- overrides that happen to live on `servers`, so they follow the channel rule.
-- NULL and 0 are different answers and the UI says so in as many words.

ALTER TABLE servers
  ADD COLUMN IF NOT EXISTS dm_retention_days INTEGER,
  ADD COLUMN IF NOT EXISTS dm_history_cap    INTEGER;

COMMENT ON COLUMN servers.dm_retention_days IS
  'Delete DMs older than this many days. NULL inherits '
  'message_retention_days; 0 explicitly keeps DMs forever.';
COMMENT ON COLUMN servers.dm_history_cap IS
  'Keep at most this many messages per DM conversation, counting both people. '
  'NULL inherits message_history_cap; 0 explicitly means no cap.';

ALTER TABLE servers DROP CONSTRAINT IF EXISTS servers_dm_limits_sane;
ALTER TABLE servers ADD CONSTRAINT servers_dm_limits_sane CHECK (
  (dm_retention_days IS NULL OR dm_retention_days >= 0)
  AND (dm_history_cap IS NULL OR dm_history_cap >= 0)
);

-- ============================================================
-- Retention, with the DM half now overridable
-- ============================================================
-- Replaces 007's function. The two channel blocks are unchanged; the two DM
-- blocks gain the same COALESCE the channel blocks already had, which is the
-- whole of this migration's behaviour.

CREATE OR REPLACE FUNCTION app.enforce_retention() RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- ---------- channel messages, by age ----------
  -- COALESCE is the inherit rule: the channel's number when it set one, the
  -- server's when it didn't.
  DELETE FROM messages m
   USING channels c, servers s
   WHERE m.channel_id = c.id
     AND c.server_id  = s.id
     AND COALESCE(c.retention_days, s.message_retention_days) > 0
     AND m.created_at < now() - make_interval(
           days => COALESCE(c.retention_days, s.message_retention_days));

  -- ---------- DM messages, by age ----------
  -- A DM's server is its sender's; the CHECK on `dm_messages` and
  -- `can_receive_dm` both keep a pair inside one server, so either end answers.
  -- There is no per-conversation override to consult, but there is now a
  -- per-server DM one, and it reads exactly like a channel's.
  DELETE FROM dm_messages d
   USING users u, servers s
   WHERE d.sender_id  = u.id
     AND u.server_id  = s.id
     AND COALESCE(s.dm_retention_days, s.message_retention_days) > 0
     AND d.created_at < now() - make_interval(
           days => COALESCE(s.dm_retention_days, s.message_retention_days));

  -- ---------- channel messages, by count ----------
  DELETE FROM messages WHERE id IN (
    SELECT id FROM (
      SELECT m.id,
             row_number() OVER (PARTITION BY m.channel_id ORDER BY m.id DESC) AS rn,
             COALESCE(c.history_cap, s.message_history_cap) AS cap
        FROM messages m
        JOIN channels c ON c.id = m.channel_id
        JOIN servers  s ON s.id = c.server_id
       WHERE COALESCE(c.history_cap, s.message_history_cap) > 0
    ) ranked WHERE rn > cap
  );

  -- ---------- DM messages, by count ----------
  -- Order-independent pair, matching `idx_dm_messages_pair` and central's
  -- equivalent sweep: a conversation is one bucket seen from either side, and
  -- the cap counts both people's messages together.
  DELETE FROM dm_messages WHERE id IN (
    SELECT id FROM (
      SELECT d.id,
             row_number() OVER (
               PARTITION BY LEAST(d.sender_id, d.recipient_id),
                            GREATEST(d.sender_id, d.recipient_id)
               ORDER BY d.id DESC
             ) AS rn,
             COALESCE(s.dm_history_cap, s.message_history_cap) AS cap
        FROM dm_messages d
        JOIN users   u ON u.id = d.sender_id
        JOIN servers s ON s.id = u.server_id
       WHERE COALESCE(s.dm_history_cap, s.message_history_cap) > 0
    ) ranked WHERE rn > cap
  );
END; $$;

REVOKE ALL ON FUNCTION app.enforce_retention() FROM PUBLIC, anon, authenticated;
