-- ============================================================
-- Rift self-hosted server — 056: deleting a member finds their rows by index
-- ============================================================
-- Found in the query review of Nov 25 2026, measured Nov 26 on a test
-- database of 50,000 members, 5,000,000 messages and 12,800,000 keyring
-- rows.
--
-- A member's row is deleted only when their server is: `delete_server`
-- deletes the server and the rest cascades. For every member, Postgres then
-- looks up each row that refers to them, and a reference with no index
-- behind it is a scan of its whole table. Three of them were on the biggest
-- tables there are — who wrapped a keyring row, who sent a message and who
-- an ephemeral reply was for — and deleting one member took 3.5 s, 1.6 s of
-- it reading the keyring. A server of 50,000 members is that, 50,000 times.
--
-- So each reference to a member from a table that grows with the members or
-- what they write has an index: 3.5 s → 11 ms a member. Where the column is
-- mostly empty the index holds only the rows that name somebody. On that
-- database they come to 125 MB, nearly all of it the keyring's (86 MB) and
-- the senders' (34 MB), and building them held up writes to `messages` and
-- `channel_keyring` for a few seconds, once, while this ran.
--
-- References from tables an admin fills by hand — webhooks, invites, the
-- soundboard, grants to bots, reports — are left: they stay small enough to
-- read whole.

CREATE INDEX IF NOT EXISTS idx_channel_keyring_wrapped_by
  ON channel_keyring (wrapped_by);
CREATE INDEX IF NOT EXISTS idx_messages_sender
  ON messages (sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_ephemeral_for
  ON messages (ephemeral_for) WHERE ephemeral_for IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_message_reactions_user
  ON message_reactions (user_id);
CREATE INDEX IF NOT EXISTS idx_dm_message_reactions_user
  ON dm_message_reactions (user_id);
CREATE INDEX IF NOT EXISTS idx_poll_votes_user
  ON poll_votes (user_id);
CREATE INDEX IF NOT EXISTS idx_dm_conversation_heads_peer
  ON dm_conversation_heads (peer_id);
CREATE INDEX IF NOT EXISTS idx_dm_calls_callee
  ON dm_calls (callee_id);
CREATE INDEX IF NOT EXISTS idx_member_blocks_blocked
  ON member_blocks (blocked_id);
CREATE INDEX IF NOT EXISTS idx_dm_links_high
  ON dm_links (user_high);
CREATE INDEX IF NOT EXISTS idx_dm_message_pins_high
  ON dm_message_pins (user_high);
CREATE INDEX IF NOT EXISTS idx_member_roles_granted_by
  ON member_roles (granted_by) WHERE granted_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_channel_members_added_by
  ON channel_members (added_by) WHERE added_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_message_pins_pinned_by
  ON message_pins (pinned_by) WHERE pinned_by IS NOT NULL;

COMMENT ON INDEX idx_channel_keyring_wrapped_by IS
  'Who wrapped a keyring row, so deleting a member (with their server) is not '
  'a read of every key. The same holds for the other indexes 056 adds.';
