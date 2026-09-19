-- ============================================================
-- Rift self-hosted server — 025: a policy asks once, not once per row
-- ============================================================
-- A row-level policy runs for every row the statement touches. When the
-- policy calls a function, that function runs for every row too — and most
-- of the questions these policies ask do not depend on the row at all.
-- `app.server_id()` is "which server is the caller in", `auth.uid()` is "who
-- is asking", `app.is_bot()` is "are they a bot": one answer per statement,
-- asked once per row.
--
-- Where the answer *does* depend on the row it is nearly always the channel,
-- and a server has tens of channels and millions of messages. Asking "can I
-- see this channel" once per message is the same waste wearing a hat.
--
-- Measured on 50,000 members, 50 channels, 5,000,000 messages and 2,000,000
-- keyring rows. Same queries, same data, only the policies differ:
--
--   a page of 50 messages ................    2.34 ms  →  0.82 ms
--   a capped unread count (100) ..........    4.69 ms  →  0.98 ms
--   unread_counts() over 50 channels .....  230 ms     → 24.5 ms
--   one channel's keyring ................ 2,140 ms    →  6.25 ms
--   count the members ....................  420 ms     →  5.9 ms
--   the member sidebar, page 20 ..........  134 ms     → 15.5 ms
--   role chips for 50 members ............ 1,100 ms    → 31 ms
--
-- Nothing here changes who may read what. Every rewrite below is the same
-- predicate rearranged so the planner can hoist it, and `policies_test.sql`
-- is the check that it still refuses what it refused before.
--
-- ---------- the two shapes ----------
--
-- **A question with no row in it** is wrapped in a scalar subquery:
-- `auth.uid()` becomes `(SELECT auth.uid())`. Postgres turns that into an
-- InitPlan, evaluated once for the statement and then treated as a constant.
-- Written bare it is a function call per row, and `auth.uid()` in particular
-- parses JSON out of a setting every single time.
--
-- **A question about the row's channel** becomes set membership:
-- `app.can_see_channel(channel_id)` becomes
-- `channel_id IN (SELECT unnest(app.visible_channels()))`. The set is built
-- once — it is the caller's channels, and there are tens of them — and the
-- per-row test is a hash lookup.
--
-- One policy is deliberately *not* rewritten. `message_reactions_select`
-- asks about a message id rather than a channel, so there is no small set to
-- hoist into; rewriting it as an EXISTS measured slower than what it
-- replaced (16 ms against 8.8 ms for a page of tallies), so it stays.

-- ============================================================
-- 1. The sets, built once
-- ============================================================

-- Every channel the caller may read: the same rule `app.can_see_channel`
-- applies, gathered rather than asked one channel at a time.
CREATE OR REPLACE FUNCTION app.visible_channels() RETURNS UUID[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(array_agg(c.id), '{}'::uuid[])
    FROM channels c
   WHERE c.server_id = app.server_id()
     AND (NOT c.is_private OR app.in_channel(c.id, auth.uid()))
$$;

COMMENT ON FUNCTION app.visible_channels() IS
  'The caller''s readable channels as one array, so a policy can test '
  'membership instead of calling app.can_see_channel for every row.';

REVOKE ALL ON FUNCTION app.visible_channels() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.visible_channels() TO authenticated;

-- The channels a bot was granted, which is `app.bot_reads_channel` gathered
-- the same way. Empty for everybody who is not a bot.
CREATE OR REPLACE FUNCTION app.bot_channels() RETURNS UUID[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(array_agg(g.channel_id), '{}'::uuid[])
    FROM bot_channel_keys g WHERE g.bot_id = auth.uid()
$$;

COMMENT ON FUNCTION app.bot_channels() IS
  'The channels this bot holds a key for, as one array. Empty for a person.';

REVOKE ALL ON FUNCTION app.bot_channels() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.bot_channels() TO authenticated;

-- The caller's own server's roles. `member_roles_select` used to reach for
-- `users` to decide whether a role assignment was in scope, which made every
-- read of it a scan of the whole membership; a role belongs to exactly one
-- server and `member_roles_insert` will not let the two sides differ, so the
-- twelve-row table answers the same question.
CREATE OR REPLACE FUNCTION app.server_roles() RETURNS UUID[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(array_agg(r.id), '{}'::uuid[])
    FROM roles r WHERE r.server_id = app.server_id()
$$;

COMMENT ON FUNCTION app.server_roles() IS
  'The roles of the caller''s server, as one array.';

REVOKE ALL ON FUNCTION app.server_roles() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION app.server_roles() TO authenticated;

-- ============================================================
-- 2. Messages
-- ============================================================
-- Same four clauses as 010, in the same order, with the channel test hoisted
-- and every `auth.uid()` and `app.is_bot()` wrapped. `app.bot_reads_version`
-- keeps its per-row call: it depends on the row's `key_version`, and it is
-- only reached by a bot that has already failed the three cheap tests before
-- it.

DROP POLICY IF EXISTS messages_select ON messages;
CREATE POLICY messages_select ON messages FOR SELECT TO authenticated
  USING (
    (channel_id IN (SELECT unnest(app.visible_channels()))
     OR channel_id IN (SELECT unnest(app.bot_channels())))
    AND ((SELECT NOT app.is_bot())
         OR to_bot = (SELECT auth.uid())
         OR sender_id = (SELECT auth.uid())
         OR app.bot_reads_version(channel_id, key_version))
    AND (ephemeral_for IS NULL
         OR ephemeral_for = (SELECT auth.uid())
         OR sender_id = (SELECT auth.uid()))
    AND (NOT is_interaction
         OR sender_id = (SELECT auth.uid())
         OR to_bot = (SELECT auth.uid()))
  );

-- ============================================================
-- 3. The keyring, the seats and the role grants
-- ============================================================
-- All three are "rows belonging to a channel", and all three were asking
-- about the channel once per row. The keyring is the one that hurt: it holds
-- a row per member per channel, so one channel's worth is as long as the
-- membership.

DROP POLICY IF EXISTS channel_keyring_select ON channel_keyring;
CREATE POLICY channel_keyring_select ON channel_keyring FOR SELECT TO authenticated
  USING (
    channel_id IN (SELECT unnest(app.visible_channels()))
    OR (user_id = (SELECT auth.uid())
        AND channel_id IN (SELECT unnest(app.bot_channels())))
  );

DROP POLICY IF EXISTS channel_members_select ON channel_members;
CREATE POLICY channel_members_select ON channel_members FOR SELECT TO authenticated
  USING (channel_id IN (SELECT unnest(app.visible_channels())));

DROP POLICY IF EXISTS channel_role_access_select ON channel_role_access;
CREATE POLICY channel_role_access_select ON channel_role_access
  FOR SELECT TO authenticated
  USING (channel_id IN (SELECT unnest(app.visible_channels())));

-- ============================================================
-- 4. Members and their roles
-- ============================================================
-- `users` is read by every list, every search, every count and every
-- mention. The two policies stay two policies — a banned member has no
-- server and must still reach their own row, which is how they find out the
-- ban was lifted — but both are hoisted.

DROP POLICY IF EXISTS users_select_members ON users;
CREATE POLICY users_select_members ON users FOR SELECT TO authenticated
  USING (server_id = (SELECT app.server_id()));

DROP POLICY IF EXISTS users_select_self ON users;
CREATE POLICY users_select_self ON users FOR SELECT TO authenticated
  USING (id = (SELECT auth.uid()));

DROP POLICY IF EXISTS users_update_self ON users;
CREATE POLICY users_update_self ON users FOR UPDATE TO authenticated
  USING (id = (SELECT auth.uid()) AND server_id = (SELECT app.server_id()))
  WITH CHECK (id = (SELECT auth.uid()) AND server_id = (SELECT app.server_id()));

DROP POLICY IF EXISTS member_roles_select ON member_roles;
CREATE POLICY member_roles_select ON member_roles FOR SELECT TO authenticated
  USING (role_id IN (SELECT unnest(app.server_roles())));

-- ============================================================
-- 5. The rest of the once-per-statement questions
-- ============================================================
-- None of these were slow on their own; they are here because leaving half
-- the codebase on the old shape is how the old shape comes back.

DROP POLICY IF EXISTS servers_select ON servers;
CREATE POLICY servers_select ON servers FOR SELECT TO authenticated
  USING (id = (SELECT app.server_id()));

DROP POLICY IF EXISTS roles_select ON roles;
CREATE POLICY roles_select ON roles FOR SELECT TO authenticated
  USING (server_id = (SELECT app.server_id()));

DROP POLICY IF EXISTS channels_select ON channels;
CREATE POLICY channels_select ON channels FOR SELECT TO authenticated
  USING (
    server_id = (SELECT app.server_id())
    AND (NOT is_private OR app.in_channel(id, (SELECT auth.uid())))
  );

DROP POLICY IF EXISTS dm_messages_select ON dm_messages;
CREATE POLICY dm_messages_select ON dm_messages FOR SELECT TO authenticated
  USING (sender_id = (SELECT auth.uid()) OR recipient_id = (SELECT auth.uid()));

DROP POLICY IF EXISTS read_state_own ON read_state;
CREATE POLICY read_state_own ON read_state FOR ALL TO authenticated
  USING (user_id = (SELECT auth.uid()))
  WITH CHECK (user_id = (SELECT auth.uid()));

DROP POLICY IF EXISTS notification_prefs_own ON notification_prefs;
CREATE POLICY notification_prefs_own ON notification_prefs FOR ALL TO authenticated
  USING (user_id = (SELECT auth.uid()))
  WITH CHECK (user_id = (SELECT auth.uid()));

DROP POLICY IF EXISTS device_tokens_own ON device_tokens;
CREATE POLICY device_tokens_own ON device_tokens FOR ALL TO authenticated
  USING (user_id = (SELECT auth.uid()))
  WITH CHECK (user_id = (SELECT auth.uid()));

DROP POLICY IF EXISTS dm_conversation_heads_select ON dm_conversation_heads;
CREATE POLICY dm_conversation_heads_select ON dm_conversation_heads
  FOR SELECT TO authenticated
  USING (user_id = (SELECT auth.uid()));

DROP POLICY IF EXISTS bot_server_grants_select ON bot_server_grants;
CREATE POLICY bot_server_grants_select ON bot_server_grants
  FOR SELECT TO authenticated
  USING (server_id = (SELECT app.server_id()));
