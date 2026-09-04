-- ============================================================
-- Rift self-hosted server — 035: the half of the grant that was missing
-- ============================================================
-- 017 built the key half of a moderation grant and built it correctly: who may
-- be granted, from which version, what revoking does, and who is told. What it
-- never did was let the bot read a message.
--
-- `messages_select` has said this since 015, and nothing changed it:
--
--     AND (NOT app.is_bot() OR to_bot = auth.uid() OR sender_id = auth.uid())
--
-- A bot reads what it is addressed and what it wrote. That stayed true of a
-- fully granted bot, in a public channel, holding the channel key: zero rows.
-- Meanwhile `grant_bot_channel_key` posts "It can read every message sent here
-- from now on" into the channel, which was a promise nothing kept.
--
-- ---------- the grant is the permission, and it is arithmetic ----------
--
-- `from_key_version` already exists and already means the right thing: the
-- first version this bot may hold, set one past the current one so the
-- rotation that follows is what it reads from. `refuse_ineligible_keyring`
-- enforces it on the way in. This reads it on the way out, so forward-only is
-- the same number in both directions rather than a policy promise on one side
-- and arithmetic on the other.
--
-- A revoke deletes the grant row and the bot's keyring rows, so it stops
-- reading in the same statement. "It keeps what it already saw" is about what
-- has been unwrapped and cannot be recalled — not about a database it still
-- gets to query.
--
-- ---------- what a granted bot still does not see ----------
--
--   * **Anything below `from_key_version`**, which is the whole point.
--   * **`key_version = 0` rows** — webhook posts, system notices, and commands
--     addressed to *other* bots. Those were never sealed under any version, so
--     no grant covers them, and the third kind is the reason to be strict
--     rather than generous: `/ask` to another bot is plaintext and personal.
--     A moderation bot has a blind spot for webhook content, and that is the
--     honest cost of making the boundary a number.
--   * **Somebody else's ephemeral reply**, and **another bot's button press**.
--     Both clauses already say so and both still apply — this widens the first
--     test in the policy, not the ones after it.
--
-- ---------- private channels ----------
--
-- A per-channel grant on a private channel is allowed (BOTS.md §6: the bulk
-- grant is what never covers one). But `can_see_channel` asks about membership,
-- and `set_channel_members` will not seat a bot — so the grant was doubly inert
-- there: no messages, and not even the bot's own wrapped key. Both now admit a
-- granted bot, scoped to its own rows.

-- ============================================================
-- 1. The two questions
-- ============================================================

-- Is there a live grant for me on this channel? Only bots have rows here, so
-- this needs no `is_bot` check of its own.
CREATE OR REPLACE FUNCTION app.bot_reads_channel(p_channel UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM bot_channel_keys g
                  WHERE g.channel_id = p_channel AND g.bot_id = auth.uid())
$$;

-- ...and does it reach this far back? Separate from the above because the
-- keyring and the grant row are per-channel questions and a message is a
-- per-version one.
CREATE OR REPLACE FUNCTION app.bot_reads_version(
  p_channel UUID,
  p_version INTEGER
) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM bot_channel_keys g
                  WHERE g.channel_id = p_channel AND g.bot_id = auth.uid()
                    AND p_version >= g.from_key_version)
$$;

REVOKE ALL ON FUNCTION app.bot_reads_channel(UUID)          FROM PUBLIC;
REVOKE ALL ON FUNCTION app.bot_reads_version(UUID, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.bot_reads_channel(UUID)          TO authenticated;
GRANT EXECUTE ON FUNCTION app.bot_reads_version(UUID, INTEGER) TO authenticated;

-- ============================================================
-- 2. Reading the channel
-- ============================================================
-- Same shape as 029's, with the grant added to the first two tests. The
-- ephemeral and interaction clauses are untouched: a grant is permission to
-- read the channel's conversation, not permission to read a reply somebody was
-- shown alone.

DROP POLICY IF EXISTS messages_select ON messages;
CREATE POLICY messages_select ON messages FOR SELECT TO authenticated
  USING (
    (app.can_see_channel(channel_id) OR app.bot_reads_channel(channel_id))
    AND (NOT app.is_bot()
         OR to_bot = auth.uid()
         OR sender_id = auth.uid()
         OR app.bot_reads_version(channel_id, key_version))
    AND (ephemeral_for IS NULL OR ephemeral_for = auth.uid()
         OR sender_id = auth.uid())
    AND (NOT is_interaction OR sender_id = auth.uid() OR to_bot = auth.uid())
  );

-- ============================================================
-- 3. Reaching its own key
-- ============================================================
-- Reading a sealed message is no use without the thing that opens it. In a
-- public channel `can_see_channel` already returned these; this is what makes a
-- private-channel grant work at all.
--
-- Scoped to the bot's own row rather than the whole keyring: the rest of it is
-- wrapped to other people's X25519 keys and would open for nobody, but it is
-- also a list of who holds a key to this channel, and a bot has no reason to
-- have it.

DROP POLICY IF EXISTS channel_keyring_select ON channel_keyring;
CREATE POLICY channel_keyring_select ON channel_keyring FOR SELECT TO authenticated
  USING (
    app.can_see_channel(channel_id)
    OR (user_id = auth.uid() AND app.bot_reads_channel(channel_id))
  );

-- And its own grant row, which is where `from_key_version` lives — a bot that
-- cannot read this cannot tell a channel it was never granted from one whose
-- history simply starts later.
DROP POLICY IF EXISTS bot_channel_keys_select ON bot_channel_keys;
CREATE POLICY bot_channel_keys_select ON bot_channel_keys
  FOR SELECT TO authenticated
  USING (app.can_see_channel(channel_id) OR bot_id = auth.uid());
