-- ============================================================
-- Rift self-hosted server — 034: who a message here can reach
-- ============================================================
-- `validate_message_mentions` (020) already strips a mention of somebody who
-- cannot enter the channel: it keeps only ids that pass `app.channel_eligible`.
-- That is the right answer and it is silent, which is the problem. The composer
-- offered the whole server roster in a private channel, so a writer could pick
-- a name, watch it highlight in the sent message, and be told nothing when the
-- ping was dropped on the way in.
--
-- A UI cannot answer this on its own without becoming a second copy of
-- `channel_eligible` — it would have to read `channel_members`, read
-- `channel_role_access`, resolve those roles through `member_roles`, and
-- remember the ban clause. Four things to keep in step with a predicate that
-- lives here. So the question is asked here, of the same function the trigger
-- uses, and there is only ever one answer.
--
-- ---------- this tells nobody anything new ----------
--
-- Every input is already readable by the caller: `channel_members_select` and
-- `channel_role_access_select` are granted to whoever can see the channel, and
-- `member_role_list` is server-wide. This resolves what they could already
-- assemble. The `can_see_channel` gate is what keeps that true — without it,
-- an outsider could ask a private channel who is in it.

CREATE OR REPLACE FUNCTION channel_audience(p_channel UUID)
  RETURNS TABLE (user_id UUID)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT u.id
    FROM channels c
    JOIN users u ON u.server_id = c.server_id
   WHERE c.id = p_channel
     -- The caller has to be inside before they may resolve the list. A private
     -- channel's membership is the one thing about it an outsider could
     -- otherwise learn.
     AND app.can_see_channel(p_channel)
     AND app.channel_eligible(p_channel, u.id)
$$;

COMMENT ON FUNCTION channel_audience(UUID) IS
  'Server members a message in this channel can actually reach — the same set '
  '`validate_message_mentions` keeps. Empty for a channel the caller cannot '
  'see. Bots are in it on the same terms as anybody: always in a public '
  'channel, and in a private one only through a role with `channel_role_access`'
  ', since `set_channel_members` refuses to seat a bot by name. That is exactly '
  'who a `/` command can reach — `messages_select` asks `can_see_channel` '
  'before it asks `to_bot`. Declining to @mention them is the composer''s job '
  '(BOTS.md §4).';

REVOKE ALL ON FUNCTION channel_audience(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION channel_audience(UUID) TO authenticated;
