-- ============================================================
-- Rift self-hosted server — 067: a reaction in one call
-- ============================================================
-- Found in the review of call counts, Nov 26 2026.
--
-- Tapping a reaction was an insert, then the counts read again, then the
-- counts read a third time when the reactor's own ring came back. Taking one
-- off was worse: an insert that failed on the primary key, a delete, and the
-- same two reads, with a Postgres error logged for each. And it could not be
-- done at all by somebody the insert policy turns away (timed out, without
-- `ADD_REACTIONS` any more, blocked in a DM): the policy is checked before
-- the key, so they got 42501, never 23505, and their reaction stayed.
--
--   * `toggle_reaction(p_scope, p_message, p_emoji)` takes the caller's own
--     reaction off if it is there and puts it on if not, and answers
--     `{reacted, counts}` with the counts `app.reaction_counts_of` gives.
--     Delete first, so taking one off never meets the insert policy. It runs
--     as the caller: the delete and insert policies and the column grants
--     are still the whole gate.
--   * A reaction's ring names who reacted (`user_id`), so the reactor's app
--     need not read the counts it was just handed. Who reacted is no news to
--     anybody on the topic: they may read the reaction rows themselves.
--   * A message holds at most twenty different emoji, as Discord's do. Each
--     new one rang the whole channel and drew another chip for everyone, and
--     nothing limited them. Checked after the insert policy, so somebody who
--     may not see a message learns nothing about its reactions from the
--     refusal (`too_many_reactions`). Two people adding the twentieth and the
--     twenty-first at the same moment may both get in; the cap is against
--     floods, not exact.
--
-- An app asks `toggle_reaction` and, on a server from before it, writes the
-- row itself as it did. Both bot SDKs write no reactions.

-- ── Toggling one ────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.toggle_reaction(
  p_scope   read_scope,
  p_message BIGINT,
  p_emoji   TEXT
) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = public AS $$
DECLARE
  v_me      UUID := auth.uid();
  v_reacted BOOLEAN;
BEGIN
  IF v_me IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  IF p_scope = 'channel' THEN
    DELETE FROM message_reactions
     WHERE message_id = p_message AND user_id = v_me AND emoji = p_emoji;
    v_reacted := NOT FOUND;
    IF v_reacted THEN
      -- A second tap racing the first finds the row it put there.
      INSERT INTO message_reactions (message_id, user_id, emoji)
      VALUES (p_message, v_me, p_emoji)
      ON CONFLICT DO NOTHING;
    END IF;
  ELSE
    DELETE FROM dm_message_reactions
     WHERE message_id = p_message AND user_id = v_me AND emoji = p_emoji;
    v_reacted := NOT FOUND;
    IF v_reacted THEN
      INSERT INTO dm_message_reactions (message_id, user_id, emoji)
      VALUES (p_message, v_me, p_emoji)
      ON CONFLICT DO NOTHING;
    END IF;
  END IF;

  RETURN jsonb_build_object(
    'reacted', v_reacted,
    'counts', app.reaction_counts_of(p_scope, p_message));
END $$;

COMMENT ON FUNCTION public.toggle_reaction(read_scope, BIGINT, TEXT) IS
  'Take the caller''s reaction off a message, or put it on if it was not '
  'there; answers {reacted, counts}. Run as the caller, so the reaction '
  'policies decide.';

-- ── At most twenty different emoji ──────────────────────────
-- After the insert, so the row has passed its policy first. Counted as the
-- owner: the caller may see the message, which is all the select policy
-- would ask, and asking it per row costs.
CREATE OR REPLACE FUNCTION app.cap_reaction_kinds() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_kinds INTEGER;
BEGIN
  IF TG_TABLE_NAME = 'message_reactions' THEN
    SELECT count(DISTINCT q.emoji) INTO v_kinds
      FROM message_reactions q WHERE q.message_id = NEW.message_id;
  ELSE
    SELECT count(DISTINCT q.emoji) INTO v_kinds
      FROM dm_message_reactions q WHERE q.message_id = NEW.message_id;
  END IF;
  IF v_kinds > 20 THEN
    RAISE EXCEPTION 'too_many_reactions';
  END IF;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS message_reactions_cap ON message_reactions;
CREATE TRIGGER message_reactions_cap
  AFTER INSERT ON message_reactions
  FOR EACH ROW EXECUTE FUNCTION app.cap_reaction_kinds();

DROP TRIGGER IF EXISTS dm_message_reactions_cap ON dm_message_reactions;
CREATE TRIGGER dm_message_reactions_cap
  AFTER INSERT ON dm_message_reactions
  FOR EACH ROW EXECUTE FUNCTION app.cap_reaction_kinds();

-- ── The rings name who reacted ──────────────────────────────
CREATE OR REPLACE FUNCTION app.announce_reaction() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_message BIGINT;
  v_user    UUID;
  v_channel UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_message := OLD.message_id;
    v_user := OLD.user_id;
  ELSE
    v_message := NEW.message_id;
    v_user := NEW.user_id;
  END IF;
  SELECT m.channel_id INTO v_channel FROM messages m WHERE m.id = v_message;
  IF v_channel IS NOT NULL THEN
    PERFORM app.announce_to_channel(v_channel, 'reaction',
      jsonb_build_object('message_id', v_message, 'channel_id', v_channel,
                         'user_id', v_user));
  END IF;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION app.announce_dm_reaction() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_message BIGINT;
  v_user    UUID;
  v_party   UUID;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  IF TG_OP = 'DELETE' THEN
    v_message := OLD.message_id;
    v_user := OLD.user_id;
  ELSE
    v_message := NEW.message_id;
    v_user := NEW.user_id;
  END IF;
  FOR v_party IN
    SELECT unnest(ARRAY[d.sender_id, d.recipient_id])
      FROM dm_messages d WHERE d.id = v_message
  LOOP
    PERFORM realtime.send(
      jsonb_build_object('message_id', v_message, 'user_id', v_user),
      'dm_reaction', 'user:' || v_party, true);
  END LOOP;
  RETURN NULL;
END $$;

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION public.toggle_reaction(read_scope, BIGINT, TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.cap_reaction_kinds() FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION public.toggle_reaction(read_scope, BIGINT, TEXT) TO authenticated;
