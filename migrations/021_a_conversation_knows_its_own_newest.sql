-- ============================================================
-- Rift self-hosted server — 021: a conversation knows its own newest message
-- ============================================================
-- The same shape central's 022 replaced, and for the same reason.
--
-- `dm_conversations()` found the newest message per peer with
-- `DISTINCT ON (peer)` over `dm_messages` — so drawing thirty rows read every
-- DM the caller had ever exchanged with anybody, sorted. There is no index
-- that could help:
--
--   * **There is no column to index.** "Peer" means whoever is not the
--     caller — a CASE evaluated per query, different for every member who
--     asks.
--   * **A conversation lives under two keys.** What you sent is filed by
--     sender, what you received by recipient, and the newest may be either.
--   * **Even a perfect index would only save the sort.** `DISTINCT ON` still
--     walks every one of your messages to find each peer's maximum.
--
-- So the index is written by hand: one row per person you talk to, holding
-- that conversation's newest message id. The list becomes a range scan of
-- your own rows, newest first, stop at thirty. Measured on central's copy of
-- this design, whose table is the same two columns and a bigint: 230-270 ms
-- for a 200-conversation account down to 9.5 ms, and flat at 5.4 ms with a
-- thousand conversations behind it, because picking the page is 0.27 ms of
-- index scan whatever the history.
--
-- A server's DMs are smaller than central's — one server's members rather
-- than everybody's friends — so this is the cheaper of the two to leave
-- broken and the easier of the two to fix. It is the same fix either way.
--
-- **Where this differs from central's.** That one is SECURITY DEFINER and
-- filters by hand, because its heads are a map of who talks to whom across
-- every account on the tier. Here the function is SECURITY INVOKER and the
-- policies do the work, as everything else on this schema does: a member
-- reads their own heads, which is their own conversation list, which they
-- already have.

-- ============================================================
-- 1. The heads
-- ============================================================

CREATE TABLE IF NOT EXISTS dm_conversation_heads (
  user_id         UUID   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  peer_id         UUID   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  last_message_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, peer_id)
);

COMMENT ON TABLE dm_conversation_heads IS
  'One row per person you have a conversation with, holding that '
  'conversation''s newest message id. Maintained by trigger; it is what makes '
  'the conversation list cost a page instead of a history.';

-- The whole point: your conversations, newest first, without a sort.
CREATE INDEX IF NOT EXISTS idx_dm_conversation_heads_recent
  ON dm_conversation_heads (user_id, last_message_id DESC);

ALTER TABLE dm_conversation_heads ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON dm_conversation_heads FROM anon, authenticated;
GRANT SELECT ON dm_conversation_heads TO authenticated;

-- Yours and nobody else's. Read-only from every session: the triggers below
-- write it, and a member who could write it could move a conversation to the
-- top of somebody else's list.
DROP POLICY IF EXISTS dm_conversation_heads_select ON dm_conversation_heads;
CREATE POLICY dm_conversation_heads_select ON dm_conversation_heads
  FOR SELECT TO authenticated USING (user_id = auth.uid());

-- ============================================================
-- 2. Keeping them true
-- ============================================================
-- An insert is the easy half — a new message is always the newest, so both
-- sides move forward. GREATEST rather than a bare assignment because a
-- backfill or a repair may run beside it, and a head that goes backwards is a
-- conversation that jumps down the list.

CREATE OR REPLACE FUNCTION app.remember_dm_head() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO dm_conversation_heads (user_id, peer_id, last_message_id)
  VALUES (NEW.sender_id, NEW.recipient_id, NEW.id),
         (NEW.recipient_id, NEW.sender_id, NEW.id)
      ON CONFLICT (user_id, peer_id) DO UPDATE
     SET last_message_id = GREATEST(dm_conversation_heads.last_message_id,
                                    EXCLUDED.last_message_id);
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION app.remember_dm_head() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS dm_messages_head ON dm_messages;
CREATE TRIGGER dm_messages_head AFTER INSERT ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION app.remember_dm_head();

-- A delete only matters when it takes the head with it, which is the rare
-- case: `app.enforce_retention` deletes the *oldest* messages, and the only
-- other delete is somebody removing their own message — usually not the
-- newest either.
--
-- When it is the head, the replacement is one backwards walk of
-- `idx_dm_messages_pair`; when nothing is left, the conversation is over and
-- the rows go.

CREATE OR REPLACE FUNCTION app.forget_dm_head() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_newest BIGINT;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM dm_conversation_heads h
     WHERE h.last_message_id = OLD.id
       AND ((h.user_id = OLD.sender_id    AND h.peer_id = OLD.recipient_id)
         OR (h.user_id = OLD.recipient_id AND h.peer_id = OLD.sender_id))
  ) THEN
    RETURN NULL;   -- something older went; the head still stands
  END IF;

  SELECT max(d.id) INTO v_newest
    FROM dm_messages d
   WHERE LEAST(d.sender_id, d.recipient_id)
           = LEAST(OLD.sender_id, OLD.recipient_id)
     AND GREATEST(d.sender_id, d.recipient_id)
           = GREATEST(OLD.sender_id, OLD.recipient_id);

  IF v_newest IS NULL THEN
    DELETE FROM dm_conversation_heads h
     WHERE (h.user_id = OLD.sender_id    AND h.peer_id = OLD.recipient_id)
        OR (h.user_id = OLD.recipient_id AND h.peer_id = OLD.sender_id);
  ELSE
    UPDATE dm_conversation_heads h
       SET last_message_id = v_newest
     WHERE ((h.user_id = OLD.sender_id    AND h.peer_id = OLD.recipient_id)
         OR (h.user_id = OLD.recipient_id AND h.peer_id = OLD.sender_id))
       AND h.last_message_id = OLD.id;
  END IF;
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION app.forget_dm_head() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS dm_messages_head_gone ON dm_messages;
CREATE TRIGGER dm_messages_head_gone AFTER DELETE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION app.forget_dm_head();

-- ---------- what is already here ----------
-- The one scan of the old shape, run once, so nobody opens the app to an
-- empty list. Idempotent: re-running it changes nothing.

INSERT INTO dm_conversation_heads (user_id, peer_id, last_message_id)
SELECT side.me, side.peer, max(side.id)
  FROM (SELECT sender_id    AS me, recipient_id AS peer, id FROM dm_messages
        UNION ALL
        SELECT recipient_id AS me, sender_id    AS peer, id FROM dm_messages) side
 GROUP BY side.me, side.peer
    ON CONFLICT (user_id, peer_id) DO UPDATE
   SET last_message_id = GREATEST(dm_conversation_heads.last_message_id,
                                  EXCLUDED.last_message_id);

-- ============================================================
-- 3. The list, read from the heads
-- ============================================================
-- Everything from `kept` down is unchanged: the same envelope, the same peer
-- identity, the same spare row proving `has_more`.
--
-- `page` reads the heads alone and the join happens under it, which is the
-- difference between a plan and a good one: asked for the join first, the
-- planner sorts every head the caller has and merges, so the cost comes back
-- with the conversation count. Reading the heads by themselves lets it walk
-- `idx_dm_conversation_heads_recent` in order and stop at thirty-one.
--
-- Nothing is lost by joining later. `dm_messages_select` admits the sender
-- and the recipient and asks nothing else — not membership, not a ban — so
-- the head of your own conversation is a row you can always read, and the
-- join can never drop one the page counted.

CREATE OR REPLACE FUNCTION dm_conversations(
  p_limit  INTEGER DEFAULT 30,
  p_before BIGINT  DEFAULT NULL
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  WITH page AS (
    SELECT h.last_message_id AS id, h.peer_id AS peer
      FROM dm_conversation_heads h
     WHERE h.user_id = auth.uid()
       AND (p_before IS NULL OR h.last_message_id < p_before)
     ORDER BY h.last_message_id DESC
     -- One row past the page, so "there is more" is proved rather than
     -- guessed from a full page. Same trick the message history and central
     -- use.
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100) + 1
  ),
  kept AS (
    SELECT d.*, p.peer
      FROM (SELECT * FROM page
             ORDER BY id DESC
             LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100)) p
      JOIN dm_messages d ON d.id = p.id
  ),
  rows AS (
    SELECT jsonb_build_object(
             'peer_id',               u.id,
             'peer_name',             u.display_name,
             'peer_username',         u.username,
             'peer_avatar_path',      u.avatar_path,
             'peer_chat_public_key',  u.chat_public_key,
             'peer_public_key',       u.public_key,
             'last_message', jsonb_build_object(
               'id',           k.id,
               'created_at',   k.created_at,
               'sender_id',    k.sender_id,
               'recipient_id', k.recipient_id,
               'ciphertext',   k.ciphertext,
               'nonce',        k.nonce,
               'signature',    k.signature,
               'key_version',  k.key_version,
               'edited_at',    k.edited_at
             )
           ) AS row,
           k.id AS sort_id
      FROM kept k
      JOIN users u ON u.id = k.peer
  )
  SELECT jsonb_build_object(
           'conversations',
           COALESCE((SELECT jsonb_agg(row ORDER BY sort_id DESC) FROM rows),
                    '[]'::jsonb),
           'has_more',
           (SELECT count(*) FROM page) > (SELECT count(*) FROM kept));
$$;

COMMENT ON FUNCTION dm_conversations(INTEGER, BIGINT) IS
  'The caller''s DM conversations, newest first, a page at a time. Read from '
  'dm_conversation_heads, so it costs a page rather than a history.';

REVOKE ALL ON FUNCTION dm_conversations(INTEGER, BIGINT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION dm_conversations(INTEGER, BIGINT) TO authenticated;
