-- ============================================================
-- Rift self-hosted server — 041: the DM conversation list, a page at a time
-- ============================================================
-- `dm_conversations()` from 003 returned every peer you have ever exchanged a
-- message with, in one answer, with no way to ask for fewer. Central had the
-- same shape and lost it in migration 013; this is the same change, made here.
--
-- It could not truncate — a JSONB scalar is not subject to the 1000-row
-- response cap, which is why 003 built it that way — so nothing was silently
-- missing. What it did instead was grow: the list is refetched on every server
-- switch and on every incoming DM, and each row carries an envelope the client
-- decrypts to draw a preview. A member who has spoken to two hundred people
-- pays two hundred decryptions to render the dozen tiles that fit on screen,
-- and pays them again the next time somebody says hello.
--
-- Bounded by how many people you have talked to rather than by how much was
-- said, so it was the slowest of the reads to become a problem and the last one
-- left. That is the only reason it is a migration of its own.
--
-- ---------- what does not change ----------
--
-- The row. Same keys, same envelope, same `DISTINCT ON (peer)` — a caller that
-- reads a conversation out of the answer needs no edit. What changes is the
-- envelope around them: an array becomes `{conversations, has_more}`, because a
-- page that cannot say whether it is the last one leaves the client guessing
-- from whether it came back full, and a full last page then offers a "load
-- more" that fetches nothing.
--
-- SECURITY INVOKER, still. `dm_messages_select` (002) is already
-- `auth.uid() IN (sender_id, recipient_id)`, so the rows this can reach are the
-- caller's own conversations and nothing else — the pairing below has no filter
-- of its own because it does not need one. Central's version is DEFINER for a
-- reason that does not exist here: it has a `blocks` table, and it must name a
-- blocked peer's handle in order to leave them out.

DROP FUNCTION IF EXISTS dm_conversations();

CREATE OR REPLACE FUNCTION dm_conversations(
  p_limit  INTEGER DEFAULT 30,
  p_before BIGINT  DEFAULT NULL
) RETURNS JSONB
  LANGUAGE sql STABLE SECURITY INVOKER SET search_path = public AS $$
  WITH newest AS (
    SELECT DISTINCT ON (peer) *
      FROM (
        SELECT d.*,
               CASE WHEN d.sender_id = auth.uid()
                    THEN d.recipient_id ELSE d.sender_id END AS peer
          FROM dm_messages d
      ) paired
     ORDER BY peer, id DESC
  ),
  -- One row past the page, so "there is more" is proved rather than guessed
  -- from a full page. Same trick the message history and central use.
  page AS (
    SELECT * FROM newest
     WHERE p_before IS NULL OR id < p_before
     ORDER BY id DESC
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100) + 1
  ),
  kept AS (
    SELECT * FROM page
     ORDER BY id DESC
     LIMIT LEAST(GREATEST(COALESCE(p_limit, 30), 1), 100)
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
  'A page of DM conversations, newest activity first, as {conversations, '
  'has_more}. Keyset-paged on the newest message id: pass the last row''s '
  'message id as p_before for the next page. Ordering by id rather than by a '
  'timestamp is what makes the cursor exact — the list reorders itself every '
  'time somebody speaks, and an offset into it means something different a '
  'second later.';

REVOKE ALL ON FUNCTION dm_conversations(INTEGER, BIGINT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dm_conversations(INTEGER, BIGINT) TO authenticated;
