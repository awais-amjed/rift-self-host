-- ============================================================
-- Rift self-hosted server — 074: a read that moves nothing writes nothing
-- ============================================================
-- Found in the speed re-review, Nov 26 2026.
--
-- `mark_read` runs on every channel opened and every window focus, and most
-- of those find the cursor already where it is asked to go. Its upsert then
-- updated nothing, but `ON CONFLICT DO UPDATE` still locks the row it
-- conflicts with, and a lock is a write: the call took a transaction id and
-- its commit waited for the log to reach disk (`app.claim_voice_node` had the
-- same cost, 065). It now reads the cursor first and answers from that when
-- there is nowhere to move; the upsert, with its guard, is unchanged for the
-- rest.
--
-- `mark_all_read` rewrote every one of the caller's channel cursors, moved or
-- not. It now writes only those behind, and its updates carry the same guard.
--
-- Both looked for a channel's newest message under the caller's own row
-- security. Where the caller sees none of the channel — a private channel
-- they are not in, a banned member, a bot outside its grants — the planner,
-- expecting the newest row near the top of `messages`, walked every row of
-- the table and kept none: 13 s for one `mark_read` with no id on a server of
-- 5 M messages, 100 s for a bot's `mark_all_read`, as often as anyone with a
-- token liked. `mark_read` now looks only in a channel the caller can see,
-- and answers 0 elsewhere as before; `mark_all_read` keeps no channel
-- cursors for a bot, which keeps none anyway.

-- ── One cursor ──────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.mark_read(
  p_scope read_scope, p_scope_id UUID, p_last_read_id BIGINT DEFAULT 0)
  RETURNS BIGINT
  LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
  v_me     UUID   := auth.uid();
  v_target BIGINT := p_last_read_id;
  v_now    BIGINT;
BEGIN
  IF v_me IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  IF v_target <= 0 THEN
    IF p_scope = 'channel' THEN
      -- Only where some of it is to be seen: elsewhere the search reads the
      -- whole table to find nothing.
      IF NOT app.is_bot() AND p_scope_id = ANY (app.visible_channels()) THEN
        SELECT COALESCE(max(m.id), 0) INTO v_target
          FROM messages m WHERE m.channel_id = p_scope_id;
      ELSE
        v_target := 0;
      END IF;
    ELSE
      v_target := COALESCE(app.dm_newest_from(p_scope_id), 0);
    END IF;
  END IF;

  -- Already there or past it: answer, and take no lock.
  SELECT r.last_read_id INTO v_now
    FROM read_state r
   WHERE r.user_id = v_me AND r.scope = p_scope AND r.scope_id = p_scope_id;
  IF v_now >= v_target THEN
    RETURN v_now;
  END IF;
  v_now := NULL;

  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
       VALUES (v_me, p_scope, p_scope_id, v_target)
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
          SET last_read_id = EXCLUDED.last_read_id,
              updated_at   = now()
        WHERE read_state.last_read_id < EXCLUDED.last_read_id
    RETURNING last_read_id INTO v_now;

  -- Nothing written: another call moved it there, or past it, meanwhile.
  IF v_now IS NULL THEN
    SELECT r.last_read_id INTO v_now
      FROM read_state r
     WHERE r.user_id = v_me AND r.scope = p_scope AND r.scope_id = p_scope_id;
  END IF;
  RETURN v_now;
END $$;

-- ── Every cursor ────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.mark_all_read()
  RETURNS VOID
  LANGUAGE plpgsql SET search_path = public AS $$
DECLARE
  v_me UUID := auth.uid();
BEGIN
  IF v_me IS NULL THEN
    RAISE EXCEPTION 'not_authenticated';
  END IF;

  -- The channels whose newest is past the cursor, or that have none yet.
  IF NOT app.is_bot() THEN
    INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
    SELECT v_me, 'channel', c.id, n.id
      FROM channels c
     CROSS JOIN LATERAL (SELECT COALESCE(max(m.id), 0) AS id
                           FROM messages m WHERE m.channel_id = c.id) n
      LEFT JOIN read_state r
        ON r.user_id = v_me AND r.scope = 'channel' AND r.scope_id = c.id
     WHERE r.user_id IS NULL OR r.last_read_id < n.id
    ON CONFLICT (user_id, scope, scope_id) DO UPDATE
       SET last_read_id = EXCLUDED.last_read_id,
           updated_at   = now()
     WHERE read_state.last_read_id < EXCLUDED.last_read_id;
  END IF;

  WITH peers AS (
    SELECT h.peer_id AS peer
      FROM dm_conversation_heads h
      LEFT JOIN read_state r
        ON r.user_id = v_me AND r.scope = 'dm' AND r.scope_id = h.peer_id
     WHERE h.user_id = v_me
       AND h.last_message_id > COALESCE(r.last_read_id, 0)
    UNION
    SELECT q.peer FROM app.dm_requests_to_me() AS q(peer)
  ), newest AS MATERIALIZED (
    SELECT p.peer, app.dm_newest_from(p.peer) AS id FROM peers p
  )
  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  SELECT v_me, 'dm', n.peer, n.id
    FROM newest n
   WHERE n.id IS NOT NULL
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE
     SET last_read_id = EXCLUDED.last_read_id,
         updated_at   = now()
   WHERE read_state.last_read_id < EXCLUDED.last_read_id;
END $$;

-- ── Grants ──────────────────────────────────────────────────
-- Unchanged by a replace; restated so this file says who may call them.
REVOKE ALL ON FUNCTION public.mark_read(read_scope, UUID, BIGINT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mark_read(read_scope, UUID, BIGINT) TO authenticated;
REVOKE ALL ON FUNCTION public.mark_all_read() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mark_all_read() TO authenticated;
