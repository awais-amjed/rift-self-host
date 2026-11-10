-- ============================================================
-- Rift self-hosted server — 026: a read on one device reaches the others
-- ============================================================
-- Read cursors were always kept here (`read_state`), so a channel read on the
-- phone *was* read. But nothing told the desktop: it re-counted only when it
-- started, when a notification level changed, or when an unread message was
-- edited. Its badge stayed until the channel was opened there too.
--
--   * A cursor that moves forward is told to its owner's own topic as `read`,
--     the way a notification level already is (`prefs`). Every device of that
--     person hears it and counts again; one that already shows nothing unread
--     there need not.
--
-- Told per statement rather than per row. "Mark all as read" moves a cursor in
-- every channel at once, and a row each would be a broadcast per channel for
-- one click. A statement that moved one cursor names it (`scope`, `scope_id`,
-- `last_read_id`); one that moved several says only `{}`, which means "count
-- everything again". A write that moved nothing — `mark_read` on a
-- conversation already read, which the app does on every focus — says nothing.
-- ============================================================

CREATE OR REPLACE FUNCTION app.announce_read() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_row RECORD;
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;

  -- Two branches rather than one query: `old_rows` exists only for an UPDATE,
  -- and PL/pgSQL plans a statement only when it reaches it.
  IF TG_OP = 'INSERT' THEN
    FOR v_row IN
      SELECT n.user_id, count(*) AS moved,
             min(n.scope::TEXT) AS scope, min(n.scope_id::TEXT) AS scope_id,
             max(n.last_read_id) AS last_read_id
        FROM new_rows n
       WHERE n.last_read_id > 0
       GROUP BY n.user_id
    LOOP
      PERFORM realtime.send(
        CASE WHEN v_row.moved = 1 THEN jsonb_build_object(
               'scope', v_row.scope, 'scope_id', v_row.scope_id,
               'last_read_id', v_row.last_read_id)
             ELSE '{}'::JSONB END,
        'read', 'user:' || v_row.user_id, true);
    END LOOP;
  ELSE
    FOR v_row IN
      SELECT n.user_id, count(*) AS moved,
             min(n.scope::TEXT) AS scope, min(n.scope_id::TEXT) AS scope_id,
             max(n.last_read_id) AS last_read_id
        FROM new_rows n
        JOIN old_rows o USING (user_id, scope, scope_id)
       WHERE n.last_read_id > o.last_read_id
       GROUP BY n.user_id
    LOOP
      PERFORM realtime.send(
        CASE WHEN v_row.moved = 1 THEN jsonb_build_object(
               'scope', v_row.scope, 'scope_id', v_row.scope_id,
               'last_read_id', v_row.last_read_id)
             ELSE '{}'::JSONB END,
        'read', 'user:' || v_row.user_id, true);
    END LOOP;
  END IF;
  RETURN NULL;
END $$;

COMMENT ON FUNCTION app.announce_read() IS
  'Tells a person''s own topic that a read cursor of theirs moved forward, so '
  'their other devices clear the badge. One broadcast per statement and person: '
  'the cursor when one moved, {} when several did.';

-- Two triggers, because a trigger with transition tables may have one event.
-- `mark_read`'s upsert fires the INSERT one for a new cursor and the UPDATE one
-- for an existing cursor; each sees only its own rows.
DROP TRIGGER IF EXISTS read_state_announce_insert ON read_state;
CREATE TRIGGER read_state_announce_insert
  AFTER INSERT ON read_state
  REFERENCING NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION app.announce_read();

DROP TRIGGER IF EXISTS read_state_announce_update ON read_state;
CREATE TRIGGER read_state_announce_update
  AFTER UPDATE ON read_state
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
  FOR EACH STATEMENT EXECUTE FUNCTION app.announce_read();

REVOKE ALL ON FUNCTION app.announce_read() FROM PUBLIC, anon, authenticated;
