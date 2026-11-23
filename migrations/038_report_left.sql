-- ============================================================
-- Rift self-hosted server — 038: a report is never closed as a kick for
-- somebody who left
-- ============================================================
-- Found in the app's review of moderation, Nov 22 2026.
--
-- Leaving is a kick by your own hand (`leave_server`, 020): the same
-- `is_banned` with `kicked_at`, and `left_at` beside it to tell the two apart.
-- `resolve_report` checks an outcome happened before recording it, and its
-- check for `kicked` asked only for `kicked_at`. So a report about somebody
-- who had left could be closed as "Kicked", a record of a moderator doing
-- something nobody did — and the app offered exactly that, saying the member
-- "was kicked".
--
-- Now `kicked` needs `left_at` empty as well. A report about somebody who
-- left is closed as what the reviewer does about it: dismissed, or banned
-- (a ban turns the leave into a ban, clearing both, which keeps them out for
-- good). The rest of the function is as 003 left it.
-- ============================================================

CREATE OR REPLACE FUNCTION resolve_report(
  p_report  BIGINT,
  p_outcome report_outcome
) RETURNS INTEGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_report reports%ROWTYPE;
  v_closed INTEGER;
BEGIN
  IF NOT app.has_perm('REVIEW_REPORTS') THEN RAISE EXCEPTION 'not_authorized'; END IF;
  IF p_outcome IS NULL THEN RAISE EXCEPTION 'outcome_required'; END IF;

  SELECT * INTO v_report FROM reports
   WHERE id = p_report AND server_id = app.server_id()
     AND target_id IS DISTINCT FROM auth.uid()
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'report_not_found'; END IF;
  IF v_report.outcome IS NOT NULL THEN RAISE EXCEPTION 'already_resolved'; END IF;

  IF p_outcome = 'deleted' AND (v_report.message_id IS NULL
       OR EXISTS (SELECT 1 FROM messages m WHERE m.id = v_report.message_id)) THEN
    RAISE EXCEPTION 'outcome_not_done';
  END IF;
  IF p_outcome = 'timed_out' AND NOT EXISTS (
       SELECT 1 FROM users u WHERE u.id = v_report.target_id
          AND u.timed_out_until > now()) THEN
    RAISE EXCEPTION 'outcome_not_done';
  END IF;
  IF p_outcome = 'banned' AND NOT EXISTS (
       SELECT 1 FROM users u WHERE u.id = v_report.target_id AND u.is_banned
          AND u.kicked_at IS NULL) THEN
    RAISE EXCEPTION 'outcome_not_done';
  END IF;
  -- Kicked by a moderator, not gone by their own hand: a kick and a leave
  -- are both `kicked_at`, and `left_at` beside it says which (020).
  IF p_outcome = 'kicked' AND NOT EXISTS (
       SELECT 1 FROM users u WHERE u.id = v_report.target_id AND u.is_banned
          AND u.kicked_at IS NOT NULL AND u.left_at IS NULL) THEN
    RAISE EXCEPTION 'outcome_not_done';
  END IF;

  UPDATE reports r
     SET outcome = p_outcome, resolved_by = auth.uid(), resolved_at = now()
   WHERE r.server_id = v_report.server_id
     AND r.outcome IS NULL
     AND r.target_id IS DISTINCT FROM auth.uid()
     AND (r.id = p_report
          OR (p_outcome = 'deleted' AND r.message_id = v_report.message_id)
          OR (p_outcome IN ('banned', 'kicked')
              AND r.target_id = v_report.target_id));
  GET DIAGNOSTICS v_closed = ROW_COUNT;
  RETURN v_closed;
END; $$;

-- CREATE OR REPLACE keeps the grants the baseline gave it (authenticated
-- only), so there is nothing to revoke or grant again here.
