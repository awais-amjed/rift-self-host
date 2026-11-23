-- ============================================================
-- Rift self-hosted server — 035: stop a ring without ending a call
-- ============================================================
-- Found in the app's review of DM calls, Nov 22 2026.
--
-- `end_dm_call` hangs up in any state, which is right for a hang-up and wrong
-- for the three things that only mean "stop ringing": the callee's Decline,
-- the caller's thirty seconds running out, and a ring dismissed from a
-- notification. Each of those can land a moment after the call was answered —
-- Decline pressed on the phone just after answering on the PC, or the caller's
-- timer firing while the answer is on its way — and then it ended a call
-- somebody was in.
--
-- The app asked `my_dm_calls` first and ended the call only if it was still
-- unanswered, which left the gap of one round trip between the question and
-- the hang-up. `end_dm_ring` closes it: the same hang-up under the same row
-- lock as `answer_dm_call`, ending the call only while it is unanswered. An
-- answered call comes back as it stands, so the caller learns it was picked
-- up and stays in it.
--
-- An app reading a server without this function falls back to asking first.
-- ============================================================

CREATE OR REPLACE FUNCTION end_dm_ring(p_call UUID) RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_me   UUID := auth.uid();
  v_call dm_calls%ROWTYPE;
BEGIN
  IF app.server_id() IS NULL THEN RAISE EXCEPTION 'not_authorized'; END IF;

  -- The lock `answer_dm_call` takes, so the two cannot cross: whichever
  -- comes second sees what the first did.
  SELECT * INTO v_call FROM dm_calls c WHERE c.id = p_call FOR UPDATE;
  IF NOT FOUND OR v_me NOT IN (v_call.caller_id, v_call.callee_id) THEN
    RAISE EXCEPTION 'call_not_found';
  END IF;
  IF v_call.ended_at IS NOT NULL OR v_call.answered_at IS NOT NULL THEN
    RETURN app.dm_call_json(v_call, v_me);
  END IF;

  UPDATE dm_calls c
     SET ended_at = now(),
         outcome  = CASE
           WHEN v_me = c.callee_id        THEN 'declined'::dm_call_outcome
           WHEN c.started_at <= now() - app.dm_call_missed_after()
                                          THEN 'missed'::dm_call_outcome
           ELSE 'cancelled'::dm_call_outcome END
   WHERE c.id = p_call
  RETURNING * INTO v_call;
  RETURN app.dm_call_json(v_call, v_me);
END; $$;

COMMENT ON FUNCTION end_dm_ring(UUID) IS
  'Stop a DM call ringing: end it only while unanswered (declined, missed or '
  'cancelled), and answer an answered or ended call as it stands.';

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION end_dm_ring(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION end_dm_ring(UUID) TO authenticated;
