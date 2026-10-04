-- ============================================================
-- Rift self-hosted server — 009: the region key check runs as its owner
-- ============================================================
-- Adding a region failed on every real server with "permission denied for
-- table livekit_node_secrets", and so would renaming one.
--
-- `require_node_key` asks whether a region has a key of its own. Its trigger
-- is deferred, so it runs at COMMIT — after `add_voice_region` (SECURITY
-- DEFINER) has returned, and so as the administrator who called it. Members,
-- administrators included, are deliberately granted nothing on
-- `livekit_node_secrets`, so the question could not be asked. The policy suite
-- never commits, which is how it passed there; it now fires the check before
-- its ROLLBACK, as the caller, the way COMMIT does.
--
-- The fix is the function's, not the grant's: it becomes SECURITY DEFINER, so
-- it reads the table as its owner whoever's commit fires it. It only answers
-- whether a row exists, and a trigger function cannot be called directly, so
-- nothing about the keys becomes reachable.
-- ============================================================

CREATE OR REPLACE FUNCTION require_node_key()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF NEW.is_default THEN RETURN NEW; END IF;
  IF NOT EXISTS (SELECT 1 FROM livekit_node_secrets s WHERE s.node_id = NEW.id) THEN
    RAISE EXCEPTION 'A region needs its own LiveKit API key and secret'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END; $$;

REVOKE ALL ON FUNCTION require_node_key() FROM PUBLIC, anon, authenticated;
