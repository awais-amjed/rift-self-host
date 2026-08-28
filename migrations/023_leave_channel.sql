-- ============================================================
-- Rift self-hosted server — 023: walking out of a private channel
-- ============================================================
-- `set_channel_members` needs the manage bit, which is right for deciding who
-- else is in a room and wrong for deciding whether *you* are. A member who was
-- added to a private channel and would rather not be in it could not leave;
-- they could only ask the person who added them.
--
-- So: one function that removes exactly the caller and nobody else. There is no
-- target parameter, which is what makes it safe to hand to every member.
--
-- Two things it does not do, both deliberate:
--
--   * **It does not rotate the key.** It does not have to — leaving makes the
--     caller ineligible, and the sweep's standing signal is "somebody sealed
--     into the current version who is no longer entitled to it". The next
--     member's client rotates. What the leaver already read, they keep; nobody
--     can take that back, and pretending otherwise would be the lie.
--   * **It does not delete the channel itself.** `reassign_or_close_channel`
--     already handles the last person out, and handles the manage bit moving
--     on if the leaver was holding it.

CREATE OR REPLACE FUNCTION leave_channel(p_channel UUID) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_private BOOLEAN;
BEGIN
  SELECT is_private INTO v_private FROM channels
   WHERE id = p_channel AND server_id = app.server_id();
  IF NOT FOUND THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  -- Leaving a channel everyone can see would be a no-op with a button.
  IF NOT v_private THEN
    RETURN jsonb_build_object('reason', 'not_private');
  END IF;

  -- Access granted through a role is not the caller's to give up: deleting
  -- their own row would leave them in the room and the button looking broken,
  -- and dropping the role grant would take everybody else out with them.
  IF EXISTS (SELECT 1 FROM channel_role_access cra
               JOIN member_roles mr ON mr.role_id = cra.role_id
              WHERE cra.channel_id = p_channel AND mr.user_id = auth.uid()) THEN
    RETURN jsonb_build_object('reason', 'in_by_role');
  END IF;

  DELETE FROM channel_members
   WHERE channel_id = p_channel AND user_id = auth.uid();

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

REVOKE ALL ON FUNCTION leave_channel(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION leave_channel(UUID) TO authenticated;
