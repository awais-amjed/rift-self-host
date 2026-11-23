-- ============================================================
-- Rift self-hosted server — 039: a DM rings its sender's devices too
-- ============================================================
-- Found in the app's review of server DMs, Nov 21 2026.
--
-- `app.announce_dm` rang only the recipient, on the reasoning that "only the
-- sender can make an edit or a delete, and the sender already knows". The
-- device that sent it does; the sender's *other* devices do not, and a
-- message sent, edited or deleted from the phone stayed as it was on the
-- desktop until something else made it read the conversation again.
-- Reactions and pins already ring both people (`announce_reaction`,
-- `pin_dm_message`).
--
-- So now:
--   * a new DM rings the sender's own topic as `dm_sent`, `{id,
--     recipient_id}`. Not `dm`: an app reads `dm` as mail arriving from
--     `sender_id` and counts it unread, and an app from before this would
--     count the sender's own message as unread from themselves. An older app
--     ignores an event it does not know.
--   * an edit or a delete rings `dm_changed` on both topics. That one is only
--     "read it again", which an older app already does with it.
-- A request rings the recipient as before (`dm_requests`), and the sender's
-- devices as `dm_sent`, since the conversation it opens is theirs to list.
-- ============================================================

CREATE OR REPLACE FUNCTION app.announce_dm() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.realtime_ready() THEN
    RETURN NULL;
  END IF;
  -- A request is announced under its own name, so a client adds to the
  -- Requests badge rather than opening a conversation the recipient has not
  -- accepted.
  IF TG_OP = 'INSERT' AND app.dm_is_request(NEW.sender_id, NEW.recipient_id) THEN
    PERFORM realtime.send(jsonb_build_object('sender_id', NEW.sender_id),
      'dm_requests', 'user:' || NEW.recipient_id, true);
  ELSIF TG_OP = 'INSERT' THEN
    PERFORM realtime.send(
      jsonb_build_object('id', NEW.id, 'sender_id', NEW.sender_id),
      'dm', 'user:' || NEW.recipient_id, true);
  END IF;

  IF TG_OP = 'INSERT' THEN
    -- The sender's other devices. The one that sent it hears this too, and
    -- reads nothing it does not already have.
    PERFORM realtime.send(
      jsonb_build_object('id', NEW.id, 'recipient_id', NEW.recipient_id),
      'dm_sent', 'user:' || NEW.sender_id, true);
  ELSIF TG_OP = 'UPDATE' THEN
    PERFORM realtime.send(jsonb_build_object('message_id', NEW.id),
      'dm_changed', 'user:' || NEW.recipient_id, true);
    PERFORM realtime.send(jsonb_build_object('message_id', NEW.id),
      'dm_changed', 'user:' || NEW.sender_id, true);
  ELSE
    PERFORM realtime.send(jsonb_build_object('message_id', OLD.id),
      'dm_changed', 'user:' || OLD.recipient_id, true);
    PERFORM realtime.send(jsonb_build_object('message_id', OLD.id),
      'dm_changed', 'user:' || OLD.sender_id, true);
  END IF;
  RETURN NULL;
END $$;

-- CREATE OR REPLACE keeps the revokes 008 gave it; the trigger is unchanged.
