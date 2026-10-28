-- ============================================================
-- Rift self-hosted server — 024: only a bot draws a panel, edits included
-- ============================================================
-- `messages_insert` refuses `blocks` from anybody but a bot: a member posting
-- blocks would be a member posting an interface. The UPDATE grant names
-- `blocks` too, so a bot can redraw its panel, and `messages_update_own`
-- scopes an edit to the sender alone — which let a member write blocks onto
-- a plain message of their own after sending it, a command to a bot being the
-- one plain message a private channel holds. Since 023 such blocks could name
-- a call, and the row then read, and the files its `image` blocks named
-- opened, for everybody who could see that call, far outside the channel:
-- a member's interface in the bar of everyone in the call.
--
--   * `messages_blocks_by_bot` refuses a change to `blocks` on a row whose
--     sender is not a bot, whoever makes it.
--   * `app.check_panel_call` also drops `call` from such a row, so nothing
--     that writes one another way plays to a call.
--   * Blocks already on a row that is not a bot's are taken off.
-- ============================================================

-- Before the trigger, which would refuse it.
UPDATE messages m SET blocks = NULL
 WHERE m.blocks IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = m.sender_id AND u.is_bot);

CREATE OR REPLACE FUNCTION app.refuse_member_blocks() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NEW.blocks IS DISTINCT FROM OLD.blocks
     AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.sender_id AND u.is_bot) THEN
    RAISE EXCEPTION 'only_a_bot_draws_a_panel' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS messages_blocks_by_bot ON messages;
CREATE TRIGGER messages_blocks_by_bot BEFORE UPDATE OF blocks ON messages
  FOR EACH ROW EXECUTE FUNCTION app.refuse_member_blocks();

-- As in 023, plus the sender: a call is a bot's to name.
CREATE OR REPLACE FUNCTION app.check_panel_call() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_call UUID;
BEGIN
  IF NEW.blocks IS NULL OR NOT (NEW.blocks ? 'call') THEN
    RETURN NEW;
  END IF;
  v_call := app.panel_call(NEW.blocks);
  IF v_call IS NULL
     OR NEW.ephemeral_for IS NOT NULL
     OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.sender_id AND u.is_bot)
     OR NOT EXISTS (
       SELECT 1 FROM channels c
         JOIN channels here ON here.id = NEW.channel_id
        WHERE c.id = v_call
          AND c.channel_type = 'voice'
          AND c.server_id = here.server_id)
     OR NOT channel_joinable_by(v_call, NEW.sender_id) THEN
    NEW.blocks := NEW.blocks - 'call';
  END IF;
  RETURN NEW;
END $$;

-- ============================================================
-- Who may call them
-- ============================================================
REVOKE ALL ON FUNCTION app.refuse_member_blocks() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.check_panel_call() FROM PUBLIC, anon, authenticated;
