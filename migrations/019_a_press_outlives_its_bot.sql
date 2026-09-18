-- ============================================================
-- Rift self-hosted server — 019: a button press outlives its bot
-- ============================================================
-- `messages_action_shape` required an interaction to name the bot it was for.
-- `messages.to_bot` is `ON DELETE SET NULL`, so removing a bot tries to clear
-- that column on every row addressed to it — and on an interaction row, the
-- constraint refuses. Removing a bot that anybody had ever pressed a button on
-- failed, and so did deleting a server containing one: the delete cascades
-- through the same column.
--
-- Found by 018's tests, which are the first thing here ever to write an
-- interaction row.
--
-- The clause was never what kept a press honest anyway. `messages_insert`
-- already refuses one that names no bot: a member's press carries
-- `key_version = 0` and no key, which that policy only allows alongside a
-- `to_bot` that `app.is_addressable_bot` accepts, and a bot may not write an
-- interaction at all. What is left here is the shape itself — a press carries
-- an action and no key, and nothing else carries an action.

ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_action_shape;
ALTER TABLE messages ADD CONSTRAINT messages_action_shape CHECK (
  ((NOT is_interaction) OR (action_id IS NOT NULL AND key_version = 0))
  AND (is_interaction OR (action_id IS NULL AND action_value IS NULL))
);
