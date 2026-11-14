-- ============================================================
-- Rift self-hosted server — 028: no edits where you can't post
-- ============================================================
-- 027 let a channel take away posting (a Read-only channel), but
-- `messages_update_own` asked only that the row was yours and you weren't
-- timed out. So in a channel that had just gone Read-only, a member could
-- still rewrite their old messages into anything — saying something new, in
-- the one channel they had been told they can't. A time-out closed the same
-- way round already, for the same reason.
--
-- Now an edit also needs `SEND_MESSAGES` in the message's channel
-- (`app.has_channel_perm`, so the channel's rows count as well as the
-- server's), refused in WITH CHECK so the editor hears it was refused rather
-- than that the row was not there.
--
-- A bot is left out of the new check: it edits only to redraw a panel it
-- already posted (`blocks`, 024), and a Read-only channel is exactly where
-- an admin puts a bot's panel. Its posting stays under `messages_insert`.
-- ============================================================

DROP POLICY IF EXISTS messages_update_own ON messages;
CREATE POLICY messages_update_own ON messages FOR UPDATE TO authenticated
  USING (sender_id = auth.uid() AND app.can_see_channel(channel_id))
  WITH CHECK (
    sender_id = auth.uid()
    AND NOT app.timed_out()
    AND (app.is_bot() OR app.has_channel_perm(channel_id, 'SEND_MESSAGES'))
  );
