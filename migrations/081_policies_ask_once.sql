-- ============================================================
-- Rift self-hosted server — 081: the last policies that asked per row ask
-- once, and an index nothing needs goes
-- ============================================================
-- Found in the speed re-review, Nov 26 2026, as notes beside its findings.
--
-- A policy that calls a helper bare runs it once for every row the scan
-- reads. Written as a scalar subquery, `(SELECT app.server_id())`, Postgres
-- plans it as an InitPlan, run once for the statement and then a constant;
-- a question about the row's channel becomes set membership in the caller's
-- channels, `channel_id IN (SELECT unnest(app.visible_channels()))`, built
-- once and tested by hash. That is the shape the rest of the policies took
-- before (see `app.visible_channels`), and these were left behind:
--
--   * `app.server_id()` bare: `soundboard_select`, `livekit_nodes_read`,
--     `invites_select_admin`, `invites_select_own`, `webhooks_select`.
--   * `app.can_see_channel(channel_id)` per row: `voice_rooms_read`,
--     `bot_voice_grants_select`, `bot_voice_summons_select`,
--     `bot_channel_keys_select`, `channel_overrides_select`.
--
-- `app.visible_channels()` answers the same channels `can_see_channel`
-- says yes to — the server's, public or the caller let in — so who sees
-- what does not change. All of these tables are small, and 071 made each
-- call cheap; this is the last of the per-row calls, not a fix for a slow
-- page. `invites_select_admin` still asks `app.may_assign_role` per row,
-- since that is about the row's role.
--
-- `idx_users_server (server_id)` is covered by the whole-table indexes on
-- `users` that lead with `server_id` (`idx_users_server_sorted` and the
-- prefix-search ones), which also serve the cascade when a server is
-- deleted; each write to `users` kept it for nothing.

-- ── Asked once ──────────────────────────────────────────────
ALTER POLICY soundboard_select ON soundboard_sounds
  USING (server_id = (SELECT app.server_id()));

ALTER POLICY livekit_nodes_read ON livekit_nodes
  USING (server_id = (SELECT app.server_id()));

ALTER POLICY invites_select_admin ON invites
  USING (
    server_id = (SELECT app.server_id()) AND (SELECT app.is_admin())
    AND (role_id IS NULL OR app.may_assign_role(role_id))
  );

ALTER POLICY invites_select_own ON invites
  USING (server_id = (SELECT app.server_id()) AND created_by = (SELECT auth.uid()));

ALTER POLICY webhooks_select ON webhooks
  USING (server_id = (SELECT app.server_id()) AND (SELECT app.can_manage_webhooks()));

ALTER POLICY voice_rooms_read ON voice_rooms
  USING (channel_id IN (SELECT unnest(app.visible_channels())));

ALTER POLICY bot_voice_grants_select ON bot_voice_grants
  USING (channel_id IN (SELECT unnest(app.visible_channels())));

ALTER POLICY bot_voice_summons_select ON bot_voice_summons
  USING (channel_id IN (SELECT unnest(app.visible_channels()))
         OR bot_id = (SELECT auth.uid()));

ALTER POLICY bot_channel_keys_select ON bot_channel_keys
  USING (channel_id IN (SELECT unnest(app.visible_channels()))
         OR bot_id = (SELECT auth.uid()));

ALTER POLICY channel_overrides_select ON channel_overrides
  USING (channel_id IN (SELECT unnest(app.visible_channels())));

-- ── An index nothing needs ──────────────────────────────────
DROP INDEX IF EXISTS idx_users_server;
