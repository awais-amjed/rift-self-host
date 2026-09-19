-- ============================================================
-- Rift self-hosted server — 008: grants, RLS, and every policy
-- ============================================================
-- Who may read and write what. This is the whole security surface in one
-- file, deliberately: a policy that lives beside the feature that needed it
-- is a policy nobody reads next to the twelve others on the same table.
--
-- Two things Supabase does by default make this file longer than it looks
-- like it should be, and both are load-bearing:
--
--   * a new table in `public` arrives readable **and writable** by
--     `authenticated`, so every grant here is preceded by a revoke;
--   * a new function arrives executable by PUBLIC.
--
-- So nothing is granted by omission. The default privileges set at the top
-- close the door for anything added later without being listed here.
-- ============================================================

GRANT USAGE ON SCHEMA app TO authenticated;

-- ============================================================
-- 2. Grants
-- ============================================================

-- Nothing unauthenticated, ever — including tables added later.
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM anon;

REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon;

-- Start from nothing for members too, then hand back exactly what the client
-- needs. RLS decides *which rows*; these decide *which columns and verbs*.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authenticated;

-- Read-only. Renaming a server is done through `update_server`, which is an
-- edge function because the same dialog writes the LiveKit API secret — and
-- that has no client-reachable path at all.
GRANT SELECT                       ON servers  TO authenticated;

GRANT SELECT                       ON users    TO authenticated;

-- Your own profile, and nothing else on the row: moderation flags and
-- permissions are not yours to write, they go through the RPCs in 003.
GRANT UPDATE (display_name, chat_public_key, avatar_path) ON users TO authenticated;

GRANT SELECT, INSERT, DELETE       ON channels TO authenticated;

GRANT SELECT, INSERT, DELETE       ON invites  TO authenticated;

GRANT SELECT, INSERT, DELETE       ON messages TO authenticated;

GRANT UPDATE (ciphertext, nonce, signature, key_version) ON messages TO authenticated;

GRANT SELECT, INSERT, DELETE       ON dm_messages TO authenticated;

GRANT UPDATE (ciphertext, nonce, signature, key_version) ON dm_messages TO authenticated;

GRANT USAGE ON SEQUENCE messages_id_seq    TO authenticated;

GRANT USAGE ON SEQUENCE dm_messages_id_seq TO authenticated;

GRANT SELECT, INSERT, DELETE       ON message_reactions    TO authenticated;

GRANT SELECT, INSERT, DELETE       ON dm_message_reactions TO authenticated;

-- A keyring row is written once and never edited: a rewrap is a new version.
GRANT SELECT, INSERT               ON channel_keyring TO authenticated;

GRANT SELECT, INSERT               ON read_state TO authenticated;

GRANT UPDATE (last_read_id, updated_at) ON read_state TO authenticated;

CREATE POLICY invites_select_own ON invites FOR SELECT TO authenticated
  USING (server_id = app.server_id() AND created_by = auth.uid());

CREATE POLICY invites_delete_own ON invites FOR DELETE TO authenticated
  USING (server_id = app.server_id() AND created_by = auth.uid());

CREATE POLICY dm_messages_insert ON dm_messages FOR INSERT TO authenticated
  WITH CHECK (sender_id = auth.uid() AND app.can_receive_dm(recipient_id));

CREATE POLICY dm_messages_update_own ON dm_messages FOR UPDATE TO authenticated
  USING (sender_id = auth.uid()) WITH CHECK (sender_id = auth.uid());

CREATE POLICY dm_messages_delete_own ON dm_messages FOR DELETE TO authenticated
  USING (sender_id = auth.uid());

CREATE POLICY message_reactions_select ON message_reactions FOR SELECT TO authenticated
  USING (app.can_see_message(message_id));

CREATE POLICY message_reactions_insert ON message_reactions FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid() AND app.can_see_message(message_id));

CREATE POLICY message_reactions_delete_own ON message_reactions FOR DELETE TO authenticated
  USING (user_id = auth.uid());

CREATE POLICY dm_reactions_select ON dm_message_reactions FOR SELECT TO authenticated
  USING (app.can_see_dm(message_id));

CREATE POLICY dm_reactions_insert ON dm_message_reactions FOR INSERT TO authenticated
  WITH CHECK (user_id = auth.uid() AND app.can_see_dm(message_id));

CREATE POLICY dm_reactions_delete_own ON dm_message_reactions FOR DELETE TO authenticated
  USING (user_id = auth.uid());

-- ============================================================
-- Function privileges
-- ============================================================
-- Postgres grants EXECUTE to PUBLIC by default, which would expose
-- register_user to anyone. Same discipline as the tables: revoke everything,
-- then hand back only what a member is meant to call.

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION new_invite_code()        TO authenticated;

GRANT EXECUTE ON FUNCTION mark_read(read_scope, UUID, BIGINT) TO authenticated;

GRANT EXECUTE ON FUNCTION mark_all_read()          TO authenticated;

GRANT EXECUTE ON FUNCTION moderate_user(UUID, BOOLEAN, BOOLEAN, BOOLEAN) TO authenticated;

-- Additive to the UPDATE (name) grant above. Who may write is still decided by
-- `channels_update_managers`; this only widens which columns their UPDATE may
-- name.
GRANT UPDATE (retention_days, history_cap) ON channels TO authenticated;

REVOKE ALL ON FUNCTION app.sync_server_bucket(UUID, BIGINT)
  FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.orphaned_attachments(INTERVAL)
  FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION sweep_attachments(INTEGER) FROM PUBLIC, anon, authenticated;

GRANT EXECUTE ON FUNCTION sweep_attachments(INTEGER) TO service_role;

REVOKE ALL ON FUNCTION app.enforce_retention() FROM PUBLIC, anon, authenticated;

REVOKE ALL ON device_tokens FROM anon;

GRANT SELECT, INSERT, UPDATE, DELETE ON device_tokens TO authenticated;

REVOKE ALL ON push_config FROM anon, authenticated;

REVOKE ALL ON notification_prefs FROM anon;

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_prefs TO authenticated;

-- New tables arrive writable by `authenticated` and new functions executable by
-- PUBLIC. Neither default is wanted here.
REVOKE ALL ON webhooks FROM anon, authenticated;

-- No INSERT and no UPDATE grant at all: creating one has to mint a secret, and
-- a secret the caller chose is not a secret. That goes through create_webhook.
-- SELECT is column-scoped so `secret_hash` never leaves the database, even to
-- the admin who made it.
GRANT SELECT (id, created_at, server_id, channel_id, created_by, name,
              last_used_at)
  ON webhooks TO authenticated;

GRANT DELETE ON webhooks TO authenticated;

CREATE POLICY webhooks_select ON webhooks FOR SELECT TO authenticated
  USING (server_id = app.server_id() AND app.can_manage_channels());

CREATE POLICY webhooks_delete ON webhooks FOR DELETE TO authenticated
  USING (server_id = app.server_id() AND app.can_manage_channels());

REVOKE ALL ON FUNCTION create_webhook(UUID, TEXT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION create_webhook(UUID, TEXT) TO authenticated;

REVOKE ALL ON FUNCTION new_webhook_secret() FROM PUBLIC;

-- Not `authenticated`, and certainly not PUBLIC: the only caller is the edge
-- function holding the service key. A member reaching this would be able to
-- post under any name in any channel by guessing a secret, without the rate
-- limit ever having to be right.
REVOKE ALL ON FUNCTION post_webhook_message(TEXT, TEXT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION post_webhook_message(TEXT, TEXT) TO service_role;

-- A bot maintains its own; nobody maintains anybody else's. Added to the
-- existing column grant rather than replacing it — `display_name`,
-- `chat_public_key` and `avatar_path` stay exactly as they were.
GRANT UPDATE (manifest) ON users TO authenticated;

REVOKE ALL ON FUNCTION grant_bot_channel_key(UUID, UUID)  FROM PUBLIC;

REVOKE ALL ON FUNCTION revoke_bot_channel_key(UUID, UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION grant_bot_channel_key(UUID, UUID)  TO authenticated;

GRANT EXECUTE ON FUNCTION revoke_bot_channel_key(UUID, UUID) TO authenticated;

REVOKE ALL ON bot_channel_keys FROM anon, authenticated;

-- Readable by every member of the server, which is rule 4. Writing goes
-- through the two functions above; there is no INSERT, UPDATE or DELETE grant,
-- so "who may listen" cannot be changed by anything that skipped the check.
GRANT SELECT ON bot_channel_keys TO authenticated;

GRANT SELECT ON channel_bot_listeners TO authenticated;

REVOKE ALL ON roles        FROM anon, authenticated;

REVOKE ALL ON member_roles FROM anon, authenticated;

-- Who holds what is not a secret from the people it is exercised on.
GRANT SELECT                ON roles        TO authenticated;

GRANT INSERT, DELETE        ON roles        TO authenticated;

-- `server_id`, `is_everyone` and `legacy_key` are absent on purpose: they are
-- what a role *is*, not how it is configured, and a member with `MANAGE_ROLES`
-- moving a role to another server or claiming the baseline is not an edit.
GRANT UPDATE (name, color, position, permissions) ON roles TO authenticated;

GRANT SELECT, INSERT, DELETE ON member_roles TO authenticated;

-- `register_user` is the service role's, and it is not SECURITY DEFINER — it
-- runs as whoever called it, and it reaches into the `app` schema. Every other
-- grant of that schema is to `authenticated`, so without this one registration
-- fails with `permission denied for schema app`.
GRANT USAGE ON SCHEMA app TO service_role;

REVOKE ALL ON FUNCTION refuse_everyone_assignment()      FROM PUBLIC;

REVOKE ALL ON FUNCTION protect_everyone_role()           FROM PUBLIC;

REVOKE ALL ON FUNCTION sync_member_permission_cache()    FROM PUBLIC;

REVOKE ALL ON FUNCTION sync_role_permission_cache()      FROM PUBLIC;

REVOKE ALL ON FUNCTION seed_default_roles()              FROM PUBLIC;

CREATE POLICY roles_insert ON roles FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND NOT is_everyone
    AND app.may_manage_role(position)
    AND app.may_hold_perms(permissions)
  );

CREATE POLICY roles_update ON roles FOR UPDATE TO authenticated
  USING (server_id = app.server_id() AND app.may_manage_role(position))
  WITH CHECK (
    server_id = app.server_id()
    AND app.may_manage_role(position)
    AND app.may_hold_perms(permissions)
  );

CREATE POLICY roles_delete ON roles FOR DELETE TO authenticated
  USING (server_id = app.server_id() AND app.may_manage_role(position));

CREATE POLICY member_roles_insert ON member_roles FOR INSERT TO authenticated
  WITH CHECK (
    app.may_assign_role(role_id)
    AND (granted_by IS NULL OR granted_by = auth.uid())
    AND EXISTS (SELECT 1 FROM users u
                 WHERE u.id = member_roles.user_id
                   AND u.server_id = app.server_id())
  );

CREATE POLICY channels_write_managers ON channels FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND (CASE WHEN is_private THEN app.has_perm('CREATE_PRIVATE_CHANNEL')
              ELSE app.has_perm('MANAGE_CHANNELS') END)
  );

CREATE POLICY channels_update_managers ON channels FOR UPDATE TO authenticated
  USING (app.can_manage_channel(id)) WITH CHECK (app.can_manage_channel(id));

CREATE POLICY channels_delete_managers ON channels FOR DELETE TO authenticated
  USING (app.can_manage_channel(id));

CREATE POLICY messages_update_own ON messages FOR UPDATE TO authenticated
  USING (sender_id = auth.uid() AND app.can_see_channel(channel_id))
  WITH CHECK (sender_id = auth.uid());

CREATE POLICY messages_delete ON messages FOR DELETE TO authenticated
  USING (
    app.can_see_channel(channel_id)
    AND (sender_id = auth.uid()
         OR app.has_perm('MANAGE_MESSAGES')
         OR app.can_manage_channel(channel_id))
  );

CREATE POLICY channel_keyring_insert ON channel_keyring FOR INSERT TO authenticated
  WITH CHECK (
    wrapped_by = auth.uid()
    AND app.can_see_channel(channel_id)
    AND app.channel_eligible(channel_id, user_id)
  );

REVOKE ALL ON channel_members     FROM anon, authenticated;

REVOKE ALL ON channel_role_access FROM anon, authenticated;

-- Readable by the room, and by nobody else — including an administrator, who
-- would learn who is talking to whom and could not read a word of it anyway.
-- No write grant at all: membership moves through the functions above, so
-- "who is in this room" cannot be changed by anything that skipped the check.
GRANT SELECT ON channel_members     TO authenticated;

GRANT SELECT ON channel_role_access TO authenticated;

REVOKE ALL ON FUNCTION refuse_ineligible_keyring()        FROM PUBLIC;

REVOKE ALL ON FUNCTION reassign_or_close_channel()        FROM PUBLIC;

REVOKE ALL ON FUNCTION set_channel_private(UUID, BOOLEAN) FROM PUBLIC;

REVOKE ALL ON FUNCTION set_channel_members(UUID, UUID[])  FROM PUBLIC;

REVOKE ALL ON FUNCTION set_channel_role_access(UUID, UUID, BOOLEAN) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION set_channel_private(UUID, BOOLEAN) TO authenticated;

GRANT EXECUTE ON FUNCTION set_channel_members(UUID, UUID[])  TO authenticated;

GRANT EXECUTE ON FUNCTION set_channel_role_access(UUID, UUID, BOOLEAN) TO authenticated;

REVOKE ALL ON FUNCTION seed_private_channel_owner() FROM PUBLIC;

-- `is_private` is not in the UPDATE grant: opening or closing a room is
-- `set_channel_private`, which knows that opening one has to leave a rotation
-- behind it. A plain UPDATE would not, and the channel would quietly hand its
-- private history to the next person who joined the server.
GRANT UPDATE (name) ON channels TO authenticated;

-- Deliberately no grant to `authenticated`. A member reads their own keyring
-- through `get_channel_key`, which returns only what is sealed to them.
REVOKE ALL ON channel_eligible_members FROM anon, authenticated;

REVOKE ALL ON FUNCTION channel_visible_to(UUID, UUID) FROM PUBLIC;

REVOKE ALL ON FUNCTION visible_channels(UUID)         FROM PUBLIC;

GRANT EXECUTE ON FUNCTION channel_visible_to(UUID, UUID) TO service_role;

GRANT EXECUTE ON FUNCTION visible_channels(UUID)         TO service_role;

REVOKE ALL ON FUNCTION user_has_permission(UUID, TEXT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION user_has_permission(UUID, TEXT) TO service_role;

REVOKE ALL ON FUNCTION my_permissions() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION my_permissions() TO authenticated;

REVOKE ALL ON FUNCTION create_channel(TEXT, TEXT, BOOLEAN, UUID[]) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION create_channel(TEXT, TEXT, BOOLEAN, UUID[]) TO authenticated;

REVOKE ALL ON FUNCTION leave_channel(UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION leave_channel(UUID) TO authenticated;

GRANT INSERT (server_id, created_by, code, max_uses, expires_at, is_bot, role_id)
  ON invites TO authenticated;

CREATE POLICY member_roles_delete ON member_roles FOR DELETE TO authenticated
  USING (
    app.may_assign_role(role_id)
    AND EXISTS (SELECT 1 FROM users u
                 WHERE u.id = member_roles.user_id
                   AND u.server_id = app.server_id())
    -- Somebody else's, or one you genuinely stand above.
    AND (member_roles.user_id <> auth.uid()
         OR EXISTS (SELECT 1 FROM roles r
                     WHERE r.id = member_roles.role_id
                       AND r.position < app.max_role_position()))
  );

REVOKE ALL ON FUNCTION app.post_system_message(UUID, TEXT) FROM PUBLIC;

-- ============================================================
-- 3. Who sees what
-- ============================================================

-- A member writes an interaction; a bot writes a panel. Neither writes the
-- other's, and the column grant is what makes that true of anything that
-- skipped the policy.
GRANT INSERT (channel_id, sender_id, ciphertext, nonce, signature, key_version,
              mentions, mentions_all, to_bot, reply_to, ephemeral_for,
              blocks, is_interaction, action_id, action_value)
  ON messages TO authenticated;

-- Editing a panel is editing a message: `messages_update_own` already scopes
-- that to the sender, which for a panel is the bot that posted it.
GRANT UPDATE (ciphertext, nonce, signature, key_version, blocks) ON messages
  TO authenticated;

CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    app.can_see_channel(channel_id)
    AND app.has_perm('SEND_MESSAGES')
    AND sender_id = auth.uid()
    AND webhook_id IS NULL AND origin_name IS NULL AND NOT is_system
    AND (key_version >= 1 OR to_bot IS NOT NULL OR app.is_bot())
    AND (to_bot IS NULL OR app.is_addressable_bot(to_bot))
    AND (to_bot IS NULL OR key_version = 0)
    AND (NOT app.is_bot() OR key_version = 0)
    AND (ephemeral_for IS NULL OR app.is_bot())
    -- Only a bot draws a panel. A member posting blocks would be a member
    -- posting an interface, which is the thing the block set exists to prevent.
    AND (blocks IS NULL OR app.is_bot())
    -- ...and only a person presses one. A bot pressing its own button is a
    -- loop, and nothing in the design needs it.
    AND (NOT is_interaction OR NOT app.is_bot())
  );

REVOKE ALL ON bot_server_grants FROM anon, authenticated;

-- Readable by every member, which is rule 4 again: the people whose messages
-- pay for the grant are not the ones who clicked the button.
GRANT SELECT ON bot_server_grants TO authenticated;

REVOKE ALL ON FUNCTION app.materialise_bot_server_grant(UUID, UUID) FROM PUBLIC;

REVOKE ALL ON FUNCTION grant_bot_server_key(UUID)  FROM PUBLIC;

REVOKE ALL ON FUNCTION revoke_bot_server_key(UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION grant_bot_server_key(UUID)  TO authenticated;

GRANT EXECUTE ON FUNCTION revoke_bot_server_key(UUID) TO authenticated;

REVOKE ALL ON FUNCTION apply_bot_server_grants()     FROM PUBLIC;

REVOKE ALL ON FUNCTION drop_bot_grants_when_closed() FROM PUBLIC;

REVOKE ALL ON bot_voice_grants FROM anon, authenticated;

-- Readable by anyone who can see the channel, which is §6's fourth rule
-- arriving in voice: the admin grants, and everybody who ever speaks in that
-- room pays for it. They are not the same people, so the notice cannot live in
-- the dialog where the decision was made.
--
-- `can_see_channel` rather than `server_id`: a private voice channel's
-- membership is not public, and neither is what is listening to it.
GRANT SELECT ON bot_voice_grants TO authenticated;

CREATE POLICY bot_voice_grants_select ON bot_voice_grants
  FOR SELECT TO authenticated USING (app.can_see_channel(channel_id));

REVOKE ALL ON FUNCTION grant_bot_voice_listen(UUID, UUID) FROM PUBLIC;

REVOKE ALL ON FUNCTION revoke_bot_voice_listen(UUID, UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION grant_bot_voice_listen(UUID, UUID) TO authenticated;

GRANT EXECUTE ON FUNCTION revoke_bot_voice_listen(UUID, UUID) TO authenticated;

REVOKE ALL ON voice_listeners FROM anon;

GRANT SELECT ON voice_listeners TO authenticated;

REVOKE ALL ON bot_voice_keys FROM anon, authenticated;

GRANT SELECT, INSERT ON bot_voice_keys TO authenticated;

CREATE POLICY bot_voice_keys_insert ON bot_voice_keys
  FOR INSERT TO authenticated
  WITH CHECK (
    wrapped_by = auth.uid()
    AND app.may_write_bot_voice_key(channel_id, bot_id, is_channel_key)
  );

CREATE POLICY bot_voice_keys_select ON bot_voice_keys
  FOR SELECT TO authenticated
  USING (bot_id = auth.uid() OR app.can_see_channel(channel_id));

REVOKE ALL ON bot_voice_key_candidates FROM anon, authenticated;

REVOKE ALL ON FUNCTION app.bot_reads_channel(UUID)          FROM PUBLIC;

REVOKE ALL ON FUNCTION app.bot_reads_version(UUID, INTEGER) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app.bot_reads_channel(UUID)          TO authenticated;

GRANT EXECUTE ON FUNCTION app.bot_reads_version(UUID, INTEGER) TO authenticated;

CREATE POLICY bot_channel_keys_select ON bot_channel_keys
  FOR SELECT TO authenticated
  USING (app.can_see_channel(channel_id) OR bot_id = auth.uid());

CREATE POLICY invites_insert ON invites FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND created_by = auth.uid()
    AND app.can_invite()
    AND (role_id IS NULL OR app.may_assign_role(role_id))
    AND (NOT is_bot OR app.has_perm('ADD_BOTS'))
  );

REVOKE ALL ON FUNCTION channel_joinable_by(UUID, UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION channel_joinable_by(UUID, UUID) TO service_role;

REVOKE ALL ON FUNCTION summon_bot_to_voice(UUID, UUID)    FROM PUBLIC;

REVOKE ALL ON FUNCTION dismiss_bot_from_voice(UUID, UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION summon_bot_to_voice(UUID, UUID)    TO authenticated;

GRANT EXECUTE ON FUNCTION dismiss_bot_from_voice(UUID, UUID) TO authenticated;

REVOKE ALL ON FUNCTION drop_bot_voice_keys_on_summon_change() FROM PUBLIC;

REVOKE ALL ON bot_voice_summons FROM anon, authenticated;

GRANT SELECT ON bot_voice_summons TO authenticated;

CREATE POLICY bot_voice_summons_select ON bot_voice_summons
  FOR SELECT TO authenticated
  USING (app.can_see_channel(channel_id) OR bot_id = auth.uid());

REVOKE ALL ON FUNCTION drop_bot_voice_summons_when_closed() FROM PUBLIC;

REVOKE ALL ON FUNCTION app.expire_bot_voice_summons() FROM PUBLIC, anon, authenticated;

REVOKE ALL ON voice_summons FROM anon;

GRANT SELECT ON voice_summons TO authenticated;

REVOKE ALL ON member_directory FROM anon;

GRANT SELECT ON member_directory TO authenticated;

-- ============================================================
-- 8. Privileges
-- ============================================================
-- New functions are executable by PUBLIC by default. Every one of these is
-- revoked and handed back to `authenticated` by name.

REVOKE ALL ON FUNCTION app.member_page_max() FROM PUBLIC;

REVOKE ALL ON FUNCTION app.member_limit(INTEGER) FROM PUBLIC;

REVOKE ALL ON FUNCTION app.member_sort_key(TEXT) FROM PUBLIC;

REVOKE ALL ON FUNCTION app.member_in_scope(UUID, BOOLEAN, BOOLEAN, UUID, BOOLEAN, BOOLEAN) FROM PUBLIC;

REVOKE ALL ON FUNCTION app.member_scope_allowed(UUID) FROM PUBLIC;

REVOKE ALL ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER) FROM PUBLIC;

REVOKE ALL ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER) FROM PUBLIC;

REVOKE ALL ON FUNCTION members_by_ids(UUID[]) FROM PUBLIC;

REVOKE ALL ON FUNCTION members_by_usernames(TEXT[], UUID) FROM PUBLIC;

REVOKE ALL ON FUNCTION member_counts(UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app.member_page_max() TO authenticated;

GRANT EXECUTE ON FUNCTION app.member_limit(INTEGER) TO authenticated;

GRANT EXECUTE ON FUNCTION app.member_sort_key(TEXT) TO authenticated;

GRANT EXECUTE ON FUNCTION app.member_in_scope(UUID, BOOLEAN, BOOLEAN, UUID, BOOLEAN, BOOLEAN) TO authenticated;

GRANT EXECUTE ON FUNCTION app.member_scope_allowed(UUID) TO authenticated;

GRANT EXECUTE ON FUNCTION members_by_usernames(TEXT[], UUID) TO authenticated;

REVOKE ALL ON FUNCTION message_reaction_tallies(read_scope, BIGINT[]) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION message_reaction_tallies(read_scope, BIGINT[]) TO authenticated;

REVOKE ALL ON FUNCTION dm_conversations(INTEGER, BIGINT) FROM PUBLIC;

-- Not reachable over the API by anybody. Both endpoints that touch it hold the
-- service key: one is admin-gated in its own code, and the other is called by
-- central with no session at all.
REVOKE ALL ON listing_tokens FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION issue_listing_token(UUID, UUID, TEXT) FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION redeem_listing_token(TEXT) FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION transfer_ownership(UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION transfer_ownership(UUID) TO authenticated;

REVOKE ALL ON FUNCTION delete_server() FROM PUBLIC;

GRANT EXECUTE ON FUNCTION delete_server() TO authenticated;

REVOKE ALL ON member_role_list FROM anon;

GRANT SELECT ON member_role_list TO authenticated;

REVOKE ALL ON FUNCTION member_roles_for(UUID[]) FROM PUBLIC;

REVOKE ALL ON FUNCTION app.announce_reaction()    FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.announce_dm()          FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.announce_dm_reaction() FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.announce_channels()    FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.announce_member()      FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.announce_prefs()       FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.announce_message() FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION unread_cap() FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION unread_cap() TO authenticated;

REVOKE ALL ON FUNCTION unread_counts() FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION unread_counts() TO authenticated;

REVOKE ALL ON FUNCTION app.push_enabled(UUID) FROM PUBLIC, anon, authenticated;

REVOKE ALL ON dm_conversation_heads FROM anon, authenticated;

GRANT SELECT ON dm_conversation_heads TO authenticated;

REVOKE ALL ON FUNCTION app.remember_dm_head() FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.forget_dm_head() FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION dm_conversations(INTEGER, BIGINT) FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION dm_conversations(INTEGER, BIGINT) TO authenticated;

REVOKE ALL ON FUNCTION get_server_details() FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION get_server_details() TO authenticated;

REVOKE ALL ON FUNCTION app.announce_channel_member()
  FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.unread_thresholds(UUID, BIGINT)
  FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION app.visible_channels() FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION app.visible_channels() TO authenticated;

REVOKE ALL ON FUNCTION app.bot_channels() FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION app.bot_channels() TO authenticated;

REVOKE ALL ON FUNCTION app.server_roles() FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION app.server_roles() TO authenticated;

CREATE POLICY messages_select ON messages FOR SELECT TO authenticated
  USING (
    (channel_id IN (SELECT unnest(app.visible_channels()))
     OR channel_id IN (SELECT unnest(app.bot_channels())))
    AND ((SELECT NOT app.is_bot())
         OR to_bot = (SELECT auth.uid())
         OR sender_id = (SELECT auth.uid())
         OR app.bot_reads_version(channel_id, key_version))
    AND (ephemeral_for IS NULL
         OR ephemeral_for = (SELECT auth.uid())
         OR sender_id = (SELECT auth.uid()))
    AND (NOT is_interaction
         OR sender_id = (SELECT auth.uid())
         OR to_bot = (SELECT auth.uid()))
  );

CREATE POLICY channel_keyring_select ON channel_keyring FOR SELECT TO authenticated
  USING (
    channel_id IN (SELECT unnest(app.visible_channels()))
    OR (user_id = (SELECT auth.uid())
        AND channel_id IN (SELECT unnest(app.bot_channels())))
  );

CREATE POLICY channel_members_select ON channel_members FOR SELECT TO authenticated
  USING (channel_id IN (SELECT unnest(app.visible_channels())));

CREATE POLICY channel_role_access_select ON channel_role_access
  FOR SELECT TO authenticated
  USING (channel_id IN (SELECT unnest(app.visible_channels())));

CREATE POLICY users_select_members ON users FOR SELECT TO authenticated
  USING (server_id = (SELECT app.server_id()));

CREATE POLICY users_select_self ON users FOR SELECT TO authenticated
  USING (id = (SELECT auth.uid()));

CREATE POLICY users_update_self ON users FOR UPDATE TO authenticated
  USING (id = (SELECT auth.uid()) AND server_id = (SELECT app.server_id()))
  WITH CHECK (id = (SELECT auth.uid()) AND server_id = (SELECT app.server_id()));

CREATE POLICY member_roles_select ON member_roles FOR SELECT TO authenticated
  USING (role_id IN (SELECT unnest(app.server_roles())));

CREATE POLICY servers_select ON servers FOR SELECT TO authenticated
  USING (id = (SELECT app.server_id()));

CREATE POLICY roles_select ON roles FOR SELECT TO authenticated
  USING (server_id = (SELECT app.server_id()));

CREATE POLICY channels_select ON channels FOR SELECT TO authenticated
  USING (
    server_id = (SELECT app.server_id())
    AND (NOT is_private OR app.in_channel(id, (SELECT auth.uid())))
  );

CREATE POLICY dm_messages_select ON dm_messages FOR SELECT TO authenticated
  USING (sender_id = (SELECT auth.uid()) OR recipient_id = (SELECT auth.uid()));

CREATE POLICY read_state_own ON read_state FOR ALL TO authenticated
  USING (user_id = (SELECT auth.uid()))
  WITH CHECK (user_id = (SELECT auth.uid()));

CREATE POLICY notification_prefs_own ON notification_prefs FOR ALL TO authenticated
  USING (user_id = (SELECT auth.uid()))
  WITH CHECK (user_id = (SELECT auth.uid()));

CREATE POLICY device_tokens_own ON device_tokens FOR ALL TO authenticated
  USING (user_id = (SELECT auth.uid()))
  WITH CHECK (user_id = (SELECT auth.uid()));

CREATE POLICY dm_conversation_heads_select ON dm_conversation_heads
  FOR SELECT TO authenticated
  USING (user_id = (SELECT auth.uid()));

CREATE POLICY bot_server_grants_select ON bot_server_grants
  FOR SELECT TO authenticated
  USING (server_id = (SELECT app.server_id()));

-- ============================================================
-- 6. Who may call them
-- ============================================================
-- CREATE OR REPLACE keeps the existing grants, but these are SECURITY
-- DEFINER now, so the grants are restated rather than assumed: `anon` must
-- not reach a function that no longer has RLS behind it.

REVOKE ALL ON FUNCTION members_by_ids(UUID[]) FROM PUBLIC, anon;

REVOKE ALL ON FUNCTION member_roles_for(UUID[]) FROM PUBLIC, anon;

REVOKE ALL ON FUNCTION member_counts(UUID) FROM PUBLIC, anon;

REVOKE ALL ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER)
  FROM PUBLIC, anon;

REVOKE ALL ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER)
  FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION members_by_ids(UUID[]) TO authenticated;

GRANT EXECUTE ON FUNCTION member_roles_for(UUID[]) TO authenticated;

GRANT EXECUTE ON FUNCTION member_counts(UUID) TO authenticated;

GRANT EXECUTE ON FUNCTION list_members(UUID, BOOLEAN, BOOLEAN, TEXT, UUID, INTEGER)
  TO authenticated;

GRANT EXECUTE ON FUNCTION search_members(TEXT, UUID, BOOLEAN, BOOLEAN, INTEGER)
  TO authenticated;

REVOKE ALL ON FUNCTION app.can_use_topic(TEXT, BOOLEAN) FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION app.can_use_topic(TEXT, BOOLEAN) TO authenticated;

REVOKE ALL ON FUNCTION app.announce_to_channel(UUID, TEXT, JSONB)
  FROM PUBLIC, anon, authenticated;

-- Internal bookkeeping. Nothing outside the triggers and `server_storage_used`
-- has any business reading it, and a new table arrives more permissive than
-- that unless it is said.
REVOKE ALL ON app.bucket_usage FROM PUBLIC, anon, authenticated;

REVOKE ALL ON FUNCTION server_storage_used() FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION server_storage_used() TO authenticated;

-- server_secrets is deliberately absent. No grant, no policy, no client path.

-- ============================================================
-- 3. Row-level security
-- ============================================================

ALTER TABLE servers              ENABLE ROW LEVEL SECURITY;

ALTER TABLE server_secrets       ENABLE ROW LEVEL SECURITY;

ALTER TABLE users                ENABLE ROW LEVEL SECURITY;

ALTER TABLE channels             ENABLE ROW LEVEL SECURITY;

ALTER TABLE invites              ENABLE ROW LEVEL SECURITY;

ALTER TABLE messages             ENABLE ROW LEVEL SECURITY;

ALTER TABLE dm_messages          ENABLE ROW LEVEL SECURITY;

ALTER TABLE message_reactions    ENABLE ROW LEVEL SECURITY;

ALTER TABLE dm_message_reactions ENABLE ROW LEVEL SECURITY;

ALTER TABLE channel_keyring      ENABLE ROW LEVEL SECURITY;

ALTER TABLE read_state           ENABLE ROW LEVEL SECURITY;

ALTER TABLE device_tokens ENABLE ROW LEVEL SECURITY;

ALTER TABLE push_config ENABLE ROW LEVEL SECURITY;

ALTER TABLE notification_prefs ENABLE ROW LEVEL SECURITY;

-- `validate_message_mentions` needs no change and is left alone deliberately.
-- Its join has `u.id <> NEW.sender_id`, so against a NULL sender it keeps
-- nothing — a webhook cannot mention anybody, cannot @all, and therefore cannot
-- be used to ring every phone on a server from a URL. That is the behaviour we
-- want; it is only an accident that it is also the behaviour we already had.

-- ============================================================
-- 4. Security
-- ============================================================

ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 4. Security
-- ============================================================

ALTER TABLE bot_channel_keys ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 7. Security
-- ============================================================
-- New tables in `public` arrive writable by `authenticated`, and new functions
-- arrive executable by PUBLIC. Both are revoked by name here; a table added
-- without this is one an ordinary member can rewrite.

ALTER TABLE roles        ENABLE ROW LEVEL SECURITY;

ALTER TABLE member_roles ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 10. Security
-- ============================================================

ALTER TABLE channel_members     ENABLE ROW LEVEL SECURITY;

ALTER TABLE channel_role_access ENABLE ROW LEVEL SECURITY;

ALTER TABLE bot_server_grants ENABLE ROW LEVEL SECURITY;

ALTER TABLE bot_voice_grants ENABLE ROW LEVEL SECURITY;

ALTER TABLE bot_voice_keys ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- 6. Security
-- ============================================================

ALTER TABLE bot_voice_summons ENABLE ROW LEVEL SECURITY;

ALTER TABLE listing_tokens ENABLE ROW LEVEL SECURITY;

ALTER TABLE dm_conversation_heads ENABLE ROW LEVEL SECURITY;
