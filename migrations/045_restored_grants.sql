-- ============================================================
-- Rift self-hosted server — 045: a restored server's grants put back
-- ============================================================
-- Found in the review of the console, Nov 25 2026.
--
-- A backup is loaded into a fresh Supabase database, and Supabase hands every
-- new table, sequence and function in `public` to `anon` and `authenticated`
-- by default. pg_dump writes an object's grants as they differ from Postgres'
-- own default (the owner, and PUBLIC on a function), not from Supabase's, so
-- nothing in the dump takes those back. And 008's revokes, which do, are
-- recorded as applied in the restored ledger and never run again. A server
-- restored before 1.9.1 therefore let anyone holding the publishable key call
-- every service-only function and write any column a row's policy allows
-- (measured on Nov 25 with a copy of a real server: 90 functions and 49
-- tables open to anon; none before the restore). The console now clears
-- those defaults before it loads a backup, so this is for the servers
-- restored before it did.
--
-- Below is what `anon`, `authenticated` and PUBLIC hold on each object in
-- `public` on a server built from 001–044, read from a database migrated
-- from nothing over Supabase's defaults (the suite's scratch database). Each
-- object is set to exactly that. On a server that was never restored this
-- changes nothing. An object a later file adds or regrants is that file's
-- business; one missing here is skipped. pg_trgm's functions are left as a
-- restore leaves them: they belong to `supabase_admin`, which this does not
-- run as, and they only compare strings.
-- ============================================================

DO $$
DECLARE
  r       RECORD;
  v_role  TEXT;
  v_privs TEXT;
  v_rel   REGCLASS;
  v_fn    REGPROCEDURE;
  v_col   TEXT;
BEGIN
  -- Tables, sequences and functions first: a revoke on a table takes its
  -- column grants with it, so those go back after.
  FOR r IN SELECT * FROM (VALUES
    ('table', 'attachment_trash', '', '', ''),
    ('table', 'banned_tags', '', '', ''),
    ('table', 'bot_channel_keys', '', 'SELECT', ''),
    ('table', 'bot_server_grants', '', 'SELECT', ''),
    ('table', 'bot_voice_grants', '', 'SELECT', ''),
    ('table', 'bot_voice_key_candidates', '', '', ''),
    ('table', 'bot_voice_keys', '', 'INSERT, SELECT', ''),
    ('table', 'bot_voice_summons', '', 'SELECT', ''),
    ('table', 'channel_bot_listeners', '', 'SELECT', ''),
    ('table', 'channel_eligible_members', '', '', ''),
    ('table', 'channel_keyring', '', 'SELECT', ''),
    ('table', 'channel_members', '', 'SELECT', ''),
    ('table', 'channel_overrides', '', 'SELECT', ''),
    ('table', 'channel_role_access', '', 'SELECT', ''),
    ('table', 'channels', '', 'DELETE, SELECT', ''),
    ('table', 'clip_notices', '', '', ''),
    ('table', 'device_tokens', '', 'DELETE, INSERT, SELECT, UPDATE', ''),
    ('table', 'dm_calls', '', '', ''),
    ('table', 'dm_conversation_heads', '', 'SELECT', ''),
    ('table', 'dm_links', '', '', ''),
    ('table', 'dm_message_pins', '', 'SELECT', ''),
    ('table', 'dm_message_reactions', '', 'DELETE, INSERT, SELECT', ''),
    ('table', 'dm_messages', '', 'DELETE, SELECT', ''),
    ('sequence', 'dm_messages_id_seq', '', 'SELECT, UPDATE, USAGE', ''),
    ('table', 'invites', '', 'DELETE, SELECT', ''),
    ('table', 'listing_tokens', '', '', ''),
    ('table', 'livekit_node_secrets', '', '', ''),
    ('table', 'livekit_nodes', '', 'DELETE, SELECT', ''),
    ('table', 'member_account_tags', '', '', ''),
    ('table', 'member_blocks', '', 'DELETE, SELECT', ''),
    ('table', 'member_directory', '', 'SELECT', ''),
    ('table', 'member_role_list', '', 'SELECT', ''),
    ('table', 'member_roles', '', 'DELETE, INSERT, SELECT', ''),
    ('table', 'message_pins', '', 'SELECT', ''),
    ('table', 'message_reactions', '', 'DELETE, INSERT, SELECT', ''),
    ('table', 'messages', '', 'DELETE, SELECT', ''),
    ('sequence', 'messages_id_seq', '', 'SELECT, UPDATE, USAGE', ''),
    ('table', 'notification_prefs', '', 'DELETE, INSERT, SELECT, UPDATE', ''),
    ('table', 'poll_votes', '', 'SELECT', ''),
    ('table', 'push_config', '', '', ''),
    ('table', 'read_state', '', 'INSERT, SELECT', ''),
    ('table', 'reports', '', 'SELECT', ''),
    ('sequence', 'reports_id_seq', '', 'SELECT, UPDATE, USAGE', ''),
    ('table', 'roles', '', 'DELETE, SELECT', ''),
    ('table', 'server_secrets', '', '', ''),
    ('table', 'servers', '', 'SELECT', ''),
    ('table', 'soundboard_sounds', '', 'DELETE, SELECT', ''),
    ('table', 'users', '', 'SELECT', ''),
    ('table', 'voice_listeners', '', 'SELECT', ''),
    ('table', 'voice_rooms', '', 'SELECT', ''),
    ('table', 'voice_summons', '', 'SELECT', ''),
    ('table', 'webhooks', '', 'DELETE', ''),
    ('column', 'channels channel_type', '', 'INSERT', ''),
    ('column', 'channels history_cap', '', 'INSERT, UPDATE', ''),
    ('column', 'channels is_private', '', 'INSERT', ''),
    ('column', 'channels livekit_node_id', '', 'INSERT, UPDATE', ''),
    ('column', 'channels name', '', 'INSERT, UPDATE', ''),
    ('column', 'channels retention_days', '', 'INSERT, UPDATE', ''),
    ('column', 'channels server_id', '', 'INSERT', ''),
    ('column', 'dm_messages attachment_paths', '', 'INSERT', ''),
    ('column', 'dm_messages ciphertext', '', 'INSERT, UPDATE', ''),
    ('column', 'dm_messages key_version', '', 'INSERT, UPDATE', ''),
    ('column', 'dm_messages nonce', '', 'INSERT, UPDATE', ''),
    ('column', 'dm_messages recipient_id', '', 'INSERT', ''),
    ('column', 'dm_messages sender_id', '', 'INSERT', ''),
    ('column', 'dm_messages signature', '', 'INSERT, UPDATE', ''),
    ('column', 'invites created_by', '', 'INSERT', ''),
    ('column', 'invites expires_at', '', 'INSERT', ''),
    ('column', 'invites is_bot', '', 'INSERT', ''),
    ('column', 'invites max_uses', '', 'INSERT', ''),
    ('column', 'invites needs_account', '', 'INSERT', ''),
    ('column', 'invites role_id', '', 'INSERT', ''),
    ('column', 'invites server_id', '', 'INSERT', ''),
    ('column', 'livekit_nodes label', '', 'UPDATE', ''),
    ('column', 'livekit_nodes url', '', 'UPDATE', ''),
    ('column', 'member_blocks blocked_id', '', 'INSERT', ''),
    ('column', 'member_blocks blocker_id', '', 'INSERT', ''),
    ('column', 'messages action_id', '', 'INSERT', ''),
    ('column', 'messages action_value', '', 'INSERT', ''),
    ('column', 'messages attachment_paths', '', 'INSERT', ''),
    ('column', 'messages blocks', '', 'INSERT, UPDATE', ''),
    ('column', 'messages channel_id', '', 'INSERT', ''),
    ('column', 'messages ciphertext', '', 'INSERT, UPDATE', ''),
    ('column', 'messages ephemeral_for', '', 'INSERT', ''),
    ('column', 'messages is_interaction', '', 'INSERT', ''),
    ('column', 'messages key_version', '', 'INSERT, UPDATE', ''),
    ('column', 'messages mentions', '', 'INSERT', ''),
    ('column', 'messages mentions_all', '', 'INSERT', ''),
    ('column', 'messages nonce', '', 'INSERT, UPDATE', ''),
    ('column', 'messages poll', '', 'INSERT', ''),
    ('column', 'messages reply_to', '', 'INSERT', ''),
    ('column', 'messages sender_id', '', 'INSERT', ''),
    ('column', 'messages signature', '', 'INSERT, UPDATE', ''),
    ('column', 'messages to_bot', '', 'INSERT', ''),
    ('column', 'read_state last_read_id', '', 'UPDATE', ''),
    ('column', 'read_state updated_at', '', 'UPDATE', ''),
    ('column', 'roles color', '', 'INSERT, UPDATE', ''),
    ('column', 'roles name', '', 'INSERT, UPDATE', ''),
    ('column', 'roles permissions', '', 'INSERT, UPDATE', ''),
    ('column', 'roles position', '', 'INSERT, UPDATE', ''),
    ('column', 'roles server_id', '', 'INSERT', ''),
    ('column', 'soundboard_sounds bytes', '', 'INSERT', ''),
    ('column', 'soundboard_sounds duration_ms', '', 'INSERT', ''),
    ('column', 'soundboard_sounds emoji', '', 'INSERT, UPDATE', ''),
    ('column', 'soundboard_sounds name', '', 'INSERT, UPDATE', ''),
    ('column', 'soundboard_sounds object_path', '', 'INSERT', ''),
    ('column', 'users avatar_path', '', 'UPDATE', ''),
    ('column', 'users chat_public_key', '', 'UPDATE', ''),
    ('column', 'users display_name', '', 'UPDATE', ''),
    ('column', 'users dm_policy', '', 'UPDATE', ''),
    ('column', 'users manifest', '', 'UPDATE', ''),
    ('column', 'webhooks channel_id', '', 'SELECT', ''),
    ('column', 'webhooks created_at', '', 'SELECT', ''),
    ('column', 'webhooks created_by', '', 'SELECT', ''),
    ('column', 'webhooks id', '', 'SELECT', ''),
    ('column', 'webhooks last_used_at', '', 'SELECT', ''),
    ('column', 'webhooks name', '', 'SELECT', ''),
    ('column', 'webhooks server_id', '', 'SELECT', ''),
    ('function', 'add_voice_region(text,text,text,text)', '', 'EXECUTE', ''),
    ('function', 'answer_dm_call(uuid)', '', 'EXECUTE', ''),
    ('function', 'answer_dm_request(uuid,boolean)', '', 'EXECUTE', ''),
    ('function', 'apply_bot_server_grants()', '', '', ''),
    ('function', 'attest_message()', '', '', ''),
    ('function', 'call_live_messages(uuid)', '', 'EXECUTE', ''),
    ('function', 'change_channel_members(uuid,uuid[],uuid[])', '', 'EXECUTE', ''),
    ('function', 'channel_joinable_by(uuid,uuid)', '', '', ''),
    ('function', 'channel_key_state(uuid,uuid)', '', '', ''),
    ('function', 'channel_key_work(uuid)', '', '', ''),
    ('function', 'channel_live_messages(uuid)', '', 'EXECUTE', ''),
    ('function', 'channel_manageable_by(uuid,uuid)', '', '', ''),
    ('function', 'channel_messages(uuid,bigint,bigint,integer)', '', 'EXECUTE', ''),
    ('function', 'channel_visible_to(uuid,uuid)', '', '', ''),
    ('function', 'check_poll()', '', '', ''),
    ('function', 'claim_attachment_sweep()', '', '', ''),
    ('function', 'claim_dm_call_room(uuid,uuid,uuid,boolean)', '', '', ''),
    ('function', 'claim_voice_node(uuid,uuid,boolean)', '', '', ''),
    ('function', 'close_poll(bigint)', '', 'EXECUTE', ''),
    ('function', 'create_channel(text,text,boolean,uuid[])', '', 'EXECUTE', ''),
    ('function', 'create_webhook(uuid,text)', '', 'EXECUTE', ''),
    ('function', 'delete_server()', '', 'EXECUTE', ''),
    ('function', 'dismiss_bot_from_voice(uuid,uuid)', '', 'EXECUTE', ''),
    ('function', 'dm_call_alive(uuid)', '', 'EXECUTE', ''),
    ('function', 'dm_call_log(uuid,timestamp with time zone)', '', 'EXECUTE', ''),
    ('function', 'dm_conversations(integer,bigint)', '', 'EXECUTE', ''),
    ('function', 'dm_link_state(uuid)', '', 'EXECUTE', ''),
    ('function', 'dm_requests()', '', 'EXECUTE', ''),
    ('function', 'drop_bot_grants_when_closed()', '', '', ''),
    ('function', 'drop_bot_voice_grants_when_closed()', '', '', ''),
    ('function', 'drop_bot_voice_keys_on_grant_change()', '', '', ''),
    ('function', 'drop_bot_voice_keys_on_summon_change()', '', '', ''),
    ('function', 'drop_bot_voice_summons_when_closed()', '', '', ''),
    ('function', 'end_dm_call(uuid)', '', 'EXECUTE', ''),
    ('function', 'end_dm_ring(uuid)', '', 'EXECUTE', ''),
    ('function', 'enforce_soundboard_max()', '', '', ''),
    ('function', 'get_server_details()', '', 'EXECUTE', ''),
    ('function', 'grant_bot_channel_key(uuid,uuid)', '', 'EXECUTE', ''),
    ('function', 'grant_bot_server_key(uuid)', '', 'EXECUTE', ''),
    ('function', 'grant_bot_voice_listen(uuid,uuid)', '', 'EXECUTE', ''),
    ('function', 'has_unread_before(uuid,read_scope,uuid,bigint)', '', '', ''),
    ('function', 'issue_listing_token(uuid,uuid,text)', '', '', ''),
    ('function', 'kick_member(uuid)', '', 'EXECUTE', ''),
    ('function', 'leave_channel(uuid)', '', 'EXECUTE', ''),
    ('function', 'leave_server()', '', 'EXECUTE', ''),
    ('function', 'list_members(uuid,boolean,boolean,text,uuid,integer)', '', 'EXECUTE', ''),
    ('function', 'mark_all_read()', '', 'EXECUTE', ''),
    ('function', 'mark_read(read_scope,uuid,bigint)', '', 'EXECUTE', ''),
    ('function', 'max_file_bytes()', '', 'EXECUTE', ''),
    ('function', 'member_counts(uuid)', '', 'EXECUTE', ''),
    ('function', 'member_roles_for(uuid[])', '', 'EXECUTE', ''),
    ('function', 'member_sidebar(integer)', '', 'EXECUTE', ''),
    ('function', 'members_by_ids(uuid[])', '', 'EXECUTE', ''),
    ('function', 'members_by_usernames(text[],uuid)', '', 'EXECUTE', ''),
    ('function', 'message_reaction_tallies(read_scope,bigint[])', '', 'EXECUTE', ''),
    ('function', 'mirror_default_livekit_node()', '', '', ''),
    ('function', 'moderate_user(uuid,boolean,boolean,boolean)', '', 'EXECUTE', ''),
    ('function', 'move_voice_node(uuid,uuid)', '', '', ''),
    ('function', 'my_dm_calls(uuid[])', '', 'EXECUTE', ''),
    ('function', 'my_permissions()', '', 'EXECUTE', ''),
    ('function', 'new_invite_code()', '', 'EXECUTE', ''),
    ('function', 'new_webhook_secret()', '', '', ''),
    ('function', 'note_clip_allowed(uuid)', '', '', ''),
    ('function', 'pin_bot_command()', '', '', ''),
    ('function', 'pin_is_bot()', '', '', ''),
    ('function', 'poll_tallies(bigint[])', '', 'EXECUTE', ''),
    ('function', 'post_webhook_message(text,text)', '', '', ''),
    ('function', 'protect_everyone_role()', '', '', ''),
    ('function', 'protect_owner_role()', '', '', ''),
    ('function', 'prune_channel_keys(uuid,integer[])', '', 'EXECUTE', ''),
    ('function', 'reassign_or_close_channel()', '', '', ''),
    ('function', 'redeem_listing_token(text)', '', '', ''),
    ('function', 'refuse_default_node_delete()', '', '', ''),
    ('function', 'refuse_default_node_secret()', '', '', ''),
    ('function', 'refuse_everyone_assignment()', '', '', ''),
    ('function', 'refuse_foreign_node_pin()', '', '', ''),
    ('function', 'refuse_ineligible_keyring()', '', '', ''),
    ('function', 'refuse_node_key_delete()', '', '', ''),
    ('function', 'refuse_owner_leaving()', '', '', ''),
    ('function', 'refuse_second_owner()', '', '', ''),
    ('function', 'register_user(text,uuid,text,text,text,text,text)', '', '', ''),
    ('function', 'release_idle_voice_node(uuid[])', '', '', ''),
    ('function', 'release_voice_node(uuid[])', '', '', ''),
    ('function', 'reorder_channels(uuid[])', '', 'EXECUTE', ''),
    ('function', 'report_member(uuid,report_reason,text)', '', 'EXECUTE', ''),
    ('function', 'report_message(bigint,report_reason,text)', '', 'EXECUTE', ''),
    ('function', 'require_node_key()', '', '', ''),
    ('function', 'resolve_report(bigint,report_outcome)', '', 'EXECUTE', ''),
    ('function', 'revoke_bot_channel_key(uuid,uuid)', '', 'EXECUTE', ''),
    ('function', 'revoke_bot_server_key(uuid)', '', 'EXECUTE', ''),
    ('function', 'revoke_bot_voice_listen(uuid,uuid)', '', 'EXECUTE', ''),
    ('function', 'ring_channel_members()', '', '', ''),
    ('function', 'ring_devices(uuid,uuid[])', '', '', ''),
    ('function', 'ring_dm_recipient()', '', '', ''),
    ('function', 'search_members(text,uuid,boolean,boolean,integer)', '', 'EXECUTE', ''),
    ('function', 'seed_default_roles()', '', '', ''),
    ('function', 'seed_private_channel_owner()', '', '', ''),
    ('function', 'server_storage_used()', '', 'EXECUTE', ''),
    ('function', 'set_channel_encrypted(uuid,boolean)', '', 'EXECUTE', ''),
    ('function', 'set_channel_members(uuid,uuid[])', '', 'EXECUTE', ''),
    ('function', 'set_channel_override(uuid,uuid,bigint,bigint)', '', 'EXECUTE', ''),
    ('function', 'set_channel_private(uuid,boolean)', '', 'EXECUTE', ''),
    ('function', 'set_channel_role_access(uuid,uuid,boolean)', '', 'EXECUTE', ''),
    ('function', 'set_invite_needs_account(text,boolean)', '', 'EXECUTE', ''),
    ('function', 'set_pinned(read_scope,bigint,boolean)', '', 'EXECUTE', ''),
    ('function', 'set_voice_region_credentials(uuid,text,text)', '', 'EXECUTE', ''),
    ('function', 'stamp_device_owner()', '', '', ''),
    ('function', 'stamp_notification_pref()', '', '', ''),
    ('function', 'stamp_soundboard_sound()', '', '', ''),
    ('function', 'start_dm_call(uuid)', '', 'EXECUTE', ''),
    ('function', 'store_channel_key_link(uuid,integer,uuid,text,text)', '', '', ''),
    ('function', 'summon_bot_to_voice(uuid,uuid)', '', 'EXECUTE', ''),
    ('function', 'sweep_attachments(integer)', '', '', ''),
    ('function', 'sync_member_permission_cache()', '', '', ''),
    ('function', 'sync_role_permission_cache()', '', '', ''),
    ('function', 'sync_server_bucket()', '', '', ''),
    ('function', 'time_out_member(uuid,integer)', '', 'EXECUTE', ''),
    ('function', 'transfer_ownership(uuid)', '', 'EXECUTE', ''),
    ('function', 'unread_cap()', '', 'EXECUTE', ''),
    ('function', 'unread_counts()', '', 'EXECUTE', ''),
    ('function', 'user_has_channel_permission(uuid,uuid,text)', '', '', ''),
    ('function', 'user_has_permission(uuid,text)', '', '', ''),
    ('function', 'validate_message_mentions()', '', '', ''),
    ('function', 'visible_channels(uuid)', '', '', ''),
    ('function', 'vote_poll(bigint,smallint[])', '', 'EXECUTE', '')
  ) AS s(kind, name, anon, authed, everyone)
  ORDER BY CASE kind WHEN 'column' THEN 2 ELSE 1 END LOOP
    IF r.kind IN ('table', 'sequence') THEN
      v_rel := to_regclass(format('public.%I', r.name));
      CONTINUE WHEN v_rel IS NULL;
      EXECUTE format('REVOKE ALL ON %s %s FROM PUBLIC, anon, authenticated',
                     CASE r.kind WHEN 'sequence' THEN 'SEQUENCE' ELSE 'TABLE' END, v_rel);
    ELSIF r.kind = 'function' THEN
      v_fn := to_regprocedure('public.' || r.name);
      CONTINUE WHEN v_fn IS NULL;
      EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon, authenticated', v_fn);
    ELSE
      v_rel := to_regclass(format('public.%I', split_part(r.name, ' ', 1)));
      v_col := split_part(r.name, ' ', 2);
      CONTINUE WHEN v_rel IS NULL OR NOT EXISTS (
        SELECT 1 FROM pg_attribute a
         WHERE a.attrelid = v_rel AND a.attname = v_col AND NOT a.attisdropped);
    END IF;

    FOREACH v_role IN ARRAY ARRAY['anon', 'authenticated', 'PUBLIC'] LOOP
      v_privs := CASE v_role WHEN 'anon' THEN r.anon
                             WHEN 'authenticated' THEN r.authed
                             ELSE r.everyone END;
      CONTINUE WHEN v_privs = '';
      IF r.kind = 'column' THEN
        SELECT string_agg(format('%s (%I)', p, v_col), ', ') INTO v_privs
          FROM unnest(string_to_array(v_privs, ', ')) p;
        EXECUTE format('GRANT %s ON TABLE %s TO %s', v_privs, v_rel, v_role);
      ELSIF r.kind = 'function' THEN
        EXECUTE format('GRANT %s ON FUNCTION %s TO %s', v_privs, v_fn, v_role);
      ELSE
        EXECUTE format('GRANT %s ON %s %s TO %s', v_privs,
                       CASE r.kind WHEN 'sequence' THEN 'SEQUENCE' ELSE 'TABLE' END,
                       v_rel, v_role);
      END IF;
    END LOOP;
  END LOOP;

END $$;
