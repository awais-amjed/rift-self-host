-- ============================================================
-- Rift self-hosted server — 004: the triggers
-- ============================================================
-- What the database keeps true regardless of who is writing. Three kinds:
--
--   * **attestation** — the server stamps who sent a message and when, so
--     the sender cannot claim otherwise;
--   * **refusal** — rules that belong to the row rather than to a code path,
--     because there is more than one way to write one;
--   * **derived state** — the permission cache on `users`, the DM heads, the
--     default roles a new server gets.
--
-- A rule enforced in an RPC is a rule the next writer forgets. These are the
-- ones that had to survive being forgotten.
-- ============================================================

-- Stamped rather than accepted from the client, the same way `messages` stamps
-- its sender: a client that could name the owner could register its token
-- against somebody else's account and be woken for that person's messages.
CREATE OR REPLACE FUNCTION stamp_device_owner()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  -- The service role has no `auth.uid()` and is not a client to be constrained
  -- — the same exemption `attest_dm` makes on central, and what lets a
  -- migration or an operator seed a row at all.
  IF auth.uid() IS NOT NULL THEN
    NEW.user_id := auth.uid();
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END; $$;

-- Stamped, not accepted: a client that could name the owner could mute a
-- channel for somebody else — a quiet and very effective way to make sure a
-- person never hears about anything.
CREATE OR REPLACE FUNCTION stamp_notification_pref()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NOT NULL THEN
    NEW.user_id := auth.uid();
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END; $$;

-- ============================================================
-- 3. `is_bot` is set once, at registration
-- ============================================================
-- Members may UPDATE (display_name, chat_public_key, avatar_path) and nothing
-- else, so no client can write this column today. The trigger is for the paths
-- that are not a client: `set_user_permissions` and `moderate_user` are
-- SECURITY DEFINER and run as the owner, and a future one that does `UPDATE
-- users SET ...` without naming its columns would carry whatever it was handed.
--
-- Turning a person into a bot, or a bot into a person, is not an edit anybody
-- should be able to make — it changes who may hold the keys to a room.

CREATE OR REPLACE FUNCTION pin_is_bot()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  NEW.is_bot := OLD.is_bot;
  RETURN NEW;
END; $$;

-- Editing a command is not a thing. `messages_update_own` already scopes to the
-- sender and the UPDATE grant names four columns, none of them `to_bot` — but
-- an edit of the *body* would silently change what a bot was asked to do,
-- after it may already have acted. The attestation trigger pins the address;
-- this pins the instruction.
-- **`to_bot` is deliberately not pinned here, and the body check is narrow.**
-- `ON DELETE SET NULL` is implemented as an UPDATE, so this trigger fires
-- during the cascade when a bot is removed. Pinning the column would put the id
-- back and the FK would reject its own cascade; refusing every update would
-- make deleting a bot that ever received a command impossible. That is exactly
-- the same trap webhook deletion has, and it is worth only falling into once.
--
-- Nothing is lost: `authenticated` holds a column-level UPDATE grant on
-- (ciphertext, nonce, signature, key_version) alone, so no member can write
-- `to_bot` by hand in the first place.
CREATE OR REPLACE FUNCTION pin_bot_command()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF OLD.to_bot IS NOT NULL
     AND NEW.ciphertext IS DISTINCT FROM OLD.ciphertext THEN
    RAISE EXCEPTION 'command_cannot_be_edited';
  END IF;
  RETURN NEW;
END; $$;

-- `@everyone` is implicit, so a row naming it would be a second answer to a
-- question that already has one — and the two would drift.
CREATE OR REPLACE FUNCTION refuse_everyone_assignment()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM roles r WHERE r.id = NEW.role_id AND r.is_everyone) THEN
    RAISE EXCEPTION 'everyone_is_implicit';
  END IF;
  RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION sync_member_permission_cache()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    PERFORM app.sync_permission_cache(OLD.user_id);
  END IF;
  IF TG_OP <> 'DELETE' THEN
    PERFORM app.sync_permission_cache(NEW.user_id);
  END IF;
  RETURN NULL;
END; $$;

-- Editing a role's permissions moves everybody holding it, and editing
-- `@everyone` moves the whole server.
CREATE OR REPLACE FUNCTION sync_role_permission_cache()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_role roles%ROWTYPE;
BEGIN
  -- Branch rather than COALESCE: on DELETE there is no NEW, and a composite
  -- COALESCE over an unassigned record is not something to find out about in
  -- production.
  IF TG_OP = 'DELETE' THEN v_role := OLD; ELSE v_role := NEW; END IF;

  IF v_role.is_everyone THEN
    PERFORM app.sync_permission_cache(u.id)
       FROM users u WHERE u.server_id = v_role.server_id;
  ELSE
    PERFORM app.sync_permission_cache(mr.user_id)
       FROM member_roles mr WHERE mr.role_id = v_role.id;
  END IF;
  RETURN NULL;
END; $$;

-- ============================================================
-- Attestation
-- ============================================================
-- The server stamps who sent a row and when, so a client cannot claim
-- otherwise. One function serves two tables — `attest_messages` on `messages`
-- and `attest_dm_messages` on `dm_messages` — and both branches are guarded by
-- `TG_TABLE_NAME`, because only `messages` has the webhook columns to clear.
--
-- ---------- the early return ----------
--
--     IF auth.uid() IS NULL THEN RETURN NEW; END IF;
--
-- Nothing reaches this trigger without a session except the service role and
-- the superuser, both of which are trusted to write a row as it stands:
-- `anon` holds no INSERT grant on either table. That branch is how
-- `post_webhook_message` writes a NULL sender, and how anything that needs to
-- back-date a row — retention tests, fixtures, a repair script — can. A
-- *member* cannot use it to claim to be a webhook, because a member has a
-- session and never takes it.

CREATE OR REPLACE FUNCTION attest_message()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  -- Everything below is about not trusting a client; there is no client here.
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    NEW.sender_id  := auth.uid();
    NEW.created_at := now();
    NEW.edited_at  := NULL;

    -- A member's insert is never a webhook's, whatever it sent. The service
    -- role never arrives here at all now, and it does not need to:
    -- `post_webhook_message` writes both columns itself.
    --
    -- Guarded on the table, like the UPDATE branch below: these two columns
    -- exist on `messages` and nowhere else, and a DM has no origin to overrule.
    IF TG_TABLE_NAME = 'messages' THEN
      NEW.webhook_id  := NULL;
      NEW.origin_name := NULL;
    END IF;
    RETURN NEW;
  END IF;

  -- An edit may only change the envelope. Identity, placement and time of
  -- sending are the server's word and stay put; edited_at is stamped here
  -- rather than trusted from the client.
  NEW.id         := OLD.id;
  NEW.sender_id  := OLD.sender_id;
  NEW.created_at := OLD.created_at;
  IF TG_TABLE_NAME = 'messages' THEN
    NEW.channel_id  := OLD.channel_id;
    -- The displayed name is frozen; the reference is not.
    --
    -- `webhook_id` is deliberately NOT pinned here, and that is not an
    -- oversight. `ON DELETE SET NULL` is implemented as an UPDATE, so this
    -- trigger fires during the cascade — pinning the column put the id back,
    -- and the FK then rejected its own cascade. Deleting a webhook that had
    -- ever posted was impossible.
    --
    -- Nothing is lost by leaving it open: `authenticated` holds a column-level
    -- UPDATE grant on (ciphertext, nonce, signature, key_version) only, so no
    -- member can write `webhook_id` by hand in the first place.
    NEW.origin_name := OLD.origin_name;
  ELSE
    NEW.recipient_id := OLD.recipient_id;
  END IF;
  IF NEW.ciphertext IS DISTINCT FROM OLD.ciphertext THEN
    NEW.edited_at := now();
  ELSE
    NEW.edited_at := OLD.edited_at;
  END IF;
  RETURN NEW;
END; $$;

-- ============================================================
-- 6. The keyring refusal, widened
-- ============================================================
-- The bot rule is on the row rather than in the clients that walk the
-- member list, on the grounds that a filter is the half that gets forgotten.
-- A private channel has exactly the same shape and deserves the same answer:
-- a client that wraps a key for somebody who is not in the room believes it did
-- something, and would otherwise carry on believing it.

CREATE OR REPLACE FUNCTION refuse_ineligible_keyring()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_from INTEGER;
BEGIN
  IF EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.is_bot) THEN
    SELECT from_key_version INTO v_from FROM bot_channel_keys
     WHERE channel_id = NEW.channel_id AND bot_id = NEW.user_id;

    IF v_from IS NULL THEN
      RAISE EXCEPTION 'bot_cannot_hold_channel_key';
    END IF;
    -- Forward-only, enforced where the row is written rather than trusted to
    -- whichever client happens to be doing the wrapping.
    IF NEW.key_version < v_from THEN
      RAISE EXCEPTION 'bot_key_version_before_grant';
    END IF;
    RETURN NEW;
  END IF;

  IF NOT app.channel_eligible(NEW.channel_id, NEW.user_id) THEN
    RAISE EXCEPTION 'not_a_channel_member';
  END IF;
  RETURN NEW;
END; $$;

-- ============================================================
-- 8. A private channel with nobody in it
-- ============================================================
-- No admin can see one, which is the point, and it is also why nobody can be
-- asked to tidy one up. So it tidies itself: the manage bit moves to whoever
-- has been there longest, and the last person out takes the room with them.

CREATE OR REPLACE FUNCTION reassign_or_close_channel()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_private BOOLEAN;
  v_next    UUID;
BEGIN
  SELECT is_private INTO v_private FROM channels WHERE id = OLD.channel_id;
  IF v_private IS NOT TRUE THEN RETURN NULL; END IF;

  IF NOT EXISTS (SELECT 1 FROM channel_members
                  WHERE channel_id = OLD.channel_id) THEN
    -- Everything goes: messages, keyring, webhooks and bot grants all cascade
    -- from `channels`. A room nobody can enter and nobody can see is not
    -- something to keep.
    DELETE FROM channels WHERE id = OLD.channel_id;
    RETURN NULL;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM channel_members
                  WHERE channel_id = OLD.channel_id AND can_manage) THEN
    -- Longest-serving, not random: somebody will ask why it was them.
    SELECT user_id INTO v_next FROM channel_members
     WHERE channel_id = OLD.channel_id
     ORDER BY added_at, user_id LIMIT 1;
    UPDATE channel_members SET can_manage = true
     WHERE channel_id = OLD.channel_id AND user_id = v_next;
  END IF;
  RETURN NULL;
END; $$;

-- Mentioning somebody into a room they cannot enter pings them about a message
-- they will never see, and tells them who else is in there.
CREATE OR REPLACE FUNCTION validate_message_mentions()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_clean UUID[];
BEGIN
  IF TG_OP = 'UPDATE' THEN
    -- Insert-only, see the grant. An edit keeps whatever it was sent as.
    NEW.mentions     := OLD.mentions;
    NEW.mentions_all := OLD.mentions_all;
    RETURN NEW;
  END IF;

  SELECT COALESCE(array_agg(DISTINCT u.id), '{}')
    INTO v_clean
    FROM unnest(COALESCE(NEW.mentions, '{}')) AS m(id)
    JOIN users u ON u.id = m.id
   WHERE u.server_id = app.channel_server_id(NEW.channel_id)
     AND NOT u.is_banned
     AND u.id <> NEW.sender_id
     AND app.channel_eligible(NEW.channel_id, u.id);

  -- A ceiling rather than a rejection: a message that names a lot of people is
  -- a message, and refusing to send it would be a strange way to say "that is
  -- too many pings". Past this, @all is the thing they wanted anyway.
  IF cardinality(v_clean) > 50 THEN
    v_clean := v_clean[1:50];
  END IF;

  NEW.mentions := v_clean;
  RETURN NEW;
END; $$;

-- A channel created private needs somebody able to run it before the statement
-- ends, or it is born orphaned and section 8 deletes it on the first removal.
CREATE OR REPLACE FUNCTION seed_private_channel_owner()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF NEW.is_private AND auth.uid() IS NOT NULL THEN
    INSERT INTO channel_members (channel_id, user_id, can_manage, added_by)
    VALUES (NEW.id, auth.uid(), true, auth.uid())
    ON CONFLICT (channel_id, user_id) DO NOTHING;
  END IF;
  RETURN NULL;
END; $$;

-- ============================================================
-- 4. A channel made later, and a channel closed later
-- ============================================================

CREATE OR REPLACE FUNCTION apply_bot_server_grants()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_bot UUID;
BEGIN
  IF NEW.channel_type <> 'text' OR NEW.is_private THEN RETURN NULL; END IF;

  FOR v_bot IN
    SELECT bot_id FROM bot_server_grants WHERE server_id = NEW.server_id
  LOOP
    -- Bypasses `grant_bot_channel_key`'s permission check on purpose: the
    -- decision was made when the server-wide grant was, and the person
    -- creating a channel now is not necessarily the one who made it.
    INSERT INTO bot_channel_keys (channel_id, bot_id, granted_by, from_key_version)
    VALUES (NEW.id, v_bot, NULL, 1)
    ON CONFLICT (channel_id, bot_id) DO NOTHING;

    PERFORM app.post_system_message(
      NEW.id,
      (SELECT display_name FROM users WHERE id = v_bot)
        || ' can read this channel: it was created under a server-wide grant.'
    );
  END LOOP;
  RETURN NULL;
END; $$;

-- Closing a channel takes it out of the server-wide grant, because the grant
-- is defined as "not private" and a channel that just became private is not
-- covered by it any more. The bot keeps what it read; the sweep rotates it out
-- of everything after, exactly as an explicit revoke would.
CREATE OR REPLACE FUNCTION drop_bot_grants_when_closed()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_bot UUID;
BEGIN
  IF OLD.is_private OR NOT NEW.is_private THEN RETURN NULL; END IF;

  FOR v_bot IN
    SELECT g.bot_id FROM bot_channel_keys g
     WHERE g.channel_id = NEW.id
       AND EXISTS (SELECT 1 FROM bot_server_grants s
                    WHERE s.server_id = NEW.server_id AND s.bot_id = g.bot_id)
  LOOP
    DELETE FROM bot_channel_keys WHERE channel_id = NEW.id AND bot_id = v_bot;
    DELETE FROM channel_keyring  WHERE channel_id = NEW.id AND user_id = v_bot;
    PERFORM app.post_system_message(
      NEW.id,
      (SELECT display_name FROM users WHERE id = v_bot)
        || ' lost access when this channel was made private. A server-wide '
        || 'grant never covers a private channel.'
    );
  END LOOP;
  RETURN NULL;
END; $$;

-- ============================================================
-- 3. A channel that becomes private
-- ============================================================
-- The same re-decision text keys get. Whoever granted this was
-- looking at a room the whole server could walk into; a room with a door is a
-- different question, and it should be asked again rather than inherited.

CREATE OR REPLACE FUNCTION drop_bot_voice_grants_when_closed()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF NEW.is_private AND NOT OLD.is_private THEN
    DELETE FROM bot_voice_grants WHERE channel_id = NEW.id;
  END IF;
  RETURN NULL;
END; $$;

-- ============================================================
-- 3. A grant that changes takes the row with it
-- ============================================================
-- Granting hearing to a bot that already holds a publish key has to replace
-- that row, or the bot keeps encrypting with a key nobody looks for and stays
-- inaudible. Revoking has the same problem in reverse — and worse, leaving the
-- channel key sealed to a bot whose grant is gone is the grant not actually
-- being revoked.
--
-- Dropping the rows is enough: the next member into the call finds the bot
-- missing a key for the current version and seals the right one.

CREATE OR REPLACE FUNCTION drop_bot_voice_keys_on_grant_change()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  DELETE FROM bot_voice_keys
   WHERE channel_id = COALESCE(NEW.channel_id, OLD.channel_id)
     AND bot_id     = COALESCE(NEW.bot_id, OLD.bot_id);
  RETURN NULL;
END; $$;

-- ============================================================
-- 4. Dismissing takes the key with it
-- ============================================================
-- Same shape as `drop_bot_voice_keys_on_grant_change`, and for the same
-- reason: a key sealed under one decision must not outlive it. Without this a
-- dismissed bot keeps a usable media key and only the token stands between it
-- and the room.

CREATE OR REPLACE FUNCTION drop_bot_voice_keys_on_summon_change()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  DELETE FROM bot_voice_keys
   WHERE channel_id = COALESCE(NEW.channel_id, OLD.channel_id)
     AND bot_id     = COALESCE(NEW.bot_id, OLD.bot_id);
  RETURN NULL;
END; $$;

-- No write grant at all: summoning moves through the functions above, so a row
-- cannot appear without the permission check that justifies it.

-- ============================================================
-- A summon outliving its reason
-- ============================================================
-- A summon ends in two ways by decision: somebody dismisses it, or the channel
-- or the bot is deleted. It also has to end when the *reason* for it is gone,
-- which is the three cases below.
--
--   1. **A channel made private must not keep its summons.** Closing a
--      channel drops its listening grants, for the obvious reason: the people
--      who granted them are not necessarily the people in the room now. A
--      summon is the same shape — without this, a bot summoned into a public
--      call could still take a token for it after it was closed, because
--      `channel_joinable_by` reads the summon and never asks about privacy.
--      That is a privacy boundary crossed by a stale row.
--
--   2. **A summon outlived the call.** Say `/play` while the bot is down and
--      everybody goes home: the row waits. The bot cannot arrive at once,
--      because dismissing took its media key — but the next time a member is in
--      that channel their client seals a new one, and the bot turns up in a
--      conversation nobody invited it to, hours later.
--
--   3. **Nobody could see one.** "Send away" lives on the participant menu,
--      which needs the bot to be *in* the call. A summon whose bot never joined
--      was invisible and unclearable. `voice_summons` below is the view a
--      client can draw it from, the sibling of `voice_listeners`.
--
-- ---------- why an hour, and why not a disconnect hook ----------
--
-- The exact end of a call is LiveKit's to know, not this database's, and asking
-- it would mean a webhook and a new failure mode for a tidy-up. An age is worse
-- at the edges and cannot break: a summon is a request to come and play *now*,
-- so one that has sat unused for an hour has been answered by events. A bot
-- that is already connected is unaffected — dropping the row takes its right to
-- a *new* token, and it is the dismiss path that disconnects.
--
-- Riding on the same hourly job as the invite sweep for the same reason: one
-- schedule to reason about.

-- ============================================================
-- 1. Closing a channel takes its summons with it
-- ============================================================
-- Deliberately not `AFTER UPDATE OF is_private`: `set_channel_private` is the
-- only writer, and matching the grant trigger's shape exactly is worth more
-- here than saving a comparison.

CREATE OR REPLACE FUNCTION drop_bot_voice_summons_when_closed()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF NEW.is_private AND NOT OLD.is_private THEN
    DELETE FROM bot_voice_summons WHERE channel_id = NEW.id;
  END IF;
  RETURN NULL;
END; $$;

-- The exception for a server being deleted: without it the cascade cannot get
-- past `@everyone`, which is otherwise permanent.
CREATE OR REPLACE FUNCTION protect_everyone_role()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.is_everyone AND EXISTS (SELECT 1 FROM servers s WHERE s.id = OLD.server_id) THEN
      RAISE EXCEPTION 'everyone_is_permanent';
    END IF;
    RETURN OLD;
  END IF;
  NEW.is_everyone := OLD.is_everyone;
  IF NEW.is_everyone THEN NEW.position := 0; END IF;
  RETURN NEW;
END; $$;

-- The two paths that do grant it — registration and transfer — run as the
-- service role or as definer, past every policy. This is what keeps them
-- honest: one holder, and never a bot, whichever path wrote the row.
CREATE OR REPLACE FUNCTION refuse_second_owner()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = NEW.role_id AND r.is_owner) THEN
    RETURN NEW;
  END IF;
  IF EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.is_bot) THEN
    RAISE EXCEPTION 'bot_cannot_own';
  END IF;
  IF EXISTS (SELECT 1 FROM member_roles mr
              WHERE mr.role_id = NEW.role_id AND mr.user_id <> NEW.user_id) THEN
    RAISE EXCEPTION 'owner_is_singular';
  END IF;
  RETURN NEW;
END; $$;

-- An owner does not leave; they transfer or delete. Without this a server
-- could end up with nobody who can do either, which is the state this whole
-- file exists to make impossible. The server being deleted is the exception:
-- its rows go with it, owner first or last.
CREATE OR REPLACE FUNCTION refuse_owner_leaving()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM servers s WHERE s.id = OLD.server_id)
     AND EXISTS (SELECT 1 FROM member_roles mr
                   JOIN roles r ON r.id = mr.role_id
                  WHERE mr.user_id = OLD.id AND r.is_owner) THEN
    RAISE EXCEPTION 'owner_cannot_leave';
  END IF;
  RETURN OLD;
END; $$;

CREATE OR REPLACE FUNCTION seed_default_roles()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  INSERT INTO roles (server_id, name, position, permissions, is_everyone, is_owner)
  VALUES
    (NEW.id, '@everyone', 0,
       app.perm('VIEW_CHANNEL')  | app.perm('SEND_MESSAGES')
     | app.perm('ATTACH_FILES')  | app.perm('ADD_REACTIONS')
     | app.perm('MENTION_ALL')
     | app.perm('CONNECT')       | app.perm('SPEAK')
     | app.perm('SCREEN_SHARE')
     | app.perm('SUMMON_BOTS')   | app.perm('CREATE_INVITE')
     | app.perm('USE_SOUNDBOARD'), true, false),
    (NEW.id, 'Moderator', 200,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS')    | app.perm('ADD_BOTS')
     | app.perm('CREATE_PRIVATE_CHANNEL')
     | app.perm('MANAGE_SOUNDBOARD'), false, false),
    (NEW.id, 'Admin',     300, app.perm('ADMINISTRATOR'), false, false),
    (NEW.id, 'Owner',     400, app.perm('ADMINISTRATOR'), false, true)
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;

-- ============================================================
-- 3. The flag goes with it
-- ============================================================
-- The view and the function that pages it both carry the column, so both
-- are remade without it, with the same grants.

CREATE OR REPLACE FUNCTION protect_owner_role()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    IF OLD.is_owner AND EXISTS (SELECT 1 FROM servers s WHERE s.id = OLD.server_id) THEN
      RAISE EXCEPTION 'owner_is_permanent';
    END IF;
    RETURN OLD;
  END IF;
  IF TG_OP = 'UPDATE' THEN
    NEW.is_owner := OLD.is_owner;
  END IF;
  IF NEW.is_owner THEN
    NEW.position    := 400;
    NEW.permissions := app.perm('ADMINISTRATOR');
    NEW.is_everyone := false;
  END IF;
  RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION ring_dm_recipient()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
BEGIN
  SELECT server_id INTO v_server_id FROM users WHERE id = NEW.recipient_id;
  IF v_server_id IS NULL THEN RETURN NEW; END IF;
  -- Cheaper than the unread gate below it, and true far less often.
  IF NOT app.push_enabled(v_server_id) THEN RETURN NEW; END IF;

  IF app.notify_level(NEW.recipient_id, 'dm', NEW.sender_id) = 'none' THEN
    RETURN NEW;
  END IF;
  IF has_unread_before(NEW.recipient_id, 'dm', NEW.sender_id, NEW.id) THEN
    RETURN NEW;
  END IF;

  PERFORM ring_devices(v_server_id, ARRAY[NEW.recipient_id]);
  RETURN NEW;
END $$;

-- ============================================================
-- 2. Keeping them true
-- ============================================================
-- An insert is the easy half — a new message is always the newest, so both
-- sides move forward. GREATEST rather than a bare assignment because a
-- backfill or a repair may run beside it, and a head that goes backwards is a
-- conversation that jumps down the list.

CREATE OR REPLACE FUNCTION app.remember_dm_head() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO dm_conversation_heads (user_id, peer_id, last_message_id)
  VALUES (NEW.sender_id, NEW.recipient_id, NEW.id),
         (NEW.recipient_id, NEW.sender_id, NEW.id)
      ON CONFLICT (user_id, peer_id) DO UPDATE
     SET last_message_id = GREATEST(dm_conversation_heads.last_message_id,
                                    EXCLUDED.last_message_id);
  RETURN NULL;
END $$;

-- A delete only matters when it takes the head with it, which is the rare
-- case: `app.enforce_retention` deletes the *oldest* messages, and the only
-- other delete is somebody removing their own message — usually not the
-- newest either.
--
-- When it is the head, the replacement is one backwards walk of
-- `idx_dm_messages_pair`; when nothing is left, the conversation is over and
-- the rows go.

CREATE OR REPLACE FUNCTION app.forget_dm_head() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_newest BIGINT;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM dm_conversation_heads h
     WHERE h.last_message_id = OLD.id
       AND ((h.user_id = OLD.sender_id    AND h.peer_id = OLD.recipient_id)
         OR (h.user_id = OLD.recipient_id AND h.peer_id = OLD.sender_id))
  ) THEN
    RETURN NULL;   -- something older went; the head still stands
  END IF;

  SELECT max(d.id) INTO v_newest
    FROM dm_messages d
   WHERE LEAST(d.sender_id, d.recipient_id)
           = LEAST(OLD.sender_id, OLD.recipient_id)
     AND GREATEST(d.sender_id, d.recipient_id)
           = GREATEST(OLD.sender_id, OLD.recipient_id);

  IF v_newest IS NULL THEN
    DELETE FROM dm_conversation_heads h
     WHERE (h.user_id = OLD.sender_id    AND h.peer_id = OLD.recipient_id)
        OR (h.user_id = OLD.recipient_id AND h.peer_id = OLD.sender_id);
  ELSE
    UPDATE dm_conversation_heads h
       SET last_message_id = v_newest
     WHERE ((h.user_id = OLD.sender_id    AND h.peer_id = OLD.recipient_id)
         OR (h.user_id = OLD.recipient_id AND h.peer_id = OLD.sender_id))
       AND h.last_message_id = OLD.id;
  END IF;
  RETURN NULL;
END $$;

-- ============================================================
-- 3. The doorbell
-- ============================================================

CREATE OR REPLACE FUNCTION ring_channel_members()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
  v_t         RECORD;
  v_targets   UUID[];
BEGIN
  IF NEW.is_interaction THEN RETURN NEW; END IF;

  SELECT server_id INTO v_server_id FROM channels WHERE id = NEW.channel_id;
  IF v_server_id IS NULL THEN RETURN NEW; END IF;
  IF NOT app.push_enabled(v_server_id) THEN RETURN NEW; END IF;

  v_t := app.unread_thresholds(NEW.channel_id, NEW.id);

  IF v_t.o_newest IS NULL THEN
    -- The first message in the channel. Nobody can have unread mail before
    -- it, so everybody eligible is rung — once, ever, per channel.
    SELECT array_agg(u.id) INTO v_targets
      FROM users u
     WHERE u.server_id = v_server_id
       AND u.id IS DISTINCT FROM NEW.sender_id
       AND NOT u.is_banned AND NOT u.is_bot
       AND (NEW.ephemeral_for IS NULL OR u.id = NEW.ephemeral_for)
       AND app.channel_eligible(NEW.channel_id, u.id);
  ELSE
    SELECT array_agg(c.user_id) INTO v_targets FROM (
      -- Everyone whose cursor is at or past the newest message they did not
      -- write. The first bound is the cheap one and drives the index; the
      -- second is the exact one and is checked on what it returns.
      SELECT r.user_id
        FROM read_state r
       WHERE r.scope = 'channel'
         AND r.scope_id = NEW.channel_id
         AND r.last_read_id >= COALESCE(v_t.o_newest_other, 0)
         AND r.last_read_id >= CASE
               WHEN v_t.o_newest_by IS DISTINCT FROM r.user_id THEN v_t.o_newest
               ELSE COALESCE(v_t.o_newest_other, 0) END
      UNION
      -- The one member who can be caught up with no `read_state` row at all:
      -- when nobody else has ever written here, everything before this
      -- message is theirs, so there is nothing of anybody else's to have
      -- missed. `o_newest_other IS NULL` is exactly that case.
      SELECT v_t.o_newest_by
       WHERE v_t.o_newest_other IS NULL AND v_t.o_newest_by IS NOT NULL
    ) c
    JOIN users u ON u.id = c.user_id
   WHERE u.server_id = v_server_id
     AND u.id IS DISTINCT FROM NEW.sender_id
     AND NOT u.is_banned AND NOT u.is_bot
     AND (NEW.ephemeral_for IS NULL OR u.id = NEW.ephemeral_for)
     AND app.channel_eligible(NEW.channel_id, u.id);
  END IF;

  PERFORM ring_devices(v_server_id, v_targets);
  RETURN NEW;
END $$;

COMMENT ON FUNCTION ring_channel_members() IS
  'Wake the phones of members who were caught up in this channel. Driven by '
  'read_state rather than the roster: being caught up is the rare case, and '
  'the roster is the expensive one to walk.';

DROP TRIGGER IF EXISTS attest_messages ON messages;
CREATE TRIGGER attest_messages BEFORE INSERT OR UPDATE ON messages
  FOR EACH ROW EXECUTE FUNCTION attest_message();

DROP TRIGGER IF EXISTS attest_dm_messages ON dm_messages;
CREATE TRIGGER attest_dm_messages BEFORE INSERT OR UPDATE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION attest_message();

DROP TRIGGER IF EXISTS device_tokens_stamp ON device_tokens;
CREATE TRIGGER device_tokens_stamp BEFORE INSERT OR UPDATE ON device_tokens
  FOR EACH ROW EXECUTE FUNCTION stamp_device_owner();

DROP TRIGGER IF EXISTS dm_messages_ring ON dm_messages;
CREATE TRIGGER dm_messages_ring AFTER INSERT ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION ring_dm_recipient();

-- ============================================================
-- The soundboard's three rules
-- ============================================================
-- Whose clip it is, a ceiling, and no blob left behind.
--
-- The ceiling is a trigger rather than a check in the RPC that inserts,
-- because there is no such RPC: adding a clip is an ordinary INSERT under a
-- policy, so the only place a count can be enforced is the row itself.

-- Stamped rather than accepted, the same rule as a device token and a
-- notification preference: a client that could name the server could hang a
-- clip on one it is not in, and a client that could name the author could put
-- somebody else's name on it.
CREATE OR REPLACE FUNCTION stamp_soundboard_sound()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF auth.uid() IS NOT NULL THEN
    NEW.server_id  := app.server_id();
    NEW.created_by := auth.uid();
  END IF;
  RETURN NEW;
END; $$;

CREATE OR REPLACE FUNCTION enforce_soundboard_max()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  IF (SELECT count(*) FROM soundboard_sounds s
       WHERE s.server_id = NEW.server_id) >= app.soundboard_max() THEN
    RAISE EXCEPTION 'soundboard_full';
  END IF;
  RETURN NEW;
END; $$;

-- There is deliberately no trigger dropping a clip's file when its row goes.
--
-- There was one, and it was wrong twice over. Storage installs a
-- `protect_objects_delete` guard on `storage.objects` that raises
-- `Direct deletion from storage tables is not allowed` for anything but its
-- own API, so the trigger did not merely fail to remove the file — it failed
-- the whole DELETE, and a clip could not be removed at all.
--
-- The guard can be opted out of with `storage.allow_delete_query`, and that
-- would still have been wrong: deleting the row in `storage.objects` does
-- not delete the bytes behind it. Only the Storage API knows where they are.
-- The trigger would have left every removed clip's 5 MB on the host's disk
-- with nothing left pointing at it — which is exactly what the guard's own
-- hint warns about.
--
-- So the client removes the object through the Storage API, after the row is
-- gone (`SoundboardRepository.deleteObject`). Row first, deliberately: an
-- orphaned object costs space, while a row whose object has gone is a clip
-- in everybody's picker that plays nothing — the same asymmetry that makes
-- `addSound` upload before it inserts.

DROP TRIGGER IF EXISTS messages_ring ON messages;
CREATE TRIGGER messages_ring AFTER INSERT ON messages
  FOR EACH ROW EXECUTE FUNCTION ring_channel_members();

DROP TRIGGER IF EXISTS notification_prefs_stamp ON notification_prefs;
CREATE TRIGGER notification_prefs_stamp BEFORE INSERT OR UPDATE ON notification_prefs
  FOR EACH ROW EXECUTE FUNCTION stamp_notification_pref();

DROP TRIGGER IF EXISTS validate_message_mentions ON messages;
CREATE TRIGGER validate_message_mentions BEFORE INSERT OR UPDATE ON messages
  FOR EACH ROW EXECUTE FUNCTION validate_message_mentions();

DROP TRIGGER IF EXISTS users_pin_is_bot ON users;
CREATE TRIGGER users_pin_is_bot BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION pin_is_bot();

DROP TRIGGER IF EXISTS messages_pin_bot_command ON messages;
CREATE TRIGGER messages_pin_bot_command BEFORE UPDATE ON messages
  FOR EACH ROW EXECUTE FUNCTION pin_bot_command();

DROP TRIGGER IF EXISTS member_roles_refuse_everyone ON member_roles;
CREATE TRIGGER member_roles_refuse_everyone BEFORE INSERT OR UPDATE ON member_roles
  FOR EACH ROW EXECUTE FUNCTION refuse_everyone_assignment();

DROP TRIGGER IF EXISTS roles_protect_everyone ON roles;
CREATE TRIGGER roles_protect_everyone BEFORE UPDATE OR DELETE ON roles
  FOR EACH ROW EXECUTE FUNCTION protect_everyone_role();

DROP TRIGGER IF EXISTS member_roles_sync_cache ON member_roles;
CREATE TRIGGER member_roles_sync_cache
  AFTER INSERT OR UPDATE OR DELETE ON member_roles
  FOR EACH ROW EXECUTE FUNCTION sync_member_permission_cache();

DROP TRIGGER IF EXISTS roles_sync_cache ON roles;
CREATE TRIGGER roles_sync_cache AFTER INSERT OR UPDATE OR DELETE ON roles
  FOR EACH ROW EXECUTE FUNCTION sync_role_permission_cache();

DROP TRIGGER IF EXISTS servers_seed_roles ON servers;
CREATE TRIGGER servers_seed_roles AFTER INSERT ON servers
  FOR EACH ROW EXECUTE FUNCTION seed_default_roles();

DROP TRIGGER IF EXISTS channel_keyring_refuse_ineligible ON channel_keyring;
CREATE TRIGGER channel_keyring_refuse_ineligible BEFORE INSERT ON channel_keyring
  FOR EACH ROW EXECUTE FUNCTION refuse_ineligible_keyring();

DROP TRIGGER IF EXISTS channel_members_reassign ON channel_members;
CREATE TRIGGER channel_members_reassign AFTER DELETE ON channel_members
  FOR EACH ROW EXECUTE FUNCTION reassign_or_close_channel();

DROP TRIGGER IF EXISTS channels_seed_owner ON channels;
CREATE TRIGGER channels_seed_owner AFTER INSERT ON channels
  FOR EACH ROW EXECUTE FUNCTION seed_private_channel_owner();

DROP TRIGGER IF EXISTS channels_apply_bot_grants ON channels;
CREATE TRIGGER channels_apply_bot_grants AFTER INSERT ON channels
  FOR EACH ROW EXECUTE FUNCTION apply_bot_server_grants();

DROP TRIGGER IF EXISTS channels_drop_bot_grants ON channels;
CREATE TRIGGER channels_drop_bot_grants AFTER UPDATE OF is_private ON channels
  FOR EACH ROW EXECUTE FUNCTION drop_bot_grants_when_closed();

DROP TRIGGER IF EXISTS channels_drop_bot_voice_grants ON channels;
CREATE TRIGGER channels_drop_bot_voice_grants AFTER UPDATE OF is_private ON channels
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_grants_when_closed();

DROP TRIGGER IF EXISTS bot_voice_grants_reset_keys ON bot_voice_grants;
CREATE TRIGGER bot_voice_grants_reset_keys
  AFTER INSERT OR DELETE ON bot_voice_grants
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_keys_on_grant_change();

DROP TRIGGER IF EXISTS bot_voice_summons_reset_keys ON bot_voice_summons;
CREATE TRIGGER bot_voice_summons_reset_keys
  AFTER INSERT OR DELETE ON bot_voice_summons
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_keys_on_summon_change();

DROP TRIGGER IF EXISTS channels_drop_bot_voice_summons ON channels;
CREATE TRIGGER channels_drop_bot_voice_summons
  AFTER UPDATE ON channels
  FOR EACH ROW EXECUTE FUNCTION drop_bot_voice_summons_when_closed();

DROP TRIGGER IF EXISTS roles_protect_owner ON roles;
CREATE TRIGGER roles_protect_owner BEFORE INSERT OR UPDATE OR DELETE ON roles
  FOR EACH ROW EXECUTE FUNCTION protect_owner_role();

DROP TRIGGER IF EXISTS member_roles_refuse_second_owner ON member_roles;
CREATE TRIGGER member_roles_refuse_second_owner BEFORE INSERT OR UPDATE ON member_roles
  FOR EACH ROW EXECUTE FUNCTION refuse_second_owner();

DROP TRIGGER IF EXISTS users_refuse_owner_leaving ON users;
CREATE TRIGGER users_refuse_owner_leaving BEFORE DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION refuse_owner_leaving();

DROP TRIGGER IF EXISTS dm_messages_head ON dm_messages;
CREATE TRIGGER dm_messages_head AFTER INSERT ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION app.remember_dm_head();

DROP TRIGGER IF EXISTS dm_messages_head_gone ON dm_messages;
CREATE TRIGGER dm_messages_head_gone AFTER DELETE ON dm_messages
  FOR EACH ROW EXECUTE FUNCTION app.forget_dm_head();

DROP TRIGGER IF EXISTS soundboard_sounds_stamp ON soundboard_sounds;
CREATE TRIGGER soundboard_sounds_stamp BEFORE INSERT ON soundboard_sounds
  FOR EACH ROW EXECUTE FUNCTION stamp_soundboard_sound();

DROP TRIGGER IF EXISTS soundboard_sounds_cap ON soundboard_sounds;
CREATE TRIGGER soundboard_sounds_cap BEFORE INSERT ON soundboard_sounds
  FOR EACH ROW EXECUTE FUNCTION enforce_soundboard_max();

