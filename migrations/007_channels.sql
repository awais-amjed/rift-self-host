-- ============================================================
-- Rift self-hosted server — 007: Private channels and who can open one
-- ============================================================
-- Channels stop being uniformly visible: an audience per channel, the
-- eligibility rules that follow from it, and creating and leaving one.
--
-- Was 5 files: 019_dm_attest_fix, 020_private_channels, 021_channel_eligibility, 022_create_channel, 023_leave_channel.
-- Merged unchanged and in the same order, so this applies exactly what
-- they applied. The sections below are those files, each still carrying
-- the reasoning it was written with.
-- ============================================================

-- ============================================================
-- Rift self-hosted server — 019: a DM could not be sent
-- ============================================================
-- `attest_message` runs on two tables — `attest_messages` on `messages` and
-- `attest_dm_messages` on `dm_messages`. 013 added the webhook columns to the
-- first and taught the trigger to clear them on a member's insert:
--
--     IF NEW.sender_id IS NOT NULL THEN
--       NEW.webhook_id  := NULL;
--       NEW.origin_name := NULL;
--     END IF;
--
-- `dm_messages` has neither column, so every DM sent by a logged-in member
-- raised `record "new" has no field "webhook_id"` and never reached the table.
-- Only a member's insert took that branch, which is why nothing else noticed:
-- the service role has no `auth.uid()` and skipped it entirely.
--
-- The UPDATE branch below it has always been guarded by `TG_TABLE_NAME`. The
-- INSERT branch was written as though it had only one table to serve.
--
-- ---------- and the line that went with it ----------
--
-- 001 opened the function with an early return:
--
--     IF auth.uid() IS NULL THEN RETURN NEW; END IF;
--
-- Nothing that reaches this trigger without a session is a client — `anon` holds
-- no INSERT grant on either table — so that branch is the service role and the
-- superuser, both of which are trusted to write a row as it stands. It is how
-- `post_webhook_message` writes a NULL sender, and how anything that needs to
-- back-date a row (retention tests, fixtures, a repair script) can.
--
-- 013 dropped it, and three things stopped working for the same reason: a
-- fixture insert had its `sender_id` overwritten with NULL and hit
-- `messages_one_origin`; a back-dating UPDATE had its `created_at` pinned back;
-- and the DM path above. It is restored here, which costs 013 nothing — a
-- *member* still cannot claim to be a webhook, because a member has a session
-- and never takes this branch.
--
-- ---------- why this was not caught ----------
--
-- `tests/policies_test.sql` sends a DM. It has been unable to run since the
-- same migration: its fixtures are written as the superuser, and 013 made
-- `sender_id := auth.uid()` — NULL, there — collide with the new
-- `messages_one_origin` CHECK. So the suite failed while loading its fixtures
-- and never reached the assertion that would have shown this.
--
-- One migration broke the code and the thing watching the code. That is the
-- argument for the suite being part of the migration rather than after it.

CREATE OR REPLACE FUNCTION attest_message()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  -- Restored from 001. Everything below is about not trusting a client; there
  -- is no client here.
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
-- Rift self-hosted server — 020: private channels
-- ============================================================
-- 018 left one permission bit unread. This is it.
--
-- ---------- why VIEW_CHANNEL is not like the other twenty ----------
--
-- Every other permission is a rule the database applies to a request. Change
-- the rule and the next request obeys it. `VIEW_CHANNEL` is not a rule: reading
-- a channel means holding a key that was sealed to you, and a sealed key cannot
-- be un-sealed. It can only be made useless by rotating to a new one.
--
-- Two things follow, and they shape the whole migration:
--
--   1. **Visibility is a list of people, not a predicate.** A key has to be
--      wrapped *for* somebody, so "who may read this channel" must resolve to
--      names before anything is encrypted. Roles are a way to *populate* that
--      list — `channel_role_access` — but what the key machinery reads is the
--      resolved set.
--   2. **Revocation is a rotation, and rotation needs somebody online.** The
--      person doing the removing is a member holding the current key, so in
--      practice it happens there and then. The exception is an admin banning
--      somebody from a private channel the admin is not in: no key, so it waits
--      for a member. Written down rather than designed around.
--
-- Everything else in a channel — send, react, connect, speak — stays an
-- ordinary rule, and per-channel overwrites for those can land later without
-- touching a single key.
--
-- ---------- admins do not see private channels ----------
--
-- Deliberately, and it is not a comfortable-sounding rule until you notice it
-- is the only one here that is actually enforced by mathematics. An admin can
-- read this database directly; what they get is ciphertext, because nothing
-- ever sealed a key to them. They can see that a private channel exists and who
-- is in it. They cannot see a word of it, and no policy edit changes that.
--
-- So there is no admin override, no "for moderation" back door, and no
-- `is_admin()` in `app.can_see_channel`. A back door would be a promise the
-- crypto cannot keep.
--
-- ---------- both directions ----------
--
-- Public → private: the excluded are sealed into the current version, so a
-- rotation is due. They keep what they already read — nobody can take that back
-- — and get nothing further.
--
-- Private → public: this one needs help. Healing only ever seals the *current*
-- version, so simply flipping the flag would hand every new arrival the key the
-- private conversation is still being written under. `rotate_from_key_version`
-- is the marker: the sweep rotates until it is past, and only then is anybody
-- new sealed in. The private history stays under keys they never held.
--
-- The marker is self-clearing, like every other rotation signal here: it is
-- compared against the current version, and the rotation is what makes the
-- comparison false.

-- ============================================================
-- 1. The flag, and the marker that makes it reversible
-- ============================================================

ALTER TABLE channels
  ADD COLUMN IF NOT EXISTS is_private BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN channels.is_private IS
  'Visible only to channel_members and holders of a channel_role_access role. '
  'No admin override: an admin holds no key either way.';

ALTER TABLE channels
  ADD COLUMN IF NOT EXISTS rotate_from_key_version INTEGER;

COMMENT ON COLUMN channels.rotate_from_key_version IS
  'Set when a channel opens up: the sweep must rotate past this version before '
  'anybody new is sealed in, or a new arrival receives the key the private '
  'conversation was written under. Self-clearing.';

CREATE INDEX IF NOT EXISTS channels_private
  ON channels (server_id) WHERE is_private;

-- ============================================================
-- 2. Who is in one
-- ============================================================

CREATE TABLE IF NOT EXISTS channel_members (
  channel_id UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  -- The private channel's own manage bit. `MANAGE_CHANNELS` is a server
  -- permission and its holders cannot see this room, so somebody inside has to
  -- be able to run it.
  can_manage BOOLEAN     NOT NULL DEFAULT false,
  added_by   UUID        REFERENCES users(id) ON DELETE SET NULL,
  -- `clock_timestamp()`, not `now()`. `now()` is the transaction's start, so
  -- everybody seated by one statement — which is exactly what closing a channel
  -- does — would share a timestamp, and "longest-serving" would come down to
  -- whose UUID sorts first. This column decides who inherits the room.
  added_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (channel_id, user_id)
);

CREATE INDEX IF NOT EXISTS channel_members_user ON channel_members (user_id);

-- Access by role, resolved rather than stored: adding a role here means
-- everybody holding it, including whoever is given it tomorrow. The sweep reads
-- through to the people, because a key can only be wrapped for a person.
CREATE TABLE IF NOT EXISTS channel_role_access (
  channel_id UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  role_id    UUID        NOT NULL REFERENCES roles(id)    ON DELETE CASCADE,
  added_by   UUID        REFERENCES users(id) ON DELETE SET NULL,
  added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, role_id)
);

CREATE INDEX IF NOT EXISTS channel_role_access_role ON channel_role_access (role_id);

-- ============================================================
-- 3. The one question everything else asks
-- ============================================================

-- Is this person inside this channel — by name, or by a role that is?
CREATE OR REPLACE FUNCTION app.in_channel(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM channel_members cm
                  WHERE cm.channel_id = p_channel AND cm.user_id = p_user)
      OR EXISTS (SELECT 1 FROM channel_role_access cra
                  JOIN member_roles mr ON mr.role_id = cra.role_id
                 WHERE cra.channel_id = p_channel AND mr.user_id = p_user)
$$;

-- May I hold a key to this channel? The question the keyring asks, and the one
-- the sweep resolves into a list.
--
-- A banned member is nobody's business, which is why it is checked here rather
-- than in each caller: a ban is exactly the case where "still in the list" and
-- "may still read" come apart.
CREATE OR REPLACE FUNCTION app.channel_eligible(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1
      FROM channels c
      JOIN users u ON u.id = p_user AND u.server_id = c.server_id
     WHERE c.id = p_channel
       AND NOT u.is_banned
       AND (NOT c.is_private OR app.in_channel(p_channel, p_user)))
$$;

-- Replaces `app.channel_server_id(x) = app.server_id()` everywhere it stood for
-- "may this member touch this channel". Same shape, one more clause.
CREATE OR REPLACE FUNCTION app.can_see_channel(p_channel UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM channels c
     WHERE c.id = p_channel
       AND c.server_id = app.server_id()
       AND (NOT c.is_private OR app.in_channel(p_channel, auth.uid())))
$$;

-- Renaming, deleting, setting retention. A public channel answers to
-- `MANAGE_CHANNELS`; a private one answers to its own members, because the
-- holders of `MANAGE_CHANNELS` cannot see it to manage it.
CREATE OR REPLACE FUNCTION app.can_manage_channel(p_channel UUID) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM channels c
     WHERE c.id = p_channel
       AND c.server_id = app.server_id()
       AND (CASE WHEN c.is_private
                 THEN EXISTS (SELECT 1 FROM channel_members cm
                               WHERE cm.channel_id = p_channel
                                 AND cm.user_id = auth.uid()
                                 AND cm.can_manage)
                 ELSE app.has_perm('MANAGE_CHANNELS') END))
$$;

-- ============================================================
-- 4. One more bit
-- ============================================================
-- Bit 21. Numbers are assigned once and never reused, so this is an addition to
-- the list — but it is delivered by redefining the function, which means the
-- migrations have to be applied in order. Re-running 018 on its own puts the
-- 21-bit version back and everything here stops resolving.
--
-- A lookup table would make each migration independent. It would also stop the
-- function being inlined into every policy that calls it, and these are read on
-- every row of every message query, so the ordering constraint is the cheaper
-- of the two costs.
--
-- On `@everyone` by default, which is the decision worth stating out loud: a
-- private channel is how a handful of people talk without asking permission, so
-- gating its creation on `MANAGE_CHANNELS` would mean asking permission. A
-- server that disagrees takes the bit off `@everyone`.

CREATE OR REPLACE FUNCTION app.perm_bit(p_name TEXT) RETURNS BIGINT
  LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE p_name
    -- Server
    WHEN 'ADMINISTRATOR'          THEN 1::BIGINT << 0   -- implies every other bit
    WHEN 'MANAGE_SERVER'          THEN 1::BIGINT << 1
    WHEN 'MANAGE_ROLES'           THEN 1::BIGINT << 2
    WHEN 'MANAGE_CHANNELS'        THEN 1::BIGINT << 3
    WHEN 'CREATE_INVITE'          THEN 1::BIGINT << 4
    WHEN 'KICK_MEMBERS'           THEN 1::BIGINT << 5
    WHEN 'BAN_MEMBERS'            THEN 1::BIGINT << 6
    WHEN 'MANAGE_BOTS'            THEN 1::BIGINT << 7   -- the §6 channel-key grant
    WHEN 'MANAGE_WEBHOOKS'        THEN 1::BIGINT << 8
    -- Text
    WHEN 'VIEW_CHANNEL'           THEN 1::BIGINT << 9
    WHEN 'SEND_MESSAGES'          THEN 1::BIGINT << 10
    WHEN 'ATTACH_FILES'           THEN 1::BIGINT << 11
    WHEN 'ADD_REACTIONS'          THEN 1::BIGINT << 12
    WHEN 'MENTION_ALL'            THEN 1::BIGINT << 13
    WHEN 'MANAGE_MESSAGES'        THEN 1::BIGINT << 14  -- delete anybody's
    -- Voice
    WHEN 'CONNECT'                THEN 1::BIGINT << 15
    WHEN 'SPEAK'                  THEN 1::BIGINT << 16
    WHEN 'SCREEN_SHARE'           THEN 1::BIGINT << 17
    WHEN 'MUTE_MEMBERS'           THEN 1::BIGINT << 18
    WHEN 'DEAFEN_MEMBERS'         THEN 1::BIGINT << 19
    WHEN 'MOVE_MEMBERS'           THEN 1::BIGINT << 20
    -- 020
    WHEN 'CREATE_PRIVATE_CHANNEL' THEN 1::BIGINT << 21
    ELSE NULL
  END
$$;

CREATE OR REPLACE FUNCTION app.perm_all() RETURNS BIGINT
  LANGUAGE sql IMMUTABLE AS $$ SELECT (1::BIGINT << 22) - 1 $$;

UPDATE roles SET permissions = permissions | app.perm('CREATE_PRIVATE_CHANNEL')
 WHERE is_everyone;

CREATE OR REPLACE FUNCTION seed_default_roles()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  INSERT INTO roles (server_id, name, position, permissions, is_everyone, legacy_key)
  VALUES
    (NEW.id, '@everyone', 0,
       app.perm('VIEW_CHANNEL')  | app.perm('SEND_MESSAGES')
     | app.perm('ATTACH_FILES')  | app.perm('ADD_REACTIONS')
     | app.perm('MENTION_ALL')
     | app.perm('CONNECT')       | app.perm('SPEAK')
     | app.perm('SCREEN_SHARE')
     | app.perm('CREATE_PRIVATE_CHANNEL'), true, NULL),
    (NEW.id, 'Members',   1, app.perm('CREATE_INVITE'), false, 'members'),
    (NEW.id, 'Moderator', 2,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS'), false, 'moderator'),
    (NEW.id, 'Admin',     3, app.perm('ADMINISTRATOR'), false, 'admin')
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;

-- ============================================================
-- 5. Every policy that meant "a channel on my server"
-- ============================================================
-- `app.channel_server_id(x) = app.server_id()` was the whole of "may I touch
-- this channel" in eight places. It is `app.can_see_channel(x)` now, and the
-- eight are rewritten here rather than in eight migrations, because a private
-- channel that leaked through one of them would not be private.

DROP POLICY IF EXISTS channels_select ON channels;
CREATE POLICY channels_select ON channels FOR SELECT TO authenticated
  USING (server_id = app.server_id()
         AND (NOT is_private OR app.in_channel(id, auth.uid())));

DROP POLICY IF EXISTS channels_write_managers ON channels;
CREATE POLICY channels_write_managers ON channels FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND (CASE WHEN is_private THEN app.has_perm('CREATE_PRIVATE_CHANNEL')
              ELSE app.has_perm('MANAGE_CHANNELS') END)
  );

DROP POLICY IF EXISTS channels_update_managers ON channels;
CREATE POLICY channels_update_managers ON channels FOR UPDATE TO authenticated
  USING (app.can_manage_channel(id)) WITH CHECK (app.can_manage_channel(id));

DROP POLICY IF EXISTS channels_delete_managers ON channels;
CREATE POLICY channels_delete_managers ON channels FOR DELETE TO authenticated
  USING (app.can_manage_channel(id));

DROP POLICY IF EXISTS messages_select ON messages;
CREATE POLICY messages_select ON messages FOR SELECT TO authenticated
  USING (
    app.can_see_channel(channel_id)
    AND (NOT app.is_bot() OR to_bot = auth.uid() OR sender_id = auth.uid())
    AND (ephemeral_for IS NULL OR ephemeral_for = auth.uid()
         OR sender_id = auth.uid())
  );

DROP POLICY IF EXISTS messages_insert ON messages;
CREATE POLICY messages_insert ON messages FOR INSERT TO authenticated
  WITH CHECK (
    app.can_see_channel(channel_id)
    AND app.has_perm('SEND_MESSAGES')
    AND sender_id = auth.uid()
    AND webhook_id IS NULL AND origin_name IS NULL
    AND (key_version >= 1 OR to_bot IS NOT NULL OR app.is_bot())
    AND (to_bot IS NULL OR app.is_addressable_bot(to_bot))
    AND (to_bot IS NULL OR key_version = 0)
    AND (NOT app.is_bot() OR key_version = 0)
    AND (ephemeral_for IS NULL OR app.is_bot())
  );

DROP POLICY IF EXISTS messages_update_own ON messages;
CREATE POLICY messages_update_own ON messages FOR UPDATE TO authenticated
  USING (sender_id = auth.uid() AND app.can_see_channel(channel_id))
  WITH CHECK (sender_id = auth.uid());

-- `MANAGE_MESSAGES` rather than 002's `can_manage_channels()`: they are the
-- same people today, and they are two different permissions now. Gated on
-- seeing the channel first, so a server moderator cannot remove a message from
-- a room they are not in — and could not read the report about either.
DROP POLICY IF EXISTS messages_delete ON messages;
CREATE POLICY messages_delete ON messages FOR DELETE TO authenticated
  USING (
    app.can_see_channel(channel_id)
    AND (sender_id = auth.uid()
         OR app.has_perm('MANAGE_MESSAGES')
         OR app.can_manage_channel(channel_id))
  );

-- The keyring is the one that actually matters: everything above is a rule, and
-- this is the arithmetic.
DROP POLICY IF EXISTS channel_keyring_select ON channel_keyring;
CREATE POLICY channel_keyring_select ON channel_keyring FOR SELECT TO authenticated
  USING (app.can_see_channel(channel_id));

DROP POLICY IF EXISTS channel_keyring_insert ON channel_keyring;
CREATE POLICY channel_keyring_insert ON channel_keyring FOR INSERT TO authenticated
  WITH CHECK (
    wrapped_by = auth.uid()
    AND app.can_see_channel(channel_id)
    AND app.channel_eligible(channel_id, user_id)
  );

DROP POLICY IF EXISTS bot_channel_keys_select ON bot_channel_keys;
CREATE POLICY bot_channel_keys_select ON bot_channel_keys
  FOR SELECT TO authenticated USING (app.can_see_channel(channel_id));

CREATE OR REPLACE FUNCTION app.can_see_message(p_message BIGINT) RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM messages m
                  WHERE m.id = p_message
                    AND app.can_see_channel(m.channel_id)
                    AND (NOT app.is_bot() OR m.to_bot = auth.uid()
                         OR m.sender_id = auth.uid()))
$$;

-- ============================================================
-- 6. The keyring refusal, widened
-- ============================================================
-- 017 put the bot rule on the row rather than in the clients that walk the
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

DROP TRIGGER IF EXISTS channel_keyring_refuse_bots ON channel_keyring;
DROP TRIGGER IF EXISTS channel_keyring_refuse_ineligible ON channel_keyring;
CREATE TRIGGER channel_keyring_refuse_ineligible BEFORE INSERT ON channel_keyring
  FOR EACH ROW EXECUTE FUNCTION refuse_ineligible_keyring();

-- ============================================================
-- 7. Opening and closing a channel
-- ============================================================

CREATE OR REPLACE FUNCTION set_channel_private(
  p_channel UUID,
  p_private BOOLEAN
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_channel channels%ROWTYPE;
  v_current INTEGER;
BEGIN
  IF NOT app.can_manage_channel(p_channel) THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  SELECT * INTO v_channel FROM channels WHERE id = p_channel;
  IF NOT FOUND THEN RAISE EXCEPTION 'channel_not_found'; END IF;
  IF v_channel.is_private = p_private THEN
    RETURN jsonb_build_object('reason', 'ok');
  END IF;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  IF p_private THEN
    -- Closing. Whoever is in the room stays in it, and the caller can run it —
    -- otherwise a manager could close a channel and lock themselves out of the
    -- thing they now own.
    UPDATE channels SET is_private = true WHERE id = p_channel;
    INSERT INTO channel_members (channel_id, user_id, can_manage, added_by)
    SELECT p_channel, u.id, u.id = auth.uid(), auth.uid()
      FROM users u
     WHERE u.server_id = v_channel.server_id AND NOT u.is_banned AND NOT u.is_bot
    ON CONFLICT (channel_id, user_id) DO NOTHING;

    UPDATE channel_members SET can_manage = true
     WHERE channel_id = p_channel AND user_id = auth.uid();
  ELSE
    -- Opening. The flag alone would hand every arrival the key the private
    -- conversation is *still being written under*, because healing seals the
    -- current version. Nobody new is sealed until the sweep has rotated past
    -- this mark.
    UPDATE channels
       SET is_private = false,
           rotate_from_key_version = v_current
     WHERE id = p_channel;
  END IF;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

-- Closing a channel to everybody but a few is the common case, and doing it as
-- "make private, then remove 40 people" leaves a window where it is private and
-- everyone is still in it. One statement instead.
CREATE OR REPLACE FUNCTION set_channel_members(
  p_channel UUID,
  p_users   UUID[]
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.can_manage_channel(p_channel) THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM channels WHERE id = p_channel
                   AND server_id = app.server_id()) THEN
    RAISE EXCEPTION 'channel_not_found';
  END IF;

  DELETE FROM channel_members
   WHERE channel_id = p_channel AND user_id <> ALL (p_users);

  INSERT INTO channel_members (channel_id, user_id, added_by)
  SELECT p_channel, u.id, auth.uid()
    FROM users u
   WHERE u.id = ANY (p_users)
     AND u.server_id = app.server_id()
     AND NOT u.is_banned
     -- A bot is keyed by `grant_bot_channel_key` and nothing else. Letting one
     -- in here would be a second door to the same room.
     AND NOT u.is_bot
  ON CONFLICT (channel_id, user_id) DO NOTHING;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION set_channel_role_access(
  p_channel UUID,
  p_role    UUID,
  p_on      BOOLEAN
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.can_manage_channel(p_channel) THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM roles r
                  WHERE r.id = p_role AND r.server_id = app.server_id()) THEN
    RAISE EXCEPTION 'role_not_found';
  END IF;

  IF p_on THEN
    INSERT INTO channel_role_access (channel_id, role_id, added_by)
    VALUES (p_channel, p_role, auth.uid())
    ON CONFLICT DO NOTHING;
  ELSE
    DELETE FROM channel_role_access
     WHERE channel_id = p_channel AND role_id = p_role;
  END IF;
  RETURN jsonb_build_object('reason', 'ok');
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

DROP TRIGGER IF EXISTS channel_members_reassign ON channel_members;
CREATE TRIGGER channel_members_reassign AFTER DELETE ON channel_members
  FOR EACH ROW EXECUTE FUNCTION reassign_or_close_channel();

-- ============================================================
-- 9. The three fan-outs that would have leaked
-- ============================================================
-- Policies decide what a query returns. These do not run inside a query — they
-- decide who gets *pushed* something, and each one was written when every
-- channel was everybody's.

-- A push notification naming a channel somebody cannot open is the loudest
-- possible way to tell them it exists.
CREATE OR REPLACE FUNCTION ring_channel_members()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_server_id UUID;
  v_targets   UUID[];
BEGIN
  SELECT server_id INTO v_server_id FROM channels WHERE id = NEW.channel_id;
  IF v_server_id IS NULL THEN RETURN NEW; END IF;

  SELECT array_agg(u.id) INTO v_targets
    FROM users u
   WHERE u.server_id = v_server_id
     AND u.id IS DISTINCT FROM NEW.sender_id
     AND NOT u.is_banned
     -- A bot has no phone, and would be woken for every message in a room it
     -- cannot read.
     AND NOT u.is_bot
     AND (NEW.ephemeral_for IS NULL OR u.id = NEW.ephemeral_for)
     AND app.channel_eligible(NEW.channel_id, u.id)
     AND NOT has_unread_before(u.id, 'channel', NEW.channel_id, NEW.id);

  PERFORM ring_devices(v_server_id, v_targets);
  RETURN NEW;
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

-- ============================================================
-- 10. Security
-- ============================================================

ALTER TABLE channel_members     ENABLE ROW LEVEL SECURITY;
ALTER TABLE channel_role_access ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON channel_members     FROM anon, authenticated;
REVOKE ALL ON channel_role_access FROM anon, authenticated;

-- Readable by the room, and by nobody else — including an administrator, who
-- would learn who is talking to whom and could not read a word of it anyway.
-- No write grant at all: membership moves through the functions above, so
-- "who is in this room" cannot be changed by anything that skipped the check.
GRANT SELECT ON channel_members     TO authenticated;
GRANT SELECT ON channel_role_access TO authenticated;

DROP POLICY IF EXISTS channel_members_select ON channel_members;
CREATE POLICY channel_members_select ON channel_members
  FOR SELECT TO authenticated USING (app.can_see_channel(channel_id));

DROP POLICY IF EXISTS channel_role_access_select ON channel_role_access;
CREATE POLICY channel_role_access_select ON channel_role_access
  FOR SELECT TO authenticated USING (app.can_see_channel(channel_id));

REVOKE ALL ON FUNCTION refuse_ineligible_keyring()        FROM PUBLIC;
REVOKE ALL ON FUNCTION reassign_or_close_channel()        FROM PUBLIC;
REVOKE ALL ON FUNCTION set_channel_private(UUID, BOOLEAN) FROM PUBLIC;
REVOKE ALL ON FUNCTION set_channel_members(UUID, UUID[])  FROM PUBLIC;
REVOKE ALL ON FUNCTION set_channel_role_access(UUID, UUID, BOOLEAN) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION set_channel_private(UUID, BOOLEAN) TO authenticated;
GRANT EXECUTE ON FUNCTION set_channel_members(UUID, UUID[])  TO authenticated;
GRANT EXECUTE ON FUNCTION set_channel_role_access(UUID, UUID, BOOLEAN) TO authenticated;

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

DROP TRIGGER IF EXISTS channels_seed_owner ON channels;
CREATE TRIGGER channels_seed_owner AFTER INSERT ON channels
  FOR EACH ROW EXECUTE FUNCTION seed_private_channel_owner();

REVOKE ALL ON FUNCTION seed_private_channel_owner() FROM PUBLIC;

-- `is_private` is not in the UPDATE grant: opening or closing a room is
-- `set_channel_private`, which knows that opening one has to leave a rotation
-- behind it. A plain UPDATE would not, and the channel would quietly hand its
-- private history to the next person who joined the server.
GRANT UPDATE (name) ON channels TO authenticated;


-- ============================================================
-- Rift self-hosted server — 021: what the key sweep needs to know
-- ============================================================
-- 020 put "who may read this channel" in the database. Four things outside the
-- database ask that question — `sweep_channel_keys`, `get_channel_key`,
-- `voice_roster` and `get_channel_token` — and all four run as the service
-- role, which is to say with row-level security switched off.
--
-- So none of them is protected by 020. Each one has to filter for itself, and
-- four hand-written filters is four places for the answer to drift. This is
-- the answer, written once, in the same place the policies read it from.
--
-- 017 did the same thing for the bot grant and for the same reason.

-- ============================================================
-- 1. Who may hold a key, and from which version
-- ============================================================
-- One row per (channel, person) that a key may legitimately be wrapped for,
-- carrying the floor that person's access starts at. The sweep's
-- `eligibleFor(channel, version)` is this view with one `<=`.
--
-- The floor is 1 for a member, because a member joining a public channel is
-- offered the current key and reads back as far as it goes. For a bot it is the
-- grant's `from_key_version`, which is what makes a moderation grant
-- forward-only (BOTS.md §6).

CREATE OR REPLACE VIEW channel_eligible_members AS
  SELECT c.id AS channel_id,
         u.id AS user_id,
         u.chat_public_key,
         u.is_bot,
         CASE WHEN u.is_bot THEN g.from_key_version ELSE 1 END AS from_key_version
    FROM channels c
    JOIN users u ON u.server_id = c.server_id
    LEFT JOIN bot_channel_keys g ON g.channel_id = c.id AND g.bot_id = u.id
   WHERE NOT u.is_banned
     -- Sealing to somebody who has published no chat key is a message nobody
     -- can ever open, so they are not "missing" an entry — they are not ready
     -- for one.
     AND u.chat_public_key IS NOT NULL
     AND CASE WHEN u.is_bot
              -- A bot is keyed only where somebody said so, never by the sweep
              -- being helpful.
              THEN g.bot_id IS NOT NULL
              ELSE (NOT c.is_private OR app.in_channel(c.id, u.id))
         END;

COMMENT ON VIEW channel_eligible_members IS
  'Service-role only. Who a channel key may be wrapped for, and from which key '
  'version. Not granted to authenticated: it would list the membership of every '
  'private channel on the server.';

-- Deliberately no grant to `authenticated`. A member reads their own keyring
-- through `get_channel_key`, which returns only what is sealed to them.
REVOKE ALL ON channel_eligible_members FROM anon, authenticated;

-- ============================================================
-- 2. Visibility without a key
-- ============================================================
-- Voice needs a different question. Joining a call is not holding a key —
-- there is no encryption in the room to hold one for — so `CONNECT` is an
-- ordinary rule, and the only thing that matters is whether the channel is
-- yours to see.
--
-- These live in `public` rather than `app` because PostgREST only exposes
-- `public`, and an edge function calling in is a PostgREST client like any
-- other. They are locked to the service role, which is the only caller that
-- needs to ask about somebody who is not itself.

CREATE OR REPLACE FUNCTION app.sees_channel(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM channels c
      JOIN users u ON u.id = p_user AND u.server_id = c.server_id
     WHERE c.id = p_channel
       AND NOT u.is_banned
       AND (NOT c.is_private OR app.in_channel(p_channel, p_user)))
$$;

CREATE OR REPLACE FUNCTION channel_visible_to(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.sees_channel(p_channel, p_user)
$$;

CREATE OR REPLACE FUNCTION visible_channels(p_user UUID)
  RETURNS TABLE (channel_id UUID)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT c.id
    FROM channels c
    JOIN users u ON u.id = p_user AND u.server_id = c.server_id
   WHERE NOT u.is_banned
     AND (NOT c.is_private OR app.in_channel(c.id, p_user))
$$;

REVOKE ALL ON FUNCTION channel_visible_to(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION visible_channels(UUID)         FROM PUBLIC;
GRANT EXECUTE ON FUNCTION channel_visible_to(UUID, UUID) TO service_role;
GRANT EXECUTE ON FUNCTION visible_channels(UUID)         TO service_role;

-- ============================================================
-- 3. Asking about somebody else's permissions
-- ============================================================
-- `app.has_perm` answers for `auth.uid()`, which is what a policy needs. An
-- edge function minting a LiveKit token is deciding about the person who asked
-- it, not about itself, so it needs the two-argument form.

CREATE OR REPLACE FUNCTION user_has_permission(p_user UUID, p_name TEXT)
  RETURNS BOOLEAN
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT (app.permissions_of(p_user)
          & (app.perm('ADMINISTRATOR') | app.perm(p_name))) <> 0
$$;

REVOKE ALL ON FUNCTION user_has_permission(UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION user_has_permission(UUID, TEXT) TO service_role;

-- ============================================================
-- 4. What a client is allowed to draw
-- ============================================================
-- A client has read three booleans off its own `users` row since 002 and drawn
-- its buttons from them. With 018 those columns are a cache of three bits out
-- of twenty-two, so a client that only reads them can only offer three of the
-- twenty-two things a member might be allowed to do — and `CREATE_PRIVATE_CHANNEL`
-- is on `@everyone`, which none of the three would ever say.
--
-- The bits themselves, then. `app.permissions()` is in the `app` schema, which
-- PostgREST does not expose; this is the same answer through the front door.
--
-- It only ever describes the caller. There is no argument to point somewhere
-- else, which is what keeps it safe to hand to `authenticated` — and a client
-- drawing a button it is not allowed to press is a cosmetic bug, because the
-- policy is still the thing that decides.

CREATE OR REPLACE FUNCTION my_permissions() RETURNS BIGINT
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT app.permissions()
$$;

REVOKE ALL ON FUNCTION my_permissions() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION my_permissions() TO authenticated;


-- ============================================================
-- Rift self-hosted server — 022: making a channel is one statement
-- ============================================================
-- 020 let a member create a private channel, and then made it impossible to
-- read back the one they had just made.
--
-- `INSERT ... RETURNING` applies the **SELECT** policy to the row it hands back,
-- and `channels_select` now asks whether the caller is in the channel. The
-- creator is seated by an AFTER INSERT trigger, which has not run when RETURNING
-- is evaluated — so the insert succeeded, the read of its own row did not, and
-- Postgres reported the whole thing as `new row violates row-level security
-- policy for table "channels"`. Which is true, and names the wrong policy.
--
-- Found by clicking the button.
--
-- Three fixes were possible and only one of them is honest. Widening
-- `channels_select` to include whoever created a channel would mean recording a
-- creator and then explaining why they can still see a room they were removed
-- from. Dropping the RETURNING would leave the client looking its own channel
-- up by name. So: one function that makes the channel, seats the people, and
-- hands the row back — which is what the two round trips were pretending to be
-- anyway, minus the moment in between where the channel exists and nobody is
-- in it.

CREATE OR REPLACE FUNCTION create_channel(
  p_name    TEXT,
  p_type    TEXT,
  p_private BOOLEAN DEFAULT false,
  p_members UUID[]  DEFAULT '{}'
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server  UUID := app.server_id();
  v_channel channels%ROWTYPE;
BEGIN
  IF v_server IS NULL THEN
    RAISE EXCEPTION 'not_a_member';
  END IF;

  -- The same split the policy makes, checked here so the failure has a name.
  -- A private channel is how a few people talk without asking permission;
  -- one the whole server can see is a change to the server's shape.
  IF p_private THEN
    IF NOT app.has_perm('CREATE_PRIVATE_CHANNEL') THEN
      RAISE EXCEPTION 'not_authorized';
    END IF;
  ELSIF NOT app.has_perm('MANAGE_CHANNELS') THEN
    RAISE EXCEPTION 'not_authorized';
  END IF;

  IF length(btrim(p_name)) = 0 THEN
    RAISE EXCEPTION 'bad_name';
  END IF;
  IF p_type NOT IN ('text', 'voice') THEN
    RAISE EXCEPTION 'bad_type';
  END IF;

  INSERT INTO channels (server_id, name, channel_type, is_private)
  VALUES (v_server, btrim(p_name), p_type::channel_type, p_private)
  RETURNING * INTO v_channel;

  -- `seed_private_channel_owner` has already seated the caller by the time this
  -- runs, so the members list only has to add the others — and cannot remove
  -- the creator by omitting them, which is the mistake the two-call version was
  -- one forgotten id away from.
  IF p_private AND array_length(p_members, 1) IS NOT NULL THEN
    INSERT INTO channel_members (channel_id, user_id, added_by)
    SELECT v_channel.id, u.id, auth.uid()
      FROM users u
     WHERE u.id = ANY (p_members)
       AND u.server_id = v_server
       AND NOT u.is_banned
       -- A bot is keyed by `grant_bot_channel_key` and nothing else.
       AND NOT u.is_bot
    ON CONFLICT DO NOTHING;
  END IF;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'id', v_channel.id,
    'name', v_channel.name,
    'channel_type', v_channel.channel_type,
    'is_private', v_channel.is_private
  );
EXCEPTION WHEN unique_violation THEN
  RETURN jsonb_build_object('reason', 'name_taken');
END; $$;

REVOKE ALL ON FUNCTION create_channel(TEXT, TEXT, BOOLEAN, UUID[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION create_channel(TEXT, TEXT, BOOLEAN, UUID[]) TO authenticated;


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
