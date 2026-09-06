-- ============================================================
-- Rift self-hosted server — 014: private channels are not everybody's to make
-- ============================================================
-- 007 put `CREATE_PRIVATE_CHANNEL` on `@everyone`, reasoning that a private
-- channel is how a handful of people talk without asking permission. It is
-- also how a server fills up with rooms nobody running it can see into, made
-- by anybody who has just walked in through an invite. That is the wrong
-- default for the place, even if it was the right one for the feature.
--
-- Moderators and up have it now. It stays a bit like any other: a server that
-- wants everybody making rooms puts it back on `@everyone` in the roles
-- editor, and one that wants it narrower still takes it off Moderator.
--
-- Nothing else moves. Whoever makes a private channel still runs it
-- (`channel_members.can_manage`, seated by the trigger in 007), and running
-- it includes deleting it — `channels_delete_managers` has asked
-- `app.can_manage_channel` since 007, which for a private channel is that
-- seat and not the server-wide permission.

CREATE OR REPLACE FUNCTION seed_default_roles()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  INSERT INTO roles (server_id, name, position, permissions, is_everyone, is_default, is_owner)
  VALUES
    (NEW.id, '@everyone', 0,
       app.perm('VIEW_CHANNEL')  | app.perm('SEND_MESSAGES')
     | app.perm('ATTACH_FILES')  | app.perm('ADD_REACTIONS')
     | app.perm('MENTION_ALL')
     | app.perm('CONNECT')       | app.perm('SPEAK')
     | app.perm('SCREEN_SHARE')
     | app.perm('SUMMON_BOTS'), true, false, false),
    (NEW.id, 'Members',   100, app.perm('CREATE_INVITE'), false, true, false),
    (NEW.id, 'Moderator', 200,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS')    | app.perm('ADD_BOTS')
     | app.perm('CREATE_PRIVATE_CHANNEL'), false, false, false),
    (NEW.id, 'Admin',     300, app.perm('ADMINISTRATOR'), false, false, false),
    (NEW.id, 'Owner',     400, app.perm('ADMINISTRATOR'), false, false, true)
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;

-- The servers that already exist: off the baseline, onto the moderator role
-- by name — a server that renamed it keeps what it has, and an admin puts the
-- bit where they want it. Rooms already made are untouched; this is about
-- who may make the next one.
UPDATE roles SET permissions = permissions & ~app.perm('CREATE_PRIVATE_CHANNEL')
 WHERE is_everyone;

UPDATE roles SET permissions = permissions | app.perm('CREATE_PRIVATE_CHANNEL')
 WHERE name = 'Moderator' AND NOT is_everyone;
