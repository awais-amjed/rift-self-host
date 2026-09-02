-- ============================================================
-- Rift self-hosted server — 036: bots are three permissions, not one
-- ============================================================
-- `MANAGE_BOTS` has been carrying three jobs of very different weight:
--
--   1. **Handing a bot a key** — to read a channel (§6) or hear a call (§6b).
--      This is the one that spends the trust model, and it stays where it is.
--   2. **Bringing a bot into the server at all** — which today needs nothing
--      but `CREATE_INVITE`, the same bit as inviting a friend. Adding a program
--      that will be in every public channel is not the same decision as adding
--      a person, and it should not have been the same bit.
--   3. **Summoning one into a voice channel** — asking the music bot to come
--      and play. This has almost no weight at all: a bot's token is minted with
--      `canSubscribe: false` unless an admin granted listening, so a summoned
--      bot publishes and cannot hear. It is the thing everybody wants to do and
--      the thing an admin least needs to control.
--
-- Lumping 3 in with 1 makes the feature unusable — nobody is giving every
-- member the ability to hand out channel keys so they can queue a song. Leaving
-- 2 under `CREATE_INVITE` makes it invisible. So: three bits, and the light one
-- is on by default.
--
-- ---------- what each server gets ----------
--
-- `SUMMON_BOTS` joins `@everyone`, on the servers that already exist as well as
-- the ones made after this. That is deliberate and it is the conservative
-- direction: the alternative is a permission nobody has, which looks exactly
-- like the feature being broken. An admin who wants it narrower takes the bit
-- off `@everyone` and puts it on a role.
--
-- `ADD_BOTS` is not backfilled onto `@everyone`, which *is* a change in what a
-- plain member may do — creating a bot invite now needs it. Admins are covered
-- without a backfill: `has_perm` treats `ADMINISTRATOR` as every bit. It goes
-- to the `Moderator` role too, since that is the role a server hands to the
-- people who set things up.

-- ============================================================
-- 1. The two new bits
-- ============================================================

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
    WHEN 'MANAGE_BOTS'            THEN 1::BIGINT << 7   -- the §6 and §6b key grants
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
    -- 036
    WHEN 'ADD_BOTS'               THEN 1::BIGINT << 22  -- create a bot invite
    WHEN 'SUMMON_BOTS'            THEN 1::BIGINT << 23  -- bring one into a call
    ELSE NULL
  END
$$;

CREATE OR REPLACE FUNCTION app.perm_all() RETURNS BIGINT
  LANGUAGE sql IMMUTABLE AS $$ SELECT (1::BIGINT << 24) - 1 $$;

-- ============================================================
-- 2. Adding a bot is its own decision
-- ============================================================
-- Same policy as 025's with one clause. The `is_bot` column is already in the
-- insert grant, so this is the only place the answer could live.

DROP POLICY IF EXISTS invites_insert ON invites;
CREATE POLICY invites_insert ON invites FOR INSERT TO authenticated
  WITH CHECK (
    server_id = app.server_id()
    AND created_by = auth.uid()
    AND app.can_invite()
    AND (role_id IS NULL OR app.may_assign_role(role_id))
    AND (NOT is_bot OR app.has_perm('ADD_BOTS'))
  );

-- ============================================================
-- 3. Defaults, for the servers that exist and the ones that do not
-- ============================================================

CREATE OR REPLACE FUNCTION seed_default_roles()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  INSERT INTO roles (server_id, name, position, permissions, is_everyone, is_default)
  VALUES
    (NEW.id, '@everyone', 0,
       app.perm('VIEW_CHANNEL')  | app.perm('SEND_MESSAGES')
     | app.perm('ATTACH_FILES')  | app.perm('ADD_REACTIONS')
     | app.perm('MENTION_ALL')
     | app.perm('CONNECT')       | app.perm('SPEAK')
     | app.perm('SCREEN_SHARE')
     | app.perm('CREATE_PRIVATE_CHANNEL')
     -- Publishing only, and reversible by taking the bit away. The reason it
     -- is here rather than on a role somebody has to invent: a music bot that
     -- needs an admin present to be asked for a song is not a music bot.
     | app.perm('SUMMON_BOTS'), true, false),
    (NEW.id, 'Members',   100, app.perm('CREATE_INVITE'), false, true),
    (NEW.id, 'Moderator', 200,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS')    | app.perm('ADD_BOTS'), false, false),
    (NEW.id, 'Admin',     300, app.perm('ADMINISTRATOR'), false, false)
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;

-- The servers that already exist. `@everyone` gains the summon bit; the
-- moderator role gains `ADD_BOTS`, matched by name because 025 dropped
-- `legacy_key` — a server that renamed it keeps whatever it has, and an admin
-- can add the bit by hand. Nothing is taken away from anybody.
UPDATE roles SET permissions = permissions | app.perm('SUMMON_BOTS')
 WHERE is_everyone;

UPDATE roles SET permissions = permissions | app.perm('ADD_BOTS')
 WHERE name = 'Moderator' AND NOT is_everyone;
