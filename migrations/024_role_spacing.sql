-- ============================================================
-- Rift self-hosted server — 024: leaving room between roles
-- ============================================================
-- 018 seeded the four default roles at 0, 1, 2 and 3, which is the tidiest
-- possible ladder and the one with nowhere to stand. Rank is what every
-- delegation rule is decided on — you may only touch a role strictly below
-- your own — so an admin at rank 3 has exactly two rungs beneath them, and the
-- third custom role has to share a rung with the second.
--
-- Two roles at the same position is not a correctness problem: neither can
-- manage the other, which is the conservative answer. It is an *ordering*
-- problem — a list sorted by position cannot say which of them is senior, and
-- neither can a reorder that works by swapping positions.
--
-- So the rungs are spaced. Nothing about the rules changes; there is simply
-- room between them for the roles a server actually invents.

UPDATE roles SET position = CASE legacy_key
  WHEN 'admin'     THEN 300
  WHEN 'moderator' THEN 200
  WHEN 'members'   THEN 100
END
WHERE legacy_key IS NOT NULL;

-- Anything already sitting above `@everyone` and below the old Admin rung is
-- lifted onto the same scale, keeping its order. A server that has never made
-- a custom role has nothing here to move.
WITH ranked AS (
  SELECT id,
         row_number() OVER (PARTITION BY server_id ORDER BY position, created_at)
           AS rung
    FROM roles
   WHERE legacy_key IS NULL AND NOT is_everyone AND position < 300
)
UPDATE roles r SET position = ranked.rung * 10
  FROM ranked WHERE ranked.id = r.id;

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
    (NEW.id, 'Members',   100, app.perm('CREATE_INVITE'), false, 'members'),
    (NEW.id, 'Moderator', 200,
       app.perm('MANAGE_CHANNELS') | app.perm('MANAGE_MESSAGES')
     | app.perm('MANAGE_WEBHOOKS') | app.perm('KICK_MEMBERS')
     | app.perm('MUTE_MEMBERS')    | app.perm('DEAFEN_MEMBERS')
     | app.perm('MOVE_MEMBERS'), false, 'moderator'),
    (NEW.id, 'Admin',     300, app.perm('ADMINISTRATOR'), false, 'admin')
  ON CONFLICT (server_id, name) DO NOTHING;
  RETURN NULL;
END; $$;
