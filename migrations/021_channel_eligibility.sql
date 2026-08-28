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
