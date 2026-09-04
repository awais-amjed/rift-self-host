-- ============================================================
-- Rift self-hosted server — 028: saying it in the channel
-- ============================================================
-- 017 built the moderation grant and four rules to make it safe to offer. The
-- fourth — *the channel says who is listening* — has been half done since:
-- there is a standing marker in the header, and it tells whoever arrives
-- later. It tells nobody who was already in the room when the grant was made.
--
-- A header chip is easy to have never noticed. A line in the scrollback is not.
--
-- Two other things 017 could not have known, both of which arrived later:
--
--   * `MANAGE_BOTS` is a permission now (018). The grant was gated on
--     `app.is_admin()`, which is the same people today — `ADMINISTRATOR`
--     implies every bit — and stops being the same people the moment somebody
--     makes a role for it.
--   * Private channels exist (020). The grant checked that a channel was on
--     your server and not that you could see it, so an administrator could key
--     a bot into a room they are deliberately outside of. Now it is the same
--     `app.can_see_channel` every other channel operation asks: for a private
--     channel, only somebody in it can let a bot in.

-- ============================================================
-- 1. A message from nobody
-- ============================================================
-- `attest_message` stamps `sender_id := auth.uid()` and, for a member's insert,
-- clears the origin — which is right, and which makes it impossible for a
-- function running on a member's behalf to write a row attributed to the
-- server rather than to them.
--
-- 019 restored 001's early return for a caller with no session, because nothing
-- without one is a client. So this drops the claim for exactly one statement
-- and puts it back. The alternative is a second attestation path, and two ways
-- to write a message is two things that can disagree about who sent it.

-- A message the server wrote about itself, not an outside service posting to a
-- URL. They are the same *shape* — an origin instead of a sender, `key_version`
-- 0 — and a client that could not tell them apart badged this one WEBHOOK,
-- which is wrong in the one way that matters: it says an integration somebody
-- installed is involved when nothing outside the server is.
--
-- A column rather than reading the name, and rather than reading `webhook_id`:
-- that one is nulled when a webhook is deleted while its messages stay (013),
-- so keying off it would turn every message a removed integration ever posted
-- into a system announcement.
ALTER TABLE messages
  ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT false;

-- No column grant, so no client can claim to be the server. Written only by
-- `app.post_system_message`, which is `SECURITY DEFINER` and owns the table.

CREATE OR REPLACE FUNCTION app.post_system_message(
  p_channel UUID,
  p_text    TEXT
) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_claims TEXT := current_setting('request.jwt.claims', true);
BEGIN
  PERFORM set_config('request.jwt.claims', '', true);

  -- `key_version` 0 and an origin rather than a sender: the same shape a
  -- webhook's message has (013), because it is the same fact — a row in an
  -- encrypted channel that no key was needed to write and none is needed to
  -- read. It is badged as plaintext like any other.
  INSERT INTO messages (channel_id, origin_name, ciphertext, key_version, is_system)
  VALUES (p_channel, 'Rift', p_text, 0, true);

  PERFORM set_config('request.jwt.claims', COALESCE(v_claims, ''), true);
END; $$;

REVOKE ALL ON FUNCTION app.post_system_message(UUID, TEXT) FROM PUBLIC;

-- ============================================================
-- 2. The grant, and the sentence it leaves behind
-- ============================================================

CREATE OR REPLACE FUNCTION grant_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current INTEGER;
  v_bot     TEXT;
  v_by      TEXT;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  -- Not "is it on my server". A private channel answers to the people in it,
  -- and an administrator standing outside one is not among them.
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  SELECT display_name INTO v_bot FROM users
   WHERE id = p_bot AND is_bot AND NOT is_banned AND server_id = app.server_id();
  IF v_bot IS NULL THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  IF EXISTS (SELECT 1 FROM bot_channel_keys
              WHERE channel_id = p_channel AND bot_id = p_bot) THEN
    RETURN jsonb_build_object('reason', 'already_granted');
  END IF;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  -- One past the current version. A channel with no key yet starts the bot at
  -- 1, which is the version its first member will bootstrap — there is no
  -- history to keep it out of.
  INSERT INTO bot_channel_keys (channel_id, bot_id, granted_by, from_key_version)
  VALUES (p_channel, p_bot, auth.uid(), GREATEST(v_current + 1, 1));

  SELECT display_name INTO v_by FROM users WHERE id = auth.uid();
  PERFORM app.post_system_message(
    p_channel,
    COALESCE(v_by, 'An admin') || ' gave ' || v_bot || ' the key to this '
      || 'channel. It can read every message sent here from now on — but '
      || 'nothing said before.'
  );

  RETURN jsonb_build_object(
    'reason', 'ok',
    'from_key_version', (SELECT from_key_version FROM bot_channel_keys
                          WHERE channel_id = p_channel AND bot_id = p_bot)
  );
END; $$;

CREATE OR REPLACE FUNCTION revoke_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_bot TEXT;
  v_by  TEXT;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT app.can_see_channel(p_channel) THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  SELECT u.display_name INTO v_bot
    FROM bot_channel_keys g JOIN users u ON u.id = g.bot_id
   WHERE g.channel_id = p_channel AND g.bot_id = p_bot;
  IF v_bot IS NULL THEN
    RETURN jsonb_build_object('reason', 'ok');
  END IF;

  DELETE FROM bot_channel_keys
   WHERE channel_id = p_channel AND bot_id = p_bot;
  -- Dropping the sealed keys does not take back what has been read — nothing
  -- can. It stops the server serving any more, and leaves the rotation to the
  -- sweep, which now sees a bot sealed into the current version with no grant.
  DELETE FROM channel_keyring
   WHERE channel_id = p_channel AND user_id = p_bot;

  SELECT display_name INTO v_by FROM users WHERE id = auth.uid();
  PERFORM app.post_system_message(
    p_channel,
    COALESCE(v_by, 'An admin') || ' took ' || v_bot || '’s access to this '
      || 'channel away. It keeps what it has already read; everything from '
      || 'here is out of its reach.'
  );

  RETURN jsonb_build_object('reason', 'ok');
END; $$;
