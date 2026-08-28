-- ============================================================
-- Rift self-hosted server — 030: granting a bot the whole server
-- ============================================================
-- BOTS.md §6's fifth rule, and the one that keeps the per-channel grant
-- honest rather than merely strict.
--
-- Per-channel is the right granularity and it is also unusable for the bots
-- people actually want. By server count the top of Discord's list is almost
-- entirely the read-everything kind — MEE6 (~21M servers, XP per message),
-- Carl-bot and Dyno (automod, logging), Pokétwo (spawns on chat activity). An
-- admin granting one of those a channel at a time, thirty times, will ask for a
-- button. Refusing to build it does not stop the button existing; it means the
-- one somebody eventually builds gets no thought.
--
-- ---------- the carve-out is the whole design ----------
--
-- A server-wide grant covers every channel where `is_private` is false, and
-- **never a private one**. A private channel is always an explicit, individual
-- decision — the same rule 020 wrote `channels.is_private` early to make
-- un-forgettable.
--
-- ---------- intent, not a snapshot ----------
--
-- The grant is a row in `bot_server_grants` *and* an ordinary
-- `bot_channel_keys` row per channel. The first is what covers a channel
-- created next week; without it an admin grants a bot the server, adds a
-- channel, and the bot silently does not work there. The second is the
-- mechanism — it carries `from_key_version`, drives the rotation sweep, and
-- drives the header marker, none of which a "the whole server" flag could do,
-- because forward-only is a fact about one channel's key history.
--
-- Which makes the downgrade almost free. Revoking one channel out of a
-- server-wide grant drops the *intent* row and leaves every other channel's
-- materialised row exactly where it was. An exception list would also work, and
-- would leave somebody a year later asking why one channel is not covered by a
-- grant that says "whole server".

-- ============================================================
-- 1. The intent
-- ============================================================

CREATE TABLE IF NOT EXISTS bot_server_grants (
  server_id  UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  bot_id     UUID        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  granted_by UUID        REFERENCES users(id) ON DELETE SET NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (server_id, bot_id)
);

COMMENT ON TABLE bot_server_grants IS
  'A standing grant covering every public text channel, including ones made '
  'later. The per-channel rows in bot_channel_keys are the mechanism; this is '
  'what makes a channel created tomorrow part of it.';

ALTER TABLE bot_server_grants ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bot_server_grants FROM anon, authenticated;

-- Readable by every member, which is rule 4 again: the people whose messages
-- pay for the grant are not the ones who clicked the button.
GRANT SELECT ON bot_server_grants TO authenticated;

DROP POLICY IF EXISTS bot_server_grants_select ON bot_server_grants;
CREATE POLICY bot_server_grants_select ON bot_server_grants
  FOR SELECT TO authenticated USING (server_id = app.server_id());

-- ============================================================
-- 2. Granting, one channel at a time
-- ============================================================
-- It loops over `grant_bot_channel_key` rather than writing rows itself, so
-- every rule lives in one place: the permission, forward-only, the refusal on
-- a channel the caller cannot see, and the sentence it leaves in each one.
--
-- Each channel says so separately, and that is not noise. A member reads the
-- channel they are in; "a bot was given the whole server" posted somewhere else
-- is a notice they never see.

CREATE OR REPLACE FUNCTION app.materialise_bot_server_grant(
  p_server UUID,
  p_bot    UUID
) RETURNS VOID
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_channel UUID;
BEGIN
  FOR v_channel IN
    SELECT id FROM channels
     WHERE server_id = p_server
       AND channel_type = 'text'
       -- The carve-out. A voice channel is excluded too, for a duller reason:
       -- it has no keyring, so there is nothing for a key grant to mean.
       AND NOT is_private
  LOOP
    PERFORM grant_bot_channel_key(p_bot, v_channel);
  END LOOP;
END; $$;

CREATE OR REPLACE FUNCTION grant_bot_server_key(p_bot UUID) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server UUID := app.server_id();
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = v_server) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  INSERT INTO bot_server_grants (server_id, bot_id, granted_by)
  VALUES (v_server, p_bot, auth.uid())
  ON CONFLICT (server_id, bot_id) DO NOTHING;

  PERFORM app.materialise_bot_server_grant(v_server, p_bot);
  RETURN jsonb_build_object('reason', 'ok');
END; $$;

CREATE OR REPLACE FUNCTION revoke_bot_server_key(p_bot UUID) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_server  UUID := app.server_id();
  v_channel UUID;
BEGIN
  IF NOT app.has_perm('MANAGE_BOTS') THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;

  DELETE FROM bot_server_grants WHERE server_id = v_server AND bot_id = p_bot;

  FOR v_channel IN
    SELECT channel_id FROM bot_channel_keys g
      JOIN channels c ON c.id = g.channel_id
     WHERE c.server_id = v_server AND g.bot_id = p_bot
  LOOP
    PERFORM revoke_bot_channel_key(p_bot, v_channel);
  END LOOP;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

REVOKE ALL ON FUNCTION app.materialise_bot_server_grant(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_bot_server_key(UUID)  FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_bot_server_key(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION grant_bot_server_key(UUID)  TO authenticated;
GRANT EXECUTE ON FUNCTION revoke_bot_server_key(UUID) TO authenticated;

-- ============================================================
-- 3. Revoking one channel downgrades the grant
-- ============================================================
-- Not an exception list. Dropping the intent row leaves every other channel's
-- materialised row exactly where it was, so the grant stops being "the whole
-- server" and becomes the set of channels it currently covers — which is what
-- the admin just said they wanted.
--
-- Written into `revoke_bot_channel_key` rather than as a trigger on
-- `bot_channel_keys`, and that distinction is the whole of it. A trigger fires
-- for *every* deletion of that row, including the one §4 does when a channel is
-- made private — so closing one channel would have cancelled the grant on all
-- the others. Downgrading is a thing a person decides, not a thing a row does.

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

  -- Naming one channel is saying "not the whole server any more". The other
  -- channels keep the rows they already have.
  DELETE FROM bot_server_grants
   WHERE bot_id = p_bot
     AND server_id = app.channel_server_id(p_channel);

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

DROP TRIGGER IF EXISTS channels_apply_bot_grants ON channels;
CREATE TRIGGER channels_apply_bot_grants AFTER INSERT ON channels
  FOR EACH ROW EXECUTE FUNCTION apply_bot_server_grants();

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

DROP TRIGGER IF EXISTS channels_drop_bot_grants ON channels;
CREATE TRIGGER channels_drop_bot_grants AFTER UPDATE OF is_private ON channels
  FOR EACH ROW EXECUTE FUNCTION drop_bot_grants_when_closed();

REVOKE ALL ON FUNCTION apply_bot_server_grants()     FROM PUBLIC;
REVOKE ALL ON FUNCTION drop_bot_grants_when_closed() FROM PUBLIC;
