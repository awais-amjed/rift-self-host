-- ============================================================
-- Rift self-hosted server — 017: moderation grants
-- ============================================================
-- BOTS.md phase 5, last on the list on purpose: it is the only part of the bot
-- design that spends the trust model rather than working around it.
--
-- Everything so far has held one line — a bot never holds a channel key, so it
-- hears what it is told and nothing else. A moderation bot cannot work that
-- way. It has to read every message, and there is no cryptographic middle
-- ground: it either holds the key or it does not.
--
-- So this is an **explicit, per-channel, admin-only grant**, and four rules are
-- what make it something you can offer rather than something you regret.
--
--   1. **Bots are still excluded from the healing sweep.** 014 made that a
--      refusal on the row rather than a filter, and that stays: the trigger now
--      consults a grant instead of refusing outright, so the only way a bot is
--      ever keyed is somebody deciding it should be.
--   2. **Forward-only.** A member joining gets every historical key version —
--      the full-scrollback decision in ARCHITECTURE.md §4. A bot gets the key
--      from *after* the grant. It has no business reading what was said before
--      somebody chose to let it listen, and "we'll rotate later" is not the
--      same promise.
--   3. **Revoking rotates.** The bot keeps what it already saw — nobody can
--      take back what has been unwrapped — and gets nothing further.
--   4. **The channel says who is listening.** Not in this file, but it is the
--      reason `bot_channel_keys` is readable by every member rather than only
--      by admins: the person whose messages are being read is not the person
--      who clicked the button, and a warning that only the admin sees reaches
--      the wrong audience entirely.
--
-- ---------- the two rotation signals ----------
--
-- `sweep_channel_keys` already knows how to notice one thing: a member sealed
-- into the current version who has since been banned. That signal is good
-- because it **clears itself** — the next version is sealed only to people
-- still eligible, so the same check comes back false once the rotation lands.
-- No flag to set and nothing to reset.
--
-- Both new signals are built the same way:
--
--   * a **granted** bot whose grant starts above the current version — the
--     grant was just made, and the rotation is what makes it forward-only;
--   * a **revoked** bot still sealed into the current version — same shape as
--     the ban, for the same reason.
--
-- Neither needs a flag, and an admin who grants and revokes twice in a minute
-- leaves nothing behind to reconcile.

-- ============================================================
-- 1. The grant
-- ============================================================

CREATE TABLE IF NOT EXISTS bot_channel_keys (
  channel_id       UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id           UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  -- Who decided. Kept for the channel's own notice: "granted by" is the half
  -- of the sentence that makes it answerable to somebody.
  granted_by       UUID        REFERENCES users(id) ON DELETE SET NULL,
  granted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- The first key version this bot may hold. Set to *one past* the current
  -- version at grant time, so the rotation that follows is what it reads from
  -- and everything before it stays shut.
  from_key_version INTEGER     NOT NULL CHECK (from_key_version >= 1),
  PRIMARY KEY (channel_id, bot_id)
);

CREATE INDEX IF NOT EXISTS idx_bot_channel_keys_bot ON bot_channel_keys (bot_id);

COMMENT ON TABLE bot_channel_keys IS
  'Which bots may hold which channel keys, and from which version (migration '
  '017). Readable by every member on purpose — the channel shows who is '
  'listening, and the people being read are not the people who granted it.';

-- ============================================================
-- 2. The refusal, now with an exception
-- ============================================================
-- Replaces 014's blanket refusal. Same shape, same loudness — a client that
-- wrapped a key for a bot it should not have believes it did something, and
-- would otherwise carry on believing it.

CREATE OR REPLACE FUNCTION refuse_bot_keyring()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
DECLARE
  v_from INTEGER;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.is_bot) THEN
    RETURN NEW;
  END IF;

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
END; $$;

-- ============================================================
-- 3. Granting and revoking
-- ============================================================
-- **Admin only, not channel manager.** Every other bot decision is scoped to
-- what the bot can be told; this one hands out the plaintext of a room. It is
-- the same weight as a ban — it changes what somebody else's messages mean —
-- and 003 already reserves that for `app.is_admin()`.

CREATE OR REPLACE FUNCTION grant_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current INTEGER;
BEGIN
  IF NOT app.is_admin() THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF app.channel_server_id(p_channel) IS DISTINCT FROM app.server_id() THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users u
                  WHERE u.id = p_bot AND u.is_bot AND NOT u.is_banned
                    AND u.server_id = app.server_id()) THEN
    RETURN jsonb_build_object('reason', 'no_such_bot');
  END IF;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  -- One past the current version. A channel with no key yet starts the bot at
  -- 1, which is the version its first member will bootstrap — there is no
  -- history to keep it out of.
  INSERT INTO bot_channel_keys (channel_id, bot_id, granted_by, from_key_version)
  VALUES (p_channel, p_bot, auth.uid(), GREATEST(v_current + 1, 1))
  ON CONFLICT (channel_id, bot_id) DO NOTHING;

  RETURN jsonb_build_object(
    'reason', 'ok',
    'from_key_version', (SELECT from_key_version FROM bot_channel_keys
                          WHERE channel_id = p_channel AND bot_id = p_bot)
  );
END; $$;

-- Revoking drops the grant *and* the keys already sealed to the bot. The
-- second half does not take back what it has read — nothing can — it stops the
-- server serving it anything more, and leaves the rotation to the sweep, which
-- will now see a bot sealed into the current version with no grant.
CREATE OR REPLACE FUNCTION revoke_bot_channel_key(
  p_bot     UUID,
  p_channel UUID
) RETURNS JSONB
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF NOT app.is_admin() THEN
    RETURN jsonb_build_object('reason', 'forbidden');
  END IF;
  IF app.channel_server_id(p_channel) IS DISTINCT FROM app.server_id() THEN
    RETURN jsonb_build_object('reason', 'no_such_channel');
  END IF;

  DELETE FROM bot_channel_keys
   WHERE channel_id = p_channel AND bot_id = p_bot;
  DELETE FROM channel_keyring
   WHERE channel_id = p_channel AND user_id = p_bot;

  RETURN jsonb_build_object('reason', 'ok');
END; $$;

REVOKE ALL ON FUNCTION grant_bot_channel_key(UUID, UUID)  FROM PUBLIC;
REVOKE ALL ON FUNCTION revoke_bot_channel_key(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION grant_bot_channel_key(UUID, UUID)  TO authenticated;
GRANT EXECUTE ON FUNCTION revoke_bot_channel_key(UUID, UUID) TO authenticated;

-- ============================================================
-- 4. Security
-- ============================================================

ALTER TABLE bot_channel_keys ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON bot_channel_keys FROM anon, authenticated;

-- Readable by every member of the server, which is rule 4. Writing goes
-- through the two functions above; there is no INSERT, UPDATE or DELETE grant,
-- so "who may listen" cannot be changed by anything that skipped the check.
GRANT SELECT ON bot_channel_keys TO authenticated;

DROP POLICY IF EXISTS bot_channel_keys_select ON bot_channel_keys;
CREATE POLICY bot_channel_keys_select ON bot_channel_keys
  FOR SELECT TO authenticated
  USING (app.channel_server_id(channel_id) = app.server_id());

-- ============================================================
-- 5. What the sweep needs to know
-- ============================================================
-- The sweep is an edge function and computes its own rotation signal, but the
-- two facts it needs are per-channel joins it should not have to invent. One
-- view, so the client, the sweep and the channel notice all read the same
-- answer.

CREATE OR REPLACE VIEW channel_bot_listeners
  WITH (security_invoker = true) AS
  SELECT g.channel_id,
         g.bot_id,
         u.username,
         u.display_name,
         g.granted_at,
         g.from_key_version,
         gb.display_name AS granted_by_name
    FROM bot_channel_keys g
    JOIN users u  ON u.id = g.bot_id
    LEFT JOIN users gb ON gb.id = g.granted_by;

GRANT SELECT ON channel_bot_listeners TO authenticated;
