-- ============================================================
-- Rift self-hosted server — 013: each channel key opens the one before it
-- ============================================================
-- A member who joins a channel is sealed every older version of its key, one
-- keyring row each, and every rotation adds a row for every member. A channel
-- of 50,000 that rotates daily grows by 50,000 rows a day, kept forever, and
-- a newcomer a year in is owed 365 of them.
--
-- So a rotation now also stores a link: the outgoing key, sealed under the
-- incoming one (AES-256-GCM, bound to the channel and the version; the format
-- is in the app's ARCHITECTURE.md §4). Whoever holds version n can open
-- n − 1 from it, and so on down. A newcomer needs one sealed row per stretch
-- of linked versions, not one per version, and a member whose client has
-- checked a link against the row it already holds can drop that row
-- (`prune_channel_keys`), leaving about one row each instead of one per
-- rotation.
--
-- A link only reaches backwards, so it gives a banned member nothing: they are
-- never sealed the version that would open it. Two rotations must not be
-- linked, because what came before them is not the newcomer's to read:
--
--   * the one that ends a channel's private stretch (`rotate_from_key_version`):
--     a link there would hand the private conversation to everyone who joins
--     after it opens;
--   * the one a bot's grant starts at: a bot holds the channel key from its
--     grant on, and a link there would open what was said before the grant.
--
-- The sweep says which a rotation is (`link` on the job, since 012), and
-- `store_channel_key_link` refuses both again here, because the server, not
-- the client, is what must never hold such a link: a server that kept one
-- could hand it over. And it only takes a link for the version just minted,
-- by the member who holds both keys: a grant that is later revoked leaves no
-- record of where it began, so a link added afterwards could cross it.
-- ============================================================

CREATE TABLE IF NOT EXISTS app.channel_key_links (
  channel_id  UUID        NOT NULL REFERENCES public.channels(id) ON DELETE CASCADE,
  -- The newer of the two: this row opens `key_version - 1`.
  key_version INTEGER     NOT NULL CHECK (key_version >= 2),
  sealed_by   UUID        REFERENCES public.users(id) ON DELETE SET NULL,
  ciphertext  TEXT        NOT NULL CHECK (length(ciphertext) <= 128),
  nonce       TEXT        NOT NULL CHECK (length(nonce) <= 64),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, key_version)
);

COMMENT ON TABLE app.channel_key_links IS
  'Version key_version - 1 of a channel key, sealed under version key_version. '
  'Written only by store_channel_key_link, at the rotation that minted '
  'key_version, and never across a channel''s opening or a bot grant''s start.';

-- ── Storing one ─────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.store_channel_key_link(
  p_channel UUID, p_version INTEGER, p_by UUID, p_ciphertext TEXT, p_nonce TEXT
) RETURNS BOOLEAN
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current INTEGER;
  v_mark    INTEGER;
BEGIN
  IF p_version IS NULL OR p_version < 2 THEN RETURN false; END IF;

  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;
  -- Only the version just minted: see the header for why not an older one.
  IF p_version <> v_current THEN RETURN false; END IF;

  SELECT rotate_from_key_version INTO v_mark FROM channels WHERE id = p_channel;
  IF v_mark IS NOT NULL AND p_version - 1 <= v_mark THEN RETURN false; END IF;

  IF EXISTS (SELECT 1 FROM bot_channel_keys
              WHERE channel_id = p_channel AND from_key_version = p_version) THEN
    RETURN false;
  END IF;

  -- Made by somebody holding both ends.
  IF (SELECT count(*) FROM channel_keyring
       WHERE channel_id = p_channel AND user_id = p_by
         AND key_version IN (p_version - 1, p_version)) <> 2 THEN
    RETURN false;
  END IF;

  INSERT INTO app.channel_key_links (channel_id, key_version, sealed_by, ciphertext, nonce)
  VALUES (p_channel, p_version, p_by, p_ciphertext, p_nonce)
  ON CONFLICT DO NOTHING;
  RETURN FOUND;
END $$;

COMMENT ON FUNCTION public.store_channel_key_link(UUID, INTEGER, UUID, TEXT, TEXT) IS
  'Service-role only (post_channel_keys, after a mint). Stores the link from '
  'the version just minted to the one before, unless that would cross an '
  'opening or a bot grant. False when it was not stored.';

-- ── Dropping a row the chain covers ─────────────────────────

-- The caller's own rows at [p_versions] of [p_channel], where a chain of links
-- reaches each from a newer row of theirs that stays. The server cannot check
-- that a link opens to the right key; the client has, by opening it and
-- comparing with the row it is dropping, which is why it is the caller's own
-- rows and nobody else's.
CREATE OR REPLACE FUNCTION public.prune_channel_keys(p_channel UUID, p_versions INTEGER[])
  RETURNS INTEGER
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE v_n INTEGER;
BEGIN
  IF NOT app.channel_eligible(p_channel, auth.uid()) THEN RETURN 0; END IF;

  DELETE FROM channel_keyring k
   WHERE k.channel_id = p_channel
     AND k.user_id = auth.uid()
     AND k.key_version = ANY(p_versions)
     AND EXISTS (
       SELECT 1 FROM channel_keyring h
        WHERE h.channel_id = p_channel
          AND h.user_id = auth.uid()
          AND h.key_version > k.key_version
          AND NOT (h.key_version = ANY(p_versions))
          AND (SELECT count(*) FROM app.channel_key_links l
                WHERE l.channel_id = p_channel
                  AND l.key_version > k.key_version
                  AND l.key_version <= h.key_version)
              = h.key_version - k.key_version);
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END $$;

COMMENT ON FUNCTION public.prune_channel_keys(UUID, INTEGER[]) IS
  'A member drops their own keyring rows that a chain of links reaches from a '
  'newer row they keep. The client checks each link opens to the key it is '
  'dropping first; the server checks only that the chain is there.';

-- ── The sweep skips what a link reaches ─────────────────────

-- As in 012, less every version the next one links to: whoever is sealed that
-- one opens this from it. What is left is the top of each linked stretch.
CREATE OR REPLACE FUNCTION app.key_history_versions(
  p_channel UUID, p_user UUID, p_current INTEGER, p_mark INTEGER
) RETURNS SETOF INTEGER
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT k.key_version
    FROM channel_keyring k
   WHERE k.channel_id = p_channel
     AND k.user_id = p_user
     AND k.key_version < p_current
     AND k.key_version > COALESCE(p_mark, 0)
     AND NOT EXISTS (SELECT 1 FROM app.channel_key_links l
                      WHERE l.channel_id = p_channel
                        AND l.key_version = k.key_version + 1)
   ORDER BY k.key_version DESC
$$;

-- ── Opening a channel hands the links over ──────────────────

-- As in 012, plus `links`: every link in the channel, newest first. A link is
-- no use without the newer key, so handing over all of them tells a member
-- nothing they could not already open.
CREATE OR REPLACE FUNCTION public.channel_key_state(p_channel UUID, p_user UUID)
  RETURNS JSONB
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_current INTEGER;
  v_mine    JSONB;
  v_links   JSONB;
  v_missing JSONB := '[]'::jsonb;
BEGIN
  SELECT COALESCE(max(key_version), 0) INTO v_current
    FROM channel_keyring WHERE channel_id = p_channel;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'key_version', k.key_version,
           'ephemeral_public_key', k.ephemeral_public_key,
           'ciphertext', k.ciphertext, 'nonce', k.nonce)
           ORDER BY k.key_version), '[]'::jsonb)
    INTO v_mine
    FROM channel_keyring k
   WHERE k.channel_id = p_channel AND k.user_id = p_user;

  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'key_version', l.key_version,
           'ciphertext', l.ciphertext, 'nonce', l.nonce)
           ORDER BY l.key_version DESC), '[]'::jsonb)
    INTO v_links
    FROM app.channel_key_links l
   WHERE l.channel_id = p_channel;

  IF v_current = 0 THEN
    v_missing := app.key_missing(p_channel, 1, p_user, 500);
  ELSIF EXISTS (SELECT 1 FROM channel_keyring
                 WHERE channel_id = p_channel AND key_version = v_current
                   AND user_id = p_user) THEN
    v_missing := app.key_missing(p_channel, v_current, p_user, 500);
    IF jsonb_array_length(v_missing) > 0
       AND NOT app.take_key_lease(p_channel, p_user) THEN
      v_missing := '[]'::jsonb;
    END IF;
  END IF;

  RETURN jsonb_build_object('current_version', v_current,
                            'my_keys', v_mine,
                            'links', v_links,
                            'members_missing', v_missing);
END $$;

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON TABLE app.channel_key_links FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.store_channel_key_link(UUID, INTEGER, UUID, TEXT, TEXT)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.prune_channel_keys(UUID, INTEGER[])
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_history_versions(UUID, UUID, INTEGER, INTEGER)
  FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.channel_key_state(UUID, UUID)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.store_channel_key_link(UUID, INTEGER, UUID, TEXT, TEXT)
  TO service_role;
GRANT EXECUTE ON FUNCTION public.prune_channel_keys(UUID, INTEGER[]) TO authenticated;
GRANT EXECUTE ON FUNCTION public.channel_key_state(UUID, UUID) TO service_role;
