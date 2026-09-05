-- ============================================================
-- Rift self-hosted server — 042: proving an admin asked for a listing
-- ============================================================
-- The public directory lives on central. Central cannot tell who administers a
-- server here: it has never heard of this database, and the two share no
-- identity — a member authenticates here with a per-server signing key derived
-- on their device, and to central with a Rift account. Nothing links them.
--
-- So `publish_server` on central checked only that the caller was signed in.
-- Any member of this server could list it publicly with a working join link,
-- write whatever description they liked, and — because the listing is unique
-- per (supabase_url, server_id) — hold the only slot for it, leaving the real
-- admin permanently unable to publish or correct their own server.
--
-- This is the missing half. An admin asks *here* for a one-time token; central
-- asks *here* whether that token is real before it writes anything. The answer
-- is authoritative because it comes from the server the listing names, over
-- its own domain — which is the only thing central can actually verify.
--
-- 010_push.sql solves a related problem in the other direction and is worth
-- reading alongside: there, this server proves itself to central with an
-- enrolled secret. Here, central asks this server a question. The difference
-- is that a listing has to be bound to a *domain*, and only a request to that
-- domain can do that.

-- ---------- tokens ----------
-- Short-lived, single-use, and stored as a digest. A leak of this table hands
-- over nothing: the token is the secret, and only its SHA-256 is kept.
--
-- No `user_id`. Which admin asked is not interesting — the question central
-- asks is "did an admin of this server ask for this", and the row existing is
-- the whole answer. Recording it would put a member id in a table read by an
-- unauthenticated endpoint, for no gain.

CREATE TABLE IF NOT EXISTS listing_tokens (
  token_hash  TEXT        PRIMARY KEY,
  server_id   UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- Five minutes: long enough for a person to finish the publish dialog they
  -- already have open, short enough that a token seen in a log is stale.
  expires_at  TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '5 minutes',

  -- Set when central redeems it. Kept rather than deleted so a replay is
  -- refused as *used* rather than as unknown, which is the difference between
  -- "you already did this" and "that never existed".
  used_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS listing_tokens_expiry ON listing_tokens (expires_at);

COMMENT ON TABLE listing_tokens IS
  'One-time proof that an admin of this server asked for it to be listed on '
  'central. Issued by the listing_token function, redeemed by central through '
  'verify_listing_token. Only a digest is stored.';

-- Not reachable over the API by anybody. Both endpoints that touch it hold the
-- service key: one is admin-gated in its own code, and the other is called by
-- central with no session at all.
REVOKE ALL ON listing_tokens FROM PUBLIC, anon, authenticated;
ALTER TABLE listing_tokens ENABLE ROW LEVEL SECURITY;

-- ---------- issuing ----------
-- Called by the `listing_token` edge function, which has already established
-- that the caller is an admin of this server. The check is repeated here
-- anyway: a function that mints proof of administration should not be one
-- whose safety depends on its only caller remembering to ask.

CREATE OR REPLACE FUNCTION issue_listing_token(
  p_server_id  UUID,
  p_token_hash TEXT
) RETURNS TIMESTAMPTZ
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_expires TIMESTAMPTZ;
BEGIN
  IF NOT app.is_admin() THEN
    RAISE EXCEPTION 'not_server_admin';
  END IF;

  -- An admin of *this* server, not of some other one on the same stack.
  IF p_server_id IS DISTINCT FROM app.server_id() THEN
    RAISE EXCEPTION 'wrong_server';
  END IF;

  -- Housekeeping on the way past, so the table cannot grow without a job to
  -- trim it. Expired rows prove nothing and redeeming one is already refused.
  DELETE FROM listing_tokens WHERE expires_at < now() - INTERVAL '1 hour';

  INSERT INTO listing_tokens (token_hash, server_id)
       VALUES (p_token_hash, p_server_id)
    RETURNING expires_at INTO v_expires;

  RETURN v_expires;
END; $$;

COMMENT ON FUNCTION issue_listing_token(UUID, TEXT) IS
  'Record a one-time listing token for this server. Admin only, and it checks '
  'that itself rather than trusting its caller to have done so.';

-- ---------- redeeming ----------
-- Called by central, which holds no session here at all — see the
-- verify_listing_token function for why that is safe and what it may learn.
--
-- Redeeming is one statement so that two arrivals of the same token cannot
-- both find it unused: the UPDATE ... WHERE used_at IS NULL either matches a
-- row or does not, and only the caller that matched gets a row back.

CREATE OR REPLACE FUNCTION redeem_listing_token(p_token_hash TEXT)
RETURNS UUID
  LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  UPDATE listing_tokens
     SET used_at = now()
   WHERE token_hash = p_token_hash
     AND used_at IS NULL
     AND expires_at > now()
  RETURNING server_id
$$;

COMMENT ON FUNCTION redeem_listing_token(TEXT) IS
  'Burn a listing token and return the server it was issued for, or nothing. '
  'Single-use and single-statement, so a replay finds it already spent.';

REVOKE ALL ON FUNCTION issue_listing_token(UUID, TEXT) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION redeem_listing_token(TEXT) FROM PUBLIC, anon, authenticated;
