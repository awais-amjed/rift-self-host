-- ============================================================
-- Rift self-hosted server — 017: a key lease is kept by doing the work
-- ============================================================
-- 012 gave each channel's key work to one member at a time: the first to be
-- handed some holds a lease on that channel for a minute, renewed each time
-- they ask again, and everyone else is told there is nothing to do there.
-- Renewed for asking, not for working. So a member whose client asks every
-- half minute and never seals anything held every channel they can see for as
-- long as they liked: nobody else healed a newcomer, and the key change a ban
-- calls for never came. Found in the Oct 7 security review.
--
-- Now a lease is renewed only when its holder has written keyring entries
-- since it was last renewed (`progress_at`, set by a trigger on the keyring,
-- so only entries actually stored count), and never past ten minutes from
-- when they took it. Asking again without having worked still answers "yours"
-- until the lease runs out, so a client that sweeps and then opens a channel
-- before it seals is not turned away from its own work. And once a lease runs
-- out, its last holder waits a lease's length before taking it again, so
-- somebody else asking in that time gets it first; with nobody else asking,
-- the work comes back to them a minute later.
--
-- At worst a member who does nothing holds a channel for a minute before an
-- honest member asking gets it, and one who seals a token entry a minute
-- holds it for ten.
-- ============================================================

-- How long a lease lasts without renewal, and how long its holder then waits.
CREATE OR REPLACE FUNCTION app.key_lease_length() RETURNS INTERVAL
  LANGUAGE sql IMMUTABLE AS $$ SELECT interval '60 seconds' $$;

-- The longest one member holds a channel's key work before resting.
CREATE OR REPLACE FUNCTION app.key_lease_longest() RETURNS INTERVAL
  LANGUAGE sql IMMUTABLE AS $$ SELECT interval '10 minutes' $$;

ALTER TABLE app.channel_key_leases
  ADD COLUMN IF NOT EXISTS since       TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS renewed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS progress_at TIMESTAMPTZ;

COMMENT ON COLUMN app.channel_key_leases.since IS
  'When the holder took the lease. Not renewed past app.key_lease_longest() from here.';
COMMENT ON COLUMN app.channel_key_leases.renewed_at IS
  'When the lease was last granted or renewed.';
COMMENT ON COLUMN app.channel_key_leases.progress_at IS
  'When the holder last stored keyring entries in this channel. The lease is '
  'renewed only when this is after renewed_at.';

-- ── Work done ───────────────────────────────────────────────

-- Entries stored, by whoever wrapped them. Only rows actually inserted reach
-- the transition table, so a batch the healing upsert skipped as already
-- there is no progress.
CREATE OR REPLACE FUNCTION app.note_key_progress() RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  UPDATE app.channel_key_leases l
     SET progress_at = now()
    FROM (SELECT DISTINCT channel_id, wrapped_by FROM stored) s
   WHERE l.channel_id = s.channel_id AND l.holder = s.wrapped_by;
  RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS channel_keyring_note_progress ON channel_keyring;
CREATE TRIGGER channel_keyring_note_progress AFTER INSERT ON channel_keyring
  REFERENCING NEW TABLE AS stored
  FOR EACH STATEMENT EXECUTE FUNCTION app.note_key_progress();

-- ── Taking one ──────────────────────────────────────────────

-- Take [p_channel]'s lease for [p_user], or keep theirs. False when somebody
-- else holds one that has not run out, or when [p_user]'s own ran out less
-- than a lease's length ago.
CREATE OR REPLACE FUNCTION app.take_key_lease(p_channel UUID, p_user UUID)
  RETURNS BOOLEAN
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_lease app.channel_key_leases%ROWTYPE;
BEGIN
  SELECT * INTO v_lease FROM app.channel_key_leases
   WHERE channel_id = p_channel FOR UPDATE;

  IF NOT FOUND THEN
    INSERT INTO app.channel_key_leases
      (channel_id, holder, expires_at, since, renewed_at)
    VALUES (p_channel, p_user, now() + app.key_lease_length(), now(), now())
    ON CONFLICT (channel_id) DO NOTHING;
    RETURN FOUND;
  END IF;

  IF v_lease.expires_at > now() THEN
    IF v_lease.holder <> p_user THEN
      RETURN false;
    END IF;
    IF v_lease.progress_at > v_lease.renewed_at
       AND now() < v_lease.since + app.key_lease_longest() THEN
      UPDATE app.channel_key_leases
         SET expires_at = now() + app.key_lease_length(), renewed_at = now()
       WHERE channel_id = p_channel;
    END IF;
    RETURN true;
  END IF;

  IF v_lease.holder = p_user
     AND now() < v_lease.expires_at + app.key_lease_length() THEN
    RETURN false;
  END IF;

  UPDATE app.channel_key_leases
     SET holder = p_user, expires_at = now() + app.key_lease_length(),
         since = now(), renewed_at = now(), progress_at = NULL
   WHERE channel_id = p_channel;
  RETURN true;
END $$;

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON FUNCTION app.key_lease_length() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.key_lease_longest() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.note_key_progress() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION app.take_key_lease(UUID, UUID) FROM PUBLIC, anon, authenticated;
