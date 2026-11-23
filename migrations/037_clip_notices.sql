-- ============================================================
-- Rift self-hosted server — 037: the server tells a call about a clip
-- ============================================================
-- Found in the app's review of call clips, Nov 23 2026.
--
-- Keeping the last stretch of a call is done on the clipper's own device,
-- and the others were told by a LiveKit data packet the clipper sent
-- (`rift.clip`). A connection sends data only with `canPublishData`, which is
-- the soundboard right (`_shared/call_rights.ts`), so a member without the
-- soundboard or Speak clipped and nobody heard about it. And a packet a member
-- sends is a packet a modified client can word, or leave out.
--
-- So the notice now comes from the server: the clipper's app calls
-- `note_clip`, which checks that its voice connection is in that call and
-- sends the packet through LiveKit's API, naming the clipper's identity. A
-- packet from the API has no sender, which no member can fake, and the app
-- believes only those (as it does a move). The data right goes back to being
-- the soundboard alone.
--
-- `note_clip_allowed` is that function's rate limit: one notice a minute per
-- member, kept here because an edge function's worker keeps nothing between
-- requests. The app keeps its own minute per clipper as well, which is what
-- spares a listener a notice for every press.
-- ============================================================

CREATE TABLE IF NOT EXISTS clip_notices (
  user_id  UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  noted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE clip_notices IS
  'When each member last had a call told they clipped it (note_clip), so '
  'the server tells a call at most once a minute per member.';

-- Whether [p_user] may have a call told about a clip now, taking the minute
-- when they may. One statement, so two calls at once cannot both take it.
CREATE OR REPLACE FUNCTION note_clip_allowed(p_user UUID) RETURNS BOOLEAN
  LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  WITH taken AS (
    INSERT INTO clip_notices AS n (user_id, noted_at)
    VALUES (p_user, now())
    ON CONFLICT (user_id) DO UPDATE SET noted_at = now()
     WHERE n.noted_at <= now() - interval '1 minute'
    RETURNING 1
  )
  SELECT EXISTS (SELECT 1 FROM taken)
$$;

COMMENT ON FUNCTION note_clip_allowed(UUID) IS
  'note_clip''s limit: true, and the minute taken, when p_user has not had a '
  'call told about a clip in the last minute.';

-- ── Grants ──────────────────────────────────────────────────

REVOKE ALL ON clip_notices FROM PUBLIC, anon, authenticated;
ALTER TABLE clip_notices ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON FUNCTION note_clip_allowed(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION note_clip_allowed(UUID) TO service_role;
