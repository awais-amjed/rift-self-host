-- ============================================================
-- Rift self-hosted server — 028: the server decides what a call costs
-- ============================================================
-- Every other expensive thing a member can do here is bounded by something
-- the operator set: how large a file may be, how much history is kept, what
-- a role may do. A **call** was the exception. A member chose the screen
-- share bitrate, any number of people could walk into a voice channel, and
-- the operator found out from the bandwidth bill or from everybody's audio
-- breaking at once. Nothing refused, nothing logged, nothing to set.
--
-- Measured 19 Sep 2026 (docs.joinrift.app/sizing/#calls), which is where
-- these two numbers come from rather than from taste:
--
--   streams = people talking × people listening
--
-- An SFU copies rather than mixes, so the cost is the *product*. A
-- 100-person call with everyone unmuted is 225 Mbps of upload; the same
-- call with five unmuted is 11 Mbps. And one screen share at the client's
-- default of 10 Mbps costs 10 Mbps *per watcher*, with nothing downscaling
-- in between — twenty-five watchers is a quarter of a gigabit, from one
-- person, on a setting they picked without being told what it costs.
--
-- So: two columns, in the same shape as every other limit in 002. Both
-- default to 0, which means off, so a server that upgrades and is never
-- touched behaves exactly as it did.
--
-- ---------- what each one actually guarantees ----------
--
-- These are not equally strong, and pretending otherwise would be the
-- dishonest part.
--
-- `max_voice_participants` is **enforced**. `get_channel_token` is the only
-- way into a call — the room cannot be joined without a token and clients
-- cannot mint their own — so counting the people already there and refusing
-- the next one is a real wall. Two things it does not catch, both
-- deliberate: two people arriving in the same instant can both be let in,
-- and a member holding an unexpired token from earlier can rejoin. Neither
-- matters for what this is for, which is stopping a channel reaching two
-- hundred people; getting from fifty to two hundred needs a hundred and
-- fifty fresh tokens and every one of them is refused.
--
-- `max_share_mbps` is **a budget the client keeps**, not a wall. LiveKit's
-- join token has no bitrate field — `VideoGrant` carries what you may
-- publish, never how much of it — so there is nothing to clamp at the point
-- the token is minted. The server states the number, the client publishes
-- within it, and an operator who needs a wall against a modified client
-- sets `limit.bytes_per_sec` in `livekit.yaml`, which is node-wide and
-- protects the uplink from anything at all. That is written down in
-- docs.joinrift.app/reference/#media rather than left to be discovered.
--
-- Counting people rather than connections, on purpose: a screen share is a
-- second connection held by the same person, and an operator who types 50
-- means fifty people, not fifty sockets. A limit that counted connections
-- would refuse somebody's screen share and tell them the call was full.
-- ============================================================

ALTER TABLE servers
  ADD COLUMN IF NOT EXISTS max_voice_participants INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS max_share_mbps         INTEGER NOT NULL DEFAULT 0;

-- A separate constraint rather than widening `servers_limits_sane`: that one
-- is 002's and still says what 002 meant.
--
-- No upper bound on either. `max_attachment_bytes` has one because Storage
-- physically refuses a larger object, so a cap past it could not be met —
-- there is no equivalent wall here, and capping how permissive an operator
-- is allowed to be would be this file inventing a policy rather than
-- carrying one.
ALTER TABLE servers
  DROP CONSTRAINT IF EXISTS servers_voice_limits_sane;
ALTER TABLE servers
  ADD CONSTRAINT servers_voice_limits_sane
  CHECK (max_voice_participants >= 0 AND max_share_mbps >= 0);

COMMENT ON COLUMN servers.max_voice_participants IS
  'How many people may be in one voice channel at once; 0 is no limit. '
  'Counted as people, not connections — a screen share is a second '
  'connection held by somebody already counted. Enforced by '
  'get_channel_token, which is the only way into a call.';

COMMENT ON COLUMN servers.max_share_mbps IS
  'The most a screen share may publish, in Mbps; 0 is no limit. A budget '
  'the client keeps rather than a wall: a LiveKit join token has no bitrate '
  'field. The wall is limit.bytes_per_sec in livekit.yaml.';
