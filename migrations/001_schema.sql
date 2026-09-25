-- ============================================================
-- Rift self-hosted server — 001: the tables
-- ============================================================
-- Every table, type and index this schema has, in the shape it is meant to
-- have. Nothing here describes how it got that way: a server is built by
-- running these eight files in order against an empty database, and that is
-- the only path any of them describe.
--
-- Where the rest of it lives:
--   002_helpers    the permission bits, the predicates policies are written in,
--                  and the views clients read a member through
--   003_api        the RPCs clients call
--   004_triggers   the triggers that keep these tables honest
--   005_realtime   what a client may subscribe to, and what is broadcast to it
--   006_storage    buckets, their policies, and the disk cap
--   007_jobs       scheduled cleanup
--   008_security   grants, RLS, and every policy — last, so that everything it
--                  names already exists
--
-- Tables are in dependency order, so this applies top to bottom with no
-- forward reference and no ALTER afterwards to fix one up.
-- ============================================================

CREATE SCHEMA IF NOT EXISTS app;

-- ============================================================
-- Extensions
-- ============================================================
-- pgcrypto backs gen_random_uuid() and new_invite_code(); pg_net is how the
-- push triggers reach the relay; pg_trgm backs member search. pg_cron is
-- declared by 007, the only file that schedules anything.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ============================================================
-- Types
-- ============================================================

-- ============================================================
-- Types
-- ============================================================

DO $$ BEGIN
  CREATE TYPE channel_type AS ENUM ('voice', 'text');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- What a read cursor points at. One table covers channels and DMs because the
-- question is identical in both cases — "how far has this person read" — and
-- keeping it in one place is what lets a single client path badge both.
DO $$ BEGIN
  CREATE TYPE read_scope AS ENUM ('channel', 'dm');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ============================================================
-- Per-conversation notification levels
-- ============================================================
-- Until now a member had one setting for a whole server: push on, or push off.
-- That is not how anybody actually reads a chat. One channel is the reason you
-- joined and three others are noise, and the only honest way to tell them apart
-- is to let the member say so.
--
-- Three levels:
--
--   all       every message rings
--   mentions  only a message that names you (or @all) rings
--   none      nothing rings
--
-- ...at three scopes: the **server**, one **channel**, one **conversation**.
-- Channels default to `mentions` and DMs to `all`, which is what people expect
-- from a chat app and, not coincidentally, what stops a busy server from
-- waking every phone on it all day.
--
-- The scopes are a fallback chain, not a fight: **the conversation's own level
-- if it has one, else the server's if it has one, else the default.** So
-- muting a server quiets everything you have not spoken about individually,
-- and a channel you deliberately set to `all` stays loud inside a muted
-- server — which is the case that makes a server-wide switch usable rather
-- than a thing you turn on once and then fight.
--
-- Discord resolves this the other way (a server mute wins over the channels
-- inside it) and then needs per-channel overrides to climb back out. One
-- ordering has to be picked; this one is the one you can predict from the menu
-- in front of you, because a channel showing an explicit level is telling you
-- it is in force.
--
-- ---------- the awkward part ----------
--
-- The server cannot read a message. So it cannot tell, on its own, whether one
-- names you — which is precisely the question `mentions` asks. Three ways out
-- were on the table:
--
--   * ring for every message in a mentions-only channel and let the phone
--     decide after decrypting. Private and instant, but a 20-member channel at
--     200 messages a day is ~190 pointless wakes per device per day.
--   * ring on a cooldown and let the phone decide. Private and cheap, but an
--     @mention can arrive minutes late, which is the one notification nobody
--     will accept being late.
--   * have the sender's client say who it named.
--
-- The third is what this does: `messages.mentions` is a plaintext array of user
-- ids, written by the sender, and `mentions_all` is the @all flag. The trade is
-- stated plainly because it is real — **the operator learns who was addressed
-- in a message**, though never what it said. It is the same class of metadata
-- this schema already keeps in the open for DMs (`dm_messages.recipient_id`)
-- and for reactions. Message *content*
-- is untouched.
--
-- Two things keep it honest:
--
--   * the column is validated below, not trusted: ids that aren't live members
--     of this server are dropped, the sender is dropped, and the array is
--     capped. A modified client can cause a wake; it cannot cause a hundred.
--   * the phone decrypts before it says anything. A client that lies about who
--     it mentioned buys a silent wake, never a false "mentioned you" — the
--     notification's wording comes from the plaintext or from nothing.
--
-- Not done here, deliberately: revoking SELECT on `mentions` from members. It
-- would buy nothing today, because there is no per-channel membership — every
-- member holds every channel key and can read the plaintext the column
-- summarises. Column-level grants would also break the next column somebody
-- adds, silently. Revisit it the day channels get their own rosters.

-- ============================================================
-- 1. The setting
-- ============================================================

DO $$ BEGIN
  CREATE TYPE notify_level AS ENUM ('all', 'mentions', 'none');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- Its own scope enum rather than borrowing `read_scope`. A read cursor cannot
-- point at a server — there is nothing to be "read up to" — so adding a value
-- there to serve this table would make the type's name a lie and permit a
-- `read_state` row nothing could interpret.
DO $$ BEGIN
  CREATE TYPE notify_scope AS ENUM ('server', 'channel', 'dm');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ============================================================
-- Servers
-- ============================================================
-- One Supabase project can host several servers (identity is derived per
-- (host, server_id), so the same person joining two of them has two distinct
-- GoTrue accounts and two rows in `users`).
--
-- The limit columns are all on this row rather than in a settings table:
-- there is exactly one row per server, members already select it for the name
-- and icon, and a client needs to *read* the caps to refuse an oversized file
-- before uploading it. `servers_select` scopes reads to your own server and
-- there is no client-reachable UPDATE grant, so an admin changes these
-- through the `update_server` edge function like the name and the LiveKit URL.
--
-- 0 means "no limit" on every one of them that is NOT NULL. The two DM
-- columns are nullable instead, because they are overrides rather than base
-- cases — NULL inherits the server-wide number, 0 opts DMs out of a sweep,
-- and N is DMs' own number. They sit on `servers` and not on a conversation
-- because a DM belongs to two people: the policy protects the operator's
-- disk, and neither end of the conversation is the right person to decide how
-- long the other's messages survive.

CREATE TABLE IF NOT EXISTS servers (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  name        TEXT        NOT NULL,
  icon_url    TEXT,
  livekit_url TEXT        NOT NULL,

  -- ── What the place costs the person running it ──
  max_attachment_bytes   BIGINT  NOT NULL DEFAULT 26214400,
  message_retention_days INTEGER NOT NULL DEFAULT 0,
  message_history_cap    INTEGER NOT NULL DEFAULT 0,
  dm_retention_days      INTEGER,
  dm_history_cap         INTEGER,
  max_voice_participants INTEGER NOT NULL DEFAULT 0,
  max_share_mbps         INTEGER NOT NULL DEFAULT 0,
  max_members            INTEGER NOT NULL DEFAULT 0,
  max_storage_bytes      BIGINT  NOT NULL DEFAULT 0,

  -- 500 MB is not arbitrary: Supabase Storage caps an object there on the
  -- free plan, and a larger number would fail silently at upload.
  CONSTRAINT servers_limits_sane CHECK (
    max_attachment_bytes BETWEEN 1 AND 524288000
    AND message_retention_days >= 0
    AND message_history_cap    >= 0
  ),
  CONSTRAINT servers_dm_limits_sane CHECK (
    (dm_retention_days IS NULL OR dm_retention_days >= 0)
    AND (dm_history_cap IS NULL OR dm_history_cap >= 0)
  ),
  CONSTRAINT servers_voice_limits_sane CHECK (
    max_voice_participants >= 0 AND max_share_mbps >= 0
  ),
  CONSTRAINT servers_size_limits_sane CHECK (
    max_members >= 0 AND max_storage_bytes >= 0
  )
);

COMMENT ON COLUMN servers.max_attachment_bytes IS
  'Per-file attachment cap. Mirrored onto the chat-attachments bucket''s '
  'file_size_limit by update_server — that mirror is the enforcement, this '
  'column is what the client reads to refuse a file before uploading it.';

COMMENT ON COLUMN servers.message_retention_days IS
  'Server-wide default: delete messages older than this many days. 0 = keep '
  'forever. A channel may override it.';

COMMENT ON COLUMN servers.message_history_cap IS
  'Server-wide default: keep at most this many messages per channel and per DM '
  'pair, newest first. 0 = no cap. A channel may override it.';

COMMENT ON COLUMN servers.dm_retention_days IS
  'Delete DMs older than this many days. NULL inherits '
  'message_retention_days; 0 explicitly keeps DMs forever.';

COMMENT ON COLUMN servers.dm_history_cap IS
  'Keep at most this many messages per DM conversation, counting both people. '
  'NULL inherits message_history_cap; 0 explicitly means no cap.';

COMMENT ON COLUMN servers.max_voice_participants IS
  'How many people may be in one voice channel at once; 0 is no limit. '
  'Counted as people, not connections — a screen share is a second '
  'connection held by somebody already counted. Enforced by '
  'get_channel_token, which is the only way into a call.';

COMMENT ON COLUMN servers.max_share_mbps IS
  'The most a screen share may publish, in Mbps; 0 is no limit. A budget '
  'the client keeps rather than a wall: a LiveKit join token has no bitrate '
  'field, and nothing server-side throttles a publisher. Deliberate — this '
  'is a limit about cost, not about trust.';

COMMENT ON COLUMN servers.max_members IS
  'How many members the server holds; 0 is no limit. Counts bots, which are '
  'members, and not banned members, who are not. Enforced by register_user.';

COMMENT ON COLUMN servers.max_storage_bytes IS
  'How many bytes of attachments the server keeps; 0 is no limit. Enforced '
  'by a trigger on storage.objects against a running total, never a SUM.';

-- LiveKit credentials live in their own table, not as columns on `servers`.
--
-- They used to sit beside the name and icon, which made the whole row
-- unshowable to a client: every read had to be laundered through an edge
-- function or the API secret went with it. Split out, `servers` becomes
-- ordinary public metadata a member can select directly, and the secret sits
-- in a table with RLS and no policy at all — unreachable by any client, only
-- ever read by `get_channel_token` on the service role.
CREATE TABLE IF NOT EXISTS server_secrets (
  server_id          UUID PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
  livekit_api_key    TEXT NOT NULL,
  livekit_secret_key TEXT NOT NULL
);

-- ============================================================
-- Where voice runs
-- ============================================================
-- A server may have more than one LiveKit, so that a call is held near the
-- people in it rather than near the database. Each row is one node, with a
-- label the operator writes — "Frankfurt", "Singapore" — because only they
-- know what their box is for.
--
-- **A room lives on exactly one node, and that is LiveKit's rule, not ours.**
-- The open-source server binds a room to a single node; cross-node media is
-- LiveKit Cloud's distributed mesh. So this is never "each person connects to
-- their nearest": it is "the call is created on one of these, and everybody
-- goes there". What multiple nodes buy is a better choice of *where*, and a
-- server whose members are mostly in one place gets a call near them.
--
-- **Every added node holds its own LiveKit key pair**, in
-- `livekit_node_secrets` below, and a region cannot exist without one. The
-- default node is the exception and not really one: it *is* the server's own
-- LiveKit, so its pair is `server_secrets`.
--
-- One shared pair was the first design and the reasoning was setup
-- convenience — a LiveKit key is a line in each box's own `livekit.yaml`, so
-- making them match costs nothing. What that missed is blast radius: the pair
-- is *on* every box, so compromising the cheapest VPS in the list yields the
-- key that mints tokens for all of them, including the one the server itself
-- runs on. Calls are end-to-end encrypted, so that buys metadata and
-- disruption rather than audio — but it is still every room on every node,
-- and rotating the answer meant a flag day across the estate.
--
-- It is required rather than offered because the operator has to write *some*
-- key into that box's `livekit.yaml` either way: a distinct one is the same
-- work, and an optional safeguard is one most people skip.
--
-- The row mirroring `servers.livekit_url` is marked `is_default` and is kept
-- in step with that column by a trigger in 004: it is the same address under
-- two names, and every part of the stack that predates regions still reads
-- the column.
CREATE TABLE IF NOT EXISTS livekit_nodes (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  server_id  UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,

  -- What a channel manager picks from. Shown to members as the region a call
  -- is in, so it is a place rather than a hostname.
  label      TEXT        NOT NULL CHECK (length(btrim(label)) BETWEEN 1 AND 40),

  -- `wss://` or `ws://`, the address a client connects to. Must be reachable
  -- from the functions container as well, which is what mints against it.
  url        TEXT        NOT NULL CHECK (url ~ '^wss?://[^ ]+$'),

  -- The mirror of `servers.livekit_url`. Exactly one per server, maintained
  -- by trigger; it cannot be deleted while the column exists.
  is_default BOOLEAN     NOT NULL DEFAULT false,

  UNIQUE (server_id, label)
);

CREATE INDEX IF NOT EXISTS livekit_nodes_server ON livekit_nodes (server_id);

CREATE UNIQUE INDEX IF NOT EXISTS livekit_nodes_one_default
  ON livekit_nodes (server_id) WHERE is_default;

COMMENT ON TABLE livekit_nodes IS
  'The LiveKit servers a Rift server may hold a call on. A call lives on one '
  'of them; see voice_rooms for which.';

-- A node's own LiveKit credentials, split off for the same reason
-- `server_secrets` is: `livekit_nodes` is ordinary metadata every member
-- reads, and a secret on that row would ride along with every read of it.
--
-- No policy and no grant — only `get_channel_token` and its neighbours, on
-- the service role, ever read this, and the only way to write it is
-- `set_voice_region_credentials`, which is an admin-checked SECURITY DEFINER
-- function because no client can reach the table directly.
--
-- **Required for every node but the default**, enforced by a deferred
-- constraint trigger in 004 rather than by the API alone: a region with no
-- key of its own would have to fall back to the server's, which is the thing
-- this table exists to stop. Adding one is therefore a single RPC that writes
-- both rows in one transaction.
--
-- The default node is refused a row here: it *is* the server's LiveKit, so
-- its key is `server_secrets` by definition and two places to write one value
-- is a way for them to disagree.
CREATE TABLE IF NOT EXISTS livekit_node_secrets (
  node_id            UUID PRIMARY KEY REFERENCES livekit_nodes(id) ON DELETE CASCADE,
  livekit_api_key    TEXT NOT NULL CHECK (length(btrim(livekit_api_key)) > 0),
  livekit_secret_key TEXT NOT NULL CHECK (length(btrim(livekit_secret_key)) > 0)
);

COMMENT ON TABLE livekit_node_secrets IS
  'A LiveKit node''s own API key and secret, required for every node but the '
  'default, whose pair is the server''s. Unreachable by any client.';

-- ============================================================
-- Members
-- ============================================================
-- `users.id` IS the GoTrue uid, so every ownership rule anywhere in this
-- schema is `= auth.uid()` with no join.
--
-- A bot is a row here too. There is no separate bot API, no bot token format
-- and no second auth path — the same row, the same SIWS login, the same JWT,
-- the same policies. That is what stops the bot surface drifting away from
-- the app surface: a capability the app has, a bot has, under the same rules.
--
-- `is_server_admin`, `is_channel_manager`, `can_create_tokens` and `is_owner`
-- are a **cache** of what this member's roles add up to, kept by a trigger in
-- 004. Clients read them off their own row to decide what to offer. The
-- authority is `member_roles`; these four are the shadow it casts.

CREATE TABLE IF NOT EXISTS users (
  id                 UUID        PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  server_id          UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  username           TEXT        NOT NULL,
  display_name       TEXT        NOT NULL,
  -- Ed25519 signing key (base58 of it is the SIWS "address").
  public_key         TEXT        NOT NULL,
  -- Stable per-(host, server) identifier derived from the seed.
  stable_id          TEXT        NOT NULL,
  -- X25519 key others seal to. Null until the client publishes it.
  chat_public_key    TEXT,
  avatar_path        TEXT,
  is_banned          BOOLEAN     NOT NULL DEFAULT false,

  -- ── The cache of what this member's roles add up to ──
  -- (`is_owner` sits at the end of the row with the rest of the later
  --  additions; it belongs to this group, not to the two flags below it.)
  is_server_admin    BOOLEAN     NOT NULL DEFAULT false,
  is_channel_manager BOOLEAN     NOT NULL DEFAULT false,
  can_create_tokens  BOOLEAN     NOT NULL DEFAULT false,

  is_muted           BOOLEAN     NOT NULL DEFAULT false,
  is_deafened        BOOLEAN     NOT NULL DEFAULT false,

  -- ── Bots ──
  is_bot             BOOLEAN     NOT NULL DEFAULT false,
  -- The command list, so a client can offer `/play` without asking a bot that
  -- is usually asleep. Plaintext and world-readable by design: it is an
  -- advertisement, and it carries the bot's own statement of what it does
  -- with what it is given, which the user needs *before* typing.
  manifest           JSONB,

  is_owner           BOOLEAN     NOT NULL DEFAULT false,

  -- Per-server uniqueness, not global: two servers in one project are two
  -- different communities and may each have a "sam".
  UNIQUE (server_id, username),
  UNIQUE (server_id, public_key),
  UNIQUE (server_id, stable_id),

  -- `@all` has to mean everybody and nobody in particular, so no one may *be*
  -- "all". A CHECK rather than a test in `register_user`, because the rule
  -- belongs to the column and there is more than one way to write a row.
  CONSTRAINT users_username_not_reserved CHECK (lower(username) <> 'all'),
  -- A username is what `@`-mentions resolve against, and the parser's
  -- alphabet is `[A-Za-z0-9_.-]` with a 32 ceiling (the client's
  -- `message_markup.dart`, and `MentionSuggestions`, which refuses a query
  -- containing whitespace). A name outside it is a member nobody can mention
  -- and search cannot reach — "Benny Smith!" was accepted here, and was
  -- unmentionable from the moment it landed. Same argument as the rule above:
  -- it belongs to the column, because `register_user` is not the only way a
  -- row gets written and a bot joining through the SDK goes round whatever a
  -- client checks.
  CONSTRAINT users_username_shape CHECK (username ~ '^[A-Za-z0-9_.-]{2,32}$'),
  CONSTRAINT users_manifest_is_bot CHECK (manifest IS NULL OR is_bot),
  -- Bounded: any member can read it and the bot writes it unattended. A
  -- manifest is a short list of verbs, not a payload.
  CONSTRAINT users_manifest_size CHECK (manifest IS NULL OR length(manifest::text) <= 8192)
);

COMMENT ON COLUMN users.is_bot IS
  'This row is a program, not a person. Set from the invite at registration and '
  'never afterwards — see 014. Bots cannot hold channel keys (channel_keyring '
  'refuses them), and clients list them separately from members.';

COMMENT ON COLUMN users.manifest IS
  'A bot''s published command list and data declaration (BOTS.md §4, §8). '
  'Written by the bot itself; NULL for a person. Advertisement, not evidence — '
  'a client renders it, and nothing is authorised by what it claims.';

CREATE INDEX IF NOT EXISTS idx_users_server ON users (server_id);

CREATE INDEX IF NOT EXISTS idx_users_bots
  ON users (server_id) WHERE is_bot;

-- Keyset paging wants (lower(display_name), id) in the index, and the search
-- wants prefix matches on both names. `text_pattern_ops` is what makes
-- `LIKE 'ab%'` on a lowercased column an index scan.
CREATE INDEX IF NOT EXISTS idx_users_server_sorted
  ON users (server_id, lower(display_name), id);

CREATE INDEX IF NOT EXISTS idx_users_display_prefix
  ON users (server_id, lower(display_name) text_pattern_ops);

CREATE INDEX IF NOT EXISTS idx_users_username_prefix
  ON users (server_id, lower(username) text_pattern_ops);

-- ============================================================
-- The member list stops walking the server
-- ============================================================
-- The five queries behind the member sidebar would each read the whole
-- membership to answer a question about a handful of people. These indexes
-- are what stops them.
--
-- Measured on 50,000 members:
--
--   resolve 50 ids (members_by_ids) .....   8.96 ms  →  0.7 ms
--   role chips for 50 (member_roles_for)   32.6  ms  →  0.8 ms
--   count the members (member_counts) ...  160   ms  →  5.9 ms
--   typeahead, no match (search_members)   120   ms  →  0.5 ms
--   the sidebar, page 20 (list_members) .   15.6 ms  →  0.2 ms
--
-- There are three separate causes and they need three separate fixes.
--
-- ---------- 1. an array parameter tells the planner nothing ----------
--
-- `members_by_ids` and `member_roles_for` take `uuid[]`. The planner has no
-- idea whether that holds one id or fifty thousand, so it plans for the
-- worst: a sequential scan of `member_roles`, or a walk of the whole server
-- in name order until fifty of the wanted ids happen to turn up. Unnesting
-- the array into a materialised CTE first gives it a row count, and it joins
-- by primary key instead.
--
-- ---------- 2. a SECURITY DEFINER call is a call per row ----------
--
-- `app.member_in_scope` cannot be inlined, so it is a real function call for
-- every member considered. Two thirds of what it asks — is this a bot, is
-- this a banned account — are comparisons on columns the query already has.
-- Only the channel question needs the function, so only the channel question
-- calls it now. That was the whole of `member_counts`: 50,000 calls to
-- compare two booleans.
--
-- ---------- 3. the caller's own row, OR'd into every read ----------
--
-- This is the one worth reading carefully, because it is not obvious and it
-- was costing the most.
--
-- `users` has two SELECT policies, and Postgres ORs permissive policies
-- together, so every read of `users` carries
-- `(id = auth.uid() OR server_id = app.server_id())`. That disjunction can
-- never be an index condition — so the planner applies it as a filter, and a
-- filter it cannot index means *nothing else can be an index condition
-- either*. The keyset paging comparison, the three prefix patterns, all of
-- it falls back to a sequential scan of the membership:
--
--   the sidebar, page 20 ........ 22,214 rows walked to return 51
--   typeahead for "zzz" ......... 50,000 rows walked to return 0
--
-- The second policy is not a mistake. A banned member has no server, so
-- `app.server_id()` is null for them, and `users_select_self` is how they can
-- still read their own row and find out the ban was lifted. It has to stay.
--
-- So these five functions become SECURITY DEFINER and enforce the same scope
-- themselves, in one place, with a constant: `v_server := app.server_id()`,
-- nothing at all if that is null, and `server_id = v_server` on every query.
-- That is exactly what `users_select_members` permits — a banned caller
-- resolves to null and gets nothing either way, which is what the INVOKER
-- versions already did — and with a constant in hand the planner uses the
-- indexes that were there all along.
--
-- `member_roles_for` is the one to be careful with: it had no scope of its
-- own at all, because `member_roles_select` was doing the scoping for it.
-- Bypassing RLS means it has to say so itself, which is the `scoped` CTE.

-- ============================================================
-- 1. The two indexes the search needed
-- ============================================================
-- `replace(lower(display_name), ' ', '')` is how "JohnSmith" finds "John
-- Smith". It was already one of the match patterns and had no index, so it
-- was the one dragging the other two into a scan.

CREATE INDEX IF NOT EXISTS idx_users_display_squashed
  ON users (server_id, replace(lower(display_name), ' ', '') text_pattern_ops);

-- Substring search ("ali" finding "khalid") cannot use a prefix index. Trigram
-- can, and is worth having on a large server — but `pg_trgm` is not guaranteed
-- to be installable on every host this runs on, and a missing extension must
-- not take the migration down with it. Without it the substring pass is a scan
-- bounded by the page limit, which is fine into the low tens of thousands.
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pg_trgm;
  CREATE INDEX IF NOT EXISTS idx_users_name_trgm
    ON users USING gin ((lower(display_name) || ' ' || lower(username)) gin_trgm_ops);
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pg_trgm unavailable — substring member search will scan';
END $$;

-- The prefilter for the infix fallback. Deliberately built on the *squashed*
-- display name so it is a true superset of both infix patterns: a needle
-- that spans a space in the display name is present here, and would not be
-- in a concatenation that kept the space.
--
-- Guarded like the other trigram index, and for the same reason: `pg_trgm`
-- is not installable on every host, and a missing extension must not take
-- the migration down with it. Without the index the
-- infix half is a scan bounded by the page limit — which is what it was
-- before this migration, so nothing is worse off.
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS pg_trgm;
  CREATE INDEX IF NOT EXISTS idx_users_search_trgm
    ON users USING gin (
      (replace(lower(display_name), ' ', '') || ' ' || lower(username))
      gin_trgm_ops);
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pg_trgm unavailable — the infix half of member search will scan';
END $$;

-- ============================================================
-- Roles
-- ============================================================

CREATE TABLE IF NOT EXISTS roles (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  server_id    UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name         TEXT        NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 40),
  color        TEXT        CHECK (color IS NULL OR color ~ '^#[0-9A-Fa-f]{6}$'),
  -- Higher outranks lower. Who may hand out or edit a role is decided by
  -- comparing positions, so this is a permission input, not decoration.
  "position"   INTEGER     NOT NULL DEFAULT 1 CHECK ("position" >= 0),
  permissions  BIGINT      NOT NULL DEFAULT 0,
  -- Held by everyone on the server without a `member_roles` row.
  is_everyone  BOOLEAN     NOT NULL DEFAULT false,
  -- The top rung. Exactly one per server, held by exactly one member.
  is_owner     BOOLEAN     NOT NULL DEFAULT false,
  UNIQUE (server_id, name)
);

COMMENT ON TABLE roles IS
  'A named set of permission bits (app.perm). `is_everyone` is the implicit '
  'baseline: it is never in member_roles and cannot be deleted.';

CREATE UNIQUE INDEX IF NOT EXISTS roles_one_everyone
  ON roles (server_id) WHERE is_everyone;

-- One per server. The seed below makes it, and the trigger under it keeps it.
CREATE UNIQUE INDEX IF NOT EXISTS roles_one_owner
  ON roles (server_id) WHERE is_owner;

CREATE INDEX IF NOT EXISTS roles_server ON roles (server_id, position DESC);

CREATE TABLE IF NOT EXISTS member_roles (
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id     UUID        NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  granted_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
  granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS member_roles_role ON member_roles (role_id);

-- ============================================================
-- Channels
-- ============================================================
-- `retention_days` and `history_cap` are per-channel overrides of the
-- server-wide numbers, with the same three-valued rule as the DM columns on
-- `servers`: NULL inherits, 0 opts out, N is this channel's own number.

CREATE TABLE IF NOT EXISTS channels (
  id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
  server_id    UUID         NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name         TEXT         NOT NULL,
  channel_type channel_type NOT NULL,
  retention_days INTEGER,
  history_cap    INTEGER,
  is_private   BOOLEAN      NOT NULL DEFAULT false,
  rotate_from_key_version INTEGER,

  -- Which LiveKit a call here is held on. NULL is "automatic" — decide from
  -- whoever opens the call, see `voice_rooms`. Set is the manager pinning it,
  -- the way Discord's region override does, because automatic picking is a
  -- guess and somebody occasionally knows better.
  --
  -- ON DELETE SET NULL: removing a node returns its channels to automatic
  -- rather than leaving them pointing at nothing.
  livekit_node_id UUID REFERENCES livekit_nodes(id) ON DELETE SET NULL,

  UNIQUE (server_id, name),
  CONSTRAINT channels_limits_sane CHECK (
    (retention_days IS NULL OR retention_days >= 0)
    AND (history_cap IS NULL OR history_cap >= 0)
  )
);

COMMENT ON COLUMN channels.retention_days IS
  'Delete messages in this channel older than this many days. NULL inherits '
  'servers.message_retention_days; 0 explicitly means keep forever.';

COMMENT ON COLUMN channels.history_cap IS
  'Keep at most this many messages in this channel. NULL inherits '
  'servers.message_history_cap; 0 explicitly means no cap.';

COMMENT ON COLUMN channels.is_private IS
  'Visible only to channel_members and holders of a channel_role_access role. '
  'No admin override: an admin holds no key either way.';

COMMENT ON COLUMN channels.livekit_node_id IS
  'Pin voice here to one LiveKit node. NULL picks automatically from the '
  'first person to open a call; see voice_rooms.';

COMMENT ON COLUMN channels.rotate_from_key_version IS
  'Set when a channel opens up: the sweep must rotate past this version before '
  'anybody new is sealed in, or a new arrival receives the key the private '
  'conversation was written under. Self-clearing.';

CREATE INDEX IF NOT EXISTS channels_private
  ON channels (server_id) WHERE is_private;

-- ============================================================
-- 2. Who is in one
-- ============================================================

CREATE TABLE IF NOT EXISTS channel_members (
  channel_id UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  -- The private channel's own manage bit. `MANAGE_CHANNELS` is a server
  -- permission and its holders cannot see this room, so somebody inside has to
  -- be able to run it.
  can_manage BOOLEAN     NOT NULL DEFAULT false,
  added_by   UUID        REFERENCES users(id) ON DELETE SET NULL,
  -- `clock_timestamp()`, not `now()`. `now()` is the transaction's start, so
  -- everybody seated by one statement — which is exactly what closing a channel
  -- does — would share a timestamp, and "longest-serving" would come down to
  -- whose UUID sorts first. This column decides who inherits the room.
  added_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (channel_id, user_id)
);

CREATE INDEX IF NOT EXISTS channel_members_user ON channel_members (user_id);

-- Access by role, resolved rather than stored: adding a role here means
-- everybody holding it, including whoever is given it tomorrow. The sweep reads
-- through to the people, because a key can only be wrapped for a person.
CREATE TABLE IF NOT EXISTS channel_role_access (
  channel_id UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  role_id    UUID        NOT NULL REFERENCES roles(id)    ON DELETE CASCADE,
  added_by   UUID        REFERENCES users(id) ON DELETE SET NULL,
  added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, role_id)
);

CREATE INDEX IF NOT EXISTS channel_role_access_role ON channel_role_access (role_id);

-- ============================================================
-- Which node a live call is on
-- ============================================================
-- One row per channel that has a call up, naming the node its room was
-- created on. This is the *answer*, where `channels.livekit_node_id` is the
-- *preference*: a room cannot move once it exists, so the second person to
-- join goes where the first one's room already is, whatever has been
-- configured since.
--
-- Written by `get_channel_token` when it creates the room, and cleared when
-- the call empties — `voice_roster` does it, because it is already asking
-- every node who is in each room and is therefore the one thing that finds
-- out. Without the clear, a channel would keep its first-ever node forever
-- and "automatic" would only ever decide once.
--
-- A stale row is harmless in the direction that matters: it sends people to a
-- node that has no such room, and LiveKit creates it there. It only costs a
-- worse choice, never a broken call, which is why this is allowed to be
-- eventually-consistent rather than transactional with LiveKit.
CREATE TABLE IF NOT EXISTS voice_rooms (
  channel_id UUID        PRIMARY KEY REFERENCES channels(id)      ON DELETE CASCADE,
  node_id    UUID        NOT NULL    REFERENCES livekit_nodes(id) ON DELETE CASCADE,
  opened_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS voice_rooms_node ON voice_rooms (node_id);

COMMENT ON TABLE voice_rooms IS
  'Where each live call actually is. The preference is channels.livekit_node_id; '
  'this is what was decided when the room was created.';

-- ============================================================
-- Invites
-- ============================================================

-- Base58, 10 characters — the same shape the edge function used to mint, moved
-- to a column default so an invite can be created by an ordinary INSERT under
-- RLS instead of needing a privileged endpoint.
-- search_path includes `extensions`: that is where Supabase installs pgcrypto,
-- and a column default runs with the *inserting* role's path, which doesn't
-- have it.
CREATE OR REPLACE FUNCTION new_invite_code() RETURNS TEXT
  LANGUAGE plpgsql VOLATILE SET search_path = public, extensions AS $$
DECLARE
  alphabet CONSTANT TEXT :=
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  out TEXT := '';
  b   INTEGER;
BEGIN
  WHILE length(out) < 10 LOOP
    b := get_byte(gen_random_bytes(1), 0);
    -- Reject the tail of the byte range so every character stays equally
    -- likely (58 does not divide 256).
    IF b < 232 THEN
      out := out || substr(alphabet, (b % 58) + 1, 1);
    END IF;
  END LOOP;
  RETURN out;
END; $$;

CREATE TABLE IF NOT EXISTS invites (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  server_id   UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  -- Who minted it: what lets a member manage their own invites under RLS
  -- without being able to enumerate everyone else's codes.
  created_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
  code        TEXT        NOT NULL UNIQUE DEFAULT new_invite_code(),
  max_uses    INTEGER,
  uses        INTEGER     NOT NULL DEFAULT 0,
  expires_at  TIMESTAMPTZ,
  -- This invite mints a bot rather than a person.
  is_bot      BOOLEAN     NOT NULL DEFAULT false,
  -- The role it hands out, on top of @everyone.
  role_id     UUID        REFERENCES roles(id) ON DELETE CASCADE
);

COMMENT ON COLUMN invites.is_bot IS
  'This invite mints a bot. Chosen when the invite is created; an ordinary '
  'invite can never produce one.';

COMMENT ON COLUMN invites.role_id IS
  'The role this invite hands out, on top of the default. CASCADE rather than '
  'SET NULL: an invite whose role was deleted would otherwise keep working and '
  'quietly grant nothing, which is worse than a link that stops.';

CREATE INDEX IF NOT EXISTS idx_invites_server ON invites (server_id);

CREATE INDEX IF NOT EXISTS idx_invites_expires
  ON invites (expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================
-- Webhooks
-- ============================================================
-- An incoming webhook is a URL an outside service POSTs to, which appears as
-- a message. The point of one is that **nobody runs anything**: GitHub is
-- never going to implement SIWS, and a community should not have to keep a
-- process alive to receive build notifications. That is also why a bot cannot
-- replace it — a bot is a program somebody hosts, and this exists precisely
-- for the case where there is no program.
--
-- Defined before `messages` because a message carries the id of the webhook
-- that posted it.

-- ============================================================
-- 2. The webhooks themselves
-- ============================================================
-- The URL *is* the credential — that is what makes a webhook usable by a
-- service that cannot log in, and it is also its weakness: a URL ends up in CI
-- config, in a screenshot, in a paste. So it is stored hashed (shown once, at
-- creation, and never again) and it is rate-limited.

CREATE TABLE IF NOT EXISTS webhooks (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  server_id    UUID        NOT NULL REFERENCES servers(id)  ON DELETE CASCADE,
  channel_id   UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  -- Who minted it, so a member can manage their own under RLS. SET NULL rather
  -- than CASCADE: the integration outlives whoever set it up.
  created_by   UUID        REFERENCES users(id) ON DELETE SET NULL,
  name         TEXT        NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  -- SHA-256 of the secret, hex. The secret itself is never stored.
  secret_hash  TEXT        NOT NULL UNIQUE,
  last_used_at TIMESTAMPTZ,
  -- Fixed window, reset on first post of a new minute. Coarse on purpose: the
  -- job is to bound a leaked URL, not to shape traffic.
  rate_window  TIMESTAMPTZ,
  rate_count   INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_webhooks_channel ON webhooks (channel_id);

CREATE INDEX IF NOT EXISTS idx_webhooks_server  ON webhooks (server_id);

-- ============================================================
-- Messages
-- ============================================================
-- Opaque E2E envelopes. The server stores and orders them and attests who
-- sent them and when; it cannot read them.
--
-- The length limits are checks in the database rather than in the client,
-- because clients insert directly: a check here is the only validation a
-- modified client cannot skip.
--
-- ---------- key_version = 0 means the body is NOT encrypted ----------
--
-- The server holds no channel key and never will, so it cannot seal what
-- arrives at a webhook URL. Escrowing a key server-side turns "readable by a
-- member who is present" into "readable by a process, forever"; a plaintext
-- *channel* type makes encryption the thing people switch off for
-- convenience. So the exception is per *message*, inside an ordinary
-- encrypted channel: a CI feed can sit in #dev next to the argument about the
-- build it broke, and #dev stays encrypted for everything a person says.
--
-- Every message at version >= 1 is Ed25519-signed and an unverifiable one is
-- never rendered. At version 0 there is no signer at all — the row is
-- attested by the server that accepted the POST and by nothing else. Hence
-- `origin_name` rather than a `sender_id` pointing somewhere: such a message
-- is not from a person, must never be attributed to one, and must be rendered
-- with its origin visible.
--
-- `webhook_id` is for management — which integration posted this, what to
-- rate-limit, what to revoke — and deliberately not what the row is rendered
-- from. Deleting a webhook must not rewrite the history it posted, so the
-- display name is denormalised onto the message at insert and frozen there.

CREATE TABLE IF NOT EXISTS messages (
  id          BIGSERIAL   PRIMARY KEY,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  channel_id  UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  -- Null for anything no member sent: a webhook, or a system notice.
  sender_id   UUID        REFERENCES users(id) ON DELETE CASCADE,
  ciphertext  TEXT        NOT NULL CHECK (length(ciphertext) <= 16384),
  nonce       TEXT        CHECK (length(nonce)     <= 64),
  signature   TEXT        CHECK (length(signature) <= 128),
  key_version INTEGER     NOT NULL CHECK (key_version >= 0),
  edited_at   TIMESTAMPTZ,

  -- ── Who it names ──
  mentions     UUID[]  NOT NULL DEFAULT '{}',
  mentions_all BOOLEAN NOT NULL DEFAULT false,

  -- ── Messages from things that cannot log in ──
  webhook_id  UUID REFERENCES webhooks(id) ON DELETE SET NULL,
  origin_name TEXT,

  -- ── Bots ──
  to_bot        UUID   REFERENCES users(id) ON DELETE SET NULL,
  reply_to      BIGINT REFERENCES messages(id) ON DELETE CASCADE,
  ephemeral_for UUID   REFERENCES users(id) ON DELETE CASCADE,
  -- A notice the server wrote itself, rather than anything a member sent.
  is_system     BOOLEAN NOT NULL DEFAULT false,
  blocks        JSONB,
  is_interaction BOOLEAN NOT NULL DEFAULT false,
  action_id     TEXT,
  action_value  TEXT,

  -- ── Polls ──
  -- The rules of a poll, in the clear, because the server enforces them: how
  -- many options there are, whether a voter may pick several, and when voting
  -- stops. The question and the options themselves are in the ciphertext.
  poll          JSONB,

  -- Exactly one origin. Both set is a message pretending to be two things;
  -- neither is a message from nobody.
  CONSTRAINT messages_one_origin
    CHECK ((sender_id IS NOT NULL) <> (origin_name IS NOT NULL)),
  -- A non-member message is always in the clear: nothing without a seed can
  -- produce a sealed envelope, so the reverse would be unopenable by anyone.
  CONSTRAINT messages_origin_is_plain
    CHECK (origin_name IS NULL OR key_version = 0),
  CONSTRAINT messages_origin_name_len
    CHECK (origin_name IS NULL OR length(origin_name) BETWEEN 1 AND 80),
  -- Envelope fields are required exactly when there is an envelope.
  CONSTRAINT messages_envelope_complete
    CHECK (key_version = 0 OR (nonce IS NOT NULL AND signature IS NOT NULL)),
  CONSTRAINT messages_blocks_are_plain CHECK (blocks IS NULL OR key_version = 0),
  CONSTRAINT messages_blocks_shape CHECK (
    blocks IS NULL
    OR (jsonb_typeof(blocks) = 'object'
        AND jsonb_typeof(blocks -> 'blocks') = 'array'
        AND jsonb_array_length(blocks -> 'blocks') <= 40)
  ),
  -- A press carries its action and nothing else does. The bot it is for is
  -- not required here: a press outlives the bot it was aimed at.
  CONSTRAINT messages_action_shape CHECK (
    ((NOT is_interaction) OR (action_id IS NOT NULL AND key_version = 0))
    AND (is_interaction OR (action_id IS NULL AND action_value IS NULL))
  ),
  CONSTRAINT messages_action_id_len
    CHECK (action_id IS NULL OR length(action_id) BETWEEN 1 AND 64),
  CONSTRAINT messages_action_value_len
    CHECK (action_value IS NULL OR length(action_value) <= 256),
  -- Only a sealed message carries a poll: its options are words, and a poll
  -- whose words are in the clear would be the one kind of message a member
  -- writes that the server can read.
  CONSTRAINT messages_poll_sealed CHECK (poll IS NULL OR key_version >= 1),
  -- Exactly these three keys. `closes_at` is checked as a time by
  -- `check_poll`, which can ask what time it is; a CHECK cannot.
  CONSTRAINT messages_poll_shape CHECK (
    poll IS NULL
    OR (jsonb_typeof(poll) = 'object'
        AND jsonb_typeof(poll -> 'options') = 'number'
        AND (poll ->> 'options')::numeric IN (2, 3, 4, 5, 6, 7, 8, 9, 10)
        AND jsonb_typeof(poll -> 'multiple') = 'boolean'
        AND jsonb_typeof(poll -> 'closes_at') = 'string'
        AND poll - 'options' - 'multiple' - 'closes_at' = '{}'::jsonb)
  )
);

COMMENT ON COLUMN messages.mentions IS
  'User ids this message names, in plaintext, written by the sender and '
  'validated below. Exists so the server can ring a mentions-only channel '
  'without reading the message. The operator learns who was addressed; not '
  'what was said.';

COMMENT ON COLUMN messages.mentions_all IS
  'The @all flag. A boolean rather than every member listed, because listing '
  'them is exactly the abuse the cap below exists to prevent.';

COMMENT ON COLUMN messages.key_version IS
  '0 = the body is NOT encrypted (webhook; later, bot commands). >= 1 = sealed '
  'under that channel key version, signed, and dropped by clients if the '
  'signature does not verify.';

COMMENT ON COLUMN messages.origin_name IS
  'Display name for a message no member sent. Frozen at insert so deleting the '
  'webhook does not rewrite its history. NULL for a member message.';

COMMENT ON COLUMN messages.to_bot IS
  'The bot this message is addressed to — a `/` command. Plaintext by '
  'necessity: the bot holds no channel key, so a sealed command would be one '
  'it could not open. NULL for every ordinary message.';

COMMENT ON COLUMN messages.ephemeral_for IS
  'A bot reply only this member sees (BOTS.md §5). Enforced by messages_select '
  'rather than by clients agreeing to hide it, and excluded from unread and '
  'from waking anybody else.';

COMMENT ON COLUMN messages.blocks IS
  'A panel: {"v":1,"blocks":[...]}. Drawn by the client with its own widgets '
  'from a fixed vocabulary; see WIRE.md. Only ever on an unencrypted message, '
  'because a panel is by definition something the bot that wrote it can read.';

COMMENT ON COLUMN messages.is_interaction IS
  'A button press or a menu choice, addressed to a bot. Never rendered as a '
  'message: `messages_select` shows it only to its sender and the bot it names.';

CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages (channel_id, id);

CREATE INDEX IF NOT EXISTS idx_messages_webhook
  ON messages (webhook_id) WHERE webhook_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_messages_to_bot
  ON messages (to_bot, id) WHERE to_bot IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_messages_reply_to
  ON messages (reply_to) WHERE reply_to IS NOT NULL;

-- ============================================================
-- Reactions
-- ============================================================
-- Deliberately NOT E2E: the server sees who reacted with which emoji. Accepted
-- metadata cost of a reaction UX (ARCHITECTURE.md §4) — message *content* stays
-- encrypted.

CREATE TABLE IF NOT EXISTS message_reactions (
  message_id BIGINT      NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  emoji      TEXT        NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id, emoji)
);

-- ============================================================
-- Pins
-- ============================================================
-- Which messages a channel keeps at hand. Not E2E, for the same reason as a
-- reaction: the server sees *that* a message was pinned and by whom, never
-- what it says. `channel_id` is copied off the message so the list is one
-- index range, and so the cap (`set_pinned`) can count it.
--
-- Written only by `set_pinned`, which checks `PIN_MESSAGES` and rings the
-- channel; there is no client INSERT or DELETE.

CREATE TABLE IF NOT EXISTS message_pins (
  message_id BIGINT      PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
  channel_id UUID        NOT NULL REFERENCES channels(id)   ON DELETE CASCADE,
  pinned_by  UUID        REFERENCES users(id)               ON DELETE SET NULL,
  pinned_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_message_pins_channel
  ON message_pins (channel_id, pinned_at DESC);

-- ============================================================
-- Poll votes
-- ============================================================
-- One row per voter per option picked. The server can read these — it has to,
-- to count them — but only as option *numbers*: what option 2 says is inside
-- the message's ciphertext.
--
-- Members see counts, not voters. The select policy shows a member their own
-- rows and nobody else's, and `poll_tallies` is how the totals are read. That
-- hides a vote from the other members, not from whoever runs the server, and
-- the client says so.
--
-- Written only by `vote_poll`, which enforces the poll's rules: open, a real
-- option, and one pick unless the poll allows several.

CREATE TABLE IF NOT EXISTS poll_votes (
  message_id BIGINT      NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  option     SMALLINT    NOT NULL CHECK (option BETWEEN 0 AND 9),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id, option)
);

-- ============================================================
-- Direct messages
-- ============================================================

CREATE TABLE IF NOT EXISTS dm_messages (
  id           BIGSERIAL   PRIMARY KEY,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sender_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext   TEXT        NOT NULL CHECK (length(ciphertext) <= 16384),
  nonce        TEXT        NOT NULL CHECK (length(nonce)      <= 64),
  signature    TEXT        NOT NULL CHECK (length(signature)  <= 128),
  key_version  INTEGER     NOT NULL CHECK (key_version >= 1),
  edited_at    TIMESTAMPTZ,
  CHECK (sender_id <> recipient_id)
);

-- Order-independent pair index: a conversation is looked up from either side.
CREATE INDEX IF NOT EXISTS idx_dm_messages_pair ON dm_messages
  (LEAST(sender_id, recipient_id), GREATEST(sender_id, recipient_id), id);

CREATE INDEX IF NOT EXISTS idx_dm_messages_recipient ON dm_messages (recipient_id, id);

CREATE INDEX IF NOT EXISTS idx_dm_messages_sender    ON dm_messages (sender_id, id);

CREATE TABLE IF NOT EXISTS dm_message_reactions (
  message_id BIGINT      NOT NULL REFERENCES dm_messages(id) ON DELETE CASCADE,
  user_id    UUID        NOT NULL REFERENCES users(id)       ON DELETE CASCADE,
  emoji      TEXT        NOT NULL CHECK (char_length(emoji) BETWEEN 1 AND 32),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id, emoji)
);

-- A DM's pins. Either of the two may pin, so there is no permission to check —
-- only that the message is theirs to see. The pair is copied off the message,
-- sorted, so a conversation's list and its cap are one index range whichever
-- side asks.
CREATE TABLE IF NOT EXISTS dm_message_pins (
  message_id BIGINT      PRIMARY KEY REFERENCES dm_messages(id) ON DELETE CASCADE,
  user_low   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_high  UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pinned_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
  pinned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (user_low < user_high)
);

CREATE INDEX IF NOT EXISTS idx_dm_message_pins_pair
  ON dm_message_pins (user_low, user_high, pinned_at DESC);

-- ============================================================
-- A conversation knows its own newest message
-- ============================================================
-- The same shape the central tier keeps, and for the same reason.
--
-- Without this table, `dm_conversations()` finds the newest message per peer with
-- `DISTINCT ON (peer)` over `dm_messages` — so drawing thirty rows read every
-- DM the caller had ever exchanged with anybody, sorted. There is no index
-- that could help:
--
--   * **There is no column to index.** "Peer" means whoever is not the
--     caller — a CASE evaluated per query, different for every member who
--     asks.
--   * **A conversation lives under two keys.** What you sent is filed by
--     sender, what you received by recipient, and the newest may be either.
--   * **Even a perfect index would only save the sort.** `DISTINCT ON` still
--     walks every one of your messages to find each peer's maximum.
--
-- So the index is written by hand: one row per person you talk to, holding
-- that conversation's newest message id. The list becomes a range scan of
-- your own rows, newest first, stop at thirty. Measured on central's copy of
-- this design, whose table is the same two columns and a bigint: 230-270 ms
-- for a 200-conversation account down to 9.5 ms, and flat at 5.4 ms with a
-- thousand conversations behind it, because picking the page is 0.27 ms of
-- index scan whatever the history.
--
-- A server's DMs are smaller than central's — one server's members rather
-- than everybody's friends — so this is the cheaper of the two to leave
-- broken and the easier of the two to fix. It is the same fix either way.
--
-- **Where this differs from central's.** That one is SECURITY DEFINER and
-- filters by hand, because its heads are a map of who talks to whom across
-- every account on the tier. Here the function is SECURITY INVOKER and the
-- policies do the work, as everything else on this schema does: a member
-- reads their own heads, which is their own conversation list, which they
-- already have.

-- ============================================================
-- 1. The heads
-- ============================================================

CREATE TABLE IF NOT EXISTS dm_conversation_heads (
  user_id         UUID   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  peer_id         UUID   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  last_message_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, peer_id)
);

COMMENT ON TABLE dm_conversation_heads IS
  'One row per person you have a conversation with, holding that '
  'conversation''s newest message id. Maintained by trigger; it is what makes '
  'the conversation list cost a page instead of a history.';

-- The whole point: your conversations, newest first, without a sort.
CREATE INDEX IF NOT EXISTS idx_dm_conversation_heads_recent
  ON dm_conversation_heads (user_id, last_message_id DESC);

-- ============================================================
-- Channel keys and read cursors
-- ============================================================

-- ============================================================
-- Channel keyring
-- ============================================================
-- Each channel key, sealed once per member (Design 2). The server holds only
-- ciphertext it cannot open.

CREATE TABLE IF NOT EXISTS channel_keyring (
  id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  channel_id           UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  key_version          INTEGER     NOT NULL CHECK (key_version >= 1),
  user_id              UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapped_by           UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ephemeral_public_key TEXT        NOT NULL,
  ciphertext           TEXT        NOT NULL,
  nonce                TEXT        NOT NULL,
  UNIQUE (channel_id, key_version, user_id)
);

CREATE INDEX IF NOT EXISTS idx_channel_keyring_user ON channel_keyring (user_id);

-- ============================================================
-- Read state
-- ============================================================
-- One cursor per conversation: the newest message id this member has read.
--
-- This replaces the `notifications` table, which fanned out one row per
-- recipient per message purely so the client could count unread. That cost a
-- write per member per message and a retention job to keep it from growing
-- forever. A cursor is one row per conversation, written when you actually read
-- something, and it produces the same badges — see unread_counts() in 003.
--
-- Central DMs keep the same shape, so both tiers can share one client path.

CREATE TABLE IF NOT EXISTS read_state (
  user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope        read_scope  NOT NULL,
  -- Channel id for 'channel', the other person's user id for 'dm'.
  scope_id     UUID        NOT NULL,
  last_read_id BIGINT      NOT NULL DEFAULT 0,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, scope, scope_id)
);

-- ============================================================
-- The doorbell stops asking everybody
-- ============================================================
-- `ring_channel_members` asks "is push even on?" first, which makes a message
-- free on a server with push turned off. This index is the other half: what it
-- costs on a server where push **is** on, which is every server anybody
-- actually runs.
--
-- Measured on a copy of this schema carrying 50,000 members, 50 channels and
-- 5,000,000 messages — a large community server, not a toy:
--
--   insert with the doorbell disabled ......      1.0 ms
--   insert with push on, 50,000 members ..... 15,326 ms
--
-- Fifteen seconds. The roster walk asks two questions per member, and the
-- expensive one is `has_unread_before`, which is a query of its own:
--
--   the whole walk ......................... 15,133 ms
--     of which has_unread_before ........... 14,584 ms
--     of which app.channel_eligible .........   286 ms
--     the plain roster, no per-member call ..     3.9 ms
--
-- So the shape is wrong rather than the indexes: 50,000 function calls, each
-- one a correlated lookup, to answer a question about one new row.
--
-- ---------- what the question actually needs ----------
--
-- `has_unread_before(u, ch, X)` asks whether there is a message in `ch`
-- between u's read cursor and X that u did not send. Written out, the newest
-- such message is the only one that matters — if it is past the cursor there
-- is unread mail, and if it is not there is none.
--
-- And that newest message is always one of **two rows**, whoever u is:
--
--   m1  the newest message before X
--   m2  the newest message before X sent by somebody other than m1's sender
--
-- If u did not send m1, the newest message u did not send is m1. If u did
-- send m1, then everything between m2 and m1 is u's too — that is what makes
-- m2 the newest from anybody else — so it is m2. There is no third case.
--
-- Two scalars, read once per message, therefore answer for every member at
-- once. Checked against the old function over 3,000 members on the fixture:
-- 3,000 rows compared, zero disagreements.
--
-- ---------- and it inverts the scan ----------
--
-- The old walk started from the roster and asked each member whether they
-- were caught up. Almost nobody is: of 3,000 members on the fixture, 2,999
-- had unread mail and were skipped, and the whole walk existed to find the
-- one who did not.
--
-- Driving from `read_state` instead asks only about the people who could
-- possibly qualify — a member is caught up only if their cursor is at or past
-- one of those two ids — and `idx_read_state_caught_up` makes that a range
-- scan. A member with no `read_state` row at all has read nothing, so has
-- unread mail, so is not rung: exactly what the old code concluded, and now
-- without visiting them.
--
--   insert with push on, 50,000 members ..... 15,326 ms  →  4.9 ms
--
-- The one member who can be caught up without a `read_state` row is the
-- sender of every prior message in the channel, whose threshold is zero
-- because there is nothing there they did not write. That is the `m2 IS NULL`
-- branch below, and it is the case the old code got right by accident.

-- ============================================================
-- 1. The cursor index
-- ============================================================
-- `read_state_pkey` is (user_id, scope, scope_id): the right index for "what
-- has this member read", which is what every other caller wants. This is the
-- other direction — "who has read this channel up to here" — and there was no
-- index for it because until now nothing asked.

CREATE INDEX IF NOT EXISTS idx_read_state_caught_up
  ON read_state (scope, scope_id, last_read_id);

COMMENT ON INDEX idx_read_state_caught_up IS
  'Who is caught up in one scope, for the push doorbell. The primary key '
  'answers the opposite question and cannot serve this one.';

-- ============================================================
-- Push
-- ============================================================

-- ---------- where a member can be reached ----------
-- A row is a device, not a person: the same account on a phone and a tablet is
-- two rows and both should ring. The token is the key because FCM hands the
-- same one back to a reinstalled app, and a device that changes hands must
-- replace the previous owner's row rather than accumulate beside it.

CREATE TABLE IF NOT EXISTS device_tokens (
  token      TEXT        PRIMARY KEY,
  user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  platform   TEXT        NOT NULL CHECK (platform IN ('android', 'ios', 'web')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_tokens_user ON device_tokens (user_id);

-- ---------- the relay credential ----------
-- Per server, not per project: one Supabase project can host several servers
-- and each is a separate community whose admin enrolled separately.
--
-- RLS with no policy at all is the point. The secret is what proves a forward
-- request came from this server; the triggers below reach it as SECURITY
-- DEFINER and no session ever can — not even the admin who configured it, who
-- had it once, at enrolment, and does not need it again.

CREATE TABLE IF NOT EXISTS push_config (
  server_id  UUID        PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
  endpoint   TEXT        NOT NULL,
  relay_id   UUID        NOT NULL,
  secret     TEXT        NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Keyed like `read_state`, and for the same reason: the question ("what do I
-- want from this") is identical whether the answer is about a server, a channel
-- or a person, so one table answers it for all three and one client path reads
-- it.
--
-- A row exists only where somebody has changed something. The default is the
-- absence of a row, which is what makes joining a server free of writes and
-- makes "reset to default" a DELETE.
CREATE TABLE IF NOT EXISTS notification_prefs (
  user_id    UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope      notify_scope NOT NULL,
  -- Server id for 'server', channel id for 'channel', the other person's user
  -- id for 'dm'.
  scope_id   UUID         NOT NULL,
  level      notify_level NOT NULL,
  updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, scope, scope_id)
);

-- Kept FULL so an UPDATE or DELETE carries the old row if this table is ever
-- added to a publication. Nothing subscribes to it today — preference changes
-- reach clients as a broadcast from 005, not as a replicated row.
ALTER TABLE notification_prefs REPLICA IDENTITY FULL;

-- ============================================================
-- What a bot has been granted
-- ============================================================
-- Bots do not hold channel keys by default. Not because a policy forbids
-- reading, but because a wrapped key *is* read access — arithmetic, not a
-- rule, and unlike a rule it cannot be taken back. Everything a bot
-- legitimately does happens over messages the server can already read.
-- These four tables are the explicit exceptions, each granted by a person.

-- ============================================================
-- Moderation grants
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
--   1. **Bots are excluded from the healing sweep.** That is a refusal on the
--      row rather than a filter in a client: the trigger consults a grant
--      rather than refusing outright, so the only way a bot is ever keyed is
--      somebody deciding it should be.
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

COMMENT ON TABLE bot_channel_keys IS
  'Which bots may hold which channel keys, and from which version (migration '
  '017). Readable by every member on purpose — the channel shows who is '
  'listening, and the people being read are not the people who granted it.';

CREATE INDEX IF NOT EXISTS idx_bot_channel_keys_bot ON bot_channel_keys (bot_id);

-- ============================================================
-- Granting a bot the whole server
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
-- decision, which is what `channels.is_private` exists to make
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

-- ============================================================
-- What a bot may hear in a call
-- ============================================================
-- BOTS.md's rule is "a bot hears what you tell it, not what you say", and
-- until this migration voice was the one place it was simply false.
--
-- `get_channel_token` never asked whether the caller was a bot. `@everyone`
-- carries CONNECT and SPEAK, a bot holds `@everyone` like anybody else, and the
-- token was minted with `canSubscribe` true. So any bot invited to a server
-- could sit in a call and receive every participant's audio, indefinitely, with
-- nothing said in any channel and nothing shown to anyone in the room.
--
-- Nobody built that on purpose. It is what happens when a rule is enforced in
-- the text path and the voice path is written by asking "what does a member
-- need", which is the same shape as the bug this whole document exists to
-- avoid.
--
-- ---------- publishing is not hearing ----------
--
-- The bot people actually ask for first is a music bot, and a music bot only
-- ever *publishes*. It needs no grant, and after this migration it gets none:
-- its token can play audio into the room and receives nothing back.
--
-- That covers the common case outright, which is what makes the strict default
-- affordable. Transcription, an AI that answers out loud, a recorder — those
-- genuinely need to hear, and they need an explicit grant.
--
-- ---------- unlike a key, this one can be taken back ----------
--
-- §6 grants a bot a channel *key*, and the awkward half of that section is that
-- a key is arithmetic: revoking rotates forward and the bot keeps everything it
-- already unwrapped. Nothing can be done about it.
--
-- Voice is not encrypted end to end — media is DTLS-SRTP to the server's own
-- LiveKit, which the operator runs (ARCHITECTURE.md §5). Subscription is
-- therefore a *permission*, not a key, and permissions really do come back:
-- revoking pushes `canSubscribe: false` onto the bot's live connection and the
-- audio stops mid-call. So this grant is honestly reversible in a way §6's is
-- not, and it is worth saying so rather than describing them as the same thing.
--
-- ---------- no server-wide form ----------
--
-- §6 has a bulk grant because thirty channels one at a time produces a button
-- somebody else builds without thinking. That argument does not carry here:
-- there is no MEE6 of voice, listening to a room full of people is a larger
-- decision than reading a text channel, and "every call on this server, plus
-- the ones made later" is not a thing anybody should be able to click once.
-- Per channel is the only form.

-- ============================================================
-- 1. The grant
-- ============================================================

CREATE TABLE IF NOT EXISTS bot_voice_grants (
  channel_id UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id     UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  granted_by UUID        REFERENCES users(id) ON DELETE SET NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, bot_id)
);

COMMENT ON TABLE bot_voice_grants IS
  'Bots whose LiveKit token may subscribe in this voice channel. Absent a row '
  'a bot publishes and hears nothing. Read by get_channel_token when it mints '
  'the grant, and by every client to draw the recording light.';

CREATE INDEX IF NOT EXISTS bot_voice_grants_bot_idx ON bot_voice_grants (bot_id);

-- ============================================================
-- The key a bot speaks with
-- ============================================================
-- Voice is end-to-end encrypted, which is in tension with the thing BOTS.md
-- §6b wants: a bot that publishes into a call but cannot hear it. Encrypting
-- is what makes a bot audible, holding the key is what makes it a listener,
-- and with one key per room those would be the same act — §2's "write but not
-- read is not expressible with a key", arriving in voice.
--
-- ---------- two directions, two keys ----------
--
-- The room runs in LiveKit's per-participant key mode, so participants need not
-- share one key. Members use the channel key. A bot uses
--
--     botKey = HMAC-SHA256(channelKey, 'voicebot:v1:<botId>')
--
-- Every member holds `channelKey`, so every member derives `botKey` and hears
-- the bot. The bot is handed only `botKey`, and HMAC does not run backwards, so
-- it cannot reach `channelKey` and cannot decrypt one member's audio. Two bots
-- in one call cannot decrypt each other either — the bot id is in the context.
--
-- ---------- and the listening grant is a key grant now ----------
--
-- "Let this bot hear" would be a flag on a LiveKit token, and revocable,
-- because a permission is not arithmetic. Encryption changes that: a bot that
-- may hear needs `channelKey` itself, and a key that has been handed over
-- cannot be taken back. So a granted bot is sealed the channel key here,
-- `is_channel_key` records which of the two it holds, and revoking means what
-- it means in §6 — rotate forward, and it keeps what it already heard. Worth
-- saying plainly rather than letting "revocable" stand.

CREATE TABLE IF NOT EXISTS bot_voice_keys (
  channel_id           UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id               UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  key_version          INTEGER     NOT NULL,
  -- false: the derived publish key. true: the channel key itself, which only a
  -- bot with a listening grant may be given.
  is_channel_key       BOOLEAN     NOT NULL DEFAULT false,
  wrapped_by           UUID        REFERENCES users(id) ON DELETE SET NULL,
  ephemeral_public_key TEXT        NOT NULL,
  ciphertext           TEXT        NOT NULL,
  nonce                TEXT        NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, bot_id, key_version)
);

COMMENT ON TABLE bot_voice_keys IS
  'The key a bot encrypts its own media with in one voice channel, sealed to '
  'its chat identity by a member. Derived from the channel key unless the bot '
  'holds a listening grant, in which case it is the channel key.';

CREATE INDEX IF NOT EXISTS bot_voice_keys_bot_idx ON bot_voice_keys (bot_id);

-- ============================================================
-- Summoning a bot into a call
-- ============================================================
-- Asking the music bot to come and play. It is the thing people most want a bot
-- for, and until now it did not work at all in a private voice channel and
-- worked only by accident in a public one.
--
-- Two walls stood in a private channel, both keyed on `channel_members`, which
-- `set_channel_members` refuses to seat a bot into:
--
--   * `channel_visible_to` — no token, so `get_channel_token` answers
--     `CHANNEL_NOT_FOUND`;
--   * `bot_voice_key_candidates` — no member's client seals it a media key, and
--     calls are end-to-end encrypted, so there is nothing for it to speak with.
--
-- A summon is the third door, and it is deliberately the smallest one: it lets
-- a bot into **one voice channel**, to **publish**, until somebody dismisses it.
--
-- ---------- why this can be a default permission ----------
--
-- `SUMMON_BOTS` is on `@everyone`, which sounds alarming for private
-- channels until you see what a summoned bot gets. Its token is minted with
-- `canSubscribe: false` unless an admin separately granted listening, and its
-- media key is `HMAC(channelKey, 'voicebot:v1:<botId>')` — derived *from* the
-- channel key rather than being it, so members can hear the bot and the bot
-- cannot invert the HMAC to hear them. A summon adds a speaker to the room. It
-- does not add a listener, and it cannot be made into one from here.
--
-- It also does not make the bot a member: `app.sees_channel` is untouched, so a
-- summoned bot cannot list the channel, read its roster, read its messages, or
-- post in it. Only `channel_joinable_by` knows about summons, and only
-- `get_channel_token` asks that.
--
-- ---------- and why the candidates view got narrower ----------
--
-- It used to list every bot on the server for every public voice channel, so
-- members' clients sealed a media key for bots that would never join. Now a
-- summon is what puts a bot on the list. That is less work for every client and
-- one less thing sitting in the database for no reason — and it is what makes
-- dismissing meaningful, because dropping the summon drops the key with it.

-- ============================================================
-- 1. The summon
-- ============================================================

CREATE TABLE IF NOT EXISTS bot_voice_summons (
  channel_id  UUID        NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  bot_id      UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
  -- Who asked. A bot in a call that nobody remembers inviting is the thing
  -- this column answers, and it is the same reason `bot_channel_keys` keeps
  -- `granted_by`.
  summoned_by UUID        REFERENCES users(id) ON DELETE SET NULL,
  summoned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (channel_id, bot_id)
);

COMMENT ON TABLE bot_voice_summons IS
  'Bots asked into a voice channel, until dismissed (migration 037). Permission '
  'to publish there and nothing else: it does not make the bot a member, and it '
  'does not let it hear — that is bot_voice_grants and MANAGE_BOTS.';

CREATE INDEX IF NOT EXISTS bot_voice_summons_bot ON bot_voice_summons (bot_id);

-- ============================================================
-- Listing in the public directory
-- ============================================================

-- ============================================================
-- Proving an admin asked for a public listing
-- ============================================================
-- Central cannot tell who administers a server here, so it asks.
--
-- ============================================================

-- ============================================================
-- Proving an admin asked for a listing
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
-- Push enrolment solves a related problem in the other direction and is worth
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

-- ============================================================
-- Soundboard
-- ============================================================
-- Short clips anybody in a call can fire, heard by everyone in it.
--
-- **Nothing about a play goes through this database.** A press is a packet on
-- the call's own data channel, and every listener plays the clip out of its
-- own speakers at its own volume. That is what makes "turn his soundboard
-- down" a real control rather than a request to the person pressing it, and
-- it is why a play costs the server nothing at all — this table is only the
-- library the packet names.
--
-- The bytes are **not encrypted**, the same trade-off avatars and reactions
-- already make: a clip every member plays gains nothing from per-member
-- wrapping. They live in the `soundboard` bucket under this server's id, and
-- are private rather than public-read so the open internet cannot enumerate
-- them.
--
-- Two ceilings, and only one of them is enforceable here:
--
--   * **size** is the bucket's `file_size_limit`, which Storage applies to
--     the upload itself — a modified client cannot get past it.
--   * **duration** is whatever the uploader says it is. Nothing in Postgres
--     can decode an mp3 to check, so `duration_ms` is a *claim*, kept for the
--     list to show and bounded only so it cannot be absurd. What actually
--     stops a twenty-minute clip is the listener: every client cuts playback
--     off at its own ceiling, which is the same shape as the cooldown and
--     works for the same reason — the person hearing it decides.

CREATE TABLE IF NOT EXISTS soundboard_sounds (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  server_id   UUID        NOT NULL REFERENCES servers(id) ON DELETE CASCADE,

  -- Who added it. SET NULL rather than CASCADE, for the same reason a webhook
  -- outlives whoever set it up: the server's soundboard is the server's.
  created_by  UUID        REFERENCES users(id) ON DELETE SET NULL,

  name        TEXT        NOT NULL CHECK (length(name) BETWEEN 1 AND 32),

  -- One grapheme's worth of decoration, so a wall of clips can be read at a
  -- glance. Not validated as an emoji — the check is a length, because
  -- deciding what counts as one is a job for the thing with a font.
  emoji       TEXT        CHECK (emoji IS NULL OR length(emoji) BETWEEN 1 AND 16),

  -- Object name inside the `soundboard` bucket: `<server id>/<random>.audio`.
  object_path TEXT        NOT NULL UNIQUE,

  -- Zero means nobody could measure it. That is a real answer rather than a
  -- failure: a desktop's audio backend will not decode from memory, some
  -- files do not carry a length, and refusing a clip over a *label* would be
  -- the wrong call. The list prints an em dash for it.
  duration_ms INTEGER     NOT NULL CHECK (duration_ms BETWEEN 0 AND 30000),
  bytes       INTEGER     NOT NULL CHECK (bytes > 0),

  -- Two clips called the same thing is a picker nobody can use.
  UNIQUE (server_id, name)
);

CREATE INDEX IF NOT EXISTS soundboard_sounds_server
  ON soundboard_sounds (server_id, created_at);

COMMENT ON TABLE soundboard_sounds IS
  'This server''s soundboard library. A play is a data-channel packet naming '
  'a row here; the database never hears about one.';

-- How many a server may hold. A number rather than a per-server column: the
-- limits in `servers` are the ones an operator pays for in disk and bandwidth,
-- and a soundboard costs neither — what it costs is a picker that stops being
-- usable, which is the same for everybody.
CREATE OR REPLACE FUNCTION app.soundboard_max() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 48 $$;

-- How many avatar objects one member may have on the disk at once.
--
-- Not a limit on changing your picture: a new avatar is written to a fresh
-- random path and the old object is left for whoever is still drawing it from
-- cache, and the sweep in 007 takes every unreferenced one away. This is the
-- ceiling on what can pile up *between* sweeps — the bound that does not
-- depend on a timer having run, because `avatars` is outside the byte cap in
-- 006 (`app.enforce_storage_cap` matches `chat-%`) and its write policy
-- accepts any path under the caller's own id. Without a number here, a
-- modified client uploads 2 MB in a loop for as long as it likes.
--
-- 16 is chosen against the sweep rather than against the feature: nobody
-- changes their picture sixteen times in a day, and the worst a member who is
-- trying to can hold is 32 MB.
CREATE OR REPLACE FUNCTION app.avatars_per_member() RETURNS INTEGER
  LANGUAGE sql IMMUTABLE AS $$ SELECT 16 $$;

-- ============================================================
-- Storage accounting
-- ============================================================
-- The running total the disk cap is checked against. Kept rather than
-- computed: summing the bucket on every upload is a scan of every object the
-- server has ever held, and it gets slower exactly as the thing it protects
-- fills up. Moved by triggers in 006.

-- ============================================================
-- 2. What each bucket is holding
-- ============================================================

CREATE TABLE IF NOT EXISTS app.bucket_usage (
  bucket_id TEXT PRIMARY KEY,
  bytes     BIGINT NOT NULL DEFAULT 0 CHECK (bytes >= 0)
);

COMMENT ON TABLE app.bucket_usage IS
  'Bytes held per chat bucket, kept current by a trigger on storage.objects '
  'so a storage cap costs one indexed read instead of a SUM of the bucket.';

