-- ============================================================
-- Rift self-hosted server — policy tests
-- ============================================================
-- What this is for: the access rules moved out of TypeScript, where they had a
-- test suite around them, and into grants and policies, where they had none.
-- These are that suite. Every case here is something a policy edit could break
-- silently — most of all the ones that assert a *denial*, because a policy that
-- accidentally permits looks exactly like a working app.
--
-- Run against a database with 001–008 applied:
--
--   docker exec -i supabase-db psql -U postgres -v ON_ERROR_STOP=1 \
--     -f - < self_hosted_server_migrations/tests/policies_test.sql
--
-- Everything runs in one transaction that ends in ROLLBACK, so it writes
-- nothing — safe against a live database. A failure raises, which aborts the
-- transaction and makes psql exit non-zero.
--
-- Fixtures are created as the superuser, which bypasses RLS; each test then
-- switches to `authenticated` with a `sub` claim, which is exactly what
-- PostgREST does with a real JWT.

\set ON_ERROR_STOP on
BEGIN;

-- `channel_joinable_by` and `channel_visible_to` are the voice token gate, and
-- in production only an edge function on the service role ever asks them —
-- 008 grants them to nobody else. They take the user to ask about as an
-- argument and are SECURITY DEFINER, so the answer does not depend on who is
-- calling; the blocks below check them in the middle of a member's actions,
-- which needs the privilege and nothing more. Rolled back with everything else.
GRANT EXECUTE ON FUNCTION channel_joinable_by(UUID, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION channel_visible_to(UUID, UUID)  TO authenticated;

-- ── Fixtures ────────────────────────────────────────────────
-- Two servers, so "scoped to my server" is testable rather than assumed.
--   Alpha: alice (admin), bob (plain), carol (inviter, no chat key)
--   Beta:  mallory

INSERT INTO auth.users (id) VALUES
  ('11111111-aaaa-4aaa-8aaa-000000000001'),  -- alice
  ('11111111-aaaa-4aaa-8aaa-000000000002'),  -- bob
  ('11111111-aaaa-4aaa-8aaa-000000000003'),  -- carol
  ('22222222-bbbb-4bbb-8bbb-000000000001');  -- mallory

INSERT INTO servers (id, name, livekit_url) VALUES
  ('aaaa0000-0000-4000-8000-000000000001', 'Alpha', 'ws://lan:7880'),
  ('bbbb0000-0000-4000-8000-000000000001', 'Beta',  'ws://lan:7880');

INSERT INTO server_secrets VALUES
  ('aaaa0000-0000-4000-8000-000000000001', 'key-alpha', 'secret-alpha'),
  ('bbbb0000-0000-4000-8000-000000000001', 'key-beta',  'secret-beta');

INSERT INTO channels (id, server_id, name, channel_type) VALUES
  ('aaaa1111-0000-4000-8000-000000000001', 'aaaa0000-0000-4000-8000-000000000001', 'general', 'text'),
  ('bbbb1111-0000-4000-8000-000000000001', 'bbbb0000-0000-4000-8000-000000000001', 'general', 'text');

INSERT INTO users (id, server_id, username, display_name, public_key, stable_id,
                   chat_public_key, is_server_admin, is_channel_manager, can_create_tokens)
VALUES
  ('11111111-aaaa-4aaa-8aaa-000000000001', 'aaaa0000-0000-4000-8000-000000000001',
   'alice', 'Alice', 'pk-alice', 'sid-alice', 'chat-alice', true,  true,  true),
  ('11111111-aaaa-4aaa-8aaa-000000000002', 'aaaa0000-0000-4000-8000-000000000001',
   'bob', 'Bob', 'pk-bob', 'sid-bob', 'chat-bob', false, false, false),
  -- carol may invite but holds no other permission, and has never published a
  -- chat key — both of which are load-bearing below.
  ('11111111-aaaa-4aaa-8aaa-000000000003', 'aaaa0000-0000-4000-8000-000000000001',
   'carol', 'Carol', 'pk-carol', 'sid-carol', NULL, false, false, true),
  ('22222222-bbbb-4bbb-8bbb-000000000001', 'bbbb0000-0000-4000-8000-000000000001',
   'mallory', 'Mallory', 'pk-mal', 'sid-mal', 'chat-mal', false, false, false);

-- The four default roles arrive with each server (018's `seed_default_roles`).
-- Assigning them from the same three booleans is what `register_user` does, so
-- doing it here keeps the fixture honest: every later test sees a member whose
-- roles and whose cached booleans agree.
INSERT INTO member_roles (user_id, role_id)
SELECT u.id, r.id
  FROM users u
  JOIN roles r ON r.server_id = u.server_id
 -- Scoped to the two fixture servers. Without it this walks every user in the
 -- database the suite is being run against, which was harmless only for as
 -- long as nobody outside the fixtures held a role.
 WHERE u.server_id IN ('aaaa0000-0000-4000-8000-000000000001',
                       'bbbb0000-0000-4000-8000-000000000001')
   AND ((r.name = 'Admin'     AND u.is_server_admin)
     OR (r.name = 'Moderator' AND u.is_channel_manager))
ON CONFLICT DO NOTHING;

-- The booleans above are a cache of the roles (006), written by hand here
-- only so the fixture reads plainly. Recompute them the way the server does,
-- so a bit the baseline carries — inviting, since 016 — reaches everybody the
-- fixture never gave a role to.
SELECT app.sync_permission_cache(id) FROM users
 WHERE server_id IN ('aaaa0000-0000-4000-8000-000000000001',
                     'bbbb0000-0000-4000-8000-000000000001');

-- Put the sequences out of the fixtures' way, permanently.
--
-- The fixtures below name message ids by hand, in the 9000s, so later tests
-- can refer to them. Other tests insert without an id — one of them a whole
-- page over the unread cap — and a sequence is not rolled back with the
-- transaction it was used in. So every run of this suite walked the sequence
-- about a hundred values closer to the hard-coded ids, and after enough runs
-- it arrived: `duplicate key value violates unique constraint
-- "messages_pkey", Key (id)=(9001)`, on a fixture that had not changed in
-- months and a machine where it had always passed before.
--
-- Raising it here rather than lowering the fixtures, because the fixtures
-- are readable and the sequence is not: nothing reads an id out of it.
SELECT setval('messages_id_seq',    GREATEST((SELECT last_value FROM messages_id_seq),    100000));
SELECT setval('dm_messages_id_seq', GREATEST((SELECT last_value FROM dm_messages_id_seq), 100000));

-- `attest_message` stamps `sender_id := auth.uid()` on every insert, so a
-- fixture written as the superuser — who has no claim — came out with no sender
-- at all, and 013's `messages_one_origin` refuses a row that is neither a
-- person nor a webhook. Setting the claim per sender costs three lines and is
-- worth more than disabling the trigger would be: these rows are then written
-- exactly the way the app writes them, attestation included.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version) VALUES
  (9001, 'aaaa1111-0000-4000-8000-000000000001', 'alpha-from-bob', 'n', 's', 1);

INSERT INTO dm_messages (id, recipient_id, ciphertext, nonce, signature, key_version) VALUES
  (8001, '11111111-aaaa-4aaa-8aaa-000000000001', 'dm-bob-to-alice', 'n', 's', 1);

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"22222222-bbbb-4bbb-8bbb-000000000001","role":"authenticated"}', true); END $$;

INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version) VALUES
  (9002, 'bbbb1111-0000-4000-8000-000000000001', 'beta-from-mallory', 'n', 's', 1);

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version) VALUES
  (9003, 'aaaa1111-0000-4000-8000-000000000001', 'alpha-from-alice', 'n', 's', 1);

-- Section 1 is about somebody with no session at all, so the fixtures do not
-- get to leave one lying around.
DO $$ BEGIN PERFORM set_config('request.jwt.claims', '{}', true); END $$;

-- ============================================================
-- 1. The unauthenticated role
-- ============================================================
-- This is the case that was actually broken: `anon` held full DML on tables
-- whose migration forgot to enable RLS, and the anon key is public by design.
-- "Denied" here must mean the grant is gone, not that a policy filtered it —
-- an empty result would also pass a naive check.

SET LOCAL ROLE anon;

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['servers','server_secrets','users','channels','invites',
                           'messages','dm_messages','message_reactions',
                           'dm_message_reactions','channel_keyring','read_state']
  LOOP
    BEGIN
      EXECUTE format('SELECT 1 FROM %I LIMIT 1', t);
      RAISE EXCEPTION 'FAIL: anon can SELECT %', t;
    EXCEPTION WHEN insufficient_privilege THEN NULL;
    END;
  END LOOP;
  RAISE NOTICE 'ok  anon cannot read any table';
END $$;

DO $$
BEGIN
  BEGIN
    DELETE FROM messages WHERE id = 9001;
    RAISE EXCEPTION 'FAIL: anon can DELETE messages';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE dm_messages SET ciphertext = 'x' WHERE id = 8001;
    RAISE EXCEPTION 'FAIL: anon can UPDATE dm_messages';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  anon cannot write messages or DMs';
END $$;

RESET ROLE;

-- ============================================================
-- 2. Server scoping
-- ============================================================

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF (SELECT count(*) FROM users) <> 3 THEN
    RAISE EXCEPTION 'FAIL: alice should see exactly her 3 co-members, saw %',
      (SELECT count(*) FROM users);
  END IF;
  IF (SELECT count(*) FROM servers) <> 1 THEN
    RAISE EXCEPTION 'FAIL: alice should see exactly her own server';
  END IF;
  IF (SELECT count(*) FROM channels) <> 1 THEN
    RAISE EXCEPTION 'FAIL: alice should see exactly her own channels';
  END IF;
  IF EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'beta-from-mallory') THEN
    RAISE EXCEPTION 'FAIL: alice can read another server''s messages';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'alpha-from-bob') THEN
    RAISE EXCEPTION 'FAIL: alice cannot read her own server''s messages';
  END IF;
  RAISE NOTICE 'ok  members see their own server and nothing else';
END $$;

DO $$
BEGIN
  BEGIN
    PERFORM 1 FROM server_secrets LIMIT 1;
    RAISE EXCEPTION 'FAIL: a member can read server_secrets';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  LiveKit credentials are unreachable by members';
END $$;

-- ============================================================
-- 3. Message writes and attestation
-- ============================================================

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_id BIGINT; v_sender UUID; v_at TIMESTAMPTZ;
BEGIN
  -- Bob claims to be Alice, and backdates. The trigger overrules both.
  INSERT INTO messages (channel_id, sender_id, created_at, ciphertext, nonce, signature, key_version)
  VALUES ('aaaa1111-0000-4000-8000-000000000001',
          '11111111-aaaa-4aaa-8aaa-000000000001', '2020-01-01T00:00:00Z',
          'forged', 'n', 's', 1)
  RETURNING id, sender_id, created_at INTO v_id, v_sender, v_at;

  IF v_sender <> '11111111-aaaa-4aaa-8aaa-000000000002' THEN
    RAISE EXCEPTION 'FAIL: sender_id was not overwritten with the caller';
  END IF;
  IF v_at < now() - interval '1 minute' THEN
    RAISE EXCEPTION 'FAIL: created_at was accepted from the client';
  END IF;
  RAISE NOTICE 'ok  the server attests sender and timestamp';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"22222222-bbbb-4bbb-8bbb-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  BEGIN
    INSERT INTO messages (channel_id, ciphertext, nonce, signature, key_version)
    VALUES ('aaaa1111-0000-4000-8000-000000000001', 'intruder', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a non-member can post into another server''s channel';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  posting is limited to your own server''s channels';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  -- Editing someone else's message matches no row rather than erroring; the
  -- distinction matters because the client reports "not found, or not yours"
  -- off an empty result.
  UPDATE messages SET ciphertext = 'hijacked' WHERE id = 9003;  -- alice's
  IF EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'hijacked') THEN
    RAISE EXCEPTION 'FAIL: a member edited a message that is not theirs';
  END IF;

  -- An edit may only touch the envelope. Moving a message to another channel
  -- is a column the grant does not cover.
  BEGIN
    UPDATE messages SET channel_id = 'bbbb1111-0000-4000-8000-000000000001' WHERE id = 9001;  -- his own
    RAISE EXCEPTION 'FAIL: a member can move a message between channels';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  edits are limited to the envelope, on your own messages';
END $$;

DO $$
DECLARE v_alice_msg BIGINT;
BEGIN
  SELECT id INTO v_alice_msg FROM messages WHERE ciphertext = 'forged';
  -- Bob owns 'forged' (his spoof was rewritten to him), so deleting it works.
  DELETE FROM messages WHERE id = v_alice_msg;
  IF EXISTS (SELECT 1 FROM messages WHERE id = v_alice_msg) THEN
    RAISE EXCEPTION 'FAIL: a member cannot delete their own message';
  END IF;
  RAISE NOTICE 'ok  a member can delete their own message';
END $$;

DO $$
BEGIN
  -- Bob is not a manager, so alice's message survives.
  DELETE FROM messages WHERE id = 9003;
  IF NOT EXISTS (SELECT 1 FROM messages WHERE id = 9003) THEN
    RAISE EXCEPTION 'FAIL: a plain member deleted someone else''s message';
  END IF;
  RAISE NOTICE 'ok  a plain member cannot delete other people''s messages';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  DELETE FROM messages WHERE id = 9003;  -- alice is an admin; bob could not
  IF EXISTS (SELECT 1 FROM messages WHERE id = 9003) THEN
    RAISE EXCEPTION 'FAIL: a moderator cannot delete a message';
  END IF;
  RAISE NOTICE 'ok  a moderator can delete anyone''s message';
END $$;

-- ============================================================
-- 4. Profile columns
-- ============================================================

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  UPDATE users SET display_name = 'Bobby' WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002';
  IF (SELECT display_name FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002') <> 'Bobby' THEN
    RAISE EXCEPTION 'FAIL: a member cannot rename themselves';
  END IF;

  -- The whole reason the split is a column grant and not a policy.
  BEGIN
    UPDATE users SET is_server_admin = true WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002';
    RAISE EXCEPTION 'FAIL: a member can promote themselves to admin';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    UPDATE users SET is_banned = false WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002';
    RAISE EXCEPTION 'FAIL: a member can clear their own ban';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- The signing key is write-once, and that is load-bearing rather than
  -- incidental. Every message carries a signature but not the key that made
  -- it: readers verify against whatever `users.public_key` says *now*. So the
  -- moment this column becomes writable, changing it silently invalidates
  -- every message its owner has ever sent — and a failed signature is dropped
  -- without being rendered, so the history would simply disappear with no
  -- error anywhere. `chat_public_key` next door is deliberately writable,
  -- which is exactly why this needs saying out loud.
  BEGIN
    UPDATE users SET public_key = 'AAAA' WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002';
    RAISE EXCEPTION 'FAIL: a member can replace their own signing key';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  UPDATE users SET display_name = 'Pwned' WHERE id = '11111111-aaaa-4aaa-8aaa-000000000001';
  IF (SELECT display_name FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-000000000001') = 'Pwned' THEN
    RAISE EXCEPTION 'FAIL: a member renamed someone else';
  END IF;
  RAISE NOTICE 'ok  a member owns their profile fields and nothing else';
END $$;

-- ============================================================
-- 5. Direct messages
-- ============================================================

DO $$
BEGIN
  INSERT INTO dm_messages (recipient_id, ciphertext, nonce, signature, key_version)
  VALUES ('11111111-aaaa-4aaa-8aaa-000000000001', 'hello-alice', 'n', 's', 1);

  -- Across servers: not a co-member.
  BEGIN
    INSERT INTO dm_messages (recipient_id, ciphertext, nonce, signature, key_version)
    VALUES ('22222222-bbbb-4bbb-8bbb-000000000001', 'hello-mallory', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a member can DM someone on another server';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  -- Carol has published no chat key, so a message to her could never be opened.
  BEGIN
    INSERT INTO dm_messages (recipient_id, ciphertext, nonce, signature, key_version)
    VALUES ('11111111-aaaa-4aaa-8aaa-000000000003', 'hello-carol', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a DM was accepted for a member with no chat key';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  DMs require a co-member who can actually decrypt';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000003","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM dm_messages) THEN
    RAISE EXCEPTION 'FAIL: a third member can read a conversation they are not in';
  END IF;
  RAISE NOTICE 'ok  a conversation is visible only to its two participants';
END $$;

-- ============================================================
-- 6. Invites
-- ============================================================

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

-- Since 016 the baseline carries CREATE_INVITE: a plain member may bring a
-- friend. The permission is still a permission — take the bit off @everyone
-- and this insert is refused — but the default is open.
DO $$
BEGIN
  INSERT INTO invites (server_id, created_by)
  VALUES ('aaaa0000-0000-4000-8000-000000000001', '11111111-aaaa-4aaa-8aaa-000000000002');
  DELETE FROM invites WHERE created_by = '11111111-aaaa-4aaa-8aaa-000000000002';
  RAISE NOTICE 'ok  a plain member may invite, by default';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000003","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_code TEXT;
BEGIN
  INSERT INTO invites (server_id, created_by)
  VALUES ('aaaa0000-0000-4000-8000-000000000001', '11111111-aaaa-4aaa-8aaa-000000000003')
  RETURNING code INTO v_code;
  IF v_code IS NULL OR length(v_code) <> 10 THEN
    RAISE EXCEPTION 'FAIL: the invite code default did not produce a 10-char code (got %)', v_code;
  END IF;

  -- Carol may invite. She may not invite somebody straight into Admin, which
  -- since 025 is one rule instead of three: an invite may only name a role its
  -- maker could have handed out by hand.
  BEGIN
    INSERT INTO invites (server_id, created_by, role_id)
    VALUES ('aaaa0000-0000-4000-8000-000000000001',
            '11111111-aaaa-4aaa-8aaa-000000000003',
            (SELECT id FROM roles
              WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001'
                AND name = 'Admin'));
    RAISE EXCEPTION 'FAIL: an inviter granted a role they do not hold';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  invites generate a code and cannot grant what you lack';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  -- A code is a bearer token; members must not be able to read each other's.
  IF EXISTS (SELECT 1 FROM invites) THEN
    RAISE EXCEPTION 'FAIL: a member can read invite codes they did not create';
  END IF;
  RAISE NOTICE 'ok  invite codes are visible only to whoever minted them';
END $$;

-- ============================================================
-- 7. Channel keyring
-- ============================================================

DO $$
BEGIN
  -- Wrapping *for* someone else is the normal case; claiming someone else did
  -- the wrapping is not.
  BEGIN
    INSERT INTO channel_keyring (channel_id, key_version, user_id, wrapped_by,
                                 ephemeral_public_key, ciphertext, nonce)
    VALUES ('aaaa1111-0000-4000-8000-000000000001', 1,
            '11111111-aaaa-4aaa-8aaa-000000000001',
            '11111111-aaaa-4aaa-8aaa-000000000001', 'eph', 'ct', 'n');
    RAISE EXCEPTION 'FAIL: a member forged wrapped_by';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  INSERT INTO channel_keyring (channel_id, key_version, user_id, wrapped_by,
                               ephemeral_public_key, ciphertext, nonce)
  VALUES ('aaaa1111-0000-4000-8000-000000000001', 1,
          '11111111-aaaa-4aaa-8aaa-000000000001',
          '11111111-aaaa-4aaa-8aaa-000000000002', 'eph', 'ct', 'n');
  RAISE NOTICE 'ok  keyring entries record who really wrapped them';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"22222222-bbbb-4bbb-8bbb-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM channel_keyring) THEN
    RAISE EXCEPTION 'FAIL: a non-member can read another server''s keyring';
  END IF;
  RAISE NOTICE 'ok  the keyring is scoped to the server it belongs to';
END $$;

-- ============================================================
-- 8. Read state and unread counts
-- ============================================================

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_n INT; v_cursor BIGINT;
BEGIN
  -- Alice has bob's 'alpha-from-bob' unread (9001 was deleted above, so use
  -- whatever bob has posted since).
  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  VALUES (auth.uid(), 'channel', 'aaaa1111-0000-4000-8000-000000000001', 0)
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE SET last_read_id = 0;

  RESET ROLE;  -- superuser: add a message from bob to count
  INSERT INTO messages (channel_id, sender_id, ciphertext, nonce, signature, key_version)
  VALUES ('aaaa1111-0000-4000-8000-000000000001', '11111111-aaaa-4aaa-8aaa-000000000002',
          'unread-1', 'n', 's', 1);
  INSERT INTO messages (channel_id, sender_id, ciphertext, nonce, signature, key_version)
  VALUES ('aaaa1111-0000-4000-8000-000000000001', '11111111-aaaa-4aaa-8aaa-000000000001',
          'mine-does-not-count', 'n', 's', 1);
  EXECUTE 'SET LOCAL ROLE authenticated';

  v_n := (unread_counts()->'channels'->>'aaaa1111-0000-4000-8000-000000000001')::INT;
  IF v_n <> 1 THEN
    RAISE EXCEPTION 'FAIL: expected 1 unread (own messages excluded), got %', v_n;
  END IF;

  v_cursor := mark_read('channel', 'aaaa1111-0000-4000-8000-000000000001');
  IF (unread_counts()->'channels') ? 'aaaa1111-0000-4000-8000-000000000001' THEN
    RAISE EXCEPTION 'FAIL: the channel is still unread after mark_read';
  END IF;

  -- A stale device must not be able to rewind what another device read.
  IF mark_read('channel', 'aaaa1111-0000-4000-8000-000000000001', 1) <> v_cursor THEN
    RAISE EXCEPTION 'FAIL: mark_read moved a cursor backwards';
  END IF;
  RAISE NOTICE 'ok  unread counts exclude your own, and cursors only move forward';
END $$;

DO $$
BEGIN
  -- Cursors are private: they are also what stops this being a read receipt.
  IF EXISTS (SELECT 1 FROM read_state WHERE user_id <> auth.uid()) THEN
    RAISE EXCEPTION 'FAIL: a member can read someone else''s read cursors';
  END IF;
  BEGIN
    INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
    VALUES ('11111111-aaaa-4aaa-8aaa-000000000002', 'dm', auth.uid(), 99);
    RAISE EXCEPTION 'FAIL: a member can write someone else''s read cursor';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  read cursors are private to their owner';
END $$;

-- ---------- 020: a badge that stops counting ----------
-- The count is capped because the badge is: "99+" is what a member sees above
-- ninety-nine either way, and an uncapped count is a walk of every message in
-- a channel nobody has opened — eleven seconds of it at two hundred thousand.

DO $$
DECLARE v_n INT; v_cap INT := unread_cap();
BEGIN
  RESET ROLE;
  INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
  VALUES ('11111111-aaaa-4aaa-8aaa-000000000001', 'channel',
          'aaaa1111-0000-4000-8000-000000000001', 0)
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE SET last_read_id = 0;

  -- `attest_message` stamps the sender from the JWT whenever there is one, so
  -- writing "from bob" while claiming to be alice quietly produces alice's own
  -- messages — which an unread count is right to ignore. No claim, no stamp.
  PERFORM set_config('request.jwt.claims', '', true);
  INSERT INTO messages (channel_id, sender_id, ciphertext, nonce, signature, key_version)
  SELECT 'aaaa1111-0000-4000-8000-000000000001',
         '11111111-aaaa-4aaa-8aaa-000000000002', 'over-the-cap', 'n', 's', 1
    FROM generate_series(1, v_cap + 5);
  PERFORM set_config('request.jwt.claims',
    '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true);
  EXECUTE 'SET LOCAL ROLE authenticated';

  v_n := (unread_counts()->'channels'->>'aaaa1111-0000-4000-8000-000000000001')::INT;
  IF v_n <> v_cap THEN
    RAISE EXCEPTION 'FAIL: expected the count to stop at %, got %', v_cap, v_n;
  END IF;
  RAISE NOTICE 'ok  an unread count stops at the cap instead of at the table';
END $$;

-- ---------- 020: the levels come back with the counts ----------
-- 009 dropped the `prefs` key while rewriting this function, and nothing
-- failed: the client read null and fell back to the defaults, so a muted
-- channel un-muted itself on the next re-seed, on every device.

DO $$
DECLARE v_prefs JSONB;
BEGIN
  INSERT INTO notification_prefs (user_id, scope, scope_id, level)
  VALUES (auth.uid(), 'channel', 'aaaa1111-0000-4000-8000-000000000001', 'none')
  ON CONFLICT (user_id, scope, scope_id) DO UPDATE SET level = 'none';

  v_prefs := unread_counts()->'prefs';
  IF v_prefs IS NULL THEN
    RAISE EXCEPTION 'FAIL: unread_counts() answered without any prefs at all';
  END IF;
  IF v_prefs->'channels'->>'aaaa1111-0000-4000-8000-000000000001' <> 'none' THEN
    RAISE EXCEPTION 'FAIL: a channel muted on one device is not read back, got %',
      v_prefs->'channels';
  END IF;
  RAISE NOTICE 'ok  a notification level set here comes back with the badges';
END $$;

-- ---------- 020: no push, no roster walk ----------
-- The whole point of the reorder. `has_unread_before` is swapped for one that
-- raises: nothing but the two doorbells calls it, so reaching it at all means
-- the roster was priced for a push nobody asked for. The savepoint puts the
-- real one back whatever happens.

DO $$
DECLARE v_server UUID := 'aaaa0000-0000-4000-8000-000000000001';
BEGIN
  RESET ROLE;
  IF app.push_enabled(v_server) THEN
    RAISE EXCEPTION 'FAIL: the test server has push configured; this proves nothing';
  END IF;
END $$;

SAVEPOINT before_tripwire;

CREATE OR REPLACE FUNCTION has_unread_before(
  p_user_id UUID, p_scope read_scope, p_scope_id UUID, p_before BIGINT
) RETURNS BOOLEAN LANGUAGE plpgsql STABLE SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  RAISE EXCEPTION 'tripwire: the roster was walked with push turned off';
END $$;

DO $$
DECLARE v_ctx TEXT;
BEGIN
  INSERT INTO messages (channel_id, sender_id, ciphertext, nonce, signature, key_version)
  VALUES ('aaaa1111-0000-4000-8000-000000000001',
          '11111111-aaaa-4aaa-8aaa-000000000002', 'no-push-here', 'n', 's', 1);
  RAISE NOTICE 'ok  a message on a server without push never prices the doorbell';
EXCEPTION WHEN raise_exception THEN
  IF SQLERRM LIKE 'tripwire:%' THEN
    GET STACKED DIAGNOSTICS v_ctx = PG_EXCEPTION_CONTEXT;
    RAISE EXCEPTION 'FAIL: % / %', SQLERRM, v_ctx;
  END IF;
  RAISE;
END $$;

ROLLBACK TO SAVEPOINT before_tripwire;

DO $$ BEGIN
  IF has_unread_before('11111111-aaaa-4aaa-8aaa-000000000001', 'channel',
                       'aaaa1111-0000-4000-8000-000000000001', 1) IS NULL THEN
    RAISE EXCEPTION 'FAIL: the real has_unread_before did not come back';
  END IF;
  EXECUTE 'SET LOCAL ROLE authenticated';
END $$;

-- ============================================================
-- 9. Moderation and permission RPCs
-- ============================================================

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  BEGIN
    PERFORM moderate_user('11111111-aaaa-4aaa-8aaa-000000000003', true, NULL, NULL);
    RAISE EXCEPTION 'FAIL: a non-admin can moderate';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'not_authorized' THEN RAISE; END IF;
  END;
  -- 025 removed `set_user_permissions`; handing out a role is the only way to
  -- grant anything now, and it refuses on the row rather than in a function.
  BEGIN
    INSERT INTO member_roles (user_id, role_id)
    SELECT '11111111-aaaa-4aaa-8aaa-000000000003', id FROM roles
     WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND name = 'Admin';
    RAISE EXCEPTION 'FAIL: a non-admin can grant permissions';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM register_user('x', auth.uid(), 'a', 'b', 'c', 'd');
    RAISE EXCEPTION 'FAIL: a member can call register_user';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  privileged RPCs refuse ordinary members';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  PERFORM moderate_user('11111111-aaaa-4aaa-8aaa-000000000002', true, NULL, NULL);
  IF NOT (SELECT is_muted FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002') THEN
    RAISE EXCEPTION 'FAIL: an admin''s mute did not take';
  END IF;

  BEGIN
    PERFORM moderate_user('22222222-bbbb-4bbb-8bbb-000000000001', NULL, NULL, true);
    RAISE EXCEPTION 'FAIL: an admin moderated someone on another server';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'user_not_found' THEN RAISE; END IF;
  END;

  BEGIN
    PERFORM moderate_user(auth.uid(), NULL, NULL, true);
    RAISE EXCEPTION 'FAIL: an admin banned themselves';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'cannot_moderate_self' THEN RAISE; END IF;
  END;

  -- The last-admin lockout used to be a named refusal inside
  -- `set_user_permissions`. It is the position rule now, and it is stronger:
  -- nobody edits or hands out the role they are standing on, so an admin
  -- cannot take their own away by any route.
  BEGIN
    DELETE FROM member_roles
     WHERE user_id = auth.uid()
       AND role_id IN (SELECT id FROM roles
                        WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001'
                          AND name = 'Admin');
    IF NOT EXISTS (SELECT 1 FROM member_roles mr JOIN roles r ON r.id = mr.role_id
                    WHERE mr.user_id = auth.uid() AND r.name = 'Admin') THEN
      RAISE EXCEPTION 'FAIL: an admin demoted themselves (last-admin lockout)';
    END IF;
  END;
  RAISE NOTICE 'ok  moderation is admin-only, same-server, and never self-inflicted';
END $$;

-- ============================================================
-- 10. Ban takes effect immediately
-- ============================================================
-- The JWT stays valid until it expires, so revocation has to come from the
-- policies. Every `app.*` helper re-checks the ban for this reason.

RESET ROLE;
UPDATE users SET is_banned = true WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002';
SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM messages) THEN
    RAISE EXCEPTION 'FAIL: a banned member can still read messages';
  END IF;
  -- Their own row, and only their own. `users_select_self` exists so that a
  -- ban can be *told* to the person it happened to: every other policy routes
  -- through app.server_id(), which is null once banned, so without this the
  -- client reads nothing at all and cannot tell being closed out from being
  -- broken. It must stay this narrow — one row, theirs.
  IF (SELECT count(*) FROM users) <> 1 THEN
    RAISE EXCEPTION 'FAIL: a banned member sees % user rows, expected only their own',
      (SELECT count(*) FROM users);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM users
                  WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002'
                    AND is_banned) THEN
    RAISE EXCEPTION 'FAIL: the one row a banned member reads is not their own ban';
  END IF;
  BEGIN
    INSERT INTO messages (channel_id, ciphertext, nonce, signature, key_version)
    VALUES ('aaaa1111-0000-4000-8000-000000000001', 'after-ban', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a banned member can still post';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  a ban applies from the next statement, not the next token';
END $$;

-- 022: and the one call the client makes says so, rather than saying the
-- server is gone. `app.server_id()` is null once banned, so the `servers` row
-- is invisible too — read as "not found" the client would drop the rail chip
-- and the member would have no way to see they were banned at all.
DO $$
DECLARE v JSONB;
BEGIN
  v := get_server_details();
  IF v IS NULL THEN
    RAISE EXCEPTION 'FAIL: a banned member reads their server as gone';
  END IF;
  IF (v->'user'->>'is_banned')::BOOLEAN IS NOT TRUE THEN
    RAISE EXCEPTION 'FAIL: the answer does not carry the ban: %', v;
  END IF;
  IF v->'channels' <> '[]'::jsonb THEN
    RAISE EXCEPTION 'FAIL: a banned member is still handed channels: %', v->'channels';
  END IF;
  -- What the client tests to tell this reply from a whole one. Sending the
  -- limits here would reset an operator's caps to the defaults.
  IF v ? 'max_attachment_bytes' THEN
    RAISE EXCEPTION 'FAIL: the banned reply carries limits it cannot have read';
  END IF;
  RAISE NOTICE 'ok  and the one call says "banned", not "no such server"';
END $$;
-- ============================================================
-- 11. Operator limits
-- ============================================================
-- Migration 007. Every limit defaults to 0 = off, so the cases that matter are
-- the ones that turn one on: a sweep that never runs proves nothing, and a
-- sweep that silently fails to apply looks exactly like a working app.
--
-- Fresh fixtures rather than the shared ones: earlier sections have been posting
-- as alice and bob all file, so their row counts are whatever those tests
-- happened to leave. A cap test that starts from an unknown number is a cap test
-- that passes for the wrong reason.

RESET ROLE;
UPDATE users SET is_banned = false WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002';

-- Alpha keeps 30 days and at most 2 messages. Beta sets nothing, so "the limit
-- is this server's, not the schema's" stays testable.
UPDATE servers SET message_retention_days = 30, message_history_cap = 2
 WHERE id = 'aaaa0000-0000-4000-8000-000000000001';

--   #inherits   — takes both of Alpha's numbers
--   #strict     — its own cap of 1 and its own 7-day age
--   #forever    — 0 for both: opts out of a server-wide sweep entirely
INSERT INTO channels (id, server_id, name, channel_type, retention_days, history_cap) VALUES
  ('aaaa1111-0000-4000-8000-000000000002', 'aaaa0000-0000-4000-8000-000000000001',
   'inherits', 'text', NULL, NULL),
  ('aaaa1111-0000-4000-8000-000000000003', 'aaaa0000-0000-4000-8000-000000000001',
   'strict', 'text', 7, 1),
  ('aaaa1111-0000-4000-8000-000000000004', 'aaaa0000-0000-4000-8000-000000000001',
   'forever', 'text', 0, 0);

-- Four messages in each, so a cap of 2 and a cap of 1 are both visible.
INSERT INTO messages (channel_id, sender_id, ciphertext, nonce, signature, key_version)
SELECT c.id, '11111111-aaaa-4aaa-8aaa-000000000002', 'm' || g, 'n', 's', 1
  FROM (VALUES ('aaaa1111-0000-4000-8000-000000000002'::UUID),
               ('aaaa1111-0000-4000-8000-000000000003'::UUID),
               ('aaaa1111-0000-4000-8000-000000000004'::UUID)) AS c(id),
       generate_series(1, 4) AS g;

DO $$
DECLARE n INT;
BEGIN
  PERFORM app.enforce_retention();

  SELECT count(*) INTO n FROM messages
   WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000002';
  IF n <> 2 THEN
    RAISE EXCEPTION 'FAIL: a NULL cap should inherit the server''s 2, left %', n;
  END IF;

  SELECT count(*) INTO n FROM messages
   WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000003';
  IF n <> 1 THEN
    RAISE EXCEPTION 'FAIL: a channel cap of 1 left % rows', n;
  END IF;

  SELECT count(*) INTO n FROM messages
   WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000004';
  IF n <> 4 THEN
    RAISE EXCEPTION 'FAIL: a channel cap of 0 should opt out, left %', n;
  END IF;

  RAISE NOTICE 'ok  a channel cap overrides, inherits on NULL, opts out on 0';
END $$;

-- Age, and the same three-way override. Back-dating needs auth.uid() gone:
-- attest_message() re-pins created_at on every UPDATE.
DO $$ BEGIN PERFORM set_config('request.jwt.claims', '', true); END $$;
UPDATE messages SET created_at = now() - interval '10 days'
 WHERE channel_id IN ('aaaa1111-0000-4000-8000-000000000003',
                      'aaaa1111-0000-4000-8000-000000000004');

DO $$
DECLARE n INT;
BEGIN
  PERFORM app.enforce_retention();

  -- #strict keeps 7 days, so a 10-day-old message goes even though Alpha's
  -- own window of 30 days would have kept it.
  SELECT count(*) INTO n FROM messages
   WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000003';
  IF n <> 0 THEN
    RAISE EXCEPTION 'FAIL: a channel window of 7 days left % rows at 10 days', n;
  END IF;

  -- #forever set 0, which means keep — even past the server's 30 days.
  SELECT count(*) INTO n FROM messages
   WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000004';
  IF n <> 4 THEN
    RAISE EXCEPTION 'FAIL: a channel window of 0 should keep everything, left %', n;
  END IF;

  -- Beta configured nothing, so a sweep that ran for Alpha must not touch it.
  IF NOT EXISTS (SELECT 1 FROM messages WHERE id = 9002) THEN
    RAISE EXCEPTION 'FAIL: retention crossed into a server that set none';
  END IF;

  RAISE NOTICE 'ok  a channel window overrides the server''s, per server';
END $$;

-- DMs have no per-channel equivalent, so they take the server's cap. It counts
-- both people together — a conversation is one bucket seen from either side.
INSERT INTO dm_messages (sender_id, recipient_id, ciphertext, nonce, signature, key_version)
VALUES
  ('11111111-aaaa-4aaa-8aaa-000000000002', '11111111-aaaa-4aaa-8aaa-000000000001', 'd1', 'n', 's', 1),
  ('11111111-aaaa-4aaa-8aaa-000000000001', '11111111-aaaa-4aaa-8aaa-000000000002', 'd2', 'n', 's', 1),
  ('11111111-aaaa-4aaa-8aaa-000000000002', '11111111-aaaa-4aaa-8aaa-000000000001', 'd3', 'n', 's', 1);

DO $$
DECLARE n INT;
BEGIN
  PERFORM app.enforce_retention();
  SELECT count(*) INTO n FROM dm_messages
   WHERE LEAST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000001'
     AND GREATEST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000002';
  IF n <> 2 THEN
    RAISE EXCEPTION 'FAIL: a DM cap of 2 across both directions left % rows', n;
  END IF;
  RAISE NOTICE 'ok  the DM cap counts a conversation, not a sender';
END $$;

-- ── DMs get the channels' override ──────────────────────────
-- Migration 009. Same three-valued rule as a channel's columns, on `servers`
-- because a DM has no single row to hang a setting off — and because a
-- conversation belongs to two people, neither of whom should be deciding how
-- long the other's messages survive.

DO $$
DECLARE n INT;
BEGIN
  -- Alpha's server-wide cap is 2 and the pair currently sits at it. A DM cap of
  -- 1 has to win.
  UPDATE servers SET dm_history_cap = 1
   WHERE id = 'aaaa0000-0000-4000-8000-000000000001';
  PERFORM app.enforce_retention();

  SELECT count(*) INTO n FROM dm_messages
   WHERE LEAST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000001'
     AND GREATEST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000002';
  IF n <> 1 THEN
    RAISE EXCEPTION 'FAIL: a DM cap of 1 should beat the server''s 2, left %', n;
  END IF;

  -- And the channels must not have moved: overriding DMs overrides only DMs.
  SELECT count(*) INTO n FROM messages
   WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000002';
  IF n <> 2 THEN
    RAISE EXCEPTION 'FAIL: a DM override changed a channel, left % rows', n;
  END IF;

  RAISE NOTICE 'ok  a DM cap overrides the server''s, and only for DMs';
END $$;

DO $$
DECLARE n INT;
BEGIN
  -- 0 is the whole point of the feature: trim the channels, keep the DMs.
  UPDATE servers SET dm_history_cap = 0
   WHERE id = 'aaaa0000-0000-4000-8000-000000000001';
  INSERT INTO dm_messages (sender_id, recipient_id, ciphertext, nonce, signature, key_version)
  SELECT '11111111-aaaa-4aaa-8aaa-000000000002', '11111111-aaaa-4aaa-8aaa-000000000001',
         'k' || g, 'n', 's', 1
    FROM generate_series(1, 3) AS g;
  PERFORM app.enforce_retention();

  SELECT count(*) INTO n FROM dm_messages
   WHERE LEAST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000001'
     AND GREATEST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000002';
  IF n <> 4 THEN
    RAISE EXCEPTION 'FAIL: a DM cap of 0 should opt out of the server''s 2, left %', n;
  END IF;
  RAISE NOTICE 'ok  a DM cap of 0 opts out of a server-wide cap';
END $$;

-- Age, and the same three-way override. Back-dating needs auth.uid() gone.
DO $$ BEGIN PERFORM set_config('request.jwt.claims', '', true); END $$;
UPDATE dm_messages SET created_at = now() - interval '10 days'
 WHERE LEAST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000001'
   AND GREATEST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000002';

DO $$
DECLARE n INT;
BEGIN
  -- Alpha's window is 30 days, so at 10 days these survive on the server's
  -- number. A DM window of 7 has to take them.
  UPDATE servers SET dm_retention_days = 7
   WHERE id = 'aaaa0000-0000-4000-8000-000000000001';
  PERFORM app.enforce_retention();

  SELECT count(*) INTO n FROM dm_messages
   WHERE LEAST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000001'
     AND GREATEST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000002';
  IF n <> 0 THEN
    RAISE EXCEPTION 'FAIL: a DM window of 7 days left % rows at 10 days', n;
  END IF;
  RAISE NOTICE 'ok  a DM window overrides the server''s';
END $$;

DO $$
DECLARE n INT;
BEGIN
  -- The mirror image, and the case an operator actually asks for: sweep the
  -- channels by age, exempt the DMs.
  UPDATE servers SET message_retention_days = 5, dm_retention_days = 0
   WHERE id = 'aaaa0000-0000-4000-8000-000000000001';

  INSERT INTO dm_messages (created_at, sender_id, recipient_id, ciphertext, nonce, signature, key_version)
  VALUES (now() - interval '10 days',
          '11111111-aaaa-4aaa-8aaa-000000000002', '11111111-aaaa-4aaa-8aaa-000000000001',
          'exempt', 'n', 's', 1);
  INSERT INTO messages (created_at, channel_id, sender_id, ciphertext, nonce, signature, key_version)
  VALUES (now() - interval '10 days', 'aaaa1111-0000-4000-8000-000000000002',
          '11111111-aaaa-4aaa-8aaa-000000000002', 'swept', 'n', 's', 1);

  PERFORM app.enforce_retention();

  SELECT count(*) INTO n FROM dm_messages WHERE ciphertext = 'exempt';
  IF n <> 1 THEN
    RAISE EXCEPTION 'FAIL: a DM window of 0 should exempt DMs from the server''s 5 days';
  END IF;

  SELECT count(*) INTO n FROM messages WHERE ciphertext = 'swept';
  IF n <> 0 THEN
    RAISE EXCEPTION 'FAIL: exempting DMs also exempted the channels';
  END IF;

  RAISE NOTICE 'ok  DMs opt out by age while the channels are still swept';
END $$;

-- Beta needs a second member before it can have a conversation of its own to
-- protect: the shared fixtures give it only mallory, and `sender_id <>
-- recipient_id` rules out talking to yourself.
INSERT INTO auth.users (id) VALUES ('22222222-bbbb-4bbb-8bbb-000000000002');
INSERT INTO users (id, server_id, username, display_name, public_key, stable_id, chat_public_key)
VALUES ('22222222-bbbb-4bbb-8bbb-000000000002', 'bbbb0000-0000-4000-8000-000000000001',
        'niles', 'Niles', 'pk-niles', 'sid-niles', 'chat-niles');
INSERT INTO dm_messages (created_at, sender_id, recipient_id, ciphertext, nonce, signature, key_version)
VALUES (now() - interval '10 days',
        '22222222-bbbb-4bbb-8bbb-000000000001', '22222222-bbbb-4bbb-8bbb-000000000002',
        'beta-dm', 'n', 's', 1);

DO $$
BEGIN
  PERFORM app.enforce_retention();

  -- Beta set none of this, and a column written on Alpha must stay on Alpha.
  IF EXISTS (SELECT 1 FROM servers
              WHERE id = 'bbbb0000-0000-4000-8000-000000000001'
                AND (dm_retention_days IS NOT NULL OR dm_history_cap IS NOT NULL)) THEN
    RAISE EXCEPTION 'FAIL: a DM override leaked onto another server';
  END IF;

  -- Ten days old, which Alpha's 5-day window would have taken. Beta configured
  -- nothing, so the same run must leave it standing.
  IF NOT EXISTS (SELECT 1 FROM dm_messages WHERE ciphertext = 'beta-dm') THEN
    RAISE EXCEPTION 'FAIL: a DM sweep crossed into a server that set none';
  END IF;

  RAISE NOTICE 'ok  a DM override belongs to one server';
END $$;

-- Back to inheriting, so the sections below see the 007 numbers they expect.
UPDATE servers SET message_retention_days = 30, dm_retention_days = NULL, dm_history_cap = NULL
 WHERE id = 'aaaa0000-0000-4000-8000-000000000001';

-- ── A bucket per server ─────────────────────────────────────
-- Migration 008. `file_size_limit` is a property of a bucket, so a shared one
-- could carry only a single number for the whole project — 007 mirrored the MAX
-- across servers and accepted that a stricter server's cap was client-enforced
-- only. A bucket each makes it exact, and the triggers are what keep it honest.

RESET ROLE;
DO $$
DECLARE lim BIGINT;
BEGIN
  -- Both fixture servers should have been given one on INSERT.
  SELECT file_size_limit INTO lim FROM storage.buckets
   WHERE id = 'chat-aaaa0000-0000-4000-8000-000000000001';
  IF lim IS NULL THEN
    RAISE EXCEPTION 'FAIL: a new server did not get its own bucket';
  END IF;
  RAISE NOTICE 'ok  creating a server mints its attachment bucket';
END $$;

DO $$
DECLARE alpha BIGINT; beta BIGINT;
BEGIN
  UPDATE servers SET max_attachment_bytes = 1048576
   WHERE id = 'aaaa0000-0000-4000-8000-000000000001';

  SELECT file_size_limit INTO alpha FROM storage.buckets
   WHERE id = 'chat-aaaa0000-0000-4000-8000-000000000001';
  IF alpha <> 1048576 THEN
    RAISE EXCEPTION 'FAIL: the bucket did not follow the column, got %', alpha;
  END IF;

  -- The whole point: one server's cap is its own. Under the shared bucket this
  -- was impossible to express.
  SELECT file_size_limit INTO beta FROM storage.buckets
   WHERE id = 'chat-bbbb0000-0000-4000-8000-000000000001';
  IF beta = 1048576 THEN
    RAISE EXCEPTION 'FAIL: changing Alpha''s cap moved Beta''s bucket too';
  END IF;
  RAISE NOTICE 'ok  a cap change moves that server''s bucket and no other';
END $$;

-- ── Attachments the messages left behind ────────────────────
-- app.orphaned_attachments finds blobs with no message, without any linkage —
-- an object is named for the scope it was uploaded to, and anything older than
-- the oldest surviving message of that scope belonged to one that is gone.

INSERT INTO storage.objects (bucket_id, name, owner, created_at) VALUES
  -- Under #forever, which kept all four of its messages: this one predates
  -- them, so it belonged to something already deleted.
  ('chat-aaaa0000-0000-4000-8000-000000000001', 'aaaa1111-0000-4000-8000-000000000004/old.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '40 days'),
  -- Under the same scope but newer than the surviving messages: keep.
  ('chat-aaaa0000-0000-4000-8000-000000000001', 'aaaa1111-0000-4000-8000-000000000004/live.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '2 hours'),
  -- The case the margin exists for. An attachment is uploaded *before* the
  -- message that carries its key, so a blob belonging to the OLDEST surviving
  -- message is itself older than the watermark. Without the margin this is
  -- swept on every run, quietly emptying the oldest message in every channel.
  ('chat-aaaa0000-0000-4000-8000-000000000001', 'aaaa1111-0000-4000-8000-000000000004/watermark.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002',
   (SELECT MIN(created_at) - interval '4 seconds' FROM messages
     WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000004')),
  -- #strict has nothing left at all, so everything under it is orphaned.
  ('chat-aaaa0000-0000-4000-8000-000000000001', 'aaaa1111-0000-4000-8000-000000000003/gone.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '3 hours'),
  -- A channel that no longer exists.
  ('chat-aaaa0000-0000-4000-8000-000000000001', 'cccc1111-0000-4000-8000-000000000009/dead.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '3 hours'),
  -- Uploaded moments ago: its message may still be in flight, so the grace
  -- period must protect it even though its scope has no messages.
  ('chat-aaaa0000-0000-4000-8000-000000000001', 'aaaa1111-0000-4000-8000-000000000003/inflight.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '2 minutes');

DO $$
DECLARE found TEXT[];
BEGIN
  SELECT array_agg(object_name ORDER BY object_name)
    INTO found FROM app.orphaned_attachments();

  IF NOT ('aaaa1111-0000-4000-8000-000000000004/old.bin' = ANY(found)) THEN
    RAISE EXCEPTION 'FAIL: a blob older than every surviving message was kept';
  END IF;
  IF 'aaaa1111-0000-4000-8000-000000000004/live.bin' = ANY(found) THEN
    RAISE EXCEPTION 'FAIL: a blob newer than the surviving messages was swept';
  END IF;
  IF NOT ('aaaa1111-0000-4000-8000-000000000003/gone.bin' = ANY(found)) THEN
    RAISE EXCEPTION 'FAIL: a blob in an emptied channel was kept';
  END IF;
  IF NOT ('cccc1111-0000-4000-8000-000000000009/dead.bin' = ANY(found)) THEN
    RAISE EXCEPTION 'FAIL: a blob of a deleted channel was kept';
  END IF;
  IF 'aaaa1111-0000-4000-8000-000000000003/inflight.bin' = ANY(found) THEN
    RAISE EXCEPTION 'FAIL: the grace period did not protect an in-flight upload';
  END IF;
  IF 'aaaa1111-0000-4000-8000-000000000004/watermark.bin' = ANY(found) THEN
    RAISE EXCEPTION
      'FAIL: swept the attachment of the oldest surviving message — a blob is '
      'uploaded before its message, so the margin has to cover that';
  END IF;
  RAISE NOTICE 'ok  orphaned blobs are found without any message→blob linkage';
END $$;

-- A DM scope is the client's conversation context with colons swapped for
-- underscores. If this drifts from DmCubit.conversationContext, every DM
-- attachment silently reads as orphaned — which would delete live ones.
UPDATE dm_messages SET created_at = now() - interval '6 hours'
 WHERE LEAST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000001'
   AND GREATEST(sender_id, recipient_id) = '11111111-aaaa-4aaa-8aaa-000000000002';

INSERT INTO storage.objects (bucket_id, name, owner, created_at) VALUES
  ('chat-aaaa0000-0000-4000-8000-000000000001',
   'dm_11111111-aaaa-4aaa-8aaa-000000000001_11111111-aaaa-4aaa-8aaa-000000000002/live.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '2 hours');

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM app.orphaned_attachments()
     WHERE object_name LIKE 'dm\_%live.bin'
  ) THEN
    RAISE EXCEPTION
      'FAIL: a live DM attachment read as orphaned — the scope format drifted '
      'from DmCubit.conversationContext';
  END IF;
  RAISE NOTICE 'ok  the DM scope format matches what the client uploads under';
END $$;

-- The sweep deletes history, so it must be unreachable from a member session —
-- both functions are in `app` precisely so PostgREST cannot expose them.
SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  BEGIN
    PERFORM app.enforce_retention();
    RAISE EXCEPTION 'FAIL: a member can run the retention sweep';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  BEGIN
    PERFORM 1 FROM app.orphaned_attachments();
    RAISE EXCEPTION 'FAIL: a member can list orphaned attachments';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  -- This one *is* in `public`, so PostgREST exposes it. The grant is the only
  -- thing standing between a member and a history sweep.
  BEGIN
    PERFORM sweep_attachments();
    RAISE EXCEPTION 'FAIL: a member can call sweep_attachments';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  the sweep functions are out of a member''s reach';
END $$;

-- ── Who may delete an attachment ────────────────────────────
-- storage.protect_delete() refuses direct DELETE on storage.objects unless the
-- Storage API's GUC is set — so set it, exactly as the API does, and the RLS
-- policy underneath becomes testable.
SET LOCAL storage.allow_delete_query = 'true';

DO $$
BEGIN
  -- Bob uploaded these, so deleting his own message's files is his to do. He
  -- can see his own server's bucket, so his own view is a fair check here.
  IF NOT EXISTS (SELECT 1 FROM storage.objects
                  WHERE name = 'aaaa1111-0000-4000-8000-000000000004/live.bin') THEN
    RAISE EXCEPTION 'FAIL: a member cannot see their own server''s attachments';
  END IF;
  DELETE FROM storage.objects
   WHERE name = 'aaaa1111-0000-4000-8000-000000000004/live.bin';
  IF EXISTS (SELECT 1 FROM storage.objects
              WHERE name = 'aaaa1111-0000-4000-8000-000000000004/live.bin') THEN
    RAISE EXCEPTION 'FAIL: an uploader cannot delete their own attachment';
  END IF;
  RAISE NOTICE 'ok  an uploader can delete the files of a message they delete';
END $$;

-- Mallory is on Beta. Before 008 every authenticated caller could read every
-- object in the one shared bucket; now a bucket belongs to a server, so she can
-- neither see Alpha's attachments nor delete them. Checked from the superuser
-- afterwards, because her own view is exactly what is being denied — asking her
-- "is it still there?" would read her blindness as a successful delete.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"22222222-bbbb-4bbb-8bbb-000000000001","role":"authenticated"}', true); END $$;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM storage.objects
              WHERE name = 'aaaa1111-0000-4000-8000-000000000003/gone.bin') THEN
    RAISE EXCEPTION 'FAIL: a member of another server can read these objects';
  END IF;
  DELETE FROM storage.objects
   WHERE name = 'aaaa1111-0000-4000-8000-000000000003/gone.bin';
  RAISE NOTICE 'ok  another server''s attachments are invisible, not just undeletable';
END $$;

RESET ROLE;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM storage.objects
                  WHERE name = 'aaaa1111-0000-4000-8000-000000000003/gone.bin') THEN
    RAISE EXCEPTION 'FAIL: a stranger deleted someone else''s attachment';
  END IF;
  RAISE NOTICE 'ok  and the object really did survive the attempt';
END $$;
SET LOCAL ROLE authenticated;
SET LOCAL storage.allow_delete_query = 'true';

-- Alice manages channels, so she may remove the files of a message she is
-- allowed to remove.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;
DO $$
BEGIN
  DELETE FROM storage.objects
   WHERE name = 'aaaa1111-0000-4000-8000-000000000003/gone.bin';
  IF EXISTS (SELECT 1 FROM storage.objects
              WHERE name = 'aaaa1111-0000-4000-8000-000000000003/gone.bin') THEN
    RAISE EXCEPTION 'FAIL: a channel manager cannot remove an attachment';
  END IF;
  RAISE NOTICE 'ok  a moderator can remove the files of a message they delete';
END $$;

-- ============================================================
-- 11b. What a call may cost the operator (028)
-- ============================================================
-- Two columns, both 0 = off. What they *do* is enforced in
-- `get_channel_token`, which is an edge function and outside this suite — so
-- what is testable here is the part the database owns: the defaults a server
-- that upgrades and is never touched reports, the constraint, and that a
-- member cannot set either of them on themselves.
--
-- That last one is the only security-shaped case of the three, and it is
-- worth having: a limit a member can raise is not a limit.

RESET ROLE;
DO $$
DECLARE v_voice INT; v_mbps INT;
BEGIN
  SELECT max_voice_participants, max_share_mbps INTO v_voice, v_mbps
    FROM servers WHERE id = 'bbbb0000-0000-4000-8000-000000000001';
  IF v_voice IS DISTINCT FROM 0 OR v_mbps IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'FAIL: a server that set nothing reports a call limit: % / %',
      v_voice, v_mbps;
  END IF;
  RAISE NOTICE 'ok  a server nobody configured caps neither the call nor the share';
END $$;

DO $$
BEGIN
  BEGIN
    UPDATE servers SET max_voice_participants = -1
     WHERE id = 'bbbb0000-0000-4000-8000-000000000001';
    RAISE EXCEPTION 'FAIL: a negative participant cap was accepted';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
  BEGIN
    UPDATE servers SET max_share_mbps = -1
     WHERE id = 'bbbb0000-0000-4000-8000-000000000001';
    RAISE EXCEPTION 'FAIL: a negative share cap was accepted';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
  RAISE NOTICE 'ok  neither call limit can be set below zero';
END $$;

-- Alpha caps its calls. The number has to survive being set, because an
-- operator typing it and it not sticking is the failure nobody would notice
-- until the bandwidth bill.
UPDATE servers SET max_voice_participants = 25, max_share_mbps = 3
 WHERE id = 'aaaa0000-0000-4000-8000-000000000001';

DO $$
DECLARE v_voice INT; v_mbps INT;
BEGIN
  SELECT max_voice_participants, max_share_mbps INTO v_voice, v_mbps
    FROM servers WHERE id = 'aaaa0000-0000-4000-8000-000000000001';
  IF v_voice <> 25 OR v_mbps <> 3 THEN
    RAISE EXCEPTION 'FAIL: the call limits did not stick: % / %', v_voice, v_mbps;
  END IF;
  SELECT max_voice_participants INTO v_voice
    FROM servers WHERE id = 'bbbb0000-0000-4000-8000-000000000001';
  IF v_voice <> 0 THEN
    RAISE EXCEPTION 'FAIL: one server''s call cap reached another';
  END IF;
  RAISE NOTICE 'ok  a call cap belongs to the server that set it';
END $$;

-- A member reads the caps — the client needs the share budget — and cannot
-- move them. Two different things could stop them, the grant or a policy, and
-- this does not care which: what it asserts is that the numbers do not move.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;
SET LOCAL ROLE authenticated;
DO $$
DECLARE v_mbps INT; v_rows INT;
BEGIN
  SELECT max_share_mbps INTO v_mbps
    FROM servers WHERE id = 'aaaa0000-0000-4000-8000-000000000001';
  IF v_mbps IS DISTINCT FROM 3 THEN
    RAISE EXCEPTION 'FAIL: a member cannot read the share budget they must keep to: %', v_mbps;
  END IF;

  BEGIN
    UPDATE servers SET max_voice_participants = 5000, max_share_mbps = 500
     WHERE id = 'aaaa0000-0000-4000-8000-000000000001';
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows <> 0 THEN
      RAISE EXCEPTION 'FAIL: a member raised the call limits on themselves';
    END IF;
  EXCEPTION WHEN insufficient_privilege THEN NULL;  -- refused outright: also no
  END;
  RAISE NOTICE 'ok  a member reads the call limits and cannot raise them';
END $$;

RESET ROLE;
UPDATE servers SET max_voice_participants = 0, max_share_mbps = 0
 WHERE id = 'aaaa0000-0000-4000-8000-000000000001';

-- ============================================================
-- 11c. How many people, and how much disk (029)
-- ============================================================
-- Both of these are walls rather than budgets, so both are testable here:
-- the member cap lives in `register_user` and the storage cap in a trigger
-- on `storage.objects`, and neither needs a client to co-operate.

RESET ROLE;
DO $$
DECLARE v_members INT; v_storage BIGINT;
BEGIN
  SELECT max_members, max_storage_bytes INTO v_members, v_storage
    FROM servers WHERE id = 'bbbb0000-0000-4000-8000-000000000001';
  IF v_members IS DISTINCT FROM 0 OR v_storage IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'FAIL: a server that set nothing caps its size: % / %',
      v_members, v_storage;
  END IF;
  RAISE NOTICE 'ok  a server nobody configured caps neither members nor disk';
END $$;

-- ── the member cap ──────────────────────────────────────────────────────
-- Alpha is capped at exactly the number of people already in it, so the next
-- arrival is the interesting one.

DO $$
DECLARE v_now INT; v_reason TEXT; v_id UUID;
BEGIN
  SELECT count(*) INTO v_now FROM users
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND NOT is_banned;
  UPDATE servers SET max_members = v_now
   WHERE id = 'aaaa0000-0000-4000-8000-000000000001';

  -- A bot invite, for two reasons. Bots count towards the cap — that is the
  -- documented rule and this pins it — and `register_user` hands the owner
  -- role to the first *person* through when a server has none, which Alpha
  -- does not have yet at this point in the file. Registering people here
  -- would quietly make one of them the owner and break section 30.
  INSERT INTO invites (server_id, code, max_uses, is_bot)
  VALUES ('aaaa0000-0000-4000-8000-000000000001', 'fulltest', 9, true);

  v_id := '11119999-0000-4000-8000-00000000f001';
  INSERT INTO auth.users (id, instance_id, aud, role, created_at, updated_at)
  VALUES (v_id, '00000000-0000-0000-0000-000000000000',
          'authenticated', 'authenticated', now(), now());

  v_reason := register_user('fulltest', v_id, 'pk-f1', 'sid-f1', 'f1', 'F1')
                ->> 'reason';
  IF v_reason IS DISTINCT FROM 'server_full' THEN
    RAISE EXCEPTION 'FAIL: a full server let somebody in: %', v_reason;
  END IF;
  RAISE NOTICE 'ok  a full server turns the next member away';
END $$;

DO $$
DECLARE v_reason TEXT; v_id UUID := '11119999-0000-4000-8000-00000000f002';
BEGIN
  -- One more seat, one more member, and then full again.
  UPDATE servers SET max_members = max_members + 1
   WHERE id = 'aaaa0000-0000-4000-8000-000000000001';
  INSERT INTO auth.users (id, instance_id, aud, role, created_at, updated_at)
  VALUES (v_id, '00000000-0000-0000-0000-000000000000',
          'authenticated', 'authenticated', now(), now());
  v_reason := register_user('fulltest', v_id, 'pk-f2', 'sid-f2', 'f2', 'F2')
                ->> 'reason';
  IF v_reason IS DISTINCT FROM 'ok' THEN
    RAISE EXCEPTION 'FAIL: a seat was freed and nobody could take it: %', v_reason;
  END IF;
  RAISE NOTICE 'ok  raising the cap by one admits exactly one';
END $$;

DO $$
DECLARE v_reason TEXT; v_id UUID := '11119999-0000-4000-8000-00000000f003';
BEGIN
  INSERT INTO auth.users (id, instance_id, aud, role, created_at, updated_at)
  VALUES (v_id, '00000000-0000-0000-0000-000000000000',
          'authenticated', 'authenticated', now(), now());

  -- Banning somebody gives their place back. An operator who has decided
  -- someone is not part of the server should not still be paying for them.
  UPDATE users SET is_banned = true
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND username = 'f2';

  v_reason := register_user('fulltest', v_id, 'pk-f3', 'sid-f3', 'f3', 'F3')
                ->> 'reason';
  IF v_reason IS DISTINCT FROM 'ok' THEN
    RAISE EXCEPTION 'FAIL: a ban did not free the seat: %', v_reason;
  END IF;
  RAISE NOTICE 'ok  a ban gives the seat back';
END $$;

RESET ROLE;
DO $$
DECLARE v_bots INT;
BEGIN
  SELECT count(*) INTO v_bots FROM users
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND is_bot;
  IF v_bots < 2 THEN
    RAISE EXCEPTION 'FAIL: the bots that filled the server are not members';
  END IF;
  RAISE NOTICE 'ok  a bot holds a seat like anybody else';
END $$;

DELETE FROM users WHERE id IN (
  '11119999-0000-4000-8000-00000000f002', '11119999-0000-4000-8000-00000000f003');
DELETE FROM auth.users WHERE id IN (
  '11119999-0000-4000-8000-00000000f001',
  '11119999-0000-4000-8000-00000000f002',
  '11119999-0000-4000-8000-00000000f003');
DELETE FROM invites WHERE code = 'fulltest';
UPDATE servers SET max_members = 0
 WHERE id = 'aaaa0000-0000-4000-8000-000000000001';

-- ── the storage cap ─────────────────────────────────────────────────────
-- The running total is the whole design: if it did not follow every write,
-- the cap would drift and eventually refuse a server with room or admit one
-- without. So the tests are about the total keeping up, not only about the
-- refusal.

DO $$
DECLARE v_bucket TEXT := 'chat-aaaa0000-0000-4000-8000-000000000001';
        v_bytes BIGINT;
BEGIN
  INSERT INTO storage.objects (bucket_id, name, owner, metadata)
  VALUES (v_bucket, 'sz/a.bin', '11111111-aaaa-4aaa-8aaa-000000000001',
          jsonb_build_object('size', 1000));
  SELECT bytes INTO v_bytes FROM app.bucket_usage WHERE bucket_id = v_bucket;
  IF v_bytes IS DISTINCT FROM 1000 THEN
    RAISE EXCEPTION 'FAIL: an upload did not reach the total: %', v_bytes;
  END IF;

  INSERT INTO storage.objects (bucket_id, name, owner, metadata)
  VALUES (v_bucket, 'sz/b.bin', '11111111-aaaa-4aaa-8aaa-000000000001',
          jsonb_build_object('size', 500));
  SELECT bytes INTO v_bytes FROM app.bucket_usage WHERE bucket_id = v_bucket;
  IF v_bytes IS DISTINCT FROM 1500 THEN
    RAISE EXCEPTION 'FAIL: the total does not add up: %', v_bytes;
  END IF;

  DELETE FROM storage.objects WHERE bucket_id = v_bucket AND name = 'sz/b.bin';
  SELECT bytes INTO v_bytes FROM app.bucket_usage WHERE bucket_id = v_bucket;
  IF v_bytes IS DISTINCT FROM 1000 THEN
    RAISE EXCEPTION 'FAIL: deleting a file did not give the space back: %', v_bytes;
  END IF;
  RAISE NOTICE 'ok  the running total follows every upload and every delete';
END $$;

DO $$
DECLARE v_bucket TEXT := 'chat-aaaa0000-0000-4000-8000-000000000001';
BEGIN
  -- 1,000 bytes held, 1,200 allowed.
  UPDATE servers SET max_storage_bytes = 1200
   WHERE id = 'aaaa0000-0000-4000-8000-000000000001';

  BEGIN
    INSERT INTO storage.objects (bucket_id, name, owner, metadata)
    VALUES (v_bucket, 'sz/toobig.bin', '11111111-aaaa-4aaa-8aaa-000000000001',
            jsonb_build_object('size', 500));
    RAISE EXCEPTION 'FAIL: an upload past the cap was accepted';
  EXCEPTION WHEN disk_full THEN NULL;
  END;

  -- And the one that does fit still goes in: a cap is not an outage.
  INSERT INTO storage.objects (bucket_id, name, owner, metadata)
  VALUES (v_bucket, 'sz/fits.bin', '11111111-aaaa-4aaa-8aaa-000000000001',
          jsonb_build_object('size', 200));
  RAISE NOTICE 'ok  the upload that would go over is refused, the one that fits is not';
END $$;

-- The cap is exact, not approximate, and that rests on the check holding the
-- bucket's row rather than glancing at it. Two uploads landing together
-- against a stale figure both fit and together do not: 950 KB under a 1 MB
-- cap admitted two 40 KB files and finished at 1,030 KB, which is how this
-- was found. A single-transaction suite cannot race anything, so what is
-- pinned here is the lock itself — drop it and the arithmetic still passes
-- every other test in this file.
DO $$
DECLARE v_src TEXT;
BEGIN
  SELECT pg_get_functiondef(oid) INTO v_src
    FROM pg_proc WHERE proname = 'enforce_storage_cap';
  IF v_src !~* 'FOR UPDATE' THEN
    RAISE EXCEPTION 'FAIL: the storage cap reads the running total without locking it';
  END IF;
  IF v_src !~* 'ON CONFLICT \(bucket_id\) DO NOTHING' THEN
    RAISE EXCEPTION 'FAIL: nothing guarantees a row to lock on a bucket''s first upload';
  END IF;
  RAISE NOTICE 'ok  the cap locks the running total it measures against';
END $$;

DO $$
DECLARE v_other TEXT := 'chat-bbbb0000-0000-4000-8000-000000000001';
BEGIN
  -- Beta has no cap and is not affected by Alpha's.
  INSERT INTO storage.objects (bucket_id, name, owner, metadata)
  VALUES (v_other, 'sz/free.bin', '22222222-bbbb-4bbb-8bbb-000000000001',
          jsonb_build_object('size', 999999));
  RAISE NOTICE 'ok  one server''s disk limit is not another''s';
END $$;

-- What a member is told about it, which is what the composer warns from.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;
SET LOCAL ROLE authenticated;
DO $$
DECLARE v_used BIGINT; v_details JSONB;
BEGIN
  v_used := server_storage_used();
  IF v_used IS DISTINCT FROM 1200 THEN
    RAISE EXCEPTION 'FAIL: the server reports the wrong usage: %', v_used;
  END IF;
  v_details := get_server_details();
  IF (v_details->>'storage_used')::BIGINT IS DISTINCT FROM 1200 THEN
    RAISE EXCEPTION 'FAIL: usage is missing from the one call a client makes';
  END IF;
  -- 028's two came late to this function and were missing for a while; a
  -- limit the client cannot read is a limit the client ignores.
  IF NOT (v_details ? 'max_share_mbps' AND v_details ? 'max_voice_participants'
          AND v_details ? 'max_members' AND v_details ? 'max_storage_bytes') THEN
    RAISE EXCEPTION 'FAIL: a limit is missing from get_server_details: %', v_details;
  END IF;
  RAISE NOTICE 'ok  a member can read how full the server is, and every limit';
END $$;

RESET ROLE;
UPDATE servers SET max_storage_bytes = 0
 WHERE id = 'aaaa0000-0000-4000-8000-000000000001';
DELETE FROM storage.objects WHERE name LIKE 'sz/%';

-- ============================================================
-- 12. Roles and granular permissions (018)
-- ============================================================
-- The three booleans are now a cache of three bits. Every test here guards a
-- way that cache, or the delegation rules that feed it, could go wrong while
-- the app still looked fine.

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

-- The backfill has to reproduce exactly what the booleans meant. If it does
-- not, every policy in this file is now testing a different server than the one
-- that shipped.
DO $$
BEGIN
  IF NOT app.has_perm('MANAGE_CHANNELS') THEN
    RAISE EXCEPTION 'FAIL: alice lost channel management in the backfill';
  END IF;
  -- She never held the bit. `ADMINISTRATOR` is what answers, and folding it
  -- into the mask rather than branching is the only reason that is true
  -- everywhere at once.
  IF NOT app.has_perm('BAN_MEMBERS') THEN
    RAISE EXCEPTION 'FAIL: ADMINISTRATOR does not imply BAN_MEMBERS';
  END IF;
  RAISE NOTICE 'ok  an administrator holds every bit without being given one';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  -- Bob holds no roles at all, so everything he can do comes from @everyone.
  IF NOT app.has_perm('SEND_MESSAGES') THEN
    RAISE EXCEPTION 'FAIL: @everyone is not being folded in for a member with no roles';
  END IF;
  IF NOT app.has_perm('CREATE_INVITE') THEN
    RAISE EXCEPTION 'FAIL: the baseline stopped carrying CREATE_INVITE (016)';
  END IF;
  IF app.has_perm('MANAGE_ROLES') THEN
    RAISE EXCEPTION 'FAIL: a plain member can manage roles';
  END IF;
  RAISE NOTICE 'ok  @everyone is implicit, and grants only what it says';
END $$;

-- A misspelled permission must not read as "denied". A policy that quietly
-- denies everything looks like a working policy until it is the only thing
-- between somebody and a room.
DO $$
BEGIN
  BEGIN
    PERFORM app.has_perm('MANAGE_CHANELS');
    RAISE EXCEPTION 'FAIL: an unknown permission name was accepted';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  an unknown permission name raises rather than denying';
END $$;

DO $$
BEGIN
  BEGIN
    INSERT INTO roles (server_id, name, position, permissions)
    VALUES ('aaaa0000-0000-4000-8000-000000000001', 'Bobs Role', 1, 0);
    RAISE EXCEPTION 'FAIL: a member who is not an administrator created a role';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  creating a role needs ADMINISTRATOR';
END $$;

-- ---------- delegation ----------
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_role UUID;
BEGIN
  INSERT INTO roles (server_id, name, position, permissions)
  VALUES ('aaaa0000-0000-4000-8000-000000000001', 'Helper', 1,
          app.perm('MANAGE_MESSAGES'))
  RETURNING id INTO v_role;
  IF v_role IS NULL THEN
    RAISE EXCEPTION 'FAIL: an admin could not create a role below her';
  END IF;

  -- Alice's own rank is Admin's, which 024 moved to 300 to leave room on the
  -- ladder. Strictly-below applies to her too: nobody edits the role they are
  -- standing on, or promotes one up to it.
  BEGIN
    INSERT INTO roles (server_id, name, position, permissions)
    VALUES ('aaaa0000-0000-4000-8000-000000000001', 'Peer', 300, 0);
    RAISE EXCEPTION 'FAIL: an admin created a role at her own rank';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  roles are created strictly below the creator';
END $$;

-- The baseline is not a role you can hand out or remove. Two answers to "what
-- can everyone do" would drift, and the drift would be silent.
DO $$
DECLARE v_everyone UUID;
BEGIN
  SELECT id INTO v_everyone FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND is_everyone;

  BEGIN
    INSERT INTO member_roles (user_id, role_id)
    VALUES ('11111111-aaaa-4aaa-8aaa-000000000002', v_everyone);
    RAISE EXCEPTION 'FAIL: @everyone was assigned to somebody';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;

  BEGIN
    DELETE FROM roles WHERE id = v_everyone;
    RAISE EXCEPTION 'FAIL: @everyone was deleted';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  @everyone cannot be assigned or deleted';
END $$;

-- ---------- the cache ----------
-- This is the one that keeps every *other* policy in this file working: the
-- three columns are no longer written by anything, so if the trigger stops
-- firing, authority silently drains out of the server.
DO $$
DECLARE v_moderator UUID;
BEGIN
  SELECT id INTO v_moderator FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001'
     AND name = 'Moderator';

  INSERT INTO member_roles (user_id, role_id)
  VALUES ('11111111-aaaa-4aaa-8aaa-000000000002', v_moderator);

  IF NOT (SELECT is_channel_manager FROM users
           WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002') THEN
    RAISE EXCEPTION 'FAIL: granting Moderator did not reach is_channel_manager';
  END IF;

  DELETE FROM member_roles
   WHERE user_id = '11111111-aaaa-4aaa-8aaa-000000000002'
     AND role_id = v_moderator;

  IF (SELECT is_channel_manager FROM users
       WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002') THEN
    RAISE EXCEPTION 'FAIL: removing Moderator left is_channel_manager set';
  END IF;
  RAISE NOTICE 'ok  the boolean cache follows role membership both ways';
END $$;

-- Editing a role moves everybody holding it, not just whoever is next to log
-- in. Without this the cache is correct only at the moment it is written.
DO $$
DECLARE v_helper UUID;
BEGIN
  SELECT id INTO v_helper FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND name = 'Helper';
  INSERT INTO member_roles (user_id, role_id)
  VALUES ('11111111-aaaa-4aaa-8aaa-000000000002', v_helper);

  UPDATE roles SET permissions = permissions | app.perm('MANAGE_CHANNELS')
   WHERE id = v_helper;

  IF NOT (SELECT is_channel_manager FROM users
           WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002') THEN
    RAISE EXCEPTION 'FAIL: editing a role did not resync its holders';
  END IF;
  RAISE NOTICE 'ok  editing a role resyncs everybody holding it';
END $$;

-- ---------- the bit that used to open the editor ----------
-- `MANAGE_ROLES` did, until 015. A role carrying it is still a role — the
-- editor is an administrator's now, and nothing below that rank reshapes
-- the ladder, whatever bits it holds.
DO $$
DECLARE v_staff UUID;
BEGIN
  INSERT INTO roles (server_id, name, position, permissions)
  VALUES ('aaaa0000-0000-4000-8000-000000000001', 'Staff', 2,
          app.perm('MANAGE_ROLES') | app.perm('CREATE_INVITE'))
  RETURNING id INTO v_staff;
  INSERT INTO member_roles (user_id, role_id)
  VALUES ('11111111-aaaa-4aaa-8aaa-000000000003', v_staff);
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000003","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT app.has_perm('MANAGE_ROLES') THEN
    RAISE EXCEPTION 'FAIL: carol did not receive MANAGE_ROLES';
  END IF;
  BEGIN
    INSERT INTO roles (server_id, name, position, permissions)
    VALUES ('aaaa0000-0000-4000-8000-000000000001', 'Greeter', 1,
            app.perm('CREATE_INVITE'));
    RAISE EXCEPTION 'FAIL: MANAGE_ROLES alone still opens the roles editor';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  the roles editor is an administrator''s, whatever bits you hold';
END $$;

-- Rank is checked on the role being handed out, not on the person handing it.
DO $$
DECLARE v_admin UUID;
BEGIN
  SELECT id INTO v_admin FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND name = 'Admin';
  BEGIN
    INSERT INTO member_roles (user_id, role_id)
    VALUES ('11111111-aaaa-4aaa-8aaa-000000000003', v_admin);
    RAISE EXCEPTION 'FAIL: somebody granted themselves a role above their rank';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  nobody hands out a role they do not outrank';
END $$;

-- The other direction, and the one 018 got wrong. Administrators are exempt
-- from the position rule when *handing out* a role, so that the only admin on
-- a server can make a second one — and the exemption applied to removals too,
-- which let an admin take Admin off themselves and leave a server with no
-- administrator and no way to appoint one (026).
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_admin UUID;
BEGIN
  SELECT id INTO v_admin FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND name = 'Admin';

  DELETE FROM member_roles WHERE user_id = auth.uid() AND role_id = v_admin;
  IF NOT EXISTS (SELECT 1 FROM member_roles
                  WHERE user_id = auth.uid() AND role_id = v_admin) THEN
    RAISE EXCEPTION 'FAIL: an admin took their own Admin role off';
  END IF;

  -- ...but a role she genuinely stands above is hers to drop.
  INSERT INTO member_roles (user_id, role_id)
  SELECT auth.uid(), id FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND name = 'Moderator'
  ON CONFLICT DO NOTHING;
  DELETE FROM member_roles
   WHERE user_id = auth.uid()
     AND role_id IN (SELECT id FROM roles
                      WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001'
                        AND name = 'Moderator');
  IF EXISTS (SELECT 1 FROM member_roles mr JOIN roles r ON r.id = mr.role_id
              WHERE mr.user_id = auth.uid() AND r.name = 'Moderator') THEN
    RAISE EXCEPTION 'FAIL: a role below her own could not be dropped';
  END IF;
  RAISE NOTICE 'ok  nobody demotes themselves out of the server';
END $$;

-- ---------- granting a role reaches the cache ----------
-- The three columns on `users` are what every policy written before 018 reads,
-- and nothing writes them by hand any more. If the trigger stops firing,
-- authority drains out of the server silently — the roles look right and none
-- of them do anything.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  INSERT INTO member_roles (user_id, role_id)
  SELECT '11111111-aaaa-4aaa-8aaa-000000000003', id FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001'
     AND name = 'Moderator';

  IF NOT (SELECT is_channel_manager FROM users
           WHERE id = '11111111-aaaa-4aaa-8aaa-000000000003') THEN
    RAISE EXCEPTION 'FAIL: granting a role did not reach the cached column';
  END IF;
  RAISE NOTICE 'ok  a role granted by hand reads back through the old columns';
END $$;

-- Registration is the service role's, and `register_user` is not SECURITY
-- DEFINER — it runs as whoever called it. Every other test in this file speaks
-- as `authenticated`, so the one path that does not was the one 018 broke: it
-- gave the function a dependency on the `app` schema, which 002 had granted to
-- `authenticated` alone. Nobody could join a server.
RESET ROLE;

INSERT INTO invites (server_id, code, max_uses)
VALUES ('aaaa0000-0000-4000-8000-000000000001', 'TESTINV0001', 5);
INSERT INTO auth.users (id) VALUES ('11111111-aaaa-4aaa-8aaa-00000000000a');
INSERT INTO auth.users (id) VALUES ('11111111-aaaa-4aaa-8aaa-00000000000b');
INSERT INTO auth.users (id) VALUES ('11111111-aaaa-4aaa-8aaa-00000000000c');

-- A username is what `@`-mentions resolve against, so one the parser cannot
-- express is a member nobody can reach. `users_username_shape` is what a
-- write that never goes through the RPC runs into — checked here, as the
-- owner, so only the constraint can be what refuses it.
DO $$
BEGIN
  BEGIN
    INSERT INTO users (id, server_id, username, display_name, public_key,
                       stable_id)
    VALUES ('11111111-aaaa-4aaa-8aaa-00000000000c',
            'aaaa0000-0000-4000-8000-000000000001',
            'Benny Smith!', 'Benny', 'pk-sp2', 'sid-sp2');
    RAISE EXCEPTION 'FAIL: the column took a username with a space';
  EXCEPTION WHEN check_violation THEN
    NULL;
  END;
  RAISE NOTICE 'ok  users_username_shape holds the line at the column';
END $$;

SET LOCAL ROLE service_role;

DO $$
DECLARE v_result JSONB;
BEGIN
  v_result := register_user('TESTINV0001',
                            '11111111-aaaa-4aaa-8aaa-00000000000a',
                            'pk-dave', 'sid-dave', 'dave', 'Dave');
  IF v_result->>'reason' <> 'ok' THEN
    RAISE EXCEPTION 'FAIL: registration returned %', v_result;
  END IF;
  -- The invite named no role, so dave holds none (016 dropped the default
  -- one); what he can do is the baseline, and that is the whole point.
  IF NOT EXISTS (SELECT 1 FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-00000000000a') THEN
    RAISE EXCEPTION 'FAIL: a new member has no row';
  END IF;
  RAISE NOTICE 'ok  somebody can still join a server';
END $$;

-- The client refuses this shape at the keystroke; this is the half a bot
-- joining through the SDK cannot go round. Named rather than left to the
-- constraint, so the caller gets a reason instead of a check violation.
DO $$
DECLARE v_result JSONB;
BEGIN
  v_result := register_user('TESTINV0001',
                            '11111111-aaaa-4aaa-8aaa-00000000000b',
                            'pk-sp', 'sid-sp', 'Benny Smith!', 'Benny');
  IF v_result->>'reason' <> 'username_invalid' THEN
    RAISE EXCEPTION 'FAIL: a username with a space registered: %', v_result;
  END IF;
  RAISE NOTICE 'ok  a username mentions cannot express is refused by name';
END $$;

SET LOCAL ROLE authenticated;

-- ============================================================
-- 13. Private channels (020)
-- ============================================================
-- The tests that matter here are the denials, and one of them is unusual: an
-- administrator is denied. That is the design — an admin holds no key either
-- way, so an override would be a promise the crypto cannot keep — and it is
-- exactly the rule a later "just for moderation" patch would quietly undo.

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

-- Bob holds no roles, and since 014 the baseline does not include making a
-- private room: that is a moderator's by default, and a bit like any other.
DO $$
BEGIN
  BEGIN
    INSERT INTO channels (id, server_id, name, channel_type, is_private)
    VALUES ('aaaa1111-0000-4000-8000-00000000fff0',
            'aaaa0000-0000-4000-8000-000000000001', 'too-soon', 'text', true);
    RAISE EXCEPTION 'FAIL: a plain member made a private channel';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  making a private channel is a permission, not a birthright';
END $$;

-- Only that bit, so bob's three cached booleans stay false and the tests
-- below that lean on him being a plain member still mean what they say.
RESET ROLE;
INSERT INTO roles (id, server_id, name, position, permissions)
VALUES ('aaaa2222-0000-4000-8000-000000000001',
        'aaaa0000-0000-4000-8000-000000000001', 'Room makers', 50,
        app.perm('CREATE_PRIVATE_CHANNEL'));
INSERT INTO member_roles (user_id, role_id)
VALUES ('11111111-aaaa-4aaa-8aaa-000000000002', 'aaaa2222-0000-4000-8000-000000000001');
SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  INSERT INTO channels (id, server_id, name, channel_type, is_private)
  VALUES ('aaaa1111-0000-4000-8000-00000000ffff',
          'aaaa0000-0000-4000-8000-000000000001', 'secret', 'text', true);

  -- Born with somebody able to run it. Without this it is orphaned from the
  -- first statement, and section 8's tidy-up would delete it on the first
  -- membership change.
  IF NOT EXISTS (SELECT 1 FROM channel_members
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-00000000ffff'
                    AND user_id = '11111111-aaaa-4aaa-8aaa-000000000002'
                    AND can_manage) THEN
    RAISE EXCEPTION 'FAIL: creating a private channel did not seat its creator';
  END IF;
  RAISE NOTICE 'ok  whoever makes a private channel can run it';
END $$;

-- A key, so there is something for the rotation marker to point past later.
DO $$
BEGIN
  INSERT INTO channel_keyring
    (channel_id, key_version, user_id, wrapped_by, ephemeral_public_key, ciphertext, nonce)
  VALUES ('aaaa1111-0000-4000-8000-00000000ffff', 1,
          '11111111-aaaa-4aaa-8aaa-000000000002',
          '11111111-aaaa-4aaa-8aaa-000000000002', 'eph', 'ct', 'n');

  INSERT INTO messages (channel_id, ciphertext, nonce, signature, key_version)
  VALUES ('aaaa1111-0000-4000-8000-00000000ffff', 'secret-from-bob', 'n', 's', 1);
END $$;

-- Making one is a single statement, and it has to be. `INSERT ... RETURNING`
-- applies the *select* policy to the row it hands back, and a private channel's
-- select policy asks whether the caller is in it — which they are not until the
-- after-insert trigger seats them, which has not run yet. The insert worked and
-- reading its own row did not, and Postgres reported it as a WITH CHECK
-- violation naming the wrong policy. Found by clicking the button (022).
DO $$
DECLARE v_result JSONB;
BEGIN
  v_result := create_channel('rls-returning', 'text', true,
                             ARRAY['11111111-aaaa-4aaa-8aaa-000000000003']::UUID[]);
  IF v_result->>'reason' <> 'ok' THEN
    RAISE EXCEPTION 'FAIL: creating a private channel returned %', v_result;
  END IF;
  IF (v_result->>'is_private')::BOOLEAN IS NOT TRUE THEN
    RAISE EXCEPTION 'FAIL: the row it handed back was not the row it made';
  END IF;

  -- The creator is seated by the function, so a caller who forgot to name
  -- themselves does not create a channel and destroy it in one statement.
  IF NOT EXISTS (SELECT 1 FROM channel_members
                  WHERE channel_id = (v_result->>'id')::UUID
                    AND user_id = '11111111-aaaa-4aaa-8aaa-000000000002'
                    AND can_manage) THEN
    RAISE EXCEPTION 'FAIL: the creator was not seated';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM channel_members
                  WHERE channel_id = (v_result->>'id')::UUID
                    AND user_id = '11111111-aaaa-4aaa-8aaa-000000000003') THEN
    RAISE EXCEPTION 'FAIL: the people it was made for were not seated';
  END IF;
  RAISE NOTICE 'ok  a private channel can be made and read back in one go';
END $$;

-- ---------- the administrator ----------
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM channels
              WHERE id = 'aaaa1111-0000-4000-8000-00000000ffff') THEN
    RAISE EXCEPTION 'FAIL: an admin can see a private channel she is not in';
  END IF;
  IF EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'secret-from-bob') THEN
    RAISE EXCEPTION 'FAIL: an admin can read a private channel''s messages';
  END IF;
  IF EXISTS (SELECT 1 FROM channel_keyring
              WHERE channel_id = 'aaaa1111-0000-4000-8000-00000000ffff') THEN
    RAISE EXCEPTION 'FAIL: an admin can read a private channel''s keyring';
  END IF;
  IF EXISTS (SELECT 1 FROM channel_members
              WHERE channel_id = 'aaaa1111-0000-4000-8000-00000000ffff') THEN
    RAISE EXCEPTION 'FAIL: an admin can see who is in a private channel';
  END IF;
  RAISE NOTICE 'ok  an administrator is outside a room she was not invited to';
END $$;

-- The one that is arithmetic rather than a rule. Everything above is a policy
-- somebody could widen; this is the row refusing to exist, because a wrapped
-- key *is* read access and no later policy edit can take one back.
DO $$
BEGIN
  BEGIN
    INSERT INTO channel_keyring
      (channel_id, key_version, user_id, wrapped_by, ephemeral_public_key, ciphertext, nonce)
    VALUES ('aaaa1111-0000-4000-8000-00000000ffff', 1,
            '11111111-aaaa-4aaa-8aaa-000000000001',
            '11111111-aaaa-4aaa-8aaa-000000000001', 'eph', 'ct', 'n');
    RAISE EXCEPTION 'FAIL: a key was wrapped for somebody outside the room';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  a key cannot be wrapped for a non-member';
END $$;

DO $$
BEGIN
  BEGIN
    INSERT INTO messages (channel_id, ciphertext, nonce, signature, key_version)
    VALUES ('aaaa1111-0000-4000-8000-00000000ffff', 'intruder', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a non-member posted into a private channel';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM set_channel_members('aaaa1111-0000-4000-8000-00000000ffff',
                                ARRAY['11111111-aaaa-4aaa-8aaa-000000000001']::UUID[]);
    RAISE EXCEPTION 'FAIL: a non-member added herself to a private channel';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  nobody talks their way in from outside';
END $$;

-- ---------- being let in ----------
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  PERFORM set_channel_members('aaaa1111-0000-4000-8000-00000000ffff',
    ARRAY['11111111-aaaa-4aaa-8aaa-000000000002',
          '11111111-aaaa-4aaa-8aaa-000000000003']::UUID[]);
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000003","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM channels
                  WHERE id = 'aaaa1111-0000-4000-8000-00000000ffff') THEN
    RAISE EXCEPTION 'FAIL: a member cannot see the channel she was added to';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'secret-from-bob') THEN
    RAISE EXCEPTION 'FAIL: a member cannot read the channel she was added to';
  END IF;
  RAISE NOTICE 'ok  being added is being able to see it';
END $$;

-- Access by role, resolved through to the people: adding a role means whoever
-- holds it, including whoever is given it tomorrow.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_admin UUID;
BEGIN
  SELECT id INTO v_admin FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND name = 'Admin';
  PERFORM set_channel_role_access('aaaa1111-0000-4000-8000-00000000ffff',
                                  v_admin, true);
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM channels
                  WHERE id = 'aaaa1111-0000-4000-8000-00000000ffff') THEN
    RAISE EXCEPTION 'FAIL: a role grant did not reach the people holding it';
  END IF;
  -- ...and now the keyring will take her, which is the whole difference
  -- between being allowed in and being able to read.
  INSERT INTO channel_keyring
    (channel_id, key_version, user_id, wrapped_by, ephemeral_public_key, ciphertext, nonce)
  VALUES ('aaaa1111-0000-4000-8000-00000000ffff', 1,
          '11111111-aaaa-4aaa-8aaa-000000000001',
          '11111111-aaaa-4aaa-8aaa-000000000001', 'eph', 'ct', 'n');
  RAISE NOTICE 'ok  access by role reaches the keyring, not just the policy';
END $$;

-- ---------- opening it back up ----------
-- The marker is the whole of private → public. Without it, flipping the flag
-- hands the next person to join the server the key the private conversation is
-- still being written under.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_mark INTEGER;
BEGIN
  PERFORM set_channel_private('aaaa1111-0000-4000-8000-00000000ffff', false);
  SELECT rotate_from_key_version INTO v_mark FROM channels
   WHERE id = 'aaaa1111-0000-4000-8000-00000000ffff';
  IF v_mark IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'FAIL: opening a channel left no rotation mark, got %', v_mark;
  END IF;
  RAISE NOTICE 'ok  opening a channel leaves a rotation to do first';
END $$;

-- And it cannot be done the quiet way. A plain UPDATE would skip the mark, and
-- the channel would hand its private history to the next arrival.
DO $$
BEGIN
  BEGIN
    UPDATE channels SET is_private = true
     WHERE id = 'aaaa1111-0000-4000-8000-00000000ffff';
    RAISE EXCEPTION 'FAIL: is_private was writable by hand';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  privacy changes only through the function that knows why';
END $$;

-- ---------- the last person out ----------
DO $$
BEGIN
  PERFORM set_channel_private('aaaa1111-0000-4000-8000-00000000ffff', true);
  -- Closing seats everybody who was there, and the closer can run it.
  IF NOT EXISTS (SELECT 1 FROM channel_members
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-00000000ffff'
                    AND user_id = '11111111-aaaa-4aaa-8aaa-000000000001') THEN
    RAISE EXCEPTION 'FAIL: closing a channel dropped somebody who was in it';
  END IF;

  -- Bob hands it to carol by leaving. Longest-serving wins, and carol was
  -- added before alice.
  PERFORM set_channel_members('aaaa1111-0000-4000-8000-00000000ffff',
    ARRAY['11111111-aaaa-4aaa-8aaa-000000000003',
          '11111111-aaaa-4aaa-8aaa-000000000001']::UUID[]);
END $$;

-- Asked from inside, deliberately. Bob has just removed himself, and to him the
-- room no longer exists — so a check made as bob would have passed whether the
-- manage bit moved or not, and would have passed if the channel had been
-- deleted outright.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000003","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM channel_members
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-00000000ffff'
                    AND user_id = '11111111-aaaa-4aaa-8aaa-000000000003'
                    AND can_manage) THEN
    RAISE EXCEPTION 'FAIL: the manage bit did not move to the longest-serving member';
  END IF;
  IF EXISTS (SELECT 1 FROM channel_members
              WHERE channel_id = 'aaaa1111-0000-4000-8000-00000000ffff'
                AND user_id = '11111111-aaaa-4aaa-8aaa-000000000002') THEN
    RAISE EXCEPTION 'FAIL: bob is still in a room he left';
  END IF;
  RAISE NOTICE 'ok  a room without a manager promotes whoever has been there longest';
END $$;

DO $$
BEGIN
  PERFORM set_channel_members('aaaa1111-0000-4000-8000-00000000ffff',
                              ARRAY[]::UUID[]);
END $$;

-- And this one has to be asked from outside the policies altogether. To every
-- member left alive, a deleted private channel and a hidden one look exactly
-- the same — and they are not the same at all, so the assertion is made as the
-- superuser, where RLS is not answering.
RESET ROLE;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM channels
              WHERE id = 'aaaa1111-0000-4000-8000-00000000ffff') THEN
    RAISE EXCEPTION 'FAIL: an empty private channel survived';
  END IF;
  -- Nobody could have seen it and nobody could have read it, so there is
  -- nothing to keep and nobody left who could ask for it back.
  IF EXISTS (SELECT 1 FROM messages
              WHERE channel_id = 'aaaa1111-0000-4000-8000-00000000ffff') THEN
    RAISE EXCEPTION 'FAIL: the messages outlived the channel';
  END IF;
  RAISE NOTICE 'ok  the last person out takes the room with them';
END $$;

SET LOCAL ROLE authenticated;

-- ---------- walking out ----------
-- Leaving is not a manager's act. `set_channel_members` needs the manage bit,
-- which is the right answer for who *else* is in a room and the wrong one for
-- whether you are — so somebody added to a private channel could not get out of
-- it without asking the person who put them there (023).
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_channel UUID; v_result JSONB;
BEGIN
  v_channel := (create_channel('exit-row', 'text', true,
                  ARRAY['11111111-aaaa-4aaa-8aaa-000000000003']::UUID[])
                ->>'id')::UUID;

  PERFORM set_config('request.jwt.claims',
    '{"sub":"11111111-aaaa-4aaa-8aaa-000000000003","role":"authenticated"}', true);

  -- Carol holds no manage bit here, which is the whole point of the test.
  IF EXISTS (SELECT 1 FROM channel_members
              WHERE channel_id = v_channel
                AND user_id = '11111111-aaaa-4aaa-8aaa-000000000003'
                AND can_manage) THEN
    RAISE EXCEPTION 'FAIL: the fixture gave the leaver the manage bit';
  END IF;

  v_result := leave_channel(v_channel);
  IF v_result->>'reason' <> 'ok' THEN
    RAISE EXCEPTION 'FAIL: a member could not leave: %', v_result;
  END IF;
  IF EXISTS (SELECT 1 FROM channels WHERE id = v_channel) THEN
    RAISE EXCEPTION 'FAIL: the room is still visible to somebody who left it';
  END IF;
  RAISE NOTICE 'ok  leaving needs nobody''s permission';
END $$;

-- Access through a role is not yours to give up: deleting your own row would
-- leave you in the room and the button looking broken, and dropping the role
-- grant would take everybody holding that role out with you.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_channel UUID; v_role UUID; v_result JSONB;
BEGIN
  v_channel := (create_channel('role-room', 'text', true, ARRAY[]::UUID[])
                ->>'id')::UUID;
  SELECT id INTO v_role FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001'
     AND name = 'Moderator';
  PERFORM set_channel_role_access(v_channel, v_role, true);

  PERFORM set_config('request.jwt.claims',
    '{"sub":"11111111-aaaa-4aaa-8aaa-000000000003","role":"authenticated"}', true);

  IF NOT EXISTS (SELECT 1 FROM channels WHERE id = v_channel) THEN
    RAISE EXCEPTION 'FAIL: a role grant did not let its holder in';
  END IF;

  v_result := leave_channel(v_channel);
  IF v_result->>'reason' <> 'in_by_role' THEN
    RAISE EXCEPTION 'FAIL: leaving a role-granted channel returned %', v_result;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM channels WHERE id = v_channel) THEN
    RAISE EXCEPTION 'FAIL: the refusal removed them anyway';
  END IF;
  RAISE NOTICE 'ok  you cannot walk out of a room a role put you in';
END $$;

-- ============================================================
-- 14. The bot key grant (017, 028)
-- ============================================================
-- The one grant that spends the trust model. Everything else a bot can do was
-- arranged so it never needs a key; this hands one over, and the four rules in
-- BOTS.md §6 are what make it something you can offer rather than regret.

RESET ROLE;

INSERT INTO auth.users (id) VALUES ('11111111-aaaa-4aaa-8aaa-0000000000b0');
INSERT INTO users (id, server_id, username, display_name, public_key, stable_id,
                   chat_public_key, is_bot)
VALUES ('11111111-aaaa-4aaa-8aaa-0000000000b0',
        'aaaa0000-0000-4000-8000-000000000001',
        'modbot', 'ModBot', 'pk-bot', 'sid-bot', 'chat-bot', true);

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF grant_bot_channel_key('11111111-aaaa-4aaa-8aaa-0000000000b0',
                           'aaaa1111-0000-4000-8000-000000000001')->>'reason'
     <> 'forbidden' THEN
    RAISE EXCEPTION 'FAIL: a plain member handed a bot a channel key';
  END IF;
  RAISE NOTICE 'ok  handing a bot a key needs MANAGE_BOTS';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
-- Counted rather than compared by id: the fixtures above insert messages with
-- explicit ids in the 9000s, which are far above the sequence, so a row this
-- function really writes comes out *below* them.
DECLARE v_result JSONB; v_before INT;
BEGIN
  SELECT count(*) INTO v_before FROM messages
   WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000001'
     AND origin_name = 'Rift';

  v_result := grant_bot_channel_key('11111111-aaaa-4aaa-8aaa-0000000000b0',
                                    'aaaa1111-0000-4000-8000-000000000001');
  IF v_result->>'reason' <> 'ok' THEN
    RAISE EXCEPTION 'FAIL: an admin could not grant: %', v_result;
  END IF;

  -- Forward-only. The channel has no keyring in this fixture, so the floor is
  -- 1 — the version its first member will bootstrap, with no history behind it.
  IF (v_result->>'from_key_version')::INT < 1 THEN
    RAISE EXCEPTION 'FAIL: the grant reaches back before it was made';
  END IF;

  -- Rule 4, the half a header chip cannot do: the people already in the room
  -- when it happened.
  IF (SELECT count(*) FROM messages
       WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000001'
         AND origin_name = 'Rift'
         AND key_version = 0
         AND ciphertext LIKE '%ModBot%') <> v_before + 1 THEN
    RAISE EXCEPTION 'FAIL: the grant left no trace in the channel';
  END IF;
  RAISE NOTICE 'ok  a grant says so in the channel it was made in';
END $$;

-- The system message is written with the claim dropped, so `attest_message`
-- leaves it alone. If that restore ever stopped happening, everything after it
-- in the same transaction would be running as nobody.
DO $$
BEGIN
  IF app.server_id() IS DISTINCT FROM 'aaaa0000-0000-4000-8000-000000000001' THEN
    RAISE EXCEPTION 'FAIL: the session was left without a claim';
  END IF;
  RAISE NOTICE 'ok  the caller gets their session back afterwards';
END $$;

DO $$
DECLARE v_before INT;
BEGIN
  SELECT count(*) INTO v_before FROM messages
   WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000001'
     AND origin_name = 'Rift';

  PERFORM revoke_bot_channel_key('11111111-aaaa-4aaa-8aaa-0000000000b0',
                                 'aaaa1111-0000-4000-8000-000000000001');
  IF EXISTS (SELECT 1 FROM bot_channel_keys
              WHERE bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: the grant survived being revoked';
  END IF;
  IF (SELECT count(*) FROM messages
       WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000001'
         AND origin_name = 'Rift') <> v_before + 1 THEN
    RAISE EXCEPTION 'FAIL: taking it away was quieter than giving it';
  END IF;
  RAISE NOTICE 'ok  and says so again when it is taken away';
END $$;

-- ============================================================
-- 15. The server-wide bot grant (030)
-- ============================================================
-- The rule that keeps per-channel granting honest rather than merely strict:
-- an admin who has to tick thirty boxes will ask for one button, and the button
-- somebody eventually builds without thinking about it is the dangerous one.

RESET ROLE;

INSERT INTO channels (id, server_id, name, channel_type) VALUES
  ('aaaa1111-0000-4000-8000-0000000000c1',
   'aaaa0000-0000-4000-8000-000000000001', 'lobby', 'text'),
  ('aaaa1111-0000-4000-8000-0000000000c2',
   'aaaa0000-0000-4000-8000-000000000001', 'shed', 'text');

INSERT INTO channel_members (channel_id, user_id, can_manage)
VALUES ('aaaa1111-0000-4000-8000-0000000000c2',
        '11111111-aaaa-4aaa-8aaa-000000000001', true);
UPDATE channels SET is_private = true
 WHERE id = 'aaaa1111-0000-4000-8000-0000000000c2';

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

-- ---------- 022: the whole server, in one question ----------
-- Five selects run one after another became one RPC. It answers under the
-- same policies, so what is asserted here is that nothing was dropped on the
-- way — including the two columns the old select never listed.

DO $$
DECLARE v JSONB; v_chan JSONB;
BEGIN
  RESET ROLE;
  UPDATE servers SET dm_retention_days = 7, dm_history_cap = 40
   WHERE id = 'aaaa0000-0000-4000-8000-000000000001';
  EXECUTE 'SET LOCAL ROLE authenticated';

  v := get_server_details();

  IF v->>'server_id' <> 'aaaa0000-0000-4000-8000-000000000001'
     OR v->>'name' IS NULL THEN
    RAISE EXCEPTION 'FAIL: the answer does not identify the server: %', v;
  END IF;

  -- The caller's own row, with the bits `my_permissions()` used to be a
  -- separate round trip for.
  IF v->'user'->>'id' <> '11111111-aaaa-4aaa-8aaa-000000000001' THEN
    RAISE EXCEPTION 'FAIL: the answer carries somebody else''s row: %', v->'user';
  END IF;
  IF NOT (v->'user'->'permissions' ? 'permission_bits') THEN
    RAISE EXCEPTION 'FAIL: the permission bits did not come with the row';
  END IF;
  IF (v->'user'->'permissions'->>'permission_bits')::BIGINT
       IS DISTINCT FROM my_permissions() THEN
    RAISE EXCEPTION 'FAIL: the bits in the answer are not the caller''s';
  END IF;

  -- The two the old select never asked for. The DM settings dialog writes
  -- them through update_server and read them back as null every time, so an
  -- operator who capped DMs watched the dialog forget it on every refresh.
  IF (v->>'dm_retention_days')::INT <> 7 OR (v->>'dm_history_cap')::INT <> 40 THEN
    RAISE EXCEPTION 'FAIL: the DM limits are missing from the answer: %', v;
  END IF;
  IF NOT (v ? 'max_attachment_bytes') THEN
    RAISE EXCEPTION 'FAIL: the operator limits are missing from the answer';
  END IF;

  -- The manage seat, which used to be a sixth read of `channel_members`.
  -- Alice holds it on the private `shed` and on nothing else.
  SELECT c INTO v_chan FROM jsonb_array_elements(v->'channels') c
   WHERE c->>'id' = 'aaaa1111-0000-4000-8000-0000000000c2';
  IF v_chan IS NULL OR (v_chan->>'can_manage')::BOOLEAN IS NOT TRUE THEN
    RAISE EXCEPTION 'FAIL: the private channel alice manages says %', v_chan;
  END IF;
  SELECT c INTO v_chan FROM jsonb_array_elements(v->'channels') c
   WHERE c->>'id' = 'aaaa1111-0000-4000-8000-0000000000c1';
  IF (v_chan->>'can_manage')::BOOLEAN IS NOT FALSE THEN
    RAISE EXCEPTION 'FAIL: a public channel came back as managed: %', v_chan;
  END IF;

  -- Whatever `channels_select` allows, and nothing besides.
  IF jsonb_array_length(v->'channels') <> (SELECT count(*) FROM channels) THEN
    RAISE EXCEPTION 'FAIL: the answer lists % channels where the policy allows %',
      jsonb_array_length(v->'channels'), (SELECT count(*) FROM channels);
  END IF;

  RESET ROLE;
  UPDATE servers SET dm_retention_days = NULL, dm_history_cap = NULL
   WHERE id = 'aaaa0000-0000-4000-8000-000000000001';
  EXECUTE 'SET LOCAL ROLE authenticated';
  RAISE NOTICE 'ok  one call carries the server, its limits, its channels and you';
END $$;

-- Nobody's row, nothing to refresh. The client turns this into dropping the
-- server rather than showing an empty one.
DO $$
DECLARE v JSONB;
BEGIN
  PERFORM set_config('request.jwt.claims',
    '{"sub":"99999999-9999-4999-8999-999999999999","role":"authenticated"}', true);
  v := get_server_details();
  IF v IS NOT NULL THEN
    RAISE EXCEPTION 'FAIL: a stranger was answered with %', v;
  END IF;
  PERFORM set_config('request.jwt.claims',
    '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true);
  RAISE NOTICE 'ok  and answers nothing at all to somebody with no row here';
END $$;

DO $$
DECLARE v_result JSONB;
BEGIN
  v_result := grant_bot_server_key('11111111-aaaa-4aaa-8aaa-0000000000b0');
  IF v_result->>'reason' <> 'ok' THEN
    RAISE EXCEPTION 'FAIL: an admin could not grant the server: %', v_result;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM bot_channel_keys
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000c1') THEN
    RAISE EXCEPTION 'FAIL: a public channel was left out of a server grant';
  END IF;

  -- The carve-out, and the whole reason 020 wrote `is_private` before there
  -- were private channels to write it for.
  IF EXISTS (SELECT 1 FROM bot_channel_keys
              WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000c2') THEN
    RAISE EXCEPTION 'FAIL: a server-wide grant reached into a private channel';
  END IF;
  RAISE NOTICE 'ok  a server grant covers the public channels and no others';
END $$;

-- Intent, not a snapshot: a channel made afterwards is covered, or an admin
-- grants a bot the server, adds a channel, and the bot silently does not work
-- there.
DO $$
DECLARE v_new UUID;
BEGIN
  v_new := (create_channel('added-later', 'text', false, ARRAY[]::UUID[])
            ->>'id')::UUID;
  IF NOT EXISTS (SELECT 1 FROM bot_channel_keys WHERE channel_id = v_new) THEN
    RAISE EXCEPTION 'FAIL: a channel made after the grant was not covered';
  END IF;

  -- ...and one made private is not, for the same reason as the first.
  v_new := (create_channel('added-private', 'text', true, ARRAY[]::UUID[])
            ->>'id')::UUID;
  IF EXISTS (SELECT 1 FROM bot_channel_keys WHERE channel_id = v_new) THEN
    RAISE EXCEPTION 'FAIL: a private channel made after the grant was covered';
  END IF;
  RAISE NOTICE 'ok  a channel made later is covered, unless it is private';
END $$;

-- Closing a channel takes it out of the grant without cancelling the grant.
-- This is the case a trigger on `bot_channel_keys` got wrong: every deletion
-- looks the same to a row, and only one of them is somebody deciding.
DO $$
BEGIN
  PERFORM set_channel_private('aaaa1111-0000-4000-8000-0000000000c1', true);

  IF EXISTS (SELECT 1 FROM bot_channel_keys
              WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000c1') THEN
    RAISE EXCEPTION 'FAIL: a closed channel kept its server-wide grant';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM bot_server_grants
                  WHERE bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: closing one channel cancelled the whole grant';
  END IF;
  RAISE NOTICE 'ok  closing a channel drops it from the grant, not the grant';
END $$;

-- Revoking one *is* somebody deciding, and it means "not the whole server any
-- more". The channels it already covers keep their rows.
DO $$
DECLARE v_covered INT;
BEGIN
  SELECT count(*) INTO v_covered FROM bot_channel_keys
    JOIN channels c ON c.id = bot_channel_keys.channel_id
   WHERE c.server_id = 'aaaa0000-0000-4000-8000-000000000001';

  PERFORM revoke_bot_channel_key('11111111-aaaa-4aaa-8aaa-0000000000b0',
                                 'aaaa1111-0000-4000-8000-000000000001');

  IF EXISTS (SELECT 1 FROM bot_server_grants
              WHERE bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: naming one channel left the grant server-wide';
  END IF;
  IF (SELECT count(*) FROM bot_channel_keys
        JOIN channels c ON c.id = bot_channel_keys.channel_id
       WHERE c.server_id = 'aaaa0000-0000-4000-8000-000000000001')
     <> v_covered - 1 THEN
    RAISE EXCEPTION 'FAIL: downgrading took more than the one channel named';
  END IF;
  RAISE NOTICE 'ok  revoking one channel downgrades rather than cancels';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF grant_bot_server_key('11111111-aaaa-4aaa-8aaa-0000000000b0')->>'reason'
     <> 'forbidden' THEN
    RAISE EXCEPTION 'FAIL: a plain member granted a bot the whole server';
  END IF;
  RAISE NOTICE 'ok  granting the server needs MANAGE_BOTS too';
END $$;

-- ============================================================
-- 16. What a bot may hear (031)
-- ============================================================
-- Voice was the one place BOTS.md's rule was simply false: `get_channel_token`
-- never asked what the caller was, `@everyone` carries CONNECT and SPEAK, and
-- the token said `canSubscribe`. A bot could sit in a call and receive
-- everybody's audio with nothing shown in the room.
--
-- The table below is what the edge function reads to decide. These tests are
-- about who may write it — the mint itself is TypeScript and out of reach from
-- here, which is exactly why the row has to be the thing that is hard to get.

RESET ROLE;

INSERT INTO channels (id, server_id, name, channel_type) VALUES
  ('aaaa1111-0000-4000-8000-0000000000d1',
   'aaaa0000-0000-4000-8000-000000000001', 'stage', 'voice');

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF grant_bot_voice_listen('11111111-aaaa-4aaa-8aaa-0000000000b0',
                            'aaaa1111-0000-4000-8000-0000000000d1')->>'reason'
     <> 'ok' THEN
    RAISE EXCEPTION 'FAIL: an admin could not let a bot listen';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM bot_voice_grants
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000d1'
                    AND bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: the grant was not recorded';
  END IF;
  RAISE NOTICE 'ok  an admin can let a bot hear a voice channel';
END $$;

-- The marker every member reads. A grant nobody in the room can see is the one
-- thing this design does not allow (BOTS.md §6, rule 4).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM voice_listeners
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000d1'
                    AND bot_name = 'ModBot') THEN
    RAISE EXCEPTION 'FAIL: the channel does not say who is listening';
  END IF;
  RAISE NOTICE 'ok  the channel says which bot can hear it, by name';
END $$;

-- A text channel has no call to hear, and a grant on one would be a row the
-- token mint never reads — a switch that looks like it does something.
DO $$
BEGIN
  IF grant_bot_voice_listen('11111111-aaaa-4aaa-8aaa-0000000000b0',
                            'aaaa1111-0000-4000-8000-000000000001')->>'reason'
     <> 'not_a_voice_channel' THEN
    RAISE EXCEPTION 'FAIL: a text channel accepted a voice grant';
  END IF;
  RAISE NOTICE 'ok  only a voice channel can be listened to';
END $$;

-- Closing a channel re-asks the question. Whoever allowed this was looking at a
-- room the whole server could walk into.
DO $$
BEGIN
  PERFORM set_channel_private('aaaa1111-0000-4000-8000-0000000000d1', true);
  IF EXISTS (SELECT 1 FROM bot_voice_grants
              WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000d1') THEN
    RAISE EXCEPTION 'FAIL: a channel made private kept its listener';
  END IF;
  RAISE NOTICE 'ok  making a channel private takes the listener out of it';
END $$;

-- And a plain member cannot put one back, in a channel they are now in.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF grant_bot_voice_listen('11111111-aaaa-4aaa-8aaa-0000000000b0',
                            'aaaa1111-0000-4000-8000-0000000000d1')->>'reason'
     = 'ok' THEN
    RAISE EXCEPTION 'FAIL: a plain member let a bot into a call';
  END IF;
  RAISE NOTICE 'ok  letting a bot listen needs MANAGE_BOTS';
END $$;

-- Nobody writes the table directly. Every rule above is in the function, and a
-- client that could insert its own row would have none of them applied.
--
-- `SET LOCAL ROLE` and not merely a claim: the checks above run as the owner
-- with a JWT claim set, which is enough for `app.has_perm` and not for a column
-- grant. A test for a grant has to actually be the role. New public tables
-- arrive writable by `authenticated` on Supabase, so this is the assertion that
-- 031's REVOKE was not forgotten.
SET LOCAL ROLE authenticated;

DO $$
BEGIN
  BEGIN
    INSERT INTO bot_voice_grants (channel_id, bot_id)
    VALUES ('aaaa1111-0000-4000-8000-0000000000d1',
            '11111111-aaaa-4aaa-8aaa-0000000000b0');
    RAISE EXCEPTION 'FAIL: a member inserted a voice grant directly';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  the grant table takes no writes from anybody';
END $$;

-- ============================================================
-- 17. The key a bot speaks with (032)
-- ============================================================
-- End-to-end encrypted calls took away the mechanism 031 had just built: a bot
-- has to encrypt to be audible, and with one key per room the key that encrypts
-- also decrypts. The fix is two keys — members use the channel key, a bot uses
-- HMAC(channelKey, 'voicebot:v1:<botId>') — and this table is where the second
-- one is put, sealed by a member.
--
-- The bytes are opaque here. What the database decides is *who may write one*
-- and *which of the two kinds it claims to be*.

RESET ROLE;

INSERT INTO channels (id, server_id, name, channel_type) VALUES
  ('aaaa1111-0000-4000-8000-0000000000e1',
   'aaaa0000-0000-4000-8000-000000000001', 'booth', 'voice');

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;
SET LOCAL ROLE authenticated;

-- A plain member seals the publish key. No grant needed and none consulted:
-- speaking was never the half that had to be allowed.
DO $$
BEGIN
  INSERT INTO bot_voice_keys (channel_id, bot_id, key_version, is_channel_key,
                              wrapped_by, ephemeral_public_key, ciphertext, nonce)
  VALUES ('aaaa1111-0000-4000-8000-0000000000e1',
          '11111111-aaaa-4aaa-8aaa-0000000000b0', 1, false,
          '11111111-aaaa-4aaa-8aaa-000000000002', 'eph', 'ct', 'n');
  RAISE NOTICE 'ok  any member can seal a bot the key it speaks with';
END $$;

-- But not the channel key. Claiming to hand over the real thing is the one
-- claim the server can check, and it checks it against the grant.
DO $$
BEGIN
  BEGIN
    INSERT INTO bot_voice_keys (channel_id, bot_id, key_version, is_channel_key,
                                wrapped_by, ephemeral_public_key, ciphertext, nonce)
    VALUES ('aaaa1111-0000-4000-8000-0000000000e1',
            '11111111-aaaa-4aaa-8aaa-0000000000b0', 2, true,
            '11111111-aaaa-4aaa-8aaa-000000000002', 'eph', 'ct', 'n');
    RAISE EXCEPTION 'FAIL: a member handed a bot the channel key with no grant';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  the channel key needs a listening grant to be sealed';
END $$;

RESET ROLE;

-- Granting drops what was sealed before it. Otherwise the bot keeps encrypting
-- with a key nobody looks for and stays inaudible after being promoted.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  PERFORM grant_bot_voice_listen('11111111-aaaa-4aaa-8aaa-0000000000b0',
                                 'aaaa1111-0000-4000-8000-0000000000e1');
  IF EXISTS (SELECT 1 FROM bot_voice_keys
              WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000e1') THEN
    RAISE EXCEPTION 'FAIL: granting left the old publish key in place';
  END IF;
  RAISE NOTICE 'ok  changing a grant clears the key sealed under the old one';
END $$;

-- And now the channel key is allowed, because the grant says so.
SET LOCAL ROLE authenticated;
DO $$
BEGIN
  INSERT INTO bot_voice_keys (channel_id, bot_id, key_version, is_channel_key,
                              wrapped_by, ephemeral_public_key, ciphertext, nonce)
  VALUES ('aaaa1111-0000-4000-8000-0000000000e1',
          '11111111-aaaa-4aaa-8aaa-0000000000b0', 1, true,
          '11111111-aaaa-4aaa-8aaa-000000000001', 'eph', 'ct', 'n');
  RAISE NOTICE 'ok  a granted bot may be sealed the channel key itself';
END $$;

RESET ROLE;

-- A bot writes nothing here. It has no channel key to derive from, so a row
-- from a bot is either nonsense or one bot handing another something it was
-- never given.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-0000000000b0","role":"authenticated"}', true); END $$;
SET LOCAL ROLE authenticated;

DO $$
BEGIN
  BEGIN
    INSERT INTO bot_voice_keys (channel_id, bot_id, key_version, is_channel_key,
                                wrapped_by, ephemeral_public_key, ciphertext, nonce)
    VALUES ('aaaa1111-0000-4000-8000-0000000000e1',
            '11111111-aaaa-4aaa-8aaa-0000000000b0', 3, false,
            '11111111-aaaa-4aaa-8aaa-0000000000b0', 'eph', 'ct', 'n');
    RAISE EXCEPTION 'FAIL: a bot sealed itself a voice key';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  a bot cannot write its own key material';
END $$;

-- It can read the one sealed for it, which is the whole point of the table.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM bot_voice_keys
                  WHERE bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: a bot cannot read the key sealed to it';
  END IF;
  RAISE NOTICE 'ok  and can read the one a member sealed for it';
END $$;

-- ============================================================
-- 18. Who a message can reach (034, asked through 039)
-- ============================================================
-- The question the composer asks so its `@` and `/` menus stop offering names
-- the trigger will strip. Three things have to hold or it is worse than the
-- roster it replaced: it resolves roles, it excludes outsiders, and an outsider
-- asking gets nothing rather than a membership list.
--
-- 034 answered it as a whole set (`channel_audience`); 039 answers it as a
-- filter on `list_members`, which is the same predicate asked a page at a time.
-- The cases below are 034's, moved onto the call that replaced it — the
-- coverage is about the rule, not about which function carries it.

RESET ROLE;

INSERT INTO auth.users (id) VALUES ('11111111-aaaa-4aaa-8aaa-0000000000a1');
INSERT INTO users (id, server_id, username, display_name, public_key, stable_id,
                   chat_public_key)
VALUES ('11111111-aaaa-4aaa-8aaa-0000000000a1',
        'aaaa0000-0000-4000-8000-000000000001',
        'dana', 'Dana', 'pk-dana', 'sid-dana', 'chat-dana');

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

-- Bob's room. Carol is in it by name; alice will get in by role; dana never
-- does; the bot is eligible, because it can hold a key.
DO $$
DECLARE v_role UUID;
BEGIN
  INSERT INTO channels (id, server_id, name, channel_type, is_private)
  VALUES ('aaaa1111-0000-4000-8000-0000000000a0',
          'aaaa0000-0000-4000-8000-000000000001', 'audience', 'text', true);
  PERFORM set_channel_members('aaaa1111-0000-4000-8000-0000000000a0',
    ARRAY['11111111-aaaa-4aaa-8aaa-000000000002',
          '11111111-aaaa-4aaa-8aaa-000000000003',
          '11111111-aaaa-4aaa-8aaa-0000000000b0']::UUID[]);

  SELECT id INTO v_role FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND name = 'Admin';
  PERFORM set_channel_role_access('aaaa1111-0000-4000-8000-0000000000a0',
                                  v_role, true);
END $$;

DO $$
DECLARE v_seen UUID[];
BEGIN
  SELECT array_agg(id ORDER BY id) INTO v_seen
    FROM list_members(p_channel => 'aaaa1111-0000-4000-8000-0000000000a0',
                      p_limit => 100);

  IF NOT ('11111111-aaaa-4aaa-8aaa-000000000003' = ANY(v_seen)) THEN
    RAISE EXCEPTION 'FAIL: somebody seated by name is not in the audience';
  END IF;
  -- The one a client could not work out for itself without re-implementing
  -- `in_channel`: alice is nowhere in `channel_members`.
  IF NOT ('11111111-aaaa-4aaa-8aaa-000000000001' = ANY(v_seen)) THEN
    RAISE EXCEPTION 'FAIL: a role grant did not resolve into the audience';
  END IF;
  IF '11111111-aaaa-4aaa-8aaa-0000000000a1' = ANY(v_seen) THEN
    RAISE EXCEPTION 'FAIL: somebody outside the room is in its audience';
  END IF;
  -- Not the bot: `set_channel_members` refuses to seat one by name, so it was
  -- never in. This is also the answer to who a `/` command reaches here —
  -- `messages_select` asks `can_see_channel` before it asks `to_bot`, so a
  -- command to a bot outside the room is a plaintext row nobody collects.
  IF '11111111-aaaa-4aaa-8aaa-0000000000b0' = ANY(v_seen) THEN
    RAISE EXCEPTION 'FAIL: a bot was seated in a private channel';
  END IF;
  RAISE NOTICE 'ok  the audience is everybody in the room, by name or by role';
END $$;

-- A role is the bot's one door, and it is a real one: the composer's `/` menu
-- reads this list, so a bot let in this way is offered and a bot outside is
-- not. Without it the command goes out in the clear addressed to somebody
-- `messages_select` will never hand it to.
RESET ROLE;
INSERT INTO member_roles (user_id, role_id)
SELECT '11111111-aaaa-4aaa-8aaa-0000000000b0', id FROM roles
 WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND name = 'Admin'
ON CONFLICT DO NOTHING;
SET LOCAL ROLE authenticated;

DO $$
BEGIN
  IF NOT EXISTS (
       SELECT 1 FROM list_members(
                       p_channel => 'aaaa1111-0000-4000-8000-0000000000a0',
                       p_bots => true, p_limit => 100)
        WHERE id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: a role did not let a bot into a private channel';
  END IF;
  -- And that is not a formality: it is exactly what `messages_select` asks
  -- before it asks `to_bot`, so this bot can now be sent a `/` command here.
  IF NOT EXISTS (SELECT 1 FROM channel_members
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000a0'
                    AND user_id = '11111111-aaaa-4aaa-8aaa-000000000002') THEN
    RAISE EXCEPTION 'FAIL: the room emptied out from under this test';
  END IF;
  RAISE NOTICE 'ok  and a role is the one way a bot gets into one';
END $$;

RESET ROLE;
DELETE FROM member_roles
 WHERE user_id = '11111111-aaaa-4aaa-8aaa-0000000000b0'
   AND role_id = (SELECT id FROM roles
                   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001'
                     AND name = 'Admin');
SET LOCAL ROLE authenticated;

-- The same question a banned member's presence answers differently. A ban is
-- exactly where "still in the list" and "may still read" come apart, and the
-- menu must not offer somebody whose mention the trigger will drop. Carol
-- stays seated throughout — that is the point.
RESET ROLE;
UPDATE users SET is_banned = true WHERE id = '11111111-aaaa-4aaa-8aaa-000000000003';
SET LOCAL ROLE authenticated;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM channel_members
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000a0'
                    AND user_id = '11111111-aaaa-4aaa-8aaa-000000000003') THEN
    RAISE EXCEPTION 'FAIL: the ban removed her seat, so this proves nothing';
  END IF;
  IF EXISTS (
       SELECT 1 FROM list_members(
                       p_channel => 'aaaa1111-0000-4000-8000-0000000000a0',
                       p_limit => 100)
        WHERE id = '11111111-aaaa-4aaa-8aaa-000000000003') THEN
    RAISE EXCEPTION 'FAIL: a banned member is still in the audience';
  END IF;
  RAISE NOTICE 'ok  a ban takes somebody out of it without taking their seat';
END $$;

RESET ROLE;
UPDATE users SET is_banned = false WHERE id = '11111111-aaaa-4aaa-8aaa-000000000003';
SET LOCAL ROLE authenticated;

-- And the denial that makes the rest safe to expose: asking about a room you
-- are not in tells you nothing, rather than telling you who is in it.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-0000000000a1","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM list_members(
                      p_channel => 'aaaa1111-0000-4000-8000-0000000000a0',
                      p_limit => 100)) THEN
    RAISE EXCEPTION 'FAIL: an outsider read a private channel''s audience';
  END IF;
  RAISE NOTICE 'ok  an outsider asking gets an empty answer, not a roster';
END $$;

-- ============================================================
-- 19. What a granted bot actually reads (035)
-- ============================================================
-- 017 built the key half of the moderation grant and it was correct. It never
-- let the bot read a message: `messages_select` restricted every bot to what it
-- was addressed and what it wrote, and no later migration touched that. The
-- grant machinery was complete and the feature did nothing.
--
-- These are the tests that would have caught it, and the ones that keep the
-- boundary a number rather than a promise.

RESET ROLE;

INSERT INTO channels (id, server_id, name, channel_type) VALUES
  ('aaaa1111-0000-4000-8000-0000000000c5',
   'aaaa0000-0000-4000-8000-000000000001', 'watched', 'text');

-- Three versions of history and a plaintext row, then a grant that starts at 3.
INSERT INTO messages (channel_id, sender_id, ciphertext, nonce, signature, key_version)
VALUES ('aaaa1111-0000-4000-8000-0000000000c5',
        '11111111-aaaa-4aaa-8aaa-000000000002', 'said-before', 'n', 's', 1),
       ('aaaa1111-0000-4000-8000-0000000000c5',
        '11111111-aaaa-4aaa-8aaa-000000000002', 'said-after',  'n', 's', 3),
       ('aaaa1111-0000-4000-8000-0000000000c5',
        '11111111-aaaa-4aaa-8aaa-000000000002', 'in-the-clear', 'n', 's', 0);

-- Somebody else's ephemeral, sent after the grant starts. A grant is permission
-- to read the channel's conversation, not a reply one person was shown.
INSERT INTO messages (channel_id, sender_id, ephemeral_for, ciphertext, nonce, signature, key_version)
VALUES ('aaaa1111-0000-4000-8000-0000000000c5',
        '11111111-aaaa-4aaa-8aaa-000000000003',
        '11111111-aaaa-4aaa-8aaa-000000000002', 'for-bob-alone', 'n', 's', 3);

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-0000000000b0","role":"authenticated"}', true); END $$;

-- Before the grant: the state 017 shipped and 035 fixes.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'said-after') THEN
    RAISE EXCEPTION 'FAIL: an ungranted bot read a member''s message';
  END IF;
  RAISE NOTICE 'ok  a bot with no grant reads nothing but its own post';
END $$;

RESET ROLE;
INSERT INTO bot_channel_keys (channel_id, bot_id, granted_by, from_key_version)
VALUES ('aaaa1111-0000-4000-8000-0000000000c5',
        '11111111-aaaa-4aaa-8aaa-0000000000b0',
        '11111111-aaaa-4aaa-8aaa-000000000001', 3);
SET LOCAL ROLE authenticated;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'said-after') THEN
    RAISE EXCEPTION 'FAIL: a granted bot still cannot read the channel';
  END IF;
  RAISE NOTICE 'ok  a granted bot reads what was said after the grant';
END $$;

DO $$
BEGIN
  -- The whole point of `from_key_version`, now read on the way out with the
  -- same number `refuse_ineligible_keyring` enforces on the way in.
  IF EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'said-before') THEN
    RAISE EXCEPTION 'FAIL: the grant reached back before it was made';
  END IF;
  -- A plaintext row was never sealed under any version, so no grant covers it.
  -- Being strict here is what keeps another bot''s `/ask` out of this one.
  IF EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'in-the-clear') THEN
    RAISE EXCEPTION 'FAIL: a granted bot read a key_version 0 row';
  END IF;
  IF EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'for-bob-alone') THEN
    RAISE EXCEPTION 'FAIL: a granted bot read somebody else''s ephemeral';
  END IF;
  RAISE NOTICE 'ok  and nothing before it, in the clear, or meant for one person';
END $$;

-- Revoking stops it in the same statement. "It keeps what it already saw" is
-- about what has been unwrapped, not about a database it still gets to query.
RESET ROLE;
DELETE FROM bot_channel_keys
 WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000c5'
   AND bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0';
SET LOCAL ROLE authenticated;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'said-after') THEN
    RAISE EXCEPTION 'FAIL: a revoked bot is still reading';
  END IF;
  RAISE NOTICE 'ok  revoking stops the reading, not just the sealing';
END $$;

-- ---------- a private channel ----------
-- Allowed per-channel (BOTS.md §6: it is the *bulk* grant that never covers
-- one), and inert before this: `can_see_channel` asks about membership and
-- `set_channel_members` will not seat a bot, so the grant bought neither the
-- messages nor the bot's own wrapped key.

RESET ROLE;
INSERT INTO messages (channel_id, sender_id, ciphertext, nonce, signature, key_version)
VALUES ('aaaa1111-0000-4000-8000-0000000000a0',
        '11111111-aaaa-4aaa-8aaa-000000000002', 'behind-a-door', 'n', 's', 4);
INSERT INTO bot_channel_keys (channel_id, bot_id, granted_by, from_key_version)
VALUES ('aaaa1111-0000-4000-8000-0000000000a0',
        '11111111-aaaa-4aaa-8aaa-0000000000b0',
        '11111111-aaaa-4aaa-8aaa-000000000002', 4);
INSERT INTO channel_keyring
  (channel_id, key_version, user_id, wrapped_by, ephemeral_public_key, ciphertext, nonce)
VALUES ('aaaa1111-0000-4000-8000-0000000000a0', 4,
        '11111111-aaaa-4aaa-8aaa-0000000000b0',
        '11111111-aaaa-4aaa-8aaa-000000000002', 'eph', 'ct', 'n');
SET LOCAL ROLE authenticated;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM messages WHERE ciphertext = 'behind-a-door') THEN
    RAISE EXCEPTION 'FAIL: a private-channel grant reads nothing';
  END IF;
  -- Reading a sealed message is no use without the thing that opens it.
  IF NOT EXISTS (SELECT 1 FROM channel_keyring
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000a0'
                    AND user_id = auth.uid()) THEN
    RAISE EXCEPTION 'FAIL: the bot cannot reach its own wrapped key';
  END IF;
  RAISE NOTICE 'ok  a private channel can be granted, key and all';
END $$;

-- And it is a reader, not a member. Reading was the exception being made; the
-- rest of what membership means is not part of it.
DO $$
BEGIN
  IF app.can_see_channel('aaaa1111-0000-4000-8000-0000000000a0') THEN
    RAISE EXCEPTION 'FAIL: a grant made the bot a member of a private channel';
  END IF;
  IF EXISTS (SELECT 1 FROM channels
              WHERE id = 'aaaa1111-0000-4000-8000-0000000000a0') THEN
    RAISE EXCEPTION 'FAIL: a granted bot can see the private channel itself';
  END IF;
  -- The keyring is other people's wrapped keys as well as its own, and that is
  -- a list of who holds a key to this room.
  IF EXISTS (SELECT 1 FROM channel_keyring
              WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000a0'
                AND user_id <> auth.uid()) THEN
    RAISE EXCEPTION 'FAIL: a granted bot read somebody else''s keyring row';
  END IF;
  RAISE NOTICE 'ok  and a reader is all it is — not the room, not the roster';
END $$;

-- ============================================================
-- 20. Bots are three permissions, not one (036)
-- ============================================================
-- `MANAGE_BOTS` was carrying jobs of very different weight: handing over a
-- channel key, bringing a program into the server, and asking the music bot to
-- play something. The last of those has to be a thing every member can do, and
-- it was sitting behind the first.

DO $$
BEGIN
  IF app.perm('ADD_BOTS') = 0 OR app.perm('SUMMON_BOTS') = 0 THEN
    RAISE EXCEPTION 'FAIL: the new bits are not in perm_bit';
  END IF;
  -- A bit outside `perm_all` is one no role can ever be given: the role editor
  -- masks against it. Forgetting to widen it is the quiet way to ship a
  -- permission that cannot be granted.
  IF (app.perm_all() & app.perm('SUMMON_BOTS')) = 0 THEN
    RAISE EXCEPTION 'FAIL: SUMMON_BOTS is outside perm_all';
  END IF;
  RAISE NOTICE 'ok  the two new bits exist and are grantable';
END $$;

-- Every server gets summoning, including the ones that already existed. A
-- permission nobody holds looks exactly like a feature that is broken.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM roles
              WHERE is_everyone
                AND (permissions & app.perm('SUMMON_BOTS')) = 0) THEN
    RAISE EXCEPTION 'FAIL: an @everyone role did not get SUMMON_BOTS';
  END IF;
  RAISE NOTICE 'ok  summoning is on by default, on old servers too';
END $$;

-- ...and adding one is not. This is the half that is a real change: creating a
-- bot invite used to need nothing but CREATE_INVITE, the same bit as inviting
-- a friend.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM roles
              WHERE is_everyone
                AND (permissions & app.perm('ADD_BOTS')) <> 0) THEN
    RAISE EXCEPTION 'FAIL: ADD_BOTS was handed to everybody';
  END IF;
  RAISE NOTICE 'ok  and adding a bot is not';
END $$;

-- Somebody who may invite and holds nothing else, which is exactly the member
-- this bit was split out for — since 016 that is anybody holding no role at
-- all, because the baseline carries CREATE_INVITE. Carol will not do: she is
-- a Moderator by now, and Moderator is one of the roles that hold `ADD_BOTS`.
-- This member was inserted by hand above, so their cache is recomputed the way
-- registration would have.
RESET ROLE;
SELECT app.sync_permission_cache('11111111-aaaa-4aaa-8aaa-0000000000a1');
SET LOCAL ROLE authenticated;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-0000000000a1","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  -- Or the denial below proves nothing: a member who cannot invite at all is
  -- refused one clause earlier.
  IF NOT app.has_perm('CREATE_INVITE') THEN
    RAISE EXCEPTION 'FAIL: this subject cannot invite anybody, so the test is empty';
  END IF;
  IF app.has_perm('ADD_BOTS') THEN
    RAISE EXCEPTION 'FAIL: a plain inviter already holds ADD_BOTS';
  END IF;
END $$;

DO $$
BEGIN
  BEGIN
    INSERT INTO invites (server_id, created_by, code, is_bot)
    VALUES ('aaaa0000-0000-4000-8000-000000000001',
            '11111111-aaaa-4aaa-8aaa-0000000000a1', 'bot-invite-1', true);
    RAISE EXCEPTION 'FAIL: a plain inviter made a bot invite';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;

  -- The same person, the same permission, inviting a person: unchanged.
  INSERT INTO invites (server_id, created_by, code, is_bot)
  VALUES ('aaaa0000-0000-4000-8000-000000000001',
          '11111111-aaaa-4aaa-8aaa-0000000000a1', 'person-invite-1', false);
  RAISE NOTICE 'ok  inviting a person is untouched, inviting a bot is not';
END $$;

-- An admin is covered without a backfill, because `has_perm` reads
-- ADMINISTRATOR as every bit. Worth asserting: the alternative is a migration
-- that has to remember every role it should have widened.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT app.has_perm('ADD_BOTS') THEN
    RAISE EXCEPTION 'FAIL: an administrator cannot add a bot';
  END IF;
  INSERT INTO invites (server_id, created_by, code, is_bot)
  VALUES ('aaaa0000-0000-4000-8000-000000000001',
          '11111111-aaaa-4aaa-8aaa-000000000001', 'bot-invite-2', true);
  RAISE NOTICE 'ok  an administrator needs no backfill to hold a new bit';
END $$;

-- ============================================================
-- 21. Summoning a bot into a call (037)
-- ============================================================
-- The thing people most want a bot for, and it did not work in a private voice
-- channel at all: `channel_visible_to` said no, so there was no token, and
-- `bot_voice_key_candidates` said no, so there was nothing to speak with.
--
-- What makes a default permission safe here is what a summon *is not*. It is
-- not membership and it is not listening.

RESET ROLE;

INSERT INTO channels (id, server_id, name, channel_type, is_private) VALUES
  ('aaaa1111-0000-4000-8000-0000000000d7',
   'aaaa0000-0000-4000-8000-000000000001', 'green-room', 'voice', true);
INSERT INTO channel_members (channel_id, user_id)
VALUES ('aaaa1111-0000-4000-8000-0000000000d7',
        '11111111-aaaa-4aaa-8aaa-000000000002');

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_result JSONB;
BEGIN
  -- Before: the bot cannot get a token for a room it is not in.
  IF channel_joinable_by('aaaa1111-0000-4000-8000-0000000000d7',
                         '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: a bot could join a private call unasked';
  END IF;

  v_result := summon_bot_to_voice('11111111-aaaa-4aaa-8aaa-0000000000b0',
                                  'aaaa1111-0000-4000-8000-0000000000d7');
  IF v_result->>'reason' <> 'ok' THEN
    RAISE EXCEPTION 'FAIL: a member in the room could not summon: %', v_result;
  END IF;

  IF NOT channel_joinable_by('aaaa1111-0000-4000-8000-0000000000d7',
                             '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: the summon did not open the token gate';
  END IF;
  RAISE NOTICE 'ok  a member can call a bot into a private call';
END $$;

-- The half that makes `SUMMON_BOTS` safe on `@everyone`: in the room, not of
-- it. Every other caller asks `sees_channel` and still gets no.
DO $$
BEGIN
  IF channel_visible_to('aaaa1111-0000-4000-8000-0000000000d7',
                        '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: a summon made the bot a member of the channel';
  END IF;
  IF app.channel_eligible('aaaa1111-0000-4000-8000-0000000000d7',
                          '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: a summon made the bot eligible for the channel key';
  END IF;
  RAISE NOTICE 'ok  and that is all it does — no membership, no channel key';
END $$;

-- A summon is what puts a bot on the sealing list now, in a public channel as
-- well as a private one. Members' clients stop sealing for bots that never join.
-- Read as the owner: the view is service-role only, like the other four
-- answers 021 computes for the edge functions.
RESET ROLE;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM bot_voice_key_candidates
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000d7'
                    AND bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: a summoned bot is not on the sealing list';
  END IF;
  -- It publishes; it does not hear. `may_listen` is the separate admin grant.
  IF (SELECT may_listen FROM bot_voice_key_candidates
       WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000d7'
         AND bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: summoning granted listening';
  END IF;
  RAISE NOTICE 'ok  it gets a key to speak with, and no permission to hear';
END $$;

SET LOCAL ROLE authenticated;

-- The bot learns where it has been asked to go by reading its own row. It
-- cannot see the channel, so this is the only way it could.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-0000000000b0","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM bot_voice_summons
                  WHERE bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: a bot cannot see that it was summoned';
  END IF;
  RAISE NOTICE 'ok  and the bot can read the summons addressed to it';
END $$;

-- Dismissing takes the media key with it. Without that a dismissed bot keeps
-- something usable and only the token stands between it and the room.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  INSERT INTO bot_voice_keys (channel_id, bot_id, key_version, is_channel_key,
                              wrapped_by, ephemeral_public_key, ciphertext, nonce)
  VALUES ('aaaa1111-0000-4000-8000-0000000000d7',
          '11111111-aaaa-4aaa-8aaa-0000000000b0', 1, false,
          '11111111-aaaa-4aaa-8aaa-000000000002', 'eph', 'ct', 'n');

  PERFORM dismiss_bot_from_voice('11111111-aaaa-4aaa-8aaa-0000000000b0',
                                 'aaaa1111-0000-4000-8000-0000000000d7');

  IF channel_joinable_by('aaaa1111-0000-4000-8000-0000000000d7',
                         '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: a dismissed bot can still take a token';
  END IF;
  IF EXISTS (SELECT 1 FROM bot_voice_keys
              WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000d7'
                AND bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: dismissing left the media key behind';
  END IF;
  RAISE NOTICE 'ok  dismissing takes the key with it, not just the welcome';
END $$;

-- The permission, and the one shape of channel this is not for.
DO $$
DECLARE v_result JSONB;
BEGIN
  v_result := summon_bot_to_voice('11111111-aaaa-4aaa-8aaa-0000000000b0',
                                  'aaaa1111-0000-4000-8000-000000000001');
  IF v_result->>'reason' <> 'not_a_voice_channel' THEN
    RAISE EXCEPTION 'FAIL: a bot was summoned into a text channel: %', v_result;
  END IF;
  RAISE NOTICE 'ok  there is nothing to summon a bot into but a call';
END $$;

RESET ROLE;
UPDATE roles SET permissions = permissions & ~app.perm('SUMMON_BOTS')
 WHERE is_everyone AND server_id = 'aaaa0000-0000-4000-8000-000000000001';
SET LOCAL ROLE authenticated;

DO $$
DECLARE v_result JSONB;
BEGIN
  v_result := summon_bot_to_voice('11111111-aaaa-4aaa-8aaa-0000000000b0',
                                  'aaaa1111-0000-4000-8000-0000000000d7');
  IF v_result->>'reason' <> 'forbidden' THEN
    RAISE EXCEPTION 'FAIL: summoning ignored the permission: %', v_result;
  END IF;
  RAISE NOTICE 'ok  and an admin who takes the bit away is obeyed';
END $$;

-- ============================================================
-- 22. A summon outliving its reason (038)
-- ============================================================
-- 037 gave a summon two ways to end and both were somebody deciding. Nothing
-- ended one because the reason for it had gone.

RESET ROLE;

INSERT INTO channels (id, server_id, name, channel_type) VALUES
  ('aaaa1111-0000-4000-8000-0000000000e8',
   'aaaa0000-0000-4000-8000-000000000001', 'open-booth', 'voice');

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  PERFORM summon_bot_to_voice('11111111-aaaa-4aaa-8aaa-0000000000b0',
                              'aaaa1111-0000-4000-8000-0000000000e8');
  IF NOT channel_joinable_by('aaaa1111-0000-4000-8000-0000000000e8',
                             '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: the summon did not take, so this proves nothing';
  END IF;
END $$;

-- Closing the channel. 031 already drops a listening grant here; a summon is
-- the same shape and was left out, so a bot called into a public call could
-- still take a token for it afterwards — `channel_joinable_by` reads the summon
-- and never asks about privacy.
DO $$
BEGIN
  PERFORM set_channel_private('aaaa1111-0000-4000-8000-0000000000e8', true);

  IF EXISTS (SELECT 1 FROM bot_voice_summons
              WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000e8') THEN
    RAISE EXCEPTION 'FAIL: closing a channel left its summons behind';
  END IF;
  IF channel_joinable_by('aaaa1111-0000-4000-8000-0000000000e8',
                         '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: a bot can still walk into a channel that closed';
  END IF;
  RAISE NOTICE 'ok  closing a channel takes its summons with it';
END $$;

-- And an hour of nobody using one. A summon is a request to come and play
-- *now*; one that has sat unanswered has been answered by events.
RESET ROLE;

INSERT INTO bot_voice_summons (channel_id, bot_id, summoned_by, summoned_at)
VALUES ('aaaa1111-0000-4000-8000-0000000000d7',
        '11111111-aaaa-4aaa-8aaa-0000000000b0',
        '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '2 hours'),
       ('aaaa1111-0000-4000-8000-0000000000d7',
        '11111111-aaaa-4aaa-8aaa-0000000000a1',
        '11111111-aaaa-4aaa-8aaa-000000000002', now())
ON CONFLICT DO NOTHING;

DO $$
BEGIN
  PERFORM app.expire_bot_voice_summons();

  IF EXISTS (SELECT 1 FROM bot_voice_summons
              WHERE bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0'
                AND channel_id = 'aaaa1111-0000-4000-8000-0000000000d7') THEN
    RAISE EXCEPTION 'FAIL: a two-hour-old summon survived the sweep';
  END IF;
  -- And the fresh one is untouched, or the sweep is just a delete.
  IF NOT EXISTS (SELECT 1 FROM bot_voice_summons
                  WHERE bot_id = '11111111-aaaa-4aaa-8aaa-0000000000a1'
                    AND channel_id = 'aaaa1111-0000-4000-8000-0000000000d7') THEN
    RAISE EXCEPTION 'FAIL: the sweep took a summon somebody had just made';
  END IF;
  RAISE NOTICE 'ok  and so does an hour of nobody answering one';
END $$;

-- The view a client draws them from, so a summon whose bot never turned up is
-- visible and therefore dismissable. `security_invoker`, so the row policy is
-- what decides — the room, or the bot itself.
SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM voice_summons
                  WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000d7'
                    AND bot_name IS NOT NULL) THEN
    RAISE EXCEPTION 'FAIL: a member in the room cannot see what was summoned';
  END IF;
  RAISE NOTICE 'ok  and the room can see what has been called in, by name';
END $$;

-- Somebody outside the room sees nothing, which is the same answer
-- `bot_voice_summons_select` gives about the table.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-0000000000a1","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM voice_summons
              WHERE channel_id = 'aaaa1111-0000-4000-8000-0000000000d7'
                AND bot_id = '11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: an outsider read a private channel''s summons';
  END IF;
  RAISE NOTICE 'ok  and somebody outside it sees nothing, view or table';
END $$;

-- ============================================================
-- 23. The roster, a page at a time (039)
-- ============================================================
-- Every client read of `users` was unbounded, and PostgREST is capped at 1000
-- rows. So the failure was not an error — it was a member who quietly did not
-- exist, in the sidebar, in the `@` menu and in mention resolution alike. What
-- replaces it has to be bounded by construction, or the ceiling comes back the
-- first time somebody adds a caller.

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

-- No caller can ask for the whole table, however it asks.
DO $$
BEGIN
  IF app.member_limit(100000) <> app.member_page_max() THEN
    RAISE EXCEPTION 'FAIL: a caller asking for everything got it';
  END IF;
  IF app.member_limit(NULL) <> 50 OR app.member_limit(0) <> 1 THEN
    RAISE EXCEPTION 'FAIL: the limit clamp has a hole at the bottom';
  END IF;
  -- Clamped, not refused: an over-eager client has a bug, and answering it with
  -- an error turns that bug into an empty sidebar.
  IF (SELECT count(*) FROM list_members(p_limit => 100000)) = 0 THEN
    RAISE EXCEPTION 'FAIL: an over-large page was refused rather than clamped';
  END IF;
  RAISE NOTICE 'ok  no query can ask for more than a page';
END $$;

-- Keyset paging: hand back the last row you were given and you get the next
-- ones. OFFSET would have been simpler and wrong — the sidebar pages while
-- people are joining and renaming themselves, and a shifting sort under an
-- OFFSET skips and repeats rows at every page boundary.
DO $$
DECLARE
  v_whole TEXT[];
  v_paged TEXT[] := ARRAY[]::TEXT[];
  v_name  TEXT;
  v_id    UUID;
BEGIN
  SELECT array_agg(display_name ORDER BY lower(display_name), id)
    INTO v_whole FROM list_members(p_bots => false);

  -- Walked one row at a time, which is the worst case for a seam: every page
  -- boundary is a chance to skip somebody or hand them over twice.
  LOOP
    SELECT display_name, id INTO v_name, v_id
      FROM list_members(p_bots => false, p_after_name => v_name,
                        p_after_id => v_id, p_limit => 1);
    EXIT WHEN v_name IS NULL;
    v_paged := v_paged || v_name;
  END LOOP;

  IF v_paged <> v_whole THEN
    RAISE EXCEPTION 'FAIL: paging lost or repeated a row: % vs %', v_paged, v_whole;
  END IF;
  IF v_whole[1] <> 'Alice' THEN
    RAISE EXCEPTION 'FAIL: the roster is not alphabetical: %', v_whole;
  END IF;
  RAISE NOTICE 'ok  the roster pages alphabetically without skipping a row';
END $$;

-- Bots are listed apart from people everywhere in the UI (BOTS.md §9), so the
-- split is in the query rather than in each caller that has to remember it.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM list_members(p_bots => false) WHERE is_bot) THEN
    RAISE EXCEPTION 'FAIL: a bot came back among the people';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM list_members(p_bots => true)
                  WHERE username = 'modbot') THEN
    RAISE EXCEPTION 'FAIL: asking for bots did not return one';
  END IF;
  RAISE NOTICE 'ok  and bots and people are asked for separately';
END $$;

-- A banned member is not in the room. Excluded by default rather than by each
-- caller remembering to filter, because the one surface that wants them — the
-- moderation modal, to lift the ban — is the exception and says so.
RESET ROLE;
UPDATE users SET is_banned = true
 WHERE id = '11111111-aaaa-4aaa-8aaa-000000000003';
SET LOCAL ROLE authenticated;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM list_members() WHERE username = 'carol') THEN
    RAISE EXCEPTION 'FAIL: a banned member is still on the roster';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM list_members(p_banned => NULL)
                  WHERE username = 'carol') THEN
    RAISE EXCEPTION 'FAIL: moderation cannot reach a banned member to unban them';
  END IF;
  -- And the count agrees with the list, or a header says "Offline — 4" over
  -- three rows and never stops saying it.
  IF (member_counts()->>'people')::INT
       <> (SELECT count(*) FROM list_members(p_bots => false)) THEN
    RAISE EXCEPTION 'FAIL: the count and the list disagree about who is here';
  END IF;
  RAISE NOTICE 'ok  a banned member is off the roster, and the count agrees';
END $$;

RESET ROLE;
UPDATE users SET is_banned = false
 WHERE id = '11111111-aaaa-4aaa-8aaa-000000000003';
SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

-- Search ranks a prefix above a substring, and squashes spaces out of the
-- display name so `animb` finds "Anim Bot" — a mention token cannot contain a
-- space, so somebody typing a two-word name has no other way to reach them.
-- The client keeps the same rule for rows it already holds; if the two orders
-- disagreed the list would reshuffle as the server's answer landed.
DO $$
DECLARE v_names TEXT[];
BEGIN
  SELECT array_agg(display_name) INTO v_names FROM search_members('a');
  IF v_names[1] <> 'Alice' THEN
    RAISE EXCEPTION 'FAIL: a prefix match did not come first: %', v_names;
  END IF;
  IF NOT 'Dana' = ANY(v_names) THEN
    RAISE EXCEPTION 'FAIL: a substring match was dropped: %', v_names;
  END IF;
  -- An empty query is a browse, which is what lets a field open on focus
  -- without a second round trip.
  IF (SELECT count(*) FROM search_members(NULL)) = 0 THEN
    RAISE EXCEPTION 'FAIL: an empty query answered with nothing to browse';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM search_members('modb') WHERE username = 'modbot') THEN
    RAISE EXCEPTION 'FAIL: search cannot find a bot by the start of its name';
  END IF;
  RAISE NOTICE 'ok  search puts a prefix match first and still finds the rest';
END $$;

-- Resolving what the caller already holds — ids from presence and from message
-- senders, names from the `@`s somebody just typed. These are the reads that
-- used to be answered out of the in-memory roster, which is the thing being
-- removed; without them, dropping the whole-table read would just move the bug.
DO $$
DECLARE v_count INT;
BEGIN
  SELECT count(*) INTO v_count FROM members_by_ids(ARRAY[
    '11111111-aaaa-4aaa-8aaa-000000000001'::UUID,
    '11111111-aaaa-4aaa-8aaa-000000000002'::UUID]);
  IF v_count <> 2 THEN
    RAISE EXCEPTION 'FAIL: two ids resolved to % members', v_count;
  END IF;
  -- Another server's member is not mine to resolve, whatever id I present.
  IF EXISTS (SELECT 1 FROM members_by_ids(ARRAY[
       '22222222-bbbb-4bbb-8bbb-000000000001'::UUID])) THEN
    RAISE EXCEPTION 'FAIL: an id from another server resolved';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM members_by_usernames(ARRAY['ALICE'])) THEN
    RAISE EXCEPTION 'FAIL: username resolution is case-sensitive';
  END IF;
  IF EXISTS (SELECT 1 FROM members_by_usernames(ARRAY['mallory'])) THEN
    RAISE EXCEPTION 'FAIL: a name on another server resolved';
  END IF;
  RAISE NOTICE 'ok  ids and @names resolve without holding the roster';
END $$;

-- Scoped to a channel, this answers what `channel_audience` answered as a whole
-- set: who a message here can actually reach. Asked per query it costs one
-- predicate instead of downloading a private channel's membership.
--
-- `green-room` is private and bob is the only member seated in it.
DO $$
DECLARE v_names TEXT[];
BEGIN
  SELECT array_agg(username) INTO v_names
    FROM list_members(p_channel => 'aaaa1111-0000-4000-8000-0000000000d7',
                      p_bots => false);
  IF NOT 'bob' = ANY(v_names) THEN
    RAISE EXCEPTION 'FAIL: a member of the room is not in its audience: %', v_names;
  END IF;
  IF 'dana' = ANY(v_names) THEN
    RAISE EXCEPTION 'FAIL: an outsider is offered as mentionable: %', v_names;
  END IF;
  -- And the same gate on the resolver, or the composer would light up a
  -- mention `validate_message_mentions` is about to strip.
  IF EXISTS (SELECT 1 FROM members_by_usernames(ARRAY['dana'],
               'aaaa1111-0000-4000-8000-0000000000d7')) THEN
    RAISE EXCEPTION 'FAIL: an outsider resolved as a reachable mention';
  END IF;
  RAISE NOTICE 'ok  a channel scope offers only who the message can reach';
END $$;

-- And somebody outside the room is told nothing at all — not a filtered list,
-- which would still leak its size. Same answer `channel_audience` gives.
-- Dana is a real member of this server, which is what makes this a test: an id
-- that resolved to nobody would return nothing for reasons of its own.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-0000000000a1","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM list_members()) THEN
    RAISE EXCEPTION 'FAIL: the outsider cannot see the server at all, so this proves nothing';
  END IF;
  IF EXISTS (SELECT 1 FROM list_members(
               p_channel => 'aaaa1111-0000-4000-8000-0000000000d7')) THEN
    RAISE EXCEPTION 'FAIL: an outsider read a private channel''s membership';
  END IF;
  IF (member_counts('aaaa1111-0000-4000-8000-0000000000d7')->>'people')::INT <> 0 THEN
    RAISE EXCEPTION 'FAIL: an outsider learned how many people are in a private room';
  END IF;
  RAISE NOTICE 'ok  and an outsider learns neither who nor how many';
END $$;

-- Role chips for the rows on screen. `member_role_list` is one row per
-- (member, role) and was read whole for the same reason the roster was, so it
-- hits the ceiling sooner than the roster does.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM member_roles_for(
                   ARRAY['11111111-aaaa-4aaa-8aaa-000000000001'::UUID])) THEN
    RAISE EXCEPTION 'FAIL: an admin came back wearing no roles at all';
  END IF;
  IF EXISTS (SELECT 1 FROM member_roles_for(
               ARRAY['11111111-aaaa-4aaa-8aaa-000000000001'::UUID])
              WHERE user_id <> '11111111-aaaa-4aaa-8aaa-000000000001') THEN
    RAISE EXCEPTION 'FAIL: asking about one member answered about others';
  END IF;
  RAISE NOTICE 'ok  role chips are fetched for the rows on screen only';
END $$;

-- ============================================================
-- 24. Reactions counted where they are stored (040)
-- ============================================================
-- The standalone reaction read asked for one row per person per emoji across a
-- page of messages, and PostgREST caps a response at 1000 rows. Fifty messages
-- with twenty reactors each is a lively channel, not an extreme one — and past
-- that point the answer was trimmed and the counts read low, with nothing to
-- say so.

RESET ROLE;

INSERT INTO channels (id, server_id, name, channel_type) VALUES
  ('aaaa1111-0000-4000-8000-0000000000f1',
   'aaaa0000-0000-4000-8000-000000000001', 'reacting', 'text');

INSERT INTO messages (id, channel_id, sender_id, ciphertext, nonce, signature,
                      key_version)
VALUES (9401, 'aaaa1111-0000-4000-8000-0000000000f1',
        '11111111-aaaa-4aaa-8aaa-000000000001', 'c', 'n', 's', 1),
       (9402, 'aaaa1111-0000-4000-8000-0000000000f1',
        '11111111-aaaa-4aaa-8aaa-000000000001', 'c', 'n', 's', 1);

-- Two people on one emoji, one person on another, and a reaction on a second
-- message — enough that a tally that lost the grouping would show it.
INSERT INTO message_reactions (message_id, user_id, emoji) VALUES
  (9401, '11111111-aaaa-4aaa-8aaa-000000000001', '👍'),
  (9401, '11111111-aaaa-4aaa-8aaa-000000000002', '👍'),
  (9401, '11111111-aaaa-4aaa-8aaa-000000000001', '🎉'),
  (9402, '11111111-aaaa-4aaa-8aaa-000000000001', '😂');

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
DECLARE
  v      JSONB;
  v_up   JSONB;
  v_pop  JSONB;
  v_emoji TEXT[];
BEGIN
  v := message_reaction_tallies('channel', ARRAY[9401, 9402]::BIGINT[]);

  SELECT e INTO v_up   FROM jsonb_array_elements(v->'9401') e
   WHERE e->>'emoji' = '👍';
  SELECT e INTO v_pop  FROM jsonb_array_elements(v->'9401') e
   WHERE e->>'emoji' = '🎉';

  IF jsonb_array_length(v->'9401') <> 2 THEN
    RAISE EXCEPTION 'FAIL: two emoji on one message came back as %',
      jsonb_array_length(v->'9401');
  END IF;
  IF (v_up->>'count')::INT <> 2 THEN
    RAISE EXCEPTION 'FAIL: two reactors on one emoji counted as %',
      v_up->>'count';
  END IF;

  -- Bob is in the 👍 and in neither of the others — "mine" is the database's
  -- answer now rather than a client comparing user ids it was handed.
  IF NOT (v_up->>'mine')::BOOLEAN THEN
    RAISE EXCEPTION 'FAIL: the caller''s own reaction is not marked as theirs';
  END IF;
  IF (v_pop->>'mine')::BOOLEAN THEN
    RAISE EXCEPTION 'FAIL: somebody else''s reaction is marked as the caller''s';
  END IF;
  IF (v->'9402'->0->>'mine')::BOOLEAN THEN
    RAISE EXCEPTION 'FAIL: another message''s reaction is marked as the caller''s';
  END IF;

  -- Stably ordered, so two clients drawing the same message draw it the same
  -- way rather than in whatever order the aggregate happened to produce.
  SELECT array_agg(e->>'emoji') INTO v_emoji
    FROM jsonb_array_elements(v->'9401') e;
  IF v_emoji <> (SELECT array_agg(x ORDER BY x) FROM unnest(v_emoji) x) THEN
    RAISE EXCEPTION 'FAIL: the tally is not in a stable order: %', v_emoji;
  END IF;
  RAISE NOTICE 'ok  reactions are tallied per emoji, with mine decided here';
END $$;

DO $$
BEGIN
  -- One row per (message, emoji) rather than per person is the whole point:
  -- four reaction rows become three entries, and the factor grows with the
  -- crowd rather than with the page.
  IF (SELECT sum(jsonb_array_length(value))
        FROM jsonb_each(message_reaction_tallies('channel',
                          ARRAY[9401, 9402]::BIGINT[]))) <> 3 THEN
    RAISE EXCEPTION 'FAIL: the tally is still one entry per person';
  END IF;
  -- And asking about nothing is an empty object, not a null the client has to
  -- guard.
  IF message_reaction_tallies('channel', ARRAY[]::BIGINT[]) <> '{}'::jsonb THEN
    RAISE EXCEPTION 'FAIL: an empty question got a non-empty answer';
  END IF;
  IF message_reaction_tallies('channel', NULL) <> '{}'::jsonb THEN
    RAISE EXCEPTION 'FAIL: a null id list is not an empty answer';
  END IF;
  RAISE NOTICE 'ok  and shrink by the crowd rather than growing with it';
END $$;

-- ── The two permissions that were offered and never asked ───
-- `ADD_REACTIONS` and `ATTACH_FILES` are in the roles editor, are saved into
-- the bitmask, and were read by nothing: the reaction policy checked only that
-- you could see the message, and the attachment bucket only that you were a
-- member of the server. A permission that cannot be taken away is worse than
-- one that does not exist — the editor says it worked.

DO $$
BEGIN
  INSERT INTO message_reactions (message_id, user_id, emoji)
  VALUES (9402, '11111111-aaaa-4aaa-8aaa-000000000002', '🔥');
  RAISE NOTICE 'ok  a member with ADD_REACTIONS may react';
END $$;

DO $$
BEGIN
  INSERT INTO storage.objects (bucket_id, name, owner)
  VALUES ('chat-aaaa0000-0000-4000-8000-000000000001',
          'aaaa1111-0000-4000-8000-0000000000f1/allowed.bin',
          '11111111-aaaa-4aaa-8aaa-000000000002');
  RAISE NOTICE 'ok  a member with ATTACH_FILES may upload';
END $$;

RESET ROLE;
UPDATE roles
   SET permissions = permissions & ~(app.perm('ADD_REACTIONS')
                                     | app.perm('ATTACH_FILES'))
 WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001'
   AND is_everyone;

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  BEGIN
    INSERT INTO message_reactions (message_id, user_id, emoji)
    VALUES (9401, '11111111-aaaa-4aaa-8aaa-000000000002', '😂');
    RAISE EXCEPTION 'FAIL: a member without ADD_REACTIONS reacted anyway';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  RAISE NOTICE 'ok  taking ADD_REACTIONS away stops the reaction';
END $$;

DO $$
BEGIN
  BEGIN
    INSERT INTO storage.objects (bucket_id, name, owner)
    VALUES ('chat-aaaa0000-0000-4000-8000-000000000001',
            'aaaa1111-0000-4000-8000-0000000000f1/refused.bin',
            '11111111-aaaa-4aaa-8aaa-000000000002');
    RAISE EXCEPTION 'FAIL: a member without ATTACH_FILES uploaded anyway';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
  RAISE NOTICE 'ok  taking ATTACH_FILES away stops the upload';
END $$;

-- Deleting one you already left stays yours: the permission governs adding,
-- not living with what you added before it was taken.
DO $$
BEGIN
  DELETE FROM message_reactions
   WHERE message_id = 9402
     AND user_id = '11111111-aaaa-4aaa-8aaa-000000000002';
  RAISE NOTICE 'ok  and leaves the ones already there to their owner';
END $$;

-- An administrator is unaffected, because `has_perm` folds ADMINISTRATOR in.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  INSERT INTO message_reactions (message_id, user_id, emoji)
  VALUES (9402, '11111111-aaaa-4aaa-8aaa-000000000001', '🔥');
  RAISE NOTICE 'ok  an administrator still holds both without being given one';
END $$;

RESET ROLE;
UPDATE roles
   SET permissions = permissions | app.perm('ADD_REACTIONS')
                                 | app.perm('ATTACH_FILES')
 WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001'
   AND is_everyone;

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;


-- ============================================================
-- 25. The DM conversation list, a page at a time (041)
-- ============================================================
-- This one never truncated — it returns a JSONB scalar, so the 1000-row cap
-- does not apply to it — and that is exactly why it outlived every other
-- unbounded read. It grew instead: one row per person you have ever messaged,
-- refetched on every server switch and every incoming DM, each row carrying an
-- envelope the client decrypts to draw a preview nobody has scrolled to.

RESET ROLE;
-- Cleared so the attest trigger leaves the sender ids below alone: it rewrites
-- them to auth.uid() whenever there is one, and the previous section left a
-- claim set for the transaction.
DO $$ BEGIN PERFORM set_config('request.jwt.claims', '', true); END $$;

INSERT INTO auth.users (id) VALUES
  ('33333333-cccc-4ccc-8ccc-000000000000'),   -- the reader
  ('33333333-cccc-4ccc-8ccc-000000000001'),
  ('33333333-cccc-4ccc-8ccc-000000000002'),
  ('33333333-cccc-4ccc-8ccc-000000000003'),
  ('33333333-cccc-4ccc-8ccc-000000000004');

-- A reader of their own, rather than alice: earlier sections have been sending
-- her DMs, and a paging test is only honest when it knows the whole list.
INSERT INTO users (id, server_id, username, display_name, public_key, stable_id,
                   chat_public_key)
VALUES
  ('33333333-cccc-4ccc-8ccc-000000000000', 'aaaa0000-0000-4000-8000-000000000001',
   'pager', 'Pager', 'pk-pager', 'sid-pager', 'chat-pager'),
  ('33333333-cccc-4ccc-8ccc-000000000001', 'aaaa0000-0000-4000-8000-000000000001',
   'pal1', 'Pal One', 'pk-pal1', 'sid-pal1', 'chat-pal1'),
  ('33333333-cccc-4ccc-8ccc-000000000002', 'aaaa0000-0000-4000-8000-000000000001',
   'pal2', 'Pal Two', 'pk-pal2', 'sid-pal2', 'chat-pal2'),
  ('33333333-cccc-4ccc-8ccc-000000000003', 'aaaa0000-0000-4000-8000-000000000001',
   'pal3', 'Pal Three', 'pk-pal3', 'sid-pal3', 'chat-pal3'),
  ('33333333-cccc-4ccc-8ccc-000000000004', 'aaaa0000-0000-4000-8000-000000000001',
   'pal4', 'Pal Four', 'pk-pal4', 'sid-pal4', 'chat-pal4');

-- Five messages, four conversations, in both directions. Pal One is spoken to
-- twice so that a list which forgot its `DISTINCT ON` would show five rows
-- where there are four people.
INSERT INTO dm_messages (id, sender_id, recipient_id, ciphertext, nonce,
                         signature, key_version) VALUES
  (9501, '33333333-cccc-4ccc-8ccc-000000000001',
         '33333333-cccc-4ccc-8ccc-000000000000', 'c', 'n', 's', 1),
  (9502, '33333333-cccc-4ccc-8ccc-000000000000',
         '33333333-cccc-4ccc-8ccc-000000000002', 'c', 'n', 's', 1),
  (9503, '33333333-cccc-4ccc-8ccc-000000000003',
         '33333333-cccc-4ccc-8ccc-000000000000', 'c', 'n', 's', 1),
  (9504, '33333333-cccc-4ccc-8ccc-000000000000',
         '33333333-cccc-4ccc-8ccc-000000000001', 'c', 'n', 's', 1),
  (9505, '33333333-cccc-4ccc-8ccc-000000000004',
         '33333333-cccc-4ccc-8ccc-000000000000', 'c', 'n', 's', 1);

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"33333333-cccc-4ccc-8ccc-000000000000","role":"authenticated"}', true); END $$;

DO $$
DECLARE
  v     JSONB;
  v_all TEXT[];
BEGIN
  v := dm_conversations();
  SELECT array_agg(e->>'peer_username')
    INTO v_all FROM jsonb_array_elements(v->'conversations') e;

  -- Newest activity first, one row per person. Pal One is at the top on the
  -- strength of 9504 rather than of the older 9501 that started it.
  IF v_all <> ARRAY['pal4', 'pal1', 'pal3', 'pal2'] THEN
    RAISE EXCEPTION 'FAIL: the conversation list is % ', v_all;
  END IF;
  IF (v->>'has_more')::BOOLEAN THEN
    RAISE EXCEPTION 'FAIL: a list that fits in one page claims another';
  END IF;
  -- The row is unchanged from 003 — the paging is around the answer, not in
  -- it, and a caller that reads a conversation out of it needs no edit.
  IF v->'conversations'->0->'last_message'->>'id' <> '9505'
     OR v->'conversations'->0->>'peer_chat_public_key' <> 'chat-pal4' THEN
    RAISE EXCEPTION 'FAIL: the row lost a key it used to carry: %',
      v->'conversations'->0;
  END IF;
  RAISE NOTICE 'ok  the newest message per peer, newest conversation first';
END $$;

-- Keyset paging on the newest message id. An OFFSET would have been simpler
-- and wrong for the same reason it is wrong for the roster, only more so: this
-- list reorders itself every time anybody says anything.
DO $$
DECLARE
  v      JSONB;
  v_page TEXT[];
BEGIN
  v := dm_conversations(p_limit => 2);
  SELECT array_agg(e->>'peer_username')
    INTO v_page FROM jsonb_array_elements(v->'conversations') e;
  IF v_page <> ARRAY['pal4', 'pal1'] THEN
    RAISE EXCEPTION 'FAIL: the first page is %', v_page;
  END IF;
  -- Proved by the spare row the query over-fetched, not guessed from the page
  -- being full — the guess is what offers a "load more" that fetches nothing.
  IF NOT (v->>'has_more')::BOOLEAN THEN
    RAISE EXCEPTION 'FAIL: a page with more behind it says it is the last';
  END IF;

  v := dm_conversations(p_limit => 2, p_before => 9504);
  SELECT array_agg(e->>'peer_username')
    INTO v_page FROM jsonb_array_elements(v->'conversations') e;
  IF v_page <> ARRAY['pal3', 'pal2'] THEN
    RAISE EXCEPTION 'FAIL: the second page is %', v_page;
  END IF;
  IF (v->>'has_more')::BOOLEAN THEN
    RAISE EXCEPTION 'FAIL: the last page claims another behind it';
  END IF;
  RAISE NOTICE 'ok  and it pages backwards through them without a gap';
END $$;

-- Walked one row at a time, which is the worst case for a seam.
DO $$
DECLARE
  v_whole TEXT[];
  v_paged TEXT[] := ARRAY[]::TEXT[];
  v      JSONB;
  v_cursor BIGINT := NULL;
BEGIN
  SELECT array_agg(e->>'peer_username')
    INTO v_whole FROM jsonb_array_elements(dm_conversations()->'conversations') e;

  LOOP
    v := dm_conversations(p_limit => 1, p_before => v_cursor);
    EXIT WHEN jsonb_array_length(v->'conversations') = 0;
    v_paged := v_paged || (v->'conversations'->0->>'peer_username');
    v_cursor := (v->'conversations'->0->'last_message'->>'id')::BIGINT;
  END LOOP;

  IF v_paged <> v_whole THEN
    RAISE EXCEPTION 'FAIL: paging lost or repeated a conversation: % vs %',
      v_paged, v_whole;
  END IF;
  RAISE NOTICE 'ok  one row at a time reaches every conversation exactly once';
END $$;

DO $$
DECLARE
  v JSONB;
BEGIN
  -- Clamped rather than refused, like the roster: an over-eager client has a
  -- bug, and answering it with an error turns that bug into an empty list.
  IF jsonb_array_length(dm_conversations(p_limit => 100000)->'conversations') = 0 THEN
    RAISE EXCEPTION 'FAIL: an over-large page was refused rather than clamped';
  END IF;
  IF jsonb_array_length(dm_conversations(p_limit => 0)->'conversations') <> 1 THEN
    RAISE EXCEPTION 'FAIL: the limit clamp has a hole at the bottom';
  END IF;

  -- Scoped by `dm_messages_select` rather than by anything written here, which
  -- is why this stays SECURITY INVOKER. Pal Two was spoken to once, by the
  -- reader, and sees that one conversation and none of the reader's others.
  PERFORM set_config('request.jwt.claims',
    '{"sub":"33333333-cccc-4ccc-8ccc-000000000002","role":"authenticated"}', true);
  v := dm_conversations();
  IF jsonb_array_length(v->'conversations') <> 1
     OR v->'conversations'->0->>'peer_username' <> 'pager' THEN
    RAISE EXCEPTION 'FAIL: a peer sees somebody else''s conversations: %', v;
  END IF;

  -- And somebody who has never sent or received one gets an empty list, not a
  -- null the client has to guard.
  PERFORM set_config('request.jwt.claims',
    '{"sub":"11111111-aaaa-4aaa-8aaa-000000000003","role":"authenticated"}', true);
  IF dm_conversations()->'conversations' <> '[]'::jsonb THEN
    RAISE EXCEPTION 'FAIL: an empty list is not an empty array';
  END IF;
  RAISE NOTICE 'ok  a page is a page, and it is only ever your own';
END $$;

-- ---------- 021: the head the list is read from ----------
-- The list used to find each peer's newest message by reading every DM the
-- caller had. `dm_conversation_heads` is that answer, kept as it is written.
-- Pager's four conversations are the fixture: pal1 sits above pal3 and pal2
-- on the strength of 9504, and 9501 is what is underneath it.

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"33333333-cccc-4ccc-8ccc-000000000000","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_mine INT; v_head BIGINT;
BEGIN
  SELECT count(*) INTO v_mine FROM dm_conversation_heads;
  IF v_mine <> 4 THEN
    RAISE EXCEPTION 'FAIL: pager sees % heads rather than their four conversations', v_mine;
  END IF;
  IF EXISTS (SELECT 1 FROM dm_conversation_heads WHERE user_id <> auth.uid()) THEN
    RAISE EXCEPTION 'FAIL: a member can read who somebody else talks to';
  END IF;

  -- Read-only from every session: a member who could write this could move a
  -- conversation to the top of somebody else's list.
  BEGIN
    UPDATE dm_conversation_heads SET last_message_id = 99999 WHERE user_id = auth.uid();
    RAISE EXCEPTION 'FAIL: a member can rewrite their own conversation order';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  SELECT last_message_id INTO v_head FROM dm_conversation_heads
   WHERE user_id = auth.uid() AND peer_id = '33333333-cccc-4ccc-8ccc-000000000001';
  IF v_head <> 9504 THEN
    RAISE EXCEPTION 'FAIL: the head of pal1''s conversation is % rather than 9504', v_head;
  END IF;
  RAISE NOTICE 'ok  a conversation head is yours to read, nobody''s to write';
END $$;

-- Deleting the newest message is the only delete that moves a head — and the
-- one retention never performs, because it takes the oldest.
DO $$
DECLARE v_all TEXT[]; v_head BIGINT;
BEGIN
  DELETE FROM dm_messages WHERE id = 9504;   -- pager's own, so the policy allows it

  SELECT last_message_id INTO v_head FROM dm_conversation_heads
   WHERE user_id = auth.uid() AND peer_id = '33333333-cccc-4ccc-8ccc-000000000001';
  IF v_head <> 9501 THEN
    RAISE EXCEPTION 'FAIL: the head is % after its message was deleted', v_head;
  END IF;

  SELECT array_agg(e->>'peer_username')
    INTO v_all FROM jsonb_array_elements(dm_conversations()->'conversations') e;
  IF v_all <> ARRAY['pal4', 'pal3', 'pal2', 'pal1'] THEN
    RAISE EXCEPTION 'FAIL: the list did not follow the head back down: %', v_all;
  END IF;
  RAISE NOTICE 'ok  deleting the newest message walks the head back, and the list with it';
END $$;

-- And an emptied conversation is not a conversation. Without this the list
-- carries a peer whose last message cannot be joined.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"33333333-cccc-4ccc-8ccc-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_all TEXT[];
BEGIN
  DELETE FROM dm_messages WHERE id = 9501;   -- pal1's own, the last one left

  IF EXISTS (SELECT 1 FROM dm_conversation_heads) THEN
    RAISE EXCEPTION 'FAIL: pal1 kept a head for a conversation with nothing in it';
  END IF;

  PERFORM set_config('request.jwt.claims',
    '{"sub":"33333333-cccc-4ccc-8ccc-000000000000","role":"authenticated"}', true);
  SELECT array_agg(e->>'peer_username')
    INTO v_all FROM jsonb_array_elements(dm_conversations()->'conversations') e;
  IF v_all <> ARRAY['pal4', 'pal3', 'pal2'] THEN
    RAISE EXCEPTION 'FAIL: an emptied conversation is still listed: %', v_all;
  END IF;
  RAISE NOTICE 'ok  and an emptied conversation leaves both sides'' lists';
END $$;



-- ============================================================
-- 26. Who the doorbell wakes (024)
-- ============================================================
-- The doorbell used to walk the whole membership and ask each member, one
-- query at a time, whether they already had unread mail here. It now reads
-- two message ids and drives from `read_state` instead. The two must agree,
-- and the cases that decide it are the awkward ones: a member with no cursor
-- at all, and a member who wrote everything before this.
--
-- `ring_devices` is swapped for a recorder so the decision can be read
-- directly. It is restored at the end of the section; the transaction rolls
-- back regardless.

RESET ROLE;

CREATE TEMP TABLE rung (server_id UUID, user_ids UUID[]);

CREATE OR REPLACE FUNCTION ring_devices(p_server_id UUID, p_user_ids UUID[])
  RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $recorder$
BEGIN
  INSERT INTO rung VALUES (p_server_id, COALESCE(p_user_ids, '{}'::uuid[]));
END $recorder$;

-- Push on for Alpha, which is what makes the doorbell run at all.
INSERT INTO push_config (server_id, endpoint, secret, relay_id)
VALUES ('aaaa0000-0000-4000-8000-000000000001', 'http://relay.invalid/push',
        'push-secret', gen_random_uuid())
ON CONFLICT (server_id) DO NOTHING;

-- A channel of its own, so the history is exactly what these tests wrote.
INSERT INTO channels (id, server_id, name, channel_type)
VALUES ('aaaa1111-0000-4000-8000-0000000000b7',
        'aaaa0000-0000-4000-8000-000000000001', 'doorbell', 'text');

-- Bob opens it and says something.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;
INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version)
VALUES (9501, 'aaaa1111-0000-4000-8000-0000000000b7', 'first', 'n', 's', 1);

-- Nobody has a cursor in this channel yet, so nobody is caught up, so the
-- only person the second message can wake is the one who wrote the first.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_targets UUID[];
BEGIN
  DELETE FROM rung;
  INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version)
  VALUES (9502, 'aaaa1111-0000-4000-8000-0000000000b7', 'second', 'n', 's', 1);

  SELECT user_ids INTO v_targets FROM rung;
  -- Bob wrote everything before this one, so there is nothing of anybody
  -- else's for him to have missed — caught up with no `read_state` row at
  -- all. This is the case the whole `o_newest_other IS NULL` branch exists
  -- for, and the one a naive rewrite silently drops.
  IF NOT ('11111111-aaaa-4aaa-8aaa-000000000002' = ANY (v_targets)) THEN
    RAISE EXCEPTION 'FAIL: the only prior writer was not woken: %', v_targets;
  END IF;
  -- Carol has read nothing here, so message 9501 is unread mail and she has
  -- already been told about it once.
  IF '11111111-aaaa-4aaa-8aaa-000000000003' = ANY (v_targets) THEN
    RAISE EXCEPTION 'FAIL: a member with unread mail was woken again: %', v_targets;
  END IF;
  -- And never the sender.
  IF '11111111-aaaa-4aaa-8aaa-000000000001' = ANY (v_targets) THEN
    RAISE EXCEPTION 'FAIL: the sender woke their own phone: %', v_targets;
  END IF;
  RAISE NOTICE 'ok  the doorbell wakes whoever was caught up, and nobody else';
END $$;

-- Carol catches up. Now she is the one to wake, and Bob — who has read
-- nothing since his own message — is not.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000003","role":"authenticated"}', true); END $$;
SET LOCAL ROLE authenticated;
INSERT INTO read_state (user_id, scope, scope_id, last_read_id)
VALUES ('11111111-aaaa-4aaa-8aaa-000000000003', 'channel',
        'aaaa1111-0000-4000-8000-0000000000b7', 9502)
ON CONFLICT (user_id, scope, scope_id) DO UPDATE SET last_read_id = 9502;
RESET ROLE;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_targets UUID[];
BEGIN
  DELETE FROM rung;
  INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version)
  VALUES (9503, 'aaaa1111-0000-4000-8000-0000000000b7', 'third', 'n', 's', 1);

  SELECT user_ids INTO v_targets FROM rung;
  IF NOT ('11111111-aaaa-4aaa-8aaa-000000000003' = ANY (v_targets)) THEN
    RAISE EXCEPTION 'FAIL: a member who had caught up was not woken: %', v_targets;
  END IF;
  IF '11111111-aaaa-4aaa-8aaa-000000000002' = ANY (v_targets) THEN
    RAISE EXCEPTION 'FAIL: bob was woken though 9502 is still unread to him: %', v_targets;
  END IF;
  RAISE NOTICE 'ok  catching up is what puts a member back in the queue';
END $$;

-- The old rule, spelled out, against the new one — over every member and a
-- range of cursors. This is the check that the two-scalar reformulation is
-- an identity and not an approximation that happens to hold for the cases
-- above.
DO $$
DECLARE
  v_ch  UUID := 'aaaa1111-0000-4000-8000-0000000000b7';
  v_x   BIGINT := 9504;
  v_t   RECORD;
  v_bad INT;
  v_n   INT;
BEGIN
  v_t := app.unread_thresholds(v_ch, v_x);
  SELECT count(*), count(*) FILTER (WHERE old_says IS DISTINCT FROM new_says)
    INTO v_n, v_bad
    FROM (
      SELECT
        EXISTS (SELECT 1 FROM messages m
                 WHERE m.channel_id = v_ch AND m.id < v_x
                   AND NOT m.is_interaction
                   AND m.sender_id IS DISTINCT FROM u.id
                   AND m.id > COALESCE(c.cursor_at, 0)) AS old_says,
        COALESCE(c.cursor_at, 0) < CASE
          WHEN v_t.o_newest_by IS DISTINCT FROM u.id THEN COALESCE(v_t.o_newest, 0)
          ELSE COALESCE(v_t.o_newest_other, 0) END AS new_says
      FROM users u
      -- Every cursor worth having: none, and each message in the channel.
      CROSS JOIN LATERAL (
        SELECT NULL::BIGINT AS cursor_at
        UNION ALL SELECT m.id FROM messages m WHERE m.channel_id = v_ch) c
     WHERE u.server_id = 'aaaa0000-0000-4000-8000-000000000001') t;

  IF v_n = 0 THEN
    RAISE EXCEPTION 'FAIL: the comparison compared nothing';
  END IF;
  IF v_bad > 0 THEN
    RAISE EXCEPTION 'FAIL: % of % member/cursor pairs disagree with the old rule',
      v_bad, v_n;
  END IF;
  RAISE NOTICE 'ok  and it answers exactly what asking each member one at a time did';
END $$;

-- Put the real one back, so nothing after this section is measuring a stub.
RESET ROLE;
CREATE OR REPLACE FUNCTION ring_devices(p_server_id UUID, p_user_ids UUID[])
  RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public, extensions AS $real$
DECLARE
  v_cfg    push_config;
  v_tokens TEXT[];
BEGIN
  IF p_user_ids IS NULL OR cardinality(p_user_ids) = 0 THEN RETURN; END IF;
  SELECT * INTO v_cfg FROM push_config WHERE server_id = p_server_id;
  IF v_cfg IS NULL THEN RETURN; END IF;
  SELECT array_agg(token) INTO v_tokens
    FROM device_tokens WHERE user_id = ANY (p_user_ids);
  IF v_tokens IS NULL THEN RETURN; END IF;
  PERFORM net.http_post(
    url     := v_cfg.endpoint,
    headers := jsonb_build_object('Content-Type', 'application/json',
                                  'x-push-secret', v_cfg.secret),
    body    := jsonb_build_object('relay_id', v_cfg.relay_id,
                                  'tokens',   to_jsonb(v_tokens)));
END $real$;
DELETE FROM push_config WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001';

-- ============================================================
-- 27. The member list carries its own scope (026)
-- ============================================================
-- These five became SECURITY DEFINER so the planner would stop tripping over
-- the `users` policies, which means RLS is no longer the thing keeping one
-- server's roster out of another's. They enforce it themselves now, and
-- these are the tests that say so — the whole point of the change is that
-- the rule moved, so the rule needs checking where it landed.
--
-- `member_roles_for` is the one that never had a scope of its own at all:
-- `member_roles_select` was doing it. Bypassing that policy without adding
-- the scope back would have handed every server's role assignments to
-- anybody who could guess a user id.

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"22222222-bbbb-4bbb-8bbb-000000000001","role":"authenticated"}', true); END $$;

DO $$
DECLARE
  v_alpha UUID[] := ARRAY['11111111-aaaa-4aaa-8aaa-000000000001',
                          '11111111-aaaa-4aaa-8aaa-000000000002',
                          '11111111-aaaa-4aaa-8aaa-000000000003']::UUID[];
  v_n BIGINT;
BEGIN
  IF EXISTS (SELECT 1 FROM list_members() WHERE server_id
             <> 'bbbb0000-0000-4000-8000-000000000001') THEN
    RAISE EXCEPTION 'FAIL: list_members reached outside the caller''s server';
  END IF;
  IF EXISTS (SELECT 1 FROM search_members('') WHERE server_id
             <> 'bbbb0000-0000-4000-8000-000000000001') THEN
    RAISE EXCEPTION 'FAIL: an empty search reached outside the caller''s server';
  END IF;
  -- By name, which is the query a directory scrape would use.
  IF EXISTS (SELECT 1 FROM search_members('alice')) THEN
    RAISE EXCEPTION 'FAIL: search_members found a member of another server';
  END IF;
  IF EXISTS (SELECT 1 FROM search_members('lic')) THEN
    RAISE EXCEPTION 'FAIL: the infix half of search_members crossed servers';
  END IF;
  -- By id, which is the query somebody holding a stolen id would use.
  IF EXISTS (SELECT 1 FROM members_by_ids(v_alpha)) THEN
    RAISE EXCEPTION 'FAIL: members_by_ids resolved ids from another server';
  END IF;
  IF EXISTS (SELECT 1 FROM member_roles_for(v_alpha)) THEN
    RAISE EXCEPTION 'FAIL: member_roles_for returned another server''s roles';
  END IF;
  v_n := (member_counts() ->> 'people')::BIGINT;
  IF v_n <> (SELECT count(*) FROM users
              WHERE server_id = 'bbbb0000-0000-4000-8000-000000000001'
                AND NOT is_bot AND NOT is_banned) THEN
    RAISE EXCEPTION 'FAIL: member_counts counted % across servers', v_n;
  END IF;
  RAISE NOTICE 'ok  the member list answers about one server, whoever asks';
END $$;

-- And a member still sees their own server, or the scope check has simply
-- broken everything rather than secured it.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM search_members('alice')) THEN
    RAISE EXCEPTION 'FAIL: a member cannot find their own server''s members';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM members_by_ids(
       ARRAY['11111111-aaaa-4aaa-8aaa-000000000001']::UUID[])) THEN
    RAISE EXCEPTION 'FAIL: a member cannot resolve an id from their own server';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM member_roles_for(
       ARRAY['11111111-aaaa-4aaa-8aaa-000000000001']::UUID[])) THEN
    RAISE EXCEPTION 'FAIL: a member cannot see their own server''s role chips';
  END IF;
  -- The space-stripped prefix, which is the pattern the new index serves.
  IF NOT EXISTS (SELECT 1 FROM search_members('ali')) THEN
    RAISE EXCEPTION 'FAIL: a prefix search found nobody';
  END IF;
  RAISE NOTICE 'ok  and it still answers about the server the caller is in';
END $$;

-- A session with no account behind it gets nothing at all, rather than an
-- error or — the failure that matters — everybody.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"99999999-9999-4999-8999-000000000009","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM list_members()) THEN
    RAISE EXCEPTION 'FAIL: a stranger listed members';
  END IF;
  IF EXISTS (SELECT 1 FROM search_members('a')) THEN
    RAISE EXCEPTION 'FAIL: a stranger searched members';
  END IF;
  IF EXISTS (SELECT 1 FROM member_roles_for(
       ARRAY['11111111-aaaa-4aaa-8aaa-000000000001']::UUID[])) THEN
    RAISE EXCEPTION 'FAIL: a stranger read role assignments';
  END IF;
  IF (member_counts() ->> 'people')::BIGINT <> 0 THEN
    RAISE EXCEPTION 'FAIL: a stranger was told how many members there are';
  END IF;
  RAISE NOTICE 'ok  no account, no roster';
END $$;

-- Hand the session back exactly as this section found it. The claim above
-- belongs to nobody, and what follows creates channels whose trigger seats
-- their creator — which a caller with no `users` row cannot be.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"33333333-cccc-4ccc-8ccc-000000000000","role":"authenticated"}', true); END $$;

-- ============================================================
-- 18b. Where the private-channel bit lands by default (014)
-- ============================================================
RESET ROLE;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM roles
              WHERE server_id = 'bbbb0000-0000-4000-8000-000000000001'
                AND is_everyone
                AND (permissions & app.perm('CREATE_PRIVATE_CHANNEL')) <> 0) THEN
    RAISE EXCEPTION 'FAIL: the baseline still lets everybody make private rooms';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM roles
                  WHERE server_id = 'bbbb0000-0000-4000-8000-000000000001'
                    AND name = 'Moderator'
                    AND (permissions & app.perm('CREATE_PRIVATE_CHANNEL')) <> 0) THEN
    RAISE EXCEPTION 'FAIL: moderators cannot make private rooms by default';
  END IF;
  RAISE NOTICE 'ok  private rooms are a moderator''s to make, by default';
END $$;

-- ============================================================
-- 18c. Realtime topics (017)
-- ============================================================
-- Every topic is private: a join is admitted by `app.can_use_topic`, through
-- the policies the console puts on `realtime.messages`. A topic that admits
-- too much is a leak nobody sees; one that admits too little is a feature that
-- silently stops updating. Both directions are asserted.

-- A private channel in Alpha that only alice is in.
INSERT INTO channels (id, server_id, name, channel_type, is_private) VALUES
  ('aaaa1111-0000-4000-8000-0000000000ff', 'aaaa0000-0000-4000-8000-000000000001', 'staff', 'text', true);
INSERT INTO channel_members (channel_id, user_id) VALUES ('aaaa1111-0000-4000-8000-0000000000ff', '11111111-aaaa-4aaa-8aaa-000000000001');

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT app.can_use_topic('server:aaaa0000-0000-4000-8000-000000000001', false) THEN
    RAISE EXCEPTION 'FAIL: a member could not join their own server''s topic';
  END IF;
  IF app.can_use_topic('server:bbbb0000-0000-4000-8000-000000000001', false) THEN
    RAISE EXCEPTION 'FAIL: a member joined another server''s topic';
  END IF;
  IF NOT app.can_use_topic('presence:aaaa0000-0000-4000-8000-000000000001', true)
     OR NOT app.can_use_topic('voice:aaaa0000-0000-4000-8000-000000000001', true) THEN
    RAISE EXCEPTION 'FAIL: a member could not announce presence or a voice location';
  END IF;
  IF NOT app.can_use_topic('user:11111111-aaaa-4aaa-8aaa-000000000002', false) THEN
    RAISE EXCEPTION 'FAIL: a member could not join their own topic';
  END IF;
  IF app.can_use_topic('user:11111111-aaaa-4aaa-8aaa-000000000001', false) THEN
    RAISE EXCEPTION 'FAIL: a member joined somebody else''s topic';
  END IF;
  IF NOT app.can_use_topic('user:11111111-aaaa-4aaa-8aaa-000000000001', true) THEN
    RAISE EXCEPTION 'FAIL: a member could not ring a co-member (a DM typing indicator)';
  END IF;
  IF app.can_use_topic('user:22222222-bbbb-4bbb-8bbb-000000000001', true) THEN
    RAISE EXCEPTION 'FAIL: a member rang somebody on another server';
  END IF;
  IF NOT app.can_use_topic('chat:aaaa1111-0000-4000-8000-000000000001', false) THEN
    RAISE EXCEPTION 'FAIL: a member could not join an open channel''s topic';
  END IF;
  IF app.can_use_topic('chat:aaaa1111-0000-4000-8000-0000000000ff', false) THEN
    RAISE EXCEPTION 'FAIL: a member joined a private channel''s topic they are not in';
  END IF;
  IF app.can_use_topic('chat:bbbb1111-0000-4000-8000-000000000001', false) THEN
    RAISE EXCEPTION 'FAIL: a member joined a channel topic on another server';
  END IF;
  IF app.can_use_topic('chat:not-a-uuid', false) OR app.can_use_topic('keysweep:aaaa0000-0000-4000-8000-000000000001', false) THEN
    RAISE EXCEPTION 'FAIL: a malformed or unknown topic was admitted';
  END IF;
  -- 027's listen-only topic, by the same rule as the channel itself.
  IF NOT app.can_use_topic('channel:aaaa1111-0000-4000-8000-000000000001', false) THEN
    RAISE EXCEPTION 'FAIL: a member could not listen to an open channel''s topic';
  END IF;
  IF app.can_use_topic('channel:aaaa1111-0000-4000-8000-0000000000ff', false) THEN
    RAISE EXCEPTION 'FAIL: a member listened to a private channel they are not in';
  END IF;
  IF app.can_use_topic('channel:bbbb1111-0000-4000-8000-000000000001', false) THEN
    RAISE EXCEPTION 'FAIL: a member listened to a channel on another server';
  END IF;
  -- Nobody writes here, not even a member of the channel. A member who could
  -- would be able to forge a message announcement to everybody in it.
  IF app.can_use_topic('channel:aaaa1111-0000-4000-8000-000000000001', true) THEN
    RAISE EXCEPTION 'FAIL: a member could speak on a channel''s database topic';
  END IF;
  IF app.can_use_topic('channel:not-a-uuid', false) THEN
    RAISE EXCEPTION 'FAIL: a malformed channel topic was admitted';
  END IF;
  RAISE NOTICE 'ok  a member joins their server''s topics and their own, and nothing else';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT app.can_use_topic('chat:aaaa1111-0000-4000-8000-0000000000ff', false) THEN
    RAISE EXCEPTION 'FAIL: a private channel''s member could not join its topic';
  END IF;
  IF NOT app.can_use_topic('channel:aaaa1111-0000-4000-8000-0000000000ff', false) THEN
    RAISE EXCEPTION 'FAIL: a private channel''s member could not hear its messages';
  END IF;
  IF app.can_use_topic('channel:aaaa1111-0000-4000-8000-0000000000ff', true) THEN
    RAISE EXCEPTION 'FAIL: a private channel''s member could speak on its database topic';
  END IF;
  RAISE NOTICE 'ok  a private channel''s topic admits its members';
END $$;

DO $$ BEGIN PERFORM set_config('request.jwt.claims', '{}', true); END $$;

DO $$
BEGIN
  IF app.can_use_topic('server:aaaa0000-0000-4000-8000-000000000001', false) OR app.can_use_topic('user:11111111-aaaa-4aaa-8aaa-000000000002', false) THEN
    RAISE EXCEPTION 'FAIL: a topic admitted somebody with no session';
  END IF;
  RAISE NOTICE 'ok  no session, no topic';
END $$;

RESET ROLE;
UPDATE users SET is_banned = true WHERE id = '11111111-aaaa-4aaa-8aaa-000000000003';
SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000003","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF app.can_use_topic('server:aaaa0000-0000-4000-8000-000000000001', false) OR app.can_use_topic('user:11111111-aaaa-4aaa-8aaa-000000000001', true) THEN
    RAISE EXCEPTION 'FAIL: a banned member still reached the server';
  END IF;
  IF NOT app.can_use_topic('user:11111111-aaaa-4aaa-8aaa-000000000003', false) THEN
    RAISE EXCEPTION 'FAIL: a banned member lost their own topic, and with it the unban';
  END IF;
  RAISE NOTICE 'ok  a ban closes the server''s topics but leaves the member their own';
END $$;

RESET ROLE;
UPDATE users SET is_banned = false WHERE id = '11111111-aaaa-4aaa-8aaa-000000000003';

-- ---------- what the database says, and to whom ----------
-- Read straight out of `realtime.messages`, which is what Realtime delivers
-- from. Skipped where Realtime has never run against this database: there is no
-- `realtime.send` to call, and the triggers correctly say nothing.

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version) VALUES
  (9101, 'aaaa1111-0000-4000-8000-000000000001', 'open-from-bob', 'n', 's', 1);
INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version, ephemeral_for)
  VALUES (9103, 'aaaa1111-0000-4000-8000-000000000001', 'just-for-alice', 'n', 's', 1, '11111111-aaaa-4aaa-8aaa-000000000001');
INSERT INTO dm_messages (id, recipient_id, ciphertext, nonce, signature, key_version) VALUES
  (8101, '11111111-aaaa-4aaa-8aaa-000000000001', 'dm-for-alice', 'n', 's', 1);
UPDATE messages SET ciphertext = 'open-from-bob-edited', edited_at = now() WHERE id = 9101;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version) VALUES
  (9102, 'aaaa1111-0000-4000-8000-0000000000ff', 'staff-only', 'n', 's', 1);

DO $$ BEGIN PERFORM set_config('request.jwt.claims', '{}', true); END $$;

DO $$
DECLARE
  v_heard INTEGER;
BEGIN
  IF NOT app.realtime_ready() THEN
    RAISE NOTICE 'skip  Realtime has never run here — nothing to deliver from';
    RETURN;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM realtime.messages
                  WHERE topic = 'server:aaaa0000-0000-4000-8000-000000000001' AND event = 'message' AND private
                    AND payload->>'id' = '9101' AND payload->>'channel_id' = 'aaaa1111-0000-4000-8000-000000000001') THEN
    RAISE EXCEPTION 'FAIL: an open channel''s message was not told to its server';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM realtime.messages
                  WHERE topic = 'server:aaaa0000-0000-4000-8000-000000000001' AND event = 'message_changed'
                    AND payload->>'message_id' = '9101') THEN
    RAISE EXCEPTION 'FAIL: an edit was not told to the server';
  END IF;

  -- 027: a private channel is announced on a topic of its own, once, whoever
  -- can see it. This used to be one row per member — the assertion that it is
  -- exactly one is the whole point of that change, because the old shape was
  -- correct and cost 176 ms on a channel 8,750 people could read.
  SELECT count(*) INTO v_heard FROM realtime.messages
   WHERE event = 'message' AND payload->>'id' = '9102'
     AND topic = 'channel:aaaa1111-0000-4000-8000-0000000000ff' AND private;
  IF v_heard <> 1 THEN
    RAISE EXCEPTION
      'FAIL: a private channel''s message was told to its own topic % times, not once',
      v_heard;
  END IF;
  -- Nobody is told individually any more except a granted bot, which hears
  -- only its own topic and is bounded by the grants rather than by the
  -- membership. Anybody else here means the per-member fanout is back.
  IF EXISTS (SELECT 1 FROM realtime.messages
              WHERE event = 'message' AND payload->>'id' = '9102'
                AND topic LIKE 'user:%'
                AND NOT EXISTS (SELECT 1 FROM bot_channel_keys g
                                 WHERE g.channel_id = 'aaaa1111-0000-4000-8000-0000000000ff'
                                   AND g.bot_id::text = substr(topic, 6))) THEN
    RAISE EXCEPTION 'FAIL: a private channel''s message was announced member by member';
  END IF;
  -- And never to the server's topic, which is everybody.
  IF EXISTS (SELECT 1 FROM realtime.messages
              WHERE topic = 'server:aaaa0000-0000-4000-8000-000000000001'
                AND payload->>'id' = '9102') THEN
    RAISE EXCEPTION 'FAIL: a private channel''s message reached the whole server';
  END IF;

  SELECT count(*) INTO v_heard FROM realtime.messages
   WHERE event = 'message' AND payload->>'id' = '9103';
  IF v_heard <> 1 OR NOT EXISTS (SELECT 1 FROM realtime.messages
                                  WHERE topic = 'user:11111111-aaaa-4aaa-8aaa-000000000001' AND payload->>'id' = '9103') THEN
    RAISE EXCEPTION 'FAIL: an ephemeral reply reached % topics, not just its recipient''s', v_heard;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM realtime.messages
                  WHERE topic = 'user:11111111-aaaa-4aaa-8aaa-000000000001' AND event = 'dm'
                    AND payload->>'id' = '8101' AND payload->>'sender_id' = '11111111-aaaa-4aaa-8aaa-000000000002') THEN
    RAISE EXCEPTION 'FAIL: a DM was not told to its recipient';
  END IF;

  IF EXISTS (SELECT 1 FROM realtime.messages
              WHERE payload ? 'ciphertext' AND payload->>'id' IN ('9101', '9102', '9103', '8101')) THEN
    RAISE EXCEPTION 'FAIL: a broadcast carried a message body';
  END IF;
  RAISE NOTICE 'ok  each write is told once, to exactly the topic that may hear it';
END $$;

-- ---------- and a seat at a private table is news to whoever got it (023) ----------
-- 017 announces `channels` when the `channels` row moves. Handing somebody a
-- seat moves no such row — it writes `channel_members` — so before 023 the
-- new member's sidebar did not know until the app was restarted. Verified
-- that way before this was written: fifteen seconds, nothing, then it
-- appeared on the next launch.

RESET ROLE;

DO $$
DECLARE
  v_chan UUID := 'aaaa1111-0000-4000-8000-0000000000ff';  -- the private one
  v_them UUID := '11111111-aaaa-4aaa-8aaa-000000000003';
  v_since BIGINT;
  v_told  INTEGER;
BEGIN
  IF NOT app.realtime_ready() THEN
    RAISE NOTICE 'skip  Realtime has never run here — nothing to deliver from';
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM channel_members
              WHERE channel_id = v_chan AND user_id = v_them) THEN
    RAISE EXCEPTION 'FAIL: they already hold the seat; this proves nothing';
  END IF;

  SELECT count(*) INTO v_since FROM realtime.messages
   WHERE topic = 'user:' || v_them AND event = 'me';

  INSERT INTO channel_members (channel_id, user_id) VALUES (v_chan, v_them);

  SELECT count(*) - v_since INTO v_told FROM realtime.messages
   WHERE topic = 'user:' || v_them AND event = 'me';
  IF v_told <> 1 THEN
    RAISE EXCEPTION 'FAIL: gaining a seat told them % times, expected once', v_told;
  END IF;

  -- `me` is what the client already re-reads the whole server on, so a seat
  -- gained arrives the same way a ban does. It must not go to the server's
  -- topic: this is one person's news, and the one person it is for is
  -- precisely the one whose last read could not see the channel.
  IF EXISTS (SELECT 1 FROM realtime.messages
              WHERE topic = 'server:aaaa0000-0000-4000-8000-000000000001'
                AND event = 'me') THEN
    RAISE EXCEPTION 'FAIL: one member''s seat was announced to the whole server';
  END IF;

  -- Losing it is the half worth more: a private channel still in the sidebar
  -- after access was taken away is the mistake with consequences.
  SELECT count(*) INTO v_since FROM realtime.messages
   WHERE topic = 'user:' || v_them AND event = 'me';
  DELETE FROM channel_members WHERE channel_id = v_chan AND user_id = v_them;
  SELECT count(*) - v_since INTO v_told FROM realtime.messages
   WHERE topic = 'user:' || v_them AND event = 'me';
  IF v_told <> 1 THEN
    RAISE EXCEPTION 'FAIL: losing a seat told them % times, expected once', v_told;
  END IF;

  RAISE NOTICE 'ok  a seat at a private table, gained or lost, reaches the one it is for';
END $$;

-- ---------- and a bot is told on its own topic (018) ----------
-- A bot is in none of the audiences a member is in: it does not join the
-- server's topic, and a grant is not membership. Everything it may hear has
-- to reach `user:<bot id>` or it goes back to polling for it.

RESET ROLE;
INSERT INTO bot_channel_keys (channel_id, bot_id, granted_by, from_key_version)
VALUES ('aaaa1111-0000-4000-8000-000000000001', '11111111-aaaa-4aaa-8aaa-0000000000b0', '11111111-aaaa-4aaa-8aaa-000000000002', 1)
ON CONFLICT DO NOTHING;

DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

-- Ordinary, addressed, and a button press.
INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version)
  VALUES (9201, 'aaaa1111-0000-4000-8000-000000000001', 'watched', 'n', 's', 1);
INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version, to_bot)
  VALUES (9202, 'aaaa1111-0000-4000-8000-000000000001', 'modbot: hello', 'n', 's', 1, '11111111-aaaa-4aaa-8aaa-0000000000b0');
-- A press carries an action and no key: `messages_action_shape` says so.
INSERT INTO messages (id, channel_id, ciphertext, nonce, signature, key_version,
                      to_bot, is_interaction, action_id)
  VALUES (9203, 'aaaa1111-0000-4000-8000-000000000001', 'pressed', 'n', 's', 0,
          '11111111-aaaa-4aaa-8aaa-0000000000b0', true, 'confirm');

DO $$ BEGIN PERFORM set_config('request.jwt.claims', '{}', true); END $$;

DO $$
BEGIN
  IF NOT app.realtime_ready() THEN
    RAISE NOTICE 'skip  Realtime has never run here — nothing to deliver from';
    RETURN;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM realtime.messages
                  WHERE topic = 'user:11111111-aaaa-4aaa-8aaa-0000000000b0' AND payload->>'id' = '9201') THEN
    RAISE EXCEPTION 'FAIL: a granted bot was not told of a message in the channel it watches';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM realtime.messages
                  WHERE topic = 'user:11111111-aaaa-4aaa-8aaa-0000000000b0' AND payload->>'id' = '9202') THEN
    RAISE EXCEPTION 'FAIL: a bot was not told of a message addressed to it';
  END IF;

  -- The press is between the presser and the bot, and `messages_select` shows
  -- it to nobody else.
  IF EXISTS (SELECT 1 FROM realtime.messages
              WHERE payload->>'id' = '9203' AND topic <> 'user:11111111-aaaa-4aaa-8aaa-0000000000b0') THEN
    RAISE EXCEPTION 'FAIL: a button press was announced beyond the bot it was for';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM realtime.messages
                  WHERE topic = 'user:11111111-aaaa-4aaa-8aaa-0000000000b0' AND payload->>'id' = '9203') THEN
    RAISE EXCEPTION 'FAIL: a bot was not told of a press meant for it';
  END IF;
  RAISE NOTICE 'ok  a bot hears what it watches, what it is asked and what it is pressed';
END $$;

-- 019: `to_bot` is ON DELETE SET NULL, and the press's own row must survive
-- that. Undone immediately — the bot is wanted by the sections below.
DO $$
BEGIN
  BEGIN
    DELETE FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-0000000000b0';
    RAISE EXCEPTION 'undo';
  EXCEPTION
    WHEN raise_exception THEN
      IF SQLERRM <> 'undo' THEN
        RAISE EXCEPTION 'FAIL: removing a bot that was pressed: %', SQLERRM;
      END IF;
    WHEN OTHERS THEN
      RAISE EXCEPTION 'FAIL: removing a bot that was pressed: %', SQLERRM;
  END;
  RAISE NOTICE 'ok  a bot that somebody pressed a button on can still be removed';
END $$;


RESET ROLE;

-- ============================================================
-- 28. The soundboard (library, bits, and the blob behind it)
-- ============================================================
-- A play never touches this database — it is a packet on the call's data
-- channel — so everything there is to protect here is the *library*: who may
-- add to it, who may read it, and whether a deleted clip leaves its bytes
-- lying in a bucket.

RESET ROLE;
DO $$ BEGIN PERFORM set_config('request.jwt.claims', '', true); END $$;

DO $$
BEGIN
  IF app.perm('MANAGE_SOUNDBOARD') = 0 OR app.perm('USE_SOUNDBOARD') = 0 THEN
    RAISE EXCEPTION 'FAIL: the soundboard bits are not in perm_bit';
  END IF;
  -- A bit outside `perm_all` is one the role editor masks off, so no role can
  -- ever be given it — a permission that exists and cannot be granted.
  IF (app.perm_all() & app.perm('MANAGE_SOUNDBOARD')) = 0
     OR (app.perm_all() & app.perm('USE_SOUNDBOARD')) = 0 THEN
    RAISE EXCEPTION 'FAIL: a soundboard bit is outside perm_all';
  END IF;
  RAISE NOTICE 'ok  both soundboard bits exist and are grantable';
END $$;

-- Playing is ordinary; adding is not. Beta is the untouched server, so its
-- roles are exactly what `seed_default_roles` made them.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM roles
              WHERE server_id = 'bbbb0000-0000-4000-8000-000000000001'
                AND is_everyone
                AND (permissions & app.perm('USE_SOUNDBOARD')) = 0) THEN
    RAISE EXCEPTION 'FAIL: the baseline cannot use the soundboard';
  END IF;
  IF EXISTS (SELECT 1 FROM roles
              WHERE server_id = 'bbbb0000-0000-4000-8000-000000000001'
                AND is_everyone
                AND (permissions & app.perm('MANAGE_SOUNDBOARD')) <> 0) THEN
    RAISE EXCEPTION 'FAIL: everybody can fill the soundboard';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM roles
                  WHERE server_id = 'bbbb0000-0000-4000-8000-000000000001'
                    AND name = 'Moderator'
                    AND (permissions & app.perm('MANAGE_SOUNDBOARD')) <> 0) THEN
    RAISE EXCEPTION 'FAIL: moderators cannot manage the soundboard';
  END IF;
  RAISE NOTICE 'ok  everybody may press one, a moderator decides what is there';
END $$;

-- ---------- adding one ----------
SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

-- Alice is an administrator. She cannot so much as *name* the two stamped
-- columns — there is no grant on them — and what she leaves out is filled in
-- for her, which is the half a widened grant would have to fall back on.
DO $$
DECLARE v_row soundboard_sounds%ROWTYPE;
BEGIN
  BEGIN
    INSERT INTO soundboard_sounds
           (server_id, created_by, name, object_path, duration_ms, bytes)
    VALUES ('bbbb0000-0000-4000-8000-000000000001',
            '11111111-aaaa-4aaa-8aaa-000000000002',
            'not-mine',
            'bbbb0000-0000-4000-8000-000000000001/x.audio', 100, 100);
    RAISE EXCEPTION 'FAIL: a client named the columns the server stamps';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  INSERT INTO soundboard_sounds (name, emoji, object_path, duration_ms, bytes)
  VALUES ('airhorn', '📯',
          'aaaa0000-0000-4000-8000-000000000001/horn.audio', 1200, 9000);

  SELECT * INTO v_row FROM soundboard_sounds WHERE name = 'airhorn';
  IF v_row.server_id <> 'aaaa0000-0000-4000-8000-000000000001' THEN
    RAISE EXCEPTION 'FAIL: a clip was not hung on its author''s server';
  END IF;
  IF v_row.created_by <> '11111111-aaaa-4aaa-8aaa-000000000001' THEN
    RAISE EXCEPTION 'FAIL: a clip was not signed with its author''s name';
  END IF;
  RAISE NOTICE 'ok  an admin adds a clip, and the server and author are stamped';
END $$;

-- Bob holds no role at all, so he is the baseline and nothing more.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  BEGIN
    INSERT INTO soundboard_sounds (name, object_path, duration_ms, bytes)
    VALUES ('bob-was-here',
            'aaaa0000-0000-4000-8000-000000000001/bob.audio', 500, 400);
    RAISE EXCEPTION 'FAIL: a plain member filled the soundboard';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    DELETE FROM soundboard_sounds WHERE name = 'airhorn';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  IF NOT EXISTS (SELECT 1 FROM soundboard_sounds WHERE name = 'airhorn') THEN
    RAISE EXCEPTION 'FAIL: a plain member deleted a clip';
  END IF;

  -- ...but he can see it, which is the point of a soundboard.
  IF NOT EXISTS (SELECT 1 FROM soundboard_sounds WHERE name = 'airhorn') THEN
    RAISE EXCEPTION 'FAIL: a member cannot read the soundboard';
  END IF;
  RAISE NOTICE 'ok  a member reads the library and cannot write to it';
END $$;

-- The bytes cannot be swapped out from under a cached clip: `object_path` has
-- no UPDATE grant, so this is refused by the grant rather than by a policy.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  BEGIN
    UPDATE soundboard_sounds
       SET object_path = 'aaaa0000-0000-4000-8000-000000000001/swapped.audio'
     WHERE name = 'airhorn';
    RAISE EXCEPTION 'FAIL: a clip was repointed at other bytes';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  -- Renaming is fine, and is the reason there is an UPDATE grant at all.
  UPDATE soundboard_sounds SET name = 'air horn' WHERE name = 'airhorn';
  RAISE NOTICE 'ok  a clip can be renamed and cannot be repointed';
END $$;

-- ---------- another server's library ----------
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"22222222-bbbb-4bbb-8bbb-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM soundboard_sounds
              WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001') THEN
    RAISE EXCEPTION 'FAIL: a member of Beta read Alpha''s soundboard';
  END IF;
  RAISE NOTICE 'ok  a soundboard stops at its own server';
END $$;

-- ---------- the ceiling ----------
RESET ROLE;
DO $$ BEGIN PERFORM set_config('request.jwt.claims', '', true); END $$;

DO $$
DECLARE i INTEGER;
BEGIN
  FOR i IN 1..(app.soundboard_max() - 1) LOOP
    INSERT INTO soundboard_sounds
           (server_id, name, object_path, duration_ms, bytes)
    VALUES ('aaaa0000-0000-4000-8000-000000000001', 'filler-' || i,
            'aaaa0000-0000-4000-8000-000000000001/f' || i || '.audio', 100, 100);
  END LOOP;

  BEGIN
    INSERT INTO soundboard_sounds
           (server_id, name, object_path, duration_ms, bytes)
    VALUES ('aaaa0000-0000-4000-8000-000000000001', 'one-too-many',
            'aaaa0000-0000-4000-8000-000000000001/over.audio', 100, 100);
    RAISE EXCEPTION 'FAIL: the soundboard went past its ceiling';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%soundboard_full%' THEN RAISE; END IF;
  END;

  -- A full board on one server is not a full board on the next.
  INSERT INTO soundboard_sounds
         (server_id, name, object_path, duration_ms, bytes)
  VALUES ('bbbb0000-0000-4000-8000-000000000001', 'beta-clip',
          'bbbb0000-0000-4000-8000-000000000001/b.audio', 100, 100);
  RAISE NOTICE 'ok  a server holds app.soundboard_max() clips and no more';
END $$;

-- ---------- the row goes, and the bytes are not this schema's to take ----------
-- This used to assert the opposite, and passed while the feature was broken.
-- A trigger on the row did `DELETE FROM storage.objects`; against a real
-- stack Storage's own `protect_objects_delete` refuses that and took the
-- whole DELETE down with it, so a clip could not be removed at all. Nothing
-- here could see it, because the scratch database's `storage.objects` is a
-- plain table from `scratch_db.sh` with none of Storage's guards on it.
--
-- So the assertion is inverted on purpose: the row leaves the object alone,
-- and the client finishes the job through the Storage API. If a future
-- trigger starts reaching into that table again, this fails and says why.
DO $$
BEGIN
  INSERT INTO storage.objects (bucket_id, name, metadata)
  VALUES ('soundboard',
          'aaaa0000-0000-4000-8000-000000000001/horn.audio',
          '{"size": 9000}'::jsonb);

  DELETE FROM soundboard_sounds WHERE name = 'air horn';

  IF NOT EXISTS (SELECT 1 FROM storage.objects
                  WHERE bucket_id = 'soundboard'
                    AND name = 'aaaa0000-0000-4000-8000-000000000001/horn.audio') THEN
    RAISE EXCEPTION
      'FAIL: something in the schema deleted a storage object. Storage '
      'refuses that against a real stack, and it would orphan the bytes '
      'even where it works — the client uses the Storage API.';
  END IF;
  RAISE NOTICE 'ok  removing a clip leaves storage.objects to the Storage API';
END $$;

-- Cleared, so the sections after this one start from the library they expect.
DELETE FROM soundboard_sounds;

-- ============================================================
-- 19. One owner per server (013)
-- ============================================================
-- Dave joined Alpha in section 12 through a plain invite, on a server whose
-- fixture admins were inserted by hand and so never passed through
-- registration. That makes him the first person *registered* on Alpha — which
-- is the whole rule, and it must hold whether the invite named a role or not.

SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000001","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  IF NOT (SELECT is_owner FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-00000000000a') THEN
    RAISE EXCEPTION 'FAIL: the first person registered did not become the owner';
  END IF;
  IF (SELECT is_owner FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-000000000001') THEN
    RAISE EXCEPTION 'FAIL: an admin inserted by hand reads as owner';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM member_role_list
                  WHERE user_id = '11111111-aaaa-4aaa-8aaa-00000000000a' AND is_owner) THEN
    RAISE EXCEPTION 'FAIL: the roster view does not say who the owner is';
  END IF;
  RAISE NOTICE 'ok  the first person in owns the server, and everybody can see it';
END $$;

-- Alice holds ADMINISTRATOR, which since 018 has let her hand out a role at
-- her own rank. The owner role is above her rank and, more to the point, is
-- not hers to hand out at any rank: not to a member, and not through an
-- invite.
DO $$
DECLARE v_owner UUID := (SELECT id FROM roles
                          WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND is_owner);
BEGIN
  BEGIN
    INSERT INTO member_roles (user_id, role_id)
    VALUES ('11111111-aaaa-4aaa-8aaa-000000000002', v_owner);
    RAISE EXCEPTION 'FAIL: an admin handed out the owner role';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  BEGIN
    INSERT INTO invites (server_id, created_by, role_id)
    VALUES ('aaaa0000-0000-4000-8000-000000000001',
            '11111111-aaaa-4aaa-8aaa-000000000001', v_owner);
    RAISE EXCEPTION 'FAIL: an admin minted an invite that grants ownership';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  nobody hands out the owner role';
END $$;

-- Nor edits it. RLS filters the row out rather than raising, so the tell is
-- that nothing changed.
DO $$
DECLARE v_count INTEGER;
BEGIN
  UPDATE roles SET name = 'Boss'
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND is_owner;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count <> 0 THEN
    RAISE EXCEPTION 'FAIL: an admin renamed the owner role';
  END IF;
  DELETE FROM roles
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND is_owner;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count <> 0 THEN
    RAISE EXCEPTION 'FAIL: an admin deleted the owner role';
  END IF;
  BEGIN
    PERFORM moderate_user('11111111-aaaa-4aaa-8aaa-00000000000a', NULL, NULL, true);
    RAISE EXCEPTION 'FAIL: an admin banned the owner';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%cannot_moderate_admin%' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM transfer_ownership('11111111-aaaa-4aaa-8aaa-000000000001');
    RAISE EXCEPTION 'FAIL: an admin took ownership for herself';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%not_owner%' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM delete_server();
    RAISE EXCEPTION 'FAIL: an admin deleted the server';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%not_owner%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  the owner role, and the owner, are beyond an admin''s reach';
END $$;

-- Even by the service role, which is what registration and every edge
-- function run as: the trigger, not the policy, is what keeps it singular.
RESET ROLE;
SET LOCAL ROLE service_role;
DO $$
BEGIN
  BEGIN
    INSERT INTO member_roles (user_id, role_id)
    SELECT '11111111-aaaa-4aaa-8aaa-000000000002', id FROM roles
     WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND is_owner;
    RAISE EXCEPTION 'FAIL: a server has two owners';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%owner_is_singular%' THEN RAISE; END IF;
  END;
  BEGIN
    DELETE FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-00000000000a';
    RAISE EXCEPTION 'FAIL: the owner left, and the server has nobody who can end it';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%owner_cannot_leave%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  one owner, who cannot leave without passing it on';
END $$;
RESET ROLE;

-- Passing it on. Dave hands Alpha to Bob and is left an admin, not a member:
-- stepping down from owning the place is not stepping down from running it.
SET LOCAL ROLE authenticated;
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-00000000000a","role":"authenticated"}', true); END $$;

DO $$
BEGIN
  BEGIN
    PERFORM transfer_ownership('11111111-aaaa-4aaa-8aaa-00000000000a');
    RAISE EXCEPTION 'FAIL: the owner transferred the server to themselves';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%cannot_transfer_to_self%' THEN RAISE; END IF;
  END;
  BEGIN
    PERFORM transfer_ownership('22222222-bbbb-4bbb-8bbb-000000000001');
    RAISE EXCEPTION 'FAIL: a server was handed to somebody on another server';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%user_not_found%' THEN RAISE; END IF;
  END;

  PERFORM transfer_ownership('11111111-aaaa-4aaa-8aaa-000000000002');

  IF NOT (SELECT is_owner FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-000000000002') THEN
    RAISE EXCEPTION 'FAIL: the new owner is not the owner';
  END IF;
  IF (SELECT is_owner FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-00000000000a') THEN
    RAISE EXCEPTION 'FAIL: the old owner is still the owner';
  END IF;
  IF NOT (SELECT is_server_admin FROM users WHERE id = '11111111-aaaa-4aaa-8aaa-00000000000a') THEN
    RAISE EXCEPTION 'FAIL: the old owner was not left an admin';
  END IF;
  IF NOT app.has_perm('ADMINISTRATOR') THEN
    RAISE EXCEPTION 'FAIL: the old owner''s permissions did not follow the cache';
  END IF;

  -- Once. The role moved, and with it the right to move it.
  BEGIN
    PERFORM transfer_ownership('11111111-aaaa-4aaa-8aaa-000000000001');
    RAISE EXCEPTION 'FAIL: a former owner transferred the server again';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM NOT LIKE '%not_owner%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  ownership moves once, and leaves an admin behind';
END $$;

-- Ending it. Bob, now the owner, deletes Alpha; the cascade takes its members
-- with it, owner included — the one delete of an owner's row that is allowed.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"11111111-aaaa-4aaa-8aaa-000000000002","role":"authenticated"}', true); END $$;

DO $$
DECLARE v_id UUID;
BEGIN
  v_id := delete_server();
  IF v_id <> 'aaaa0000-0000-4000-8000-000000000001' THEN
    RAISE EXCEPTION 'FAIL: delete_server answered with the wrong server: %', v_id;
  END IF;
  RAISE NOTICE 'ok  the owner can end the server';
END $$;

RESET ROLE;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM servers WHERE id = 'aaaa0000-0000-4000-8000-000000000001') THEN
    RAISE EXCEPTION 'FAIL: the server is still there';
  END IF;
  IF EXISTS (SELECT 1 FROM users WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001') THEN
    RAISE EXCEPTION 'FAIL: the cascade stopped at the owner';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM servers WHERE id = 'bbbb0000-0000-4000-8000-000000000001') THEN
    RAISE EXCEPTION 'FAIL: deleting one server took another with it';
  END IF;
  RAISE NOTICE 'ok  and it takes everything of its own with it, and nothing else';
END $$;

RESET ROLE;
ROLLBACK;
