-- ============================================================
-- Rift self-hosted server — policy tests
-- ============================================================
-- What this is for: the access rules moved out of TypeScript, where they had a
-- test suite around them, and into grants and policies, where they had none.
-- These are that suite. Every case here is something a policy edit could break
-- silently — most of all the ones that assert a *denial*, because a policy that
-- accidentally permits looks exactly like a working app.
--
-- Run against a database with 001–007 applied:
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

INSERT INTO messages (id, channel_id, sender_id, ciphertext, nonce, signature, key_version) VALUES
  (9001, 'aaaa1111-0000-4000-8000-000000000001', '11111111-aaaa-4aaa-8aaa-000000000002',
   'alpha-from-bob', 'n', 's', 1),
  (9002, 'bbbb1111-0000-4000-8000-000000000001', '22222222-bbbb-4bbb-8bbb-000000000001',
   'beta-from-mallory', 'n', 's', 1),
  (9003, 'aaaa1111-0000-4000-8000-000000000001', '11111111-aaaa-4aaa-8aaa-000000000001',
   'alpha-from-alice', 'n', 's', 1);

INSERT INTO dm_messages (id, sender_id, recipient_id, ciphertext, nonce, signature, key_version) VALUES
  (8001, '11111111-aaaa-4aaa-8aaa-000000000002', '11111111-aaaa-4aaa-8aaa-000000000001',
   'dm-bob-to-alice', 'n', 's', 1);

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

DO $$
BEGIN
  BEGIN
    INSERT INTO invites (server_id, created_by)
    VALUES ('aaaa0000-0000-4000-8000-000000000001', '11111111-aaaa-4aaa-8aaa-000000000002');
    RAISE EXCEPTION 'FAIL: a member without can_create_tokens minted an invite';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  inviting requires the permission';
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

  -- Carol may invite, but she is not an admin, so she cannot mint one.
  BEGIN
    INSERT INTO invites (server_id, created_by, is_server_admin)
    VALUES ('aaaa0000-0000-4000-8000-000000000001', '11111111-aaaa-4aaa-8aaa-000000000003', true);
    RAISE EXCEPTION 'FAIL: an inviter granted a permission they do not hold';
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
  BEGIN
    PERFORM set_user_permissions('11111111-aaaa-4aaa-8aaa-000000000003', true, NULL, NULL);
    RAISE EXCEPTION 'FAIL: a non-admin can grant permissions';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'not_authorized' THEN RAISE; END IF;
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

  BEGIN
    PERFORM set_user_permissions(auth.uid(), false, NULL, NULL);
    RAISE EXCEPTION 'FAIL: an admin can demote themselves (last-admin lockout)';
  EXCEPTION WHEN raise_exception THEN
    IF SQLERRM <> 'cannot_change_own_permissions' THEN RAISE; END IF;
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
  IF EXISTS (SELECT 1 FROM users) THEN
    RAISE EXCEPTION 'FAIL: a banned member can still read the member list';
  END IF;
  BEGIN
    INSERT INTO messages (channel_id, ciphertext, nonce, signature, key_version)
    VALUES ('aaaa1111-0000-4000-8000-000000000001', 'after-ban', 'n', 's', 1);
    RAISE EXCEPTION 'FAIL: a banned member can still post';
  EXCEPTION WHEN insufficient_privilege THEN NULL;
  END;
  RAISE NOTICE 'ok  a ban applies from the next statement, not the next token';
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

-- ── Attachments the messages left behind ────────────────────
-- app.orphaned_attachments finds blobs with no message, without any linkage —
-- an object is named for the scope it was uploaded to, and anything older than
-- the oldest surviving message of that scope belonged to one that is gone.

INSERT INTO storage.objects (bucket_id, name, owner, created_at) VALUES
  -- Under #forever, which kept all four of its messages: this one predates
  -- them, so it belonged to something already deleted.
  ('chat-attachments', 'aaaa1111-0000-4000-8000-000000000004/old.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '40 days'),
  -- Under the same scope but newer than the surviving messages: keep.
  ('chat-attachments', 'aaaa1111-0000-4000-8000-000000000004/live.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '2 hours'),
  -- The case the margin exists for. An attachment is uploaded *before* the
  -- message that carries its key, so a blob belonging to the OLDEST surviving
  -- message is itself older than the watermark. Without the margin this is
  -- swept on every run, quietly emptying the oldest message in every channel.
  ('chat-attachments', 'aaaa1111-0000-4000-8000-000000000004/watermark.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002',
   (SELECT MIN(created_at) - interval '4 seconds' FROM messages
     WHERE channel_id = 'aaaa1111-0000-4000-8000-000000000004')),
  -- #strict has nothing left at all, so everything under it is orphaned.
  ('chat-attachments', 'aaaa1111-0000-4000-8000-000000000003/gone.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '3 hours'),
  -- A channel that no longer exists.
  ('chat-attachments', 'cccc1111-0000-4000-8000-000000000009/dead.bin',
   '11111111-aaaa-4aaa-8aaa-000000000002', now() - interval '3 hours'),
  -- Uploaded moments ago: its message may still be in flight, so the grace
  -- period must protect it even though its scope has no messages.
  ('chat-attachments', 'aaaa1111-0000-4000-8000-000000000003/inflight.bin',
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
  ('chat-attachments',
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
  -- Bob uploaded these, so deleting his own message's files is his to do.
  DELETE FROM storage.objects
   WHERE name = 'aaaa1111-0000-4000-8000-000000000004/live.bin';
  IF EXISTS (SELECT 1 FROM storage.objects
              WHERE name = 'aaaa1111-0000-4000-8000-000000000004/live.bin') THEN
    RAISE EXCEPTION 'FAIL: an uploader cannot delete their own attachment';
  END IF;
  RAISE NOTICE 'ok  an uploader can delete the files of a message they delete';
END $$;

-- Mallory is on Beta and owns nothing here.
DO $$ BEGIN PERFORM set_config('request.jwt.claims',
  '{"sub":"22222222-bbbb-4bbb-8bbb-000000000001","role":"authenticated"}', true); END $$;
DO $$
BEGIN
  DELETE FROM storage.objects
   WHERE name = 'aaaa1111-0000-4000-8000-000000000003/gone.bin';
  IF NOT EXISTS (SELECT 1 FROM storage.objects
                  WHERE name = 'aaaa1111-0000-4000-8000-000000000003/gone.bin') THEN
    RAISE EXCEPTION 'FAIL: a stranger deleted someone else''s attachment';
  END IF;
  RAISE NOTICE 'ok  attachments are not deletable by whoever feels like it';
END $$;

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

RESET ROLE;
ROLLBACK;
