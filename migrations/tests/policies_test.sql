-- ============================================================
-- Rift self-hosted server — policy tests
-- ============================================================
-- What this is for: the access rules moved out of TypeScript, where they had a
-- test suite around them, and into grants and policies, where they had none.
-- These are that suite. Every case here is something a policy edit could break
-- silently — most of all the ones that assert a *denial*, because a policy that
-- accidentally permits looks exactly like a working app.
--
-- Run against a database with 001–009 applied:
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
     OR (r.name = 'Moderator' AND u.is_channel_manager)
     OR (r.name = 'Members'   AND u.can_create_tokens))
ON CONFLICT DO NOTHING;

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
  IF app.has_perm('CREATE_INVITE') THEN
    RAISE EXCEPTION 'FAIL: bob could never mint invites, and can now';
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
   WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND name = 'Members'
  ON CONFLICT DO NOTHING;
  DELETE FROM member_roles
   WHERE user_id = auth.uid()
     AND role_id IN (SELECT id FROM roles
                      WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001'
                        AND name = 'Members');
  IF EXISTS (SELECT 1 FROM member_roles mr JOIN roles r ON r.id = mr.role_id
              WHERE mr.user_id = auth.uid() AND r.name = 'Members') THEN
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
  IF NOT EXISTS (
    SELECT 1 FROM member_roles mr
      JOIN roles r ON r.id = mr.role_id
     WHERE mr.user_id = '11111111-aaaa-4aaa-8aaa-00000000000a'
       AND r.is_default) THEN
    RAISE EXCEPTION 'FAIL: a new member did not receive their roles';
  END IF;
  RAISE NOTICE 'ok  somebody can still join a server';
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
-- this bit was split out for. Carol will not do: she is a Moderator by now, and
-- Moderator is one of the roles the migration hands `ADD_BOTS` to.
RESET ROLE;
INSERT INTO member_roles (user_id, role_id)
SELECT '11111111-aaaa-4aaa-8aaa-0000000000a1', id FROM roles
 WHERE server_id = 'aaaa0000-0000-4000-8000-000000000001' AND name = 'Members'
ON CONFLICT DO NOTHING;
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
