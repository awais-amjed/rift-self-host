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
    RAISE EXCEPTION 'FAIL: a member without MANAGE_ROLES created a role';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;
  RAISE NOTICE 'ok  creating a role needs MANAGE_ROLES';
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

-- ---------- the subset rule ----------
-- Position alone is not enough. Somebody who may manage rank 1 could otherwise
-- put `BAN_MEMBERS` on it and hand it to themselves.
DO $$
DECLARE v_staff UUID;
BEGIN
  INSERT INTO roles (server_id, name, position, permissions)
  VALUES ('aaaa0000-0000-4000-8000-000000000001', 'Staff', 2,
          app.perm('MANAGE_ROLES'))
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
    VALUES ('aaaa0000-0000-4000-8000-000000000001', 'Sneak', 1,
            app.perm('BAN_MEMBERS'));
    RAISE EXCEPTION 'FAIL: a permission was granted by somebody who lacks it';
  EXCEPTION WHEN insufficient_privilege OR raise_exception THEN
    IF SQLERRM LIKE 'FAIL:%' THEN RAISE; END IF;
  END;

  -- ...and she may still make one out of what she actually holds.
  INSERT INTO roles (server_id, name, position, permissions)
  VALUES ('aaaa0000-0000-4000-8000-000000000001', 'Greeter', 1,
          app.perm('CREATE_INVITE'));
  RAISE NOTICE 'ok  a role may only carry permissions its author holds';
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

RESET ROLE;
ROLLBACK;
