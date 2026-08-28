-- ============================================================
-- Rift self-hosted server — 019: a DM could not be sent
-- ============================================================
-- `attest_message` runs on two tables — `attest_messages` on `messages` and
-- `attest_dm_messages` on `dm_messages`. 013 added the webhook columns to the
-- first and taught the trigger to clear them on a member's insert:
--
--     IF NEW.sender_id IS NOT NULL THEN
--       NEW.webhook_id  := NULL;
--       NEW.origin_name := NULL;
--     END IF;
--
-- `dm_messages` has neither column, so every DM sent by a logged-in member
-- raised `record "new" has no field "webhook_id"` and never reached the table.
-- Only a member's insert took that branch, which is why nothing else noticed:
-- the service role has no `auth.uid()` and skipped it entirely.
--
-- The UPDATE branch below it has always been guarded by `TG_TABLE_NAME`. The
-- INSERT branch was written as though it had only one table to serve.
--
-- ---------- and the line that went with it ----------
--
-- 001 opened the function with an early return:
--
--     IF auth.uid() IS NULL THEN RETURN NEW; END IF;
--
-- Nothing that reaches this trigger without a session is a client — `anon` holds
-- no INSERT grant on either table — so that branch is the service role and the
-- superuser, both of which are trusted to write a row as it stands. It is how
-- `post_webhook_message` writes a NULL sender, and how anything that needs to
-- back-date a row (retention tests, fixtures, a repair script) can.
--
-- 013 dropped it, and three things stopped working for the same reason: a
-- fixture insert had its `sender_id` overwritten with NULL and hit
-- `messages_one_origin`; a back-dating UPDATE had its `created_at` pinned back;
-- and the DM path above. It is restored here, which costs 013 nothing — a
-- *member* still cannot claim to be a webhook, because a member has a session
-- and never takes this branch.
--
-- ---------- why this was not caught ----------
--
-- `tests/policies_test.sql` sends a DM. It has been unable to run since the
-- same migration: its fixtures are written as the superuser, and 013 made
-- `sender_id := auth.uid()` — NULL, there — collide with the new
-- `messages_one_origin` CHECK. So the suite failed while loading its fixtures
-- and never reached the assertion that would have shown this.
--
-- One migration broke the code and the thing watching the code. That is the
-- argument for the suite being part of the migration rather than after it.

CREATE OR REPLACE FUNCTION attest_message()
  RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = public AS $$
BEGIN
  -- Restored from 001. Everything below is about not trusting a client; there
  -- is no client here.
  IF auth.uid() IS NULL THEN
    RETURN NEW;
  END IF;

  IF TG_OP = 'INSERT' THEN
    NEW.sender_id  := auth.uid();
    NEW.created_at := now();
    NEW.edited_at  := NULL;

    -- A member's insert is never a webhook's, whatever it sent. The service
    -- role never arrives here at all now, and it does not need to:
    -- `post_webhook_message` writes both columns itself.
    --
    -- Guarded on the table, like the UPDATE branch below: these two columns
    -- exist on `messages` and nowhere else, and a DM has no origin to overrule.
    IF TG_TABLE_NAME = 'messages' THEN
      NEW.webhook_id  := NULL;
      NEW.origin_name := NULL;
    END IF;
    RETURN NEW;
  END IF;

  -- An edit may only change the envelope. Identity, placement and time of
  -- sending are the server's word and stay put; edited_at is stamped here
  -- rather than trusted from the client.
  NEW.id         := OLD.id;
  NEW.sender_id  := OLD.sender_id;
  NEW.created_at := OLD.created_at;
  IF TG_TABLE_NAME = 'messages' THEN
    NEW.channel_id  := OLD.channel_id;
    -- The displayed name is frozen; the reference is not.
    --
    -- `webhook_id` is deliberately NOT pinned here, and that is not an
    -- oversight. `ON DELETE SET NULL` is implemented as an UPDATE, so this
    -- trigger fires during the cascade — pinning the column put the id back,
    -- and the FK then rejected its own cascade. Deleting a webhook that had
    -- ever posted was impossible.
    --
    -- Nothing is lost by leaving it open: `authenticated` holds a column-level
    -- UPDATE grant on (ciphertext, nonce, signature, key_version) only, so no
    -- member can write `webhook_id` by hand in the first place.
    NEW.origin_name := OLD.origin_name;
  ELSE
    NEW.recipient_id := OLD.recipient_id;
  END IF;
  IF NEW.ciphertext IS DISTINCT FROM OLD.ciphertext THEN
    NEW.edited_at := now();
  ELSE
    NEW.edited_at := OLD.edited_at;
  END IF;
  RETURN NEW;
END; $$;
