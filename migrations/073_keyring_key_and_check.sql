-- ============================================================
-- Rift self-hosted server — 073: a sealed key costs one index, checked once
-- ============================================================
-- Found in the speed re-review, Nov 26 2026.
--
-- Every channel key sealed for a member is a `channel_keyring` row, and a
-- rotation in a channel of 50,000 writes 50,000 of them, 500 a batch. Two
-- things made each batch slow.
--
--   * The table's primary key was `id`, a random UUID nothing reads: no
--     function, endpoint or SDK selects it, and nothing references it. Every
--     row went in at a random place in that index, so a batch touched as many
--     of its pages as it had rows (510 MB on a 12.8 M-row test server, never
--     scanned). It goes. The real key, `(channel_id, key_version, user_id)`,
--     is the table's unique constraint already, the one upserts name, so it
--     stays the key; it cannot simply become the primary key, since its index
--     belongs to that constraint, and rebuilding it would lock the table for
--     as long. `id` itself stays, with its default, for anyone reading `*`.
--   * `refuse_ineligible_keyring` ran for every row: two eligibility checks
--     and a lookup of the member. It now runs once for the statement, over the
--     rows the statement wrote, asking the same questions of all of them at
--     once and refusing with the same three reasons: the sealer is not in the
--     channel, a bot has no grant (or one from a later version), or the member
--     is not in it. It runs before the triggers that note key progress, so a
--     refused batch does no other work.
--
-- One difference: a row an upsert skipped as already there is no longer
-- checked, since it was never written.
--
-- A 500-row batch on the test server: 36–133 ms before, 17.5 ms without the
-- old index, 7.7 ms without the per-row check as well.

-- ── No index on a key nobody reads ──────────────────────────
-- `channel_keyring_channel_id_key_version_user_id_key` remains the key.
ALTER TABLE channel_keyring DROP CONSTRAINT channel_keyring_pkey;

-- ── Who may hold a sealed key, asked once a statement ───────
DROP TRIGGER IF EXISTS channel_keyring_refuse_ineligible ON channel_keyring;

CREATE OR REPLACE FUNCTION public.refuse_ineligible_keyring()
  RETURNS TRIGGER
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- A key is only as trustworthy as whoever sealed it. A bot never seals, it
  -- is sealed *for*, so this is a plain member test, bots included.
  IF EXISTS (
    SELECT 1
      FROM (SELECT DISTINCT channel_id, wrapped_by FROM fresh) w
     WHERE NOT app.channel_eligible(w.channel_id, w.wrapped_by)) THEN
    RAISE EXCEPTION 'wrapper_not_a_channel_member';
  END IF;

  -- A bot holds a key only under its grant, and only from the version the
  -- grant names: forward-only, enforced where the row is written.
  IF EXISTS (
    SELECT 1
      FROM fresh f
      JOIN users u ON u.id = f.user_id AND u.is_bot
      LEFT JOIN bot_channel_keys g
        ON g.channel_id = f.channel_id AND g.bot_id = f.user_id
     WHERE g.bot_id IS NULL) THEN
    RAISE EXCEPTION 'bot_cannot_hold_channel_key';
  END IF;
  IF EXISTS (
    SELECT 1
      FROM fresh f
      JOIN users u ON u.id = f.user_id AND u.is_bot
      JOIN bot_channel_keys g
        ON g.channel_id = f.channel_id AND g.bot_id = f.user_id
     WHERE f.key_version < g.from_key_version) THEN
    RAISE EXCEPTION 'bot_key_version_before_grant';
  END IF;

  -- Anyone else: `app.channel_eligible`, for all the rows at once. On the
  -- channel's server, not banned, and in it when it is private.
  IF EXISTS (
    SELECT 1
      FROM fresh f
      LEFT JOIN users u    ON u.id = f.user_id
      LEFT JOIN channels c ON c.id = f.channel_id
     WHERE NOT COALESCE(u.is_bot, false)
       AND (u.id IS NULL OR c.id IS NULL
            OR u.server_id IS DISTINCT FROM c.server_id
            OR u.is_banned
            OR (c.is_private
                AND NOT EXISTS (SELECT 1 FROM channel_members cm
                                 WHERE cm.channel_id = f.channel_id
                                   AND cm.user_id = f.user_id)
                AND NOT EXISTS (SELECT 1 FROM channel_role_access cra
                                  JOIN member_roles mr ON mr.role_id = cra.role_id
                                 WHERE cra.channel_id = f.channel_id
                                   AND mr.user_id = f.user_id)))) THEN
    RAISE EXCEPTION 'not_a_channel_member';
  END IF;
  RETURN NULL;
END $$;

COMMENT ON FUNCTION public.refuse_ineligible_keyring() IS
  'Refuses a statement that seals a channel key for, or by, somebody outside '
  'the channel, or for a bot outside its grant. Once a statement, over the rows '
  'it wrote.';

-- Named to fire before `channel_keyring_note_minted` and
-- `channel_keyring_note_progress`: triggers of one kind fire in name order.
CREATE TRIGGER channel_keyring_check_eligible
  AFTER INSERT ON channel_keyring
  REFERENCING NEW TABLE AS fresh
  FOR EACH STATEMENT EXECUTE FUNCTION public.refuse_ineligible_keyring();

-- ── Grants ──────────────────────────────────────────────────
REVOKE ALL ON FUNCTION public.refuse_ineligible_keyring() FROM PUBLIC, anon, authenticated;
