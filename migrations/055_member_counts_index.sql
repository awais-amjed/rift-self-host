-- ============================================================
-- Rift self-hosted server — 055: the sidebar's member count reads an index
-- ============================================================
-- Found in the query review of Nov 25 2026, measured Nov 26 on a test
-- database of 50,001 members, 20 of them bots and 2,000 banned.
--
-- `member_counts`, which every open of the member sidebar asks through
-- `member_sidebar`, counts the people and bots in the server who are not
-- banned. Nothing indexed that, so each count read the whole `users` table:
-- 1,667 pages, 7.2 ms.
--
-- This index holds exactly those members and the two things the count
-- needs, so the count is an index-only scan of 44 pages: 7.2 → 4.2 ms. The
-- table is written when somebody joins, leaves, is banned or changes their
-- profile, which is rare beside how often the sidebar is opened.
--
-- The other two pages the review looked at stay as they are. The bots page
-- already has `idx_users_bots`. The banned page, which only a moderator
-- opens, walks the name index until it has a page; with almost nobody
-- banned that is a pass over every member, 9 ms at 50,000. A partial index
-- would not serve it, as `list_members` takes the filter as a parameter.

CREATE INDEX IF NOT EXISTS idx_users_counted
  ON users (server_id, is_bot) WHERE NOT is_banned;

COMMENT ON INDEX idx_users_counted IS
  'The members `member_counts` counts — not banned, people and bots apart — '
  'so the sidebar header is an index-only scan rather than a read of every user.';
