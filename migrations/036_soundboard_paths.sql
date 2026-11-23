-- ============================================================
-- Rift self-hosted server — 036: a clip's object name is a plain name
-- ============================================================
-- Found in the app's review of the soundboard, Nov 23 2026.
--
-- `soundboard_insert` checks that a clip's `object_path` starts with this
-- server's folder, and nothing about the rest. Every member's app reads the
-- path and keeps the clip's bytes in a file of its own, and until the app's
-- own fix it named that file after the path: one holding `..\` wrote and
-- deleted files outside the cache on Windows. The app now names its file by a
-- hash and drops a row whose name is not plain (`SoundboardApi.ownsPath`), but
-- older apps stay out there, and the database is where a rule about what a row
-- may hold belongs.
--
-- So `object_path` is now `<server id>/<name>`: the server id as Postgres
-- writes a UUID, then one name of letters, digits, `.`, `_` and `-`, not
-- starting with a dot, with no `..`, at most 128 characters. The app's own
-- names (`<24 hex>.audio`) are well inside it.
--
-- A row already breaking it was put there by hand or by a modified client,
-- and the app since review 17 never shows it. It is deleted here rather than
-- left behind a NOT VALID check, so the table says what it holds; its object
-- goes with the next sweep (`app.orphaned_attachments`), which keeps only
-- objects a row names.
-- ============================================================

DELETE FROM soundboard_sounds
 WHERE NOT (object_path ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$'
            AND position('..' IN object_path) = 0);

ALTER TABLE soundboard_sounds DROP CONSTRAINT IF EXISTS soundboard_sounds_object_path_plain;
ALTER TABLE soundboard_sounds ADD CONSTRAINT soundboard_sounds_object_path_plain
  CHECK (object_path ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$'
         AND position('..' IN object_path) = 0);

COMMENT ON CONSTRAINT soundboard_sounds_object_path_plain ON soundboard_sounds IS
  'object_path is <server id>/<plain name>: no further folders, no "..", '
  'nothing a client could turn into a path outside its cache.';
