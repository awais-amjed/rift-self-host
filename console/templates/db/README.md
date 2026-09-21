# Postgres init scripts

Copied unmodified from [supabase/supabase](https://github.com/supabase/supabase)
(`docker/volumes/db/`), Apache-2.0 — they keep that licence rather than the repository's
AGPL, and its text is in `../LICENSE-APACHE-2.0`. They run once, when the database volume is
first created, and set up the roles and settings the Supabase services expect before any Rift
migration has anything to attach to.

Upstream's set also includes `logs.sql` and `pooler.sql`. Both are omitted: this stack
runs neither the analytics service nor Supavisor.

Refresh them by hand against a matching `supabase/postgres` tag if the image in
`docker-compose.yml` is ever bumped — they are not covered by `scripts/sync.sh`, which
only tracks the Rift app repo.
