# The edge runtime's router

`main/index.ts` is copied unmodified from
[supabase/supabase](https://github.com/supabase/supabase)
(`docker/volumes/functions/main/`), Apache-2.0. It keeps that licence rather than the
repository's AGPL, and its text is in `../LICENSE-APACHE-2.0`.

It is what `supabase/edge-runtime` boots (`--main-service`): it reads the first
path segment, spawns a worker for `/home/deno/functions/<name>`, and hands it
the request. Rift's own functions never see it, and it has no Rift-specific
behaviour — but nothing runs without it, and it does not live in the app repo,
so `scripts/sync.sh` would never bring it across. Hence a template.
