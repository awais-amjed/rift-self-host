# rift-self-host

Everything needed to run your own Rift server.

```bash
curl -fsSL https://joinrift.app/self-host/docker-compose.yml -o docker-compose.yml
docker compose up -d
# then open http://localhost:8080
```

That starts one container. It serves a setup page that asks for a domain,
generates every secret, brings up the rest of the stack, and hands you an
invite link to paste into the app. You should never have to open a `.env`.

---

## What this is

A Rift server is a Supabase project (Postgres, PostgREST, GoTrue, Realtime,
Storage, Edge Functions) plus a LiveKit server for voice and video. Both are
ordinary open-source software with official images. Nothing here is a fork.

Everything Rift adds on top is **data, not modified software**:

| What Rift adds | Where it goes |
|---|---|
| Schema, policies, RPCs | `migrations/` — SQL applied to Postgres |
| Server endpoints | `functions/` — Deno, mounted into the edge runtime |
| Non-default settings | environment variables in `docker-compose.yml` |
| Voice config | a generated `livekit.yaml` |

So the stack runs `supabase/*`, `kong`, `postgrest`, `livekit/livekit-server`
and `caddy` exactly as their authors publish them, and this repo builds
**one** image of its own: the console.

## The console

`console/` is the only thing here that becomes an image. It carries the
migrations, the functions and a web UI, and it owns the jobs that are easy to
get silently wrong:

- generating the JWT signing key and signing the anon and service-role keys
- writing `.env` and `livekit.yaml`
- applying migrations, and knowing which have already run
- installing the edge functions and removing ones that no longer exist
- creating the first server, so the operator gets an invite link instead of a
  service-role key to paste
- reporting whether the stack is actually healthy, in the specific ways this
  stack fails quietly

It reaches the other containers through the Docker socket, which is how it can
report status and restart things. **That is root on the host.** It therefore
binds to `127.0.0.1` by default and sets a password on first run. Reach it
from another machine over an SSH tunnel, not by exposing the port.

### Where the line falls

The console configures **infrastructure**: the domain, the secrets, the
containers, updates. It does not configure the **server** — name, icon,
retention, upload limits, roles and members are all in the Rift app's own admin
UI, which talks to `update_server`. Two places to change one setting is how
they end up disagreeing.

## Layout

```
docker-compose.yml     what an operator downloads
console/               the one custom image
migrations/            vendored from the app repo
functions/             vendored from the app repo
scripts/sync.sh        refreshes both from ../rift
```

`migrations/` and `functions/` are copies, committed so this repo builds on its
own. `scripts/sync.sh` refreshes them and is the only thing that should ever
write there — edit the originals in the app repo.

## API keys

Servers issue Supabase's **new opaque keys** — `sb_publishable_` for clients,
`sb_secret_` for the console — rather than the legacy `anon` / `service_role`
JWTs that Supabase is retiring by the end of 2026. Kong holds both credentials
and swaps an opaque key for a signed ES256 JWT before the request reaches any
service, so a client holding an older legacy key still works.

Sessions are signed with a P-256 keypair generated at setup, not with the shared
secret. That is not a preference: Rift's edge functions verify callers locally
against the JWKS GoTrue publishes, and a stack configured with only
`JWT_SECRET` signs HS256 and publishes an empty JWKS — so every authenticated
call fails while every container reports healthy.

## Updating

```bash
curl -fsSL https://joinrift.app/self-host/docker-compose.yml -o docker-compose.yml
docker compose pull
docker compose up -d
```

The console applies the rest itself on start: it installs the endpoints the new
image carries, runs any migrations the database has not seen, reloads the edge
runtime, and records the release it brought everything to. Watch it with
`docker compose logs console`.

That is worth stating because the obvious assumption is wrong. A pull delivers
new console code, new migrations *and* new endpoints in one image — but only
the first of those runs by itself. Without the console applying them you get a
new console sitting on an old schema serving old endpoints, which looks like it
worked.

**Fetch the compose file first.** It pins every upstream image tag, so a
release that moves GoTrue or Kong cannot reach you through the console image at
all. This is the step that gets skipped.

There is a switch for the automatic part, in the console's Release panel or as
`RIFT_AUTO_APPLY` in `.env`. Turn it off if a schema change should never happen
merely because a machine rebooted; the console then offers Apply as a button.
The switch takes effect immediately either way — it is read from `.env` on use
rather than from the environment the console started with, which is the only
way a console can honour a setting it cannot restart itself to pick up.

### When a migration has changed under you

The migrator refuses to run if a file that already ran here has since been
edited — the database was built by a version of it that no longer exists, so
anything applied on top is guesswork. If you know the database already matches
the new files, record that and carry on:

```bash
docker compose exec console deno run --allow-env --allow-read \
  --allow-run=psql /app/src/migrations/cli.ts --accept-drift
```

## Requirements

- Docker with the Compose plugin
- A domain name pointing at the machine, and ports 80/443 reachable.
  **TLS is not optional**: Android blocks cleartext HTTP, so a server on plain
  `http://` works from a desktop and is invisible to every phone.
- UDP 7882 and TCP 7881 open, for voice. Media goes straight to those ports and
  cannot be proxied — only LiveKit's signalling passes through Caddy.
- Roughly 4 GB of RAM and 2 CPUs to be comfortable

## Building it

```bash
scripts/sync.sh                     # refresh migrations/ and functions/
docker build -f console/Dockerfile -t riftapp/rift-console:latest .
```

The build context is the repository root, not `console/` — the migrations and
endpoints are vendored beside it and go into the image.

The console's own checks:

```bash
cd console
deno test --allow-read --allow-write --allow-env --allow-run=psql
deno lint && deno fmt --check
```

`templates/` is excluded from `fmt` and `lint`, and that exclusion is
load-bearing rather than cosmetic — `deno fmt` reads the YAML there and rewrites
`{{PLACEHOLDER}}` into `{ { PLACEHOLDER } }`, which survives rendering and hands
LiveKit an API key named after the placeholder.

## What works, and what has not been proved

Verified by running the whole thing end to end against a real Docker daemon:
ten containers healthy, all 41 migrations applied and recorded, Realtime's
limits surviving a container recreate, `messages` refusing the anon key, and the
invite the console minted resolving back through `resolve_invite` to the server
it names.

**Two real clients, end to end.** Against a stack built from this repo with
nothing patched by hand, two members using the app's own `CryptoRepository`
each signed in over SIWS, registered, exchanged the channel key wrapped for one
another, and sent messages the other decrypted — with the sender's signature
verified. The server held only ciphertext throughout, and the `@mention`
resolved to the right member id.

That is the check the earlier runs were missing. They exercised
`resolve_invite`, which takes no token, and `create_server`, which compares a
key directly — so they passed on a stack where **nobody could log in and no
authenticated call worked**. Two separate faults, both invisible until a client
actually tried to authenticate:

- GoTrue signed HS256 and published an empty JWKS, so every authenticated
  edge-function call failed.
- `GOTRUE_SITE_URL` named the server's domain, so the fixed `localhost` URI
  every client signs was refused.

Not yet proved, and worth doing before anyone else runs one:

- **A real certificate.** The runs used a domain that does not exist, so Caddy
  never completed an ACME challenge; clients reached Kong directly over http.
- **A real call.** LiveKit starts and is routed, but nobody has joined a voice
  channel through it.
- **The Flutter app itself.** The two clients were headless, sharing the app's
  crypto and hitting the same endpoints and tables, but not its UI.
- **A real call.** LiveKit starts and is routed, but no client has joined a
  channel through it, so the single-UDP-port choice is reasoned rather than
  measured.
- **An upgrade.** The ledger is what makes one possible and it is tested, but
  there has never been a second version to apply.
- **The `studio` profile**, which has not been started once.
- **Backups.** Nothing here dumps the database or the attachment volume.
