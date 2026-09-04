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

Not yet proved, and worth doing before anyone else runs one:

- **A real certificate.** The end-to-end run used a domain that does not exist,
  so Caddy never completed an ACME challenge. Everything downstream of it was
  reached container-to-container.
- **A real call.** LiveKit starts and is routed, but no client has joined a
  channel through it, so the single-UDP-port choice is reasoned rather than
  measured.
- **An upgrade.** The ledger is what makes one possible and it is tested, but
  there has never been a second version to apply.
- **The `studio` profile**, which has not been started once.
- **Backups.** Nothing here dumps the database or the attachment volume.
