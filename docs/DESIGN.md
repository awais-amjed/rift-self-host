# Design of the self-hosted stack

Why a Rift server is shaped the way it is. For running one, see the
[self-hosting guide](https://docs.joinrift.app/); for what a client may call,
[`API.md`](../API.md).

## What this is

A Rift server is a Supabase project (Postgres, PostgREST, GoTrue, Realtime,
Storage, Edge Functions) plus a LiveKit server for voice and video. Both are
ordinary open-source software with official images. Nothing here is a fork.

Everything Rift adds on top is **data, not modified software**:

| What Rift adds | Where it goes |
|---|---|
| Schema, policies, RPCs | `migrations/` — SQL applied to Postgres |
| Server endpoints | `supabase/functions/` — Deno, mounted into the edge runtime |
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

## A server's address is permanent

**Decided September 2026.** A Rift server is named once, and the name is what
moves when the machine does.

Every member's identity is derived from the address they joined at — the SIWS
keypair from `(host, serverId)`, and the X25519 key they are sealed with from
the host alone. Change the address and every member gets a new `auth.uid()`, a
new `stable_id` that no ban follows, and a new chat key that cannot open a
single message in their history. There is no migration for that; it is a
server-wide identity reset.

A DNS name is what makes this a non-problem rather than a trap. Repoint the
record and the host is unchanged, so identities, stored URLs, the certificate
and the public listing all keep working. That is what names are for, and it is
why HTTPS on a name is the only supported way to run a server people use.

Two consequences worth stating plainly:

- **Bring your own proxy if you have one.** Setup has a *"I have my own
  reverse proxy"* toggle for a machine that already terminates TLS for
  something else. It skips Caddy, publishes Kong and LiveKit's signalling on
  `127.0.0.1`, and the dashboard shows the two upstreams plus the stack's own
  Caddyfile repointed at them. The domain is still required — it is what your
  proxy serves, and what every member's identity derives from. Route
  `/rtc /rtc/* /twirp/* /validate` to signalling and everything else to the
  API, or messages will work and calls will not. Voice **media** is not the
  proxy's to carry either way — it goes straight to UDP 7882, with TCP 7881 as
  a fallback, and those have to be open whichever proxy you use.
- **Local testing is disposable.** The console offers it, and says on every page
  load that the stack cannot become a real server. Use it to try Rift. A real
  server has a switch of its own — *Local testing* on the dashboard — which
  publishes the API and LiveKit on a LAN address and points every server's
  `livekit_url` there until it is switched back. That column is the only
  address a client takes from the server, so voice is the only thing that
  moves; the domain keeps answering throughout, and members who joined through
  it keep working. Anybody who joins through the local link does not: their
  identity is derived from the LAN address, and they are stranded when it goes
  back.
- **No name, no server.** If a domain is impractical — CGNAT, a home
  connection — Tailscale issues real certificates for `*.ts.net`, which is a
  name and a certificate without a registrar. An air-gapped LAN with neither is
  the one case with no good answer: a self-signed certificate and desktop-only
  clients, or nothing.

## Why updating works the way it does

An update is a new compose file and `docker compose pull && docker compose up -d`.
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

There is no switch for this. Somebody who does not want a release does not pull
it; having pulled one, the only states worth being in are applied or failed
loudly. The Release panel still has an Apply button, for the case where a
boot-time apply was interrupted or left the reload undone.

### When a migration has changed under you

The migrator refuses to run if a file that already ran here has since been
edited — the database was built by a version of it that no longer exists, so
anything applied on top is guesswork. If you know the database already matches
the new files, record that and carry on:

```bash
docker compose exec console deno run --allow-env --allow-read \
  --allow-run=psql /app/src/migrations/cli.ts --accept-drift
```
