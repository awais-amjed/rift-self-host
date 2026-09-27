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

## Layout

```
docker-compose.yml     what an operator downloads
console/               the one custom image
migrations/            the schema, applied in filename order
migrations/tests/      policy tests — what each role may actually reach
supabase/functions/    the server's endpoints, mounted into the edge runtime
scripts/db_test.sh     runs both suites against a Postgres container
```

`migrations/` and `supabase/functions/` **are the originals**. They used to be copies of
directories in the app repo, refreshed by a sync script; they now live here,
where the thing that ships them lives, and the app repo has none.

There are eight files and they are split by *kind* — tables, helpers, RPCs,
triggers, realtime, storage, jobs, security — not by feature. Nothing in them
describes how the schema got here: each one states the shape it is meant to
have, so a table is created with its final columns rather than altered into
them afterwards. There are no real deployments yet, so there is nothing to
migrate *from*; when that changes, a change becomes 009 and the eight stay put.

That also means the schema's tests are here. `./scripts/db_test.sh` builds a
scratch database from these files, applies all eight, and runs both suites
against it — so it tests the schema this repository ships rather than whatever
is in a long-lived development database. (It used to run the policy suite
against the dev stack's live database, which meant applying each new migration
there by hand before its own tests would pass.)

There are two suites because a policy test only ever sees the finished shape:
it cannot catch a file that does not apply, and it cannot catch something
reachable that nobody granted — by the time it runs, whatever Supabase's
defaults handed out looks exactly like something this schema meant. So
`migration_test.sh` builds a server from nothing and then asks what `anon` can
reach. The stand-in it builds on installs Supabase's real default privileges
for that reason; without them the question answers itself.

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

## Requirements

- Docker with the Compose plugin
- A domain name pointing at the machine, and ports 80/443 reachable — unless
  you bring your own reverse proxy, in which case it needs the domain and the
  ports and this stack needs neither. **TLS is not optional either way**:
  Android blocks cleartext HTTP, so a server on plain `http://` works from a
  desktop and is invisible to every phone.
- UDP 7882 and TCP 7881 open, for voice. Media goes straight to those ports and
  cannot be proxied — only LiveKit's signalling passes through Caddy.

  Three ports is the whole list because `livekit.yaml` sets `rtc.udp_port`,
  which multiplexes every participant onto one UDP port; without it LiveKit
  advertises host candidates across 50000–60000 and that range is what has to
  be open instead. There is no embedded TURN server, so 3478 and 5349 are not
  used — a client on a network that blocks UDP falls back to ICE/TCP on 7881.
  See [LiveKit's ports reference](https://docs.livekit.io/transport/self-hosting/ports-firewall/).
- Roughly 4 GB of RAM and 2 CPUs to be comfortable

## Building it

```bash
docker build -f console/Dockerfile -t riftapp/rift-console:latest .
```

The build context is the repository root, not `console/` — the migrations and
endpoints sit beside it and go into the image.

The console's own checks:

```bash
cd console
deno task test     # no Docker or Postgres needed
deno task check    # type check, lint, fmt --check
```

Both type check against whatever Deno is installed locally, and the image pins
`denoland/deno:alpine-2.1.4`. A newer local Deno reports three `Uint8Array is
not assignable to BufferSource` errors in `backup/seal.ts` and fails both
tasks: TypeScript 5.7 made `Uint8Array` generic over its buffer, and
WebCrypto's `BufferSource` wants the non-shared one. Annotating them
`Uint8Array<ArrayBuffer>` would fix the local check and break the pinned one,
where the type takes no argument — so the fix is to bump the image, not the
source. Until then, append `--no-check` to run the cases themselves:

```bash
deno test --allow-env --allow-read --allow-write --allow-run=psql --no-check
```

**Nothing in `style.ts` or any other page module may contain a backtick.** Each
is a single template literal from its first line to its last, so a backtick
inside one — in a CSS comment, in prose, quoting a selector — closes it early
and the module stops parsing. `page_test.ts` catches it the moment it is run,
because it imports every page.

`templates/` is excluded from `fmt` and `lint`, and that exclusion is
load-bearing rather than cosmetic — `deno fmt` reads the YAML there and rewrites
`{{PLACEHOLDER}}` into `{ { PLACEHOLDER } }`, which survives rendering and hands
LiveKit an API key named after the placeholder.

## What works, and what has not been proved

Verified by running the whole thing end to end against a real Docker daemon:
ten containers healthy, all eight migrations applied and recorded, Realtime's
limits surviving a container recreate, `messages` refusing the anon key, and the
invite the console minted resolving back through `resolve_invite` to the server
it names.

**Two real clients, end to end — the Flutter app itself.** Against a stack
built from this repo with nothing patched by hand, two instances of the desktop
client each signed in over SIWS, registered, exchanged the channel key wrapped
for one another, and sent messages the other decrypted. The server held only
ciphertext throughout. Both then joined a voice channel and saw each other in
an end-to-end encrypted call, while a second call ran in another channel; a
private channel stayed invisible to the member who was not in it; and a bot
joined through the SDK, was summoned into that private channel, and opened the
media key a member had sealed for it.

**Audio, both ways.** Two desktop clients in an end-to-end encrypted call on a
stack built from this repo, each playing into its own virtual audio device and
recording the other's: the sound came out the other side in both directions,
and LiveKit reported the tracks as encrypted. A phone on the Android emulator
heard the desktop the same way. (These were one-to-one DM calls; a channel call
runs through the same media path.)

**An upgrade, applied.** A stack built at one release was brought to the next
by rebuilding the console image and restarting it: it installed the new
endpoints, refused to touch the schema because a migration had been edited
since it ran, said so in a sentence with the command to resolve it, and
finished after `--accept-drift`. A withdrawn endpoint stopped answering.

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
- **The `studio` profile**, which has not been started once.
- **Backups stay on the same disk.** The console makes them daily and keeps the newest few in `backups/`; copying them off the machine is up to the operator.

## Where this sits

Rift is seven repositories, meant to be cloned as siblings.

| Repo | Holds |
|---|---|
| `rift` | the client: Flutter app, Rust crate, `rift_crypto` |
| `rift-self-host` | a server's schema, endpoints and console — anyone runs one |
| `rift-central` | accounts, the server and bot directories, the push relay — we run it |
| `rift-bot-sdk` | the TypeScript bot SDK |
| `rift-admin` | the directory moderation dashboard — its own site and accounts |
| `rift-models` | the on-device image classifier and the tooling that builds it |
| `rift-website` | joinrift.app, and the self-hosting docs |
