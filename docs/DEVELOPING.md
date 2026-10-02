# Developing rift-self-host

How this repository is laid out, how to build and test it, and what has been
proved against a real stack. The design reasons are in [`DESIGN.md`](DESIGN.md).

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

`001` to `008` are the baseline, split by *kind* — tables, helpers, RPCs,
triggers, realtime, storage, jobs, security — not by feature, and each states
the shape it is meant to have. Since Oct 3 2026 they are locked: a change to
the schema is the next numbered file, which the console runs once on every
server after the ones it has, and the existing files stay put.
`migrations/locked.sha256` holds each file's checksum, and
`./scripts/check_locked.sh` (the first thing `db_test.sh` runs) fails on an
edit or on a new file without its line. A new file revokes and grants what it
adds itself, since the baseline's blanket revoke ran before it.

That also means the schema's tests are here. `./scripts/db_test.sh` builds a
scratch database from these files, applies every one in order, and runs both suites
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
