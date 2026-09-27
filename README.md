# rift-self-host

Run your own [Rift](https://joinrift.app) server: chat, voice, video and screen
sharing for your community, on a machine you control. Messages and calls are
end-to-end encrypted, so the server stores ciphertext it cannot read.

A server is a standard [Supabase](https://supabase.com) stack plus
[LiveKit](https://livekit.io) for calls, set up and kept healthy by one small
console. You never edit a `.env` by hand.

> **Status: in development.** There are no releases yet, and the schema is
> still rewritten in place. Try it, but don't put a community on it yet.

## Quick start

You need Docker with Compose, a domain pointing at the machine, and ports 80,
443, UDP 7882 and TCP 7881 open.

```bash
curl -fsSL https://joinrift.app/self-host/docker-compose.yml -o docker-compose.yml
docker compose up -d
```

Then open `http://localhost:8080` (over an SSH tunnel if the machine is
remote). The setup page asks for your domain, generates every secret, starts
the rest of the stack, and gives you an invite link to paste into the Rift app.

The full walkthrough, including running behind your own reverse proxy, is the
[installation guide](https://docs.joinrift.app/install/).

## Requirements

- Docker with the Compose plugin
- A domain name, and HTTPS — phones refuse plain `http://`
- Ports 80 and 443 (unless you bring your own proxy), plus UDP 7882 and TCP 7881
  for voice
- About 4 GB of RAM and 2 CPUs — see [sizing](https://docs.joinrift.app/sizing/)

**Choose the domain carefully: a server's address is permanent.** Every
member's identity is derived from it, so moving to a new address makes everyone
a stranger. Move the machine, never the name.

## Updating

```bash
curl -fsSL https://joinrift.app/self-host/docker-compose.yml -o docker-compose.yml
docker compose pull
docker compose up -d
```

Fetch the compose file first: it pins every upstream image. The console applies
new migrations and endpoints by itself on start — see
[updating](https://docs.joinrift.app/updating/).

## Documentation

**Running a server** — on the website:
[install](https://docs.joinrift.app/install/) ·
[the console](https://docs.joinrift.app/console/) ·
[updating](https://docs.joinrift.app/updating/) ·
[backups](https://docs.joinrift.app/backups/) ·
[call regions](https://docs.joinrift.app/regions/) ·
[strict networks](https://docs.joinrift.app/turn/) ·
[sizing](https://docs.joinrift.app/sizing/) ·
[troubleshooting](https://docs.joinrift.app/troubleshooting/)

**Working on it** — in this repository:

| Document | For |
|---|---|
| [`docs/DESIGN.md`](docs/DESIGN.md) | why the stack is shaped this way: the console, keys, permanent addresses, updates |
| [`docs/DEVELOPING.md`](docs/DEVELOPING.md) | the layout, building and testing, and what has been proved on a real stack |
| [`API.md`](API.md) | what a client may call, and over which transport |

## What's in here

```
docker-compose.yml     what an operator downloads
console/               the setup and management console — the one image this repo builds
migrations/            the database schema, policies and functions, split by kind
supabase/functions/    the server's edge functions
scripts/               the database test suites
```

## Development

```bash
# The schema's tests: build a scratch database from migrations/ and check
# what every role can reach. Needs a running Supabase Postgres container
# (default name supabase-db).
RIFT_PG_CONTAINER=<container> ./scripts/db_test.sh

# The console's own tests, and building its image.
cd console && deno task test
docker build -f console/Dockerfile -t riftapp/rift-console:latest .
```

The build context is the repository root, because the migrations and functions
go into the image. Details, and the gotchas, are in
[`docs/DEVELOPING.md`](docs/DEVELOPING.md).

## Related repositories

| Repository | What it is |
|---|---|
| `rift` | the app — Flutter client for desktop, mobile and web |
| **`rift-self-host`** | this: a server anyone can run |
| `rift-central` | the optional shared service: accounts, the public directory, push relay |
| `rift-bot-sdk` | the TypeScript SDK for building bots |

## License

[AGPL-3.0](LICENSE). The upstream files under `console/templates/` keep their
Apache-2.0 licence (see [`console/templates/LICENSE-APACHE-2.0`](console/templates/LICENSE-APACHE-2.0)).
