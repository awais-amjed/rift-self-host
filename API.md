# Rift server API

How a client talks to a self-hosted Rift server. There are two transports, and which one a call
uses is a deliberate line rather than an accident of history:

- **Direct PostgREST**, under the policies in `migrations/008_security.sql`.
  This is almost everything: reading and sending messages, editing your own, member lists,
  channels, invites, reactions, read cursors.
- **Edge functions**, in [`supabase/functions/`](supabase/functions/), for the things that
  genuinely can't be a table call.

The client mirror is `lib/data/repositories/server_repository.dart` (+ `server_db.dart`); keep
them in sync.

> **This used to be 29 functions.** Every read and write went through one, because clients
> weren't trusted with the database — which was never a decision, just the consequence of tables
> that had no policies on them. Two of them (`messages`, `dm_messages`) turned out to have no RLS
> at all, so the anon key that every member holds could read *and delete* every message on a
> server. Fixing that properly meant writing the policies; once written, most of the endpoints
> had nothing left to do.

## What stayed an edge function, and why

An endpoint earns its place only if it holds a secret, or runs before the caller is a member.

| Function | Auth | Why it can't be a table call |
|---|---|---|
| `login` | none (self-authenticating via the signature) | Proxies GoTrue's `grant_type=web3` with the service key, so the client needs no anon key. Returns the session (`access_token`, `refresh_token`, …). `Chain ID: solana:mainnet` |
| `register` | Bearer (SIWS JWT) | Claims an invite and creates the profile row **before** the caller is a member of anything. One atomic `register_user` RPC, so a failed register never burns an invite use. **`max_members` is enforced here**, last of the refusals and with the server row locked, so two invites racing cannot both be the last one through. Bots hold a seat; banned members do not. **A caller who is already a member** (they left, which is local to the device) is signed back in to that membership: the response is the same context plus `rejoined: true`, the typed username and display name are ignored, and the invite is not used up — but it must still be live and for this server. A banned member is refused with `user_banned` |
| `resolve_invite` | none | Runs before the client has the server's anon key — it is what hands the key out. Maps an invite to `server_id` + `server_name` **without consuming it**, so the per-`(host, server_id)` SIWS identity can be derived before login |
| `create_server` | `service_key` in body | Writes the LiveKit API secret. Also seeds a `general` text channel and a `voice` voice channel — they differ in name because `(server_id, name)` is unique. Returns `server_id`, `name`, `supabase_url`, `supabase_key`, `invite_code` (single-use admin invite) |
| `update_server` | Bearer + `is_server_admin` | Writes the LiveKit API key/secret into `server_secrets`, which has no grant and no policy. Name, icon and the operator limits — including the DM overrides `dm_retention_days` / `dm_history_cap`, where **null is a value** meaning "inherit the server-wide number" and an omitted key means "leave it alone" — ride along rather than splitting one dialog across two transports. It does **not** touch storage: each server owns a `chat-<serverId>` bucket and a trigger moves that bucket's `file_size_limit` when the column changes, in the same statement. `max_voice_participants`, `max_share_mbps`, `max_members`, `max_storage_bytes` and `dm_openings_per_hour` ride along the same way; all are 0 = off |
| `sweep_attachments` | Bearer (any member) | Needs the **Storage API**, not a secret: `storage.protect_delete()` refuses a direct DELETE on `storage.objects`, so no database role can free an attachment blob. Applies the server's retention settings via the `sweep_attachments` RPC (service-role only) and removes the blobs whose messages are gone. Safe for any member — it removes only unreferenced objects |
| `get_channel_token` | Bearer | Mints a LiveKit JWT with the API secret, on the node this channel's call is held on (see **More than one region**). Identity is `<userId>~<deviceId>`; `roomAdmin` for channel managers, 1 h TTL. **Moderation is enforced here at join time** — muted users get no `microphone` in `canPublishSources`, deafened users get `canSubscribe: false`. **A bot** gets `canSubscribe` only with a `bot_voice_grants` row, never `roomAdmin`, and is refused outright until a member has sealed it a media key (calls are E2E encrypted — BOTS.md §6b). **`max_voice_participants` is enforced here**: a new arrival past it is refused `voice_channel_full`, counted as *people* so a member's screen share does not use a place, and bots are exempt because a summoned bot is not what fills a call. The reply also carries `max_share_mbps`, which the client keeps — a LiveKit token has no bitrate field, so there is nothing here to clamp — and **`livekit_url`**, the address that token is good for |
| `get_dm_call_token` | Bearer | The same answer as `get_channel_token` (`token`, `identity`, `livekit_url`, `max_share_mbps`, plus `room`) for a call between two members. The room is `dm-<callId>`, a name no channel id can be, so `voice_roster` and a moderator's mute never see it; a ban does reach it. Who may call whom was decided by `start_dm_call`; this asks `claim_dm_call_room` only whether the caller is on the call and may join yet — the caller from the first ring, the callee once they have answered — and claims a node on the first ask (the client's measured preference if it is one of this server's, else the default, falling back to the default once if the chosen node does not answer). Voice moderation flags are not applied: they are about the server's channels. `call_not_found` covers no such call, not yours, ended and a `call_id` that is not a UUID alike |
| `set_bot_voice_listen` | Bearer + `MANAGE_BOTS` (checked by the RPC) | Lets a bot hear a voice channel, or stops it. Calls `grant_bot_voice_listen` / `revoke_bot_voice_listen` with the caller's JWT, then pushes the new permission onto the bot's live connection with the API secret — the row alone is half the job, exactly as with `moderate_user`, because a token is good for its hour whatever the table says |
| `moderate_user` | Bearer + `MANAGE_CHANNELS` to mute/deafen, `BAN_MEMBERS` to ban (checked by the RPC) | Mute/deafen/ban. Nobody bans an admin or another holder of `BAN_MEMBERS` (`cannot_ban_peer`). Calls the `moderate_user` RPC with the caller's JWT — the rules stay in the database — then uses the LiveKit API secret to push the new permissions and metadata onto every live connection the target holds. See below |
| `delete_channel` | Bearer + `channel_manageable_by`, asked before anything is touched; `channels_delete_managers` still decides the row | Deletes the LiveKit room with the API secret, then the row with the caller's JWT. Rooms are named by channel id, so without the first half everyone carries on talking in a room whose channel is gone. Deleting a room disconnects its participants — that **is** the kick — which is why the permission is asked first: the room going before the policy had been consulted let any member end any call by asking to delete its channel and being refused |
| `delete_server` | Bearer + owner (checked by the `delete_server` RPC) | Runs the RPC with the caller's JWT — the row delete cascades to everything the server holds — then, with the service role, drops every voice channel's LiveKit room, the `chat-<serverId>` bucket and the members' avatars, none of which a database role can reach. Each of those is best-effort and reported back in `errors` rather than allowed to keep a server alive |
| `move_user` | Bearer + `is_server_admin` / `is_channel_manager` (checked here — nothing is written down, so there is no RPC to defer to) | Pulls a member from the call they're in into another voice channel, by sending their connections a "join this channel" packet with the API secret. See below |
| `move_call` | Bearer + `channel_manageable_by` (the channel's own managers when it is private, `MANAGE_CHANNELS` when it is not) | Moves a live call to another of this server's regions: opens the room there, re-points `voice_rooms`, and tells everybody in the old room to rejoin. A private channel answers to its own managers only, as everywhere else — a server-wide admin outside it gets the same refusal as a channel that does not exist. See **More than one region** |
| `voice_roster` | Bearer | Who is in which voice channel right now, `{userId: channelId}`, read off LiveKit. The snapshot a client starts from before the `voice:<serverId>` broadcasts can tell it anything — see ARCHITECTURE.md §5. Also `started`, `{channelId: epochMs}`: when LiveKit created each visible, occupied call's room, which the sidebar counts up from. Also `regions`: each region's `load` as `low` / `medium` / `high` (null with `reachable: false` when it did not answer), taken from forwarded streams across **every** room on the node. A level and never a count, because counts over rooms the caller cannot see told any member when a private call started and how many were in it; and no `idle`, which would announce the first one |
| `configure_push` | Bearer + `is_server_admin` | Writes `push_config`, a table with no grant and no policy — the secret in it is what proves a forward request came from this server, and nothing a client can read back may hold it. `{status:true}` answers whether push is on and with which relay id (never the secret); `{endpoint, relay_id, secret}` turns it on; `{disable:true}` turns it off and hands the relay id back so the admin's client can revoke it on central |
| `webhook` | **none** | The one endpoint anybody may call. Deploy with `--no-verify-jwt`: the whole point of a webhook is that the caller cannot log in. `POST /functions/v1/webhook/<secret>` with `{text}` — or `{content}`, the field Discord's webhooks use, so anything already pointed at one works by changing the URL. A raw non-JSON body is taken as the text. Deliberately thin: the lookup, the rate check and the insert are one `post_webhook_message` statement in the database, and all that is left here is being reachable without a JWT and ringing the `chat:<channelId>` doorbell afterwards. See BOTS.md §7 |
| `listing_token` | Bearer + `is_server_admin` (checked here **and** by the RPC) | The proof central cannot produce for itself. The public directory lives on central, which has never heard of this database and shares no identity with it — a member signs in here with a key derived on their device and to central with a Rift account, and nothing links the two. So `publish_server` there could only check that its caller was signed in, and every *member* of a server holds the URL, id and invite code that was all it took to list somebody else's server permanently. This mints a 256-bit single-use token, five-minute life, digest-only at rest |
| `verify_listing_token` | **none** | Central redeems a token here before writing a listing. Deploy with `--no-verify-jwt`: central holds no session on this server and never will. The token *is* the credential, and the reply is deliberately almost empty — a valid one returns the server id the caller already named, and every failure returns one flat refusal, so there is no oracle for whether a server exists or a token was ever real. Burned in the same statement that checks it, so a replay is refused |
| `get_channel_key` | Bearer | Channel-key distribution (below). For a **voice** channel it also returns `bots_missing` — bots that may speak there and have no media key yet — and, for a bot caller, `my_voice_key`: the one key a bot is ever sealed |
| `post_channel_keys` | Bearer | Channel-key distribution (below) |
| `sweep_channel_keys` | Bearer | Channel-key distribution (below). Covers **voice channels too** since calls became encrypted; it filtered to text, which was harmless while voice held no keys and a hole the moment it did — a banned member's voice key would never have rotated |

### Moderation has to reach the live room

A mute is two writes, and for a long time only the first one happened. The flag
went into `users`, and `get_channel_token` refused the `microphone` source *the
next time a token was minted*. Nothing touched the call that was already in
progress, so a moderator watched a muted member keep talking — and the client
caches LiveKit tokens for 55 minutes, so even leaving and rejoining handed back
the old grant. In practice the mute landed somewhere up to an hour later.

`moderate_user` therefore does three things after the row is written:

1. `updateParticipant` on **every** connection the target holds — each device,
   plus their screenshare — replacing permissions and metadata. Rooms are named
   by channel id, so the search is scoped to this server's channels rather than
   every room on a shared LiveKit deployment. Revoking the microphone source
   makes LiveKit unpublish the track outright.
2. `mutePublishedTrack` on a live microphone, so audio already flowing stops now
   rather than at their next publish. Un-muting deliberately does *not* unmute
   their track — it restores the permission and leaves the mic to them.
3. `removeParticipant` instead of the above, when the action is a ban.

**A server deafen takes the microphone as well as the ears** — you can't hold up
your end of a conversation you can't hear, and every client already drew it that
way. `micDenied(muted, deafened)` is where that lives, so the grant and the live
permission agree on it.

**Moderation never overwrites what the member chose.** `LiveKitState` keeps
`isMicEnabled`/`isDeafened` as the member's own toggles and `isServerMuted`/
`isServerDeafened` as what was imposed; `isMicOn` is the conjunction. Lifting a
mute therefore needs no guesswork — the member's own choice was still recorded,
so someone who had muted themselves stays muted and someone who hadn't comes
back on. The client reacts to its own metadata changing by republishing the mic
(a revoked source makes LiveKit unpublish the track, so releasing it has to
publish again) and by resubscribing to remote audio when a deafen lifts.

The permission encoding is a trap worth knowing: `canPublishSources` on an
**AccessToken grant** uses `undefined` for "all sources", while the same field on
a live **ParticipantPermission** uses an **empty list**. `_shared/moderation.ts`
holds both forms as separate functions so the two enforcement points cannot
drift, and neither can be passed the other's encoding.

The client half is `TokenCubit.invalidateServerTokens`, called when
`ServerMembersCubit` sees the local user's own `is_muted`/`is_deafened` change —
otherwise the cached token would outlive the moderation that revoked it.

### Moving someone is a signal, not a server-side move

LiveKit can relocate a participant between rooms itself, and `move_user`
deliberately doesn't. Rift's channels are end-to-end encrypted and the **client**
is what holds the keys: a connection dragged sideways underneath it would land in
a room whose key it never fetched — deaf in the call, with the sidebar, presence
and chat all still pointing at the old channel, and a token minted for somewhere
else. So the target is *told* to join, and takes the ordinary path: fetch a
token, fetch the channel key, connect, publish. Everything that makes a normal
join correct stays in one place.

The instruction goes out over the LiveKit data channel, addressed to the target's
own identities, topic `rift.move`. **A packet sent through the API arrives with no
sender**, and no peer in the room can imitate that — which is the client's
authenticity check, and the reason a member can't move anyone. `VoiceSignal` on
the Flutter side refuses anything with a sender, a different topic, or a version
it doesn't know, and returns null rather than throwing on the arbitrary bytes a
public data channel carries.

Every device they're joined from is moved, the same rule moderation uses. Their
screen share is not: switching channels stops it client-side, which is the honest
outcome — a share belongs to the call it was started in. Someone who isn't in
voice at all gets `user_not_in_voice`; there is no connection to tell, and no way
to make a client join from nothing.

### How a structural change reaches everyone

There are two paths, and the second is the one that has to be right.

`server_events` is a **Broadcast doorbell**: whoever makes a change pings
`server_events:<serverId>` and every subscriber re-reads `get_server_details`.
It is a courtesy — it only rings if the actor remembered to ring it, and it
reaches nobody who was offline at the time.

`channels` and `users` are in the **realtime publication**, and `ServerTableWatcher`
subscribes to each on the selected server. That is the authoritative half: a
rename, a deletion, a join or a ban lands whatever the actor did. The row event
is used as a doorbell rather than a delta — Realtime re-checks the migration-002
policies per subscriber, so what arrives is only what that member could have
selected anyway, and the real read is the refetch it triggers.

**Deleting a channel evicts whoever is in it, twice over.** LiveKit does the
real work: `delete_channel` drops the room, which disconnects every device in
it. The client then tidies up locally — `ChannelEviction` compares what we are
still pointed at against the refreshed list, so a call we're no longer allowed
to be in is left properly and a chat whose channel is gone is closed. It never
acts on a *failed* refresh, or the first network blip would evict everyone from
everything.

**A ban rotates the channel key.** The server can stop serving a banned member,
but it cannot take back a key they already unwrapped — so everything sent from
then on has to move to a new one. `sweep_channel_keys` offers the job to any
member who holds the current version: they mint the next one and seal it to the
people still here, which heals anyone missing an entry in the same pass.

The signal is that the current version's keyring covers somebody now banned, and
it clears itself — the next version is sealed only to the eligible, so the check
comes back false once the rotation lands, and an unban afterwards heals that
member into the current key rather than triggering another rotation. There is no
flag to set and nothing to reset. Old versions stay in the ring, so scrollback
written under them is still readable by everyone who could read it before.

`post_channel_keys` also refuses a batch that seals to a **bot** with no
`bot_channel_keys` grant to that channel at that version — the same rule
`refuse_ineligible_keyring` puts on the row, named here so one ineligible
recipient does not come back as a database error for every real member beside
it. It has to be the grant and not the bot flag: the sweep seals the next
version to everyone eligible, so a blanket refusal fails the **rotation**, and a
channel with a grant on it could then never rotate for any reason — a banned
member's included.

**The key-distribution trio is a deliberate deferral, not a rule.** `post_channel_keys` enforces
the `key_version ≤ current+1` race (first writer wins, losers refetch and re-wrap) and
`sweep_channel_keys` computes healing sets across channels. Both are expressible as RPCs, but
getting them wrong breaks decryption silently rather than loudly, so they were left on the
service role until they can be moved with care.

### Push runs on central, for everyone

`push_send` lives on the central project (the `rift-central` repository) and is the
only thing holding FCM credentials. It has to be: registration tokens are scoped
to the Firebase project an app was built against, so only the holder of Rift's
credentials can wake a Rift install — and self-hosted operators cannot be handed
those keys. Their servers ask central to forward instead.

What it learns is a device token and a moment. Not who sent the message, not what
it said, not which server or channel. The payload is empty and sent as `data`
rather than `notification`, so the app's handler draws the notification instead of
the system — which is what keeps the sender and the text out of a payload Google
can read, and lets the phone say something true about a message it decrypts
itself.

**Two callers, two credentials.** Central's own `dm_messages` trigger presents the
deployment secret in `x-push-secret` and names a `{recipient}`, whose devices are
looked up here. A self-hosted server presents a **relay credential** its admin
enrolled (central's `push_relays`) and supplies `{relay_id, tokens: [...]}` — the
tokens it already holds for its own member, so central never learns who that is.
Both secrets live in tables with RLS and no policy at all, read only by the
SECURITY DEFINER trigger that sends.

A relay credential is verified and metered in one statement (`claim_relay_push`),
so two forwards that each see room under the day's ceiling cannot both be let
through. It is minted by `enroll_push_relay` from a signed-in central account —
the server's admin — which gives every forward an owner, a daily cap and a revoke
button; an account may hold a small number at a time. Without that this would be
an open FCM proxy for Rift's project.

Tokens FCM reports as `UNREGISTERED`/`INVALID_ARGUMENT` are deleted **from
central's own registry only**. A relayed token lives in a database central holds
no credentials for, and reporting the dead ones back would tell it which of a
server's members had uninstalled the app — so that side sweeps on staleness
instead (see `push_config` in 001_schema.sql).

**Ringing is gated on the unread transition**, on both tiers. A doorbell says
*look again*; it says nothing new when the badge is already lit, and the phone
reads everything unread when it wakes. So a message only rings if its
conversation had nothing unread before it — per conversation, so a first message
from someone new still rings while an unread thread with somebody else sits
there. The consequence worth knowing: a member who has never opened a channel
that already had messages is permanently in the "unread" state there, and is
never rung for it.

### What the phone does with an empty doorbell

`PushWakeService` (`lib/logic/services/push_wake/`) runs in the background
isolate. It reads the master seed from secure storage, and from that alone:

* **self-hosted servers** — a *fresh* SIWS login per server (stateless: sign a
  message with a derived key, one round trip, nothing shared left behind),
  `unread_counts()`, the newest message in each unread conversation, and the
  channel key unwrapped from that member's keyring entry;
* **central** — the session the app already persisted, used **inertly**: the
  stored access token if it has not expired, never refreshed and never written
  back. Refreshing would rotate a refresh token the still-running app is holding.
  Past an hour central simply contributes nothing, and the doorbell falls back to
  saying that something arrived.

Which servers this device is on comes from a small `push_wake.json` the app
writes beside its hydrated state — the isolate cannot ask the app, and reading
the app's own Hive box from a second isolate is a lock, not a read. A second
file remembers the newest message already announced per conversation, so a later
doorbell does not repeat it. One notification per conversation, posted under a
stable id derived from the scope, so it updates in place rather than stacking.

`push_send` is central's, not a server's, and deploying it is documented in the
`rift-central` repository beside the function itself.

### A webhook rings its own doorbell

The open-channel doorbell is a Realtime **broadcast**, sent by the client that just inserted a
message — which is fine right up until the thing inserting the message is not a client. A webhook
row would have been stored correctly and reached nobody with the channel open until they reopened
it.

So the `webhook` function sends the broadcast itself, on the same `chat:<channelId>` topic with the
same empty `new_message` payload the app sends. It is **best-effort and never allowed to fail the
request**: the message is already stored by the time it runs, every client re-reads on open, and
the unread badge comes from the row itself. A webhook that got a 500 because a doorbell did not
ring would be retried by its caller and post the message twice.

The push half needed a fix rather than an addition. `ring_channel_members` excluded the sender with
`u.id <> NEW.sender_id`, and against a NULL sender that comparison is NULL rather than true — so
the `WHERE` dropped **every** row and a webhook message woke nobody at all, silently, and only for
the messages a human did not send. Migration 013 makes it `IS DISTINCT FROM`.

### Response format (edge functions only)

```jsonc
{ "success": true,  "data": { ... } }                                  // success
{ "success": false, "error": "Human message", "code": "machine_code" } // failure
```

`code` values live in `_shared/error_codes.ts`, mirrored in `lib/data/enums/error_code.dart`.
Direct calls return PostgREST errors instead; `ServerDb.run` maps them into the same
`APIResponse`, including turning a `PGRST301`/expired JWT into `token_expired` so the client's
silent re-login still triggers.

## What moved to the database

| Was | Now |
|---|---|
| `list_messages` | `channel_messages(p_channel, p_before, p_after, p_limit)`, with the sender embedded (`users!messages_sender_id_fkey`). It was a plain `select` until load testing found that `channel_id=eq.…&order=id.desc&limit=51` is answered by walking the **primary key** — every channel shares one table and one sequence, so opening a channel that had gone quiet crossed every message written anywhere on the server since. 4.4 s against 5,000,000 messages, 1.5 ms through the RPC. It takes the page as ids off `idx_messages_channel` (`app.channel_page_ids`, SECURITY DEFINER, which checks only that the channel is open to you) and fetches the rows by key under `messages_select`, so a page can come back shorter than it asked for |
| `list_dms` | `select` with the sender embedded. Not affected: a DM page is found by `LEAST/GREATEST(sender_id, recipient_id)`, which the primary key cannot serve, so the pair index is the only candidate |
| `send_message`, `send_dm` | `insert`; a BEFORE trigger stamps `sender_id = auth.uid()` and `created_at`, so a client can't post as someone else or backdate |
| `edit_message`, `edit_dm`, `delete_message`, `delete_dm` | `update`/`delete` scoped by policy; the column grant limits an edit to the envelope |
| `list_users`, `get_server_details` | `select` on `users` / `servers` / `channels`, all scoped to your server |
| `create_channel` | `insert` gated on `app.can_manage_channels()` |
| `rename_channel` | `update`; the column grant covers only `name`. A LiveKit room is named by the channel's **id**, so renaming a voice channel doesn't touch the call inside it |
| `delete_channel` | still policy-gated, but back behind an edge function — it is the only thing that can drop the LiveKit room (above) |
| `create_invite` | `insert`; the code comes from a column default, and the policy refuses any permission the caller doesn't hold |
| `update_profile`, `publish_chat_key` | `update` on your own row — the column grant covers only `display_name`, `chat_public_key`, `avatar_path` and `dm_policy` |
| `toggle_reaction`, `list_reactions` | `insert`/`delete` keyed by `(message, user, emoji)`; a duplicate-key error *is* the "already reacted" answer |
| `moderate_user`, `set_user_permissions` | RPCs — RLS is row-level, so a policy allowing an admin to write another member's flags would also let them rewrite that member's identity. `moderate_user` kept the RPC but regained an edge function in front of it, which is the only thing that can reach LiveKit (above) |
| `list_dm_conversations` | `dm_conversations(p_limit, p_before)` — `DISTINCT ON` instead of a thousand rows grouped in TypeScript, and since 041 a page of them rather than every peer you have ever messaged |
| the `notifications` table | `unread_counts()` + `mark_read()` over `read_state` |
| *(new)* pins | `set_pinned(p_scope, p_message, p_pinned)` for channels and DMs alike, then a `select` on `message_pins` / `dm_message_pins` with the message embedded to list them. A function rather than an insert because of the cap — fifty per conversation, and the fifty-first raises `pin_limit` — and because a channel pin takes `PIN_MESSAGES` (or managing a private channel) while a DM pin takes only being one of the two, and not being banned or blocked by the other (`dm_not_accepted`). Nobody timed out pins or unpins (`timed_out`). It rings `pin` on the channel, or `dm_pin` on both sides' user topics, with the message id. A pin names a message and never its words |
| *(new)* polls | posted as a message: the question and options in the sealed body, and the rules the server enforces in `messages.poll` — `{options, multiple, closes_at}`, set once on insert and refused on an edit. Posting one takes `CREATE_POLLS`, which `@everyone` has by default. Then `vote_poll(p_message, p_options)` replaces the caller's ballot (an empty array takes it back), `poll_tallies(p_ids)` reads `{counts, voters, mine}`, and `close_poll(p_message)` lets the author end it early. **Members see counts, never ballots**: `poll_votes` shows each member only their own rows. The server can still read every row — it counts them |
| *(new)* reports | `report_message(p_message, p_reason, p_note)` and `report_member(p_target, p_reason, p_note)` file one; reasons are `spam`, `harassment`, `explicit`, `other`, the note is up to 1,000 characters. **A message report copies the sealed envelope server-side** — ciphertext, nonce, signature, key version, author — so the reporter supplies nothing that could be forged, the report outlives the message, and the database still never holds the words; a reviewer's client opens it with the channel key it holds and checks the signature. One report per message per reporter, one open report per member per reporter (`already_reported`), twenty open per reporter (`too_many_reports`). Reviewers (`REVIEW_REPORTS`, on `Moderator` by default) `select` from `reports`, never one about themselves; `resolve_report(p_report, p_outcome)` records `dismissed`, `deleted`, `timed_out` or `banned` after **checking it happened** (`outcome_not_done`), and closes every open report the action settles — all of a message's for a deletion, all of a person's for a ban. Rings `reports` on each reviewer's user topic. Closed reports are deleted after 90 days |
| *(new)* time-outs | `time_out_member(p_target, p_minutes)` — text's mute: no messages, DMs, reactions, edits, pins or typing until `users.timed_out_until`. `MUTE_MEMBERS`; 0 lifts it; at most 28 days; never yourself, an admin, or another holder of the bit (`cannot_moderate_peer`) |
| *(new)* who may start a DM | `users.dm_policy` — `everyone`, `requests` or `nobody` — written by the member. Only a *first* message asks (`dm_links`, one row per pair that has ever talked, kept past retention). A first DM to `requests` becomes a request: no ring, no head for the recipient, no unread count, rung as `dm_requests` rather than `dm`, and the sender's second message is `dm_request_pending`. `dm_requests()` lists a member's waiting ones in the `dm_conversations` shape; `answer_dm_request(p_peer, p_accept)` accepts or ignores, and **replying accepts**. `dm_link_state(p_peer)` is `none`, `open`, `waiting`, `asked` or `ignored` — `waiting` covers being ignored, which the sender is never told. A first DM to `nobody` is `dm_not_accepted`. Opening conversations is limited by `servers.dm_openings_per_hour` (default 10, admins exempt): `dm_rate_limited` |
| *(new)* DM calls | `dm_calls`, one row per call, no grant on the table. `start_dm_call(p_peer)` rings (only an open conversation — `call_needs_conversation`; a block either way is `call_not_accepted`; `timed_out`; `cannot_connect` without `CONNECT`, or from a bot; `call_rate_limited` after five unanswered calls to one person in an hour). If the pair already has a call ringing it is returned, and if that one is ringing the caller, it is answered — calling back is picking up. One already *answered* is ended where it went quiet and a new one rings: pressing Call means the presser is not in it, and rejoining a call both ends had left rang nobody. `answer_dm_call(p_call)` is the callee's, once (`call_not_ringing`, `call_ended` past the 45-second window). `end_dm_call(p_call)` from either end records `completed`, `declined`, `missed` (a caller giving up after 15 s) or `cancelled`. `dm_call_alive(p_call)` is the heartbeat, every twenty seconds; the `rift-dm-call-sweep` job ends a ring past its window as missed and an answered call silent for three minutes as completed, at the moment it went quiet. The job runs as `postgres`, which is granted `app.close_stale_dm_calls` by name in 008. `my_dm_calls(p_known)` lists the caller's calls still going, plus any named; `dm_call_log(p_peer, p_since)` is a conversation's ended calls. Every change of state rings `dm_calls` on both people's `user:` topics (empty); a ring, and the end of a ring, push the callee's phones, unless that conversation is muted to `none`. A ban hangs up, and so does a block (a ring the blocker was getting is `declined`, one they were making `cancelled`). Ended calls follow the DM retention age |
| *(new)* blocks | `insert`/`delete`/`select` on `member_blocks`, your own rows only. A blocked member's DM is `dm_not_accepted` — the same answer a `nobody` setting gives — and they cannot read that the block exists. Nor can they edit what they already sent you, react to or pin in the conversation, or send typing to your `user:` topic. Their waiting request leaves your list |
| *(new)* the soundboard | `select`/`insert`/`update`/`delete` on `soundboard_sounds`, gated on `MANAGE_SOUNDBOARD`; `server_id` and `created_by` have no column grant and are stamped. **Playing one is not here at all** — a press is a packet on the call's LiveKit data channel and every listener plays the clip locally, so the server neither carries the audio nor learns that it happened |

## Database schema

Defined by `migrations/`, run in order on a fresh instance. The central
project has its own set, in the `rift-central` repository.

Eight files, split by *kind* rather than by feature, so an object is defined in
exactly one place and the order is a dependency order.

1. **001_schema.sql** — every type, table and index, in final shape. Notable shapes:
   `server_secrets` split out of `servers` so the rest of that row is safe to read directly;
   envelope length limits as CHECK constraints (they used to be TypeScript in
   `_shared/chat.ts`, which is no validation at all once clients write directly); `read_state`
   as one cursor per conversation.
2. **002_helpers.sql** — the permission bits, the `app.*` predicates every policy is written
   in terms of, and the views a client reads a member through. They are `SECURITY DEFINER` on
   purpose: a policy that consults an RLS-locked table (say `messages` checking `channels`)
   evaluates false for everyone and silently denies — including every Realtime change it
   should have delivered.
3. **003_api.sql** — the RPCs: `register_user`, `moderate_user`, `create_channel`,
   `get_server_details`, `unread_counts`, `mark_read`, `dm_conversations` and the rest.
4. **004_triggers.sql** — attestation, the refusals that belong to a row rather than to a
   code path, and the derived state (the permission cache on `users`, DM heads, the roles a
   new server is born with).
5. **005_realtime.sql** — what a client may subscribe to. Nothing is in the `supabase_realtime`
   publication: each change is *broadcast* by a trigger onto a topic only the entitled may
   join, so what is in the payload is a decision rather than a consequence.
6. **006_storage.sql** — `chat-<serverId>` per server, `avatars` (2 MB, **not** encrypted —
   same accepted trade-off as reactions), `soundboard` (5 MB a clip, unencrypted for the same
   reason, one folder per server), `servers` (public, fetched before login), plus the
   running byte total and the trigger that refuses an upload over the cap.
7. **007_jobs.sql** — the scheduled work: retention sweeps, expiring invites and summons,
   and orphaned attachments.
8. **008_security.sql** — `anon` revoked from everything, column-level grants for
   `authenticated`, RLS on every table, and every policy. **It is last on purpose.** Supabase's
   own default privileges grant EXECUTE on each new function in `public` to `anon` and
   `authenticated`, and `ALTER DEFAULT PRIVILEGES ... REVOKE` does not undo them — so the
   blanket `REVOKE ALL ON ALL FUNCTIONS` has to run once every function exists. Anything
   granted here is granted by name; nothing is reachable by omission.

Central's set is smaller and has no edge functions behind it at all. Its RPCs are `claim_handle`,
`send_dm`, `dm_quota`, `unread_counts`, `mark_read` and `dm_conversations`. Two of those exist
purely because **a PostgREST upsert cannot be used against a column-granted table**: the generated
`ON CONFLICT DO UPDATE` writes every payload column, conflict key included, and the privilege
check happens at plan time — so it is refused whether or not the row exists. `claim_handle` and
`mark_read` do the same upserts without touching the key.

## Deployment

### Hosted Supabase project

```bash
supabase functions deploy --project-ref <ref>
```

From the root of this repository — the endpoints are under `supabase/functions/`,
which is where the CLI looks. Apply the migrations via the SQL editor or `psql`,
in filename order.

A stack built with the console needs none of this: it installs the endpoints
from its own image and runs the migrations itself.

### Self-hosted Docker stack

The docker-compose stack serves functions from its `volumes/functions/` directory via the
`main` router (path `/functions/v1/<name>` → `/home/deno/functions/<name>`):

```bash
cp -rf edge_functions/supabase/functions/. <stack>/volumes/functions/
docker restart supabase-edge-functions
```

Deleting a function from the repo does **not** remove it from a stack that already has it —
delete the directory in `volumes/functions/` too, or the old endpoint keeps answering.

Apply migrations with `docker exec -i supabase-db psql -U postgres -v ON_ERROR_STOP=1 -f - < <file>`.

Requirements for the stack's GoTrue config: enable the SIWS grant with
`GOTRUE_EXTERNAL_WEB3_SOLANA_ENABLED=true` (dev keeps signup on so SIWS auto-creates the
`auth.users` row; production sets `GOTRUE_DISABLE_SIGNUP=true` and provisions via `register`).
Leave `SITE_URL` as a `localhost` URL, or add `http://localhost` to `ADDITIONAL_REDIRECT_URLS`.
The server's own URL is never required to appear in either setting, and pointing them at it is
the mistake this section exists to prevent — see below.

#### Why the SIWS domain is fixed

Every Rift client signs a SIWS message naming `localhost` and `http://localhost`, whatever
address the server is actually reachable at. That is a constant, not a placeholder somebody
forgot to change.

GoTrue's web3 grant (`internal/api/web3.go`, read at v2.189.0 and still true at v2.197.0)
puts four gates on the message's first line and its `URI`, and **exempts `localhost` from three of them**:

| Gate | Rule |
|---|---|
| `siws.IsValidDomain` | `^(localhost\|<label>(.<label>)*.<tld≥2 letters>)(:port)?$` — a bare IP such as `192.168.1.6` never matches |
| scheme | must be `https` unless the URI's hostname is `localhost` |
| `IsRedirectURLValid` | must match `SITE_URL`'s hostname or `URI_ALLOW_LIST`; for an IP host it short-circuits to "loopback only", so **no allow-list entry can admit a LAN IP** |
| domain ↔ URI | unless localhost, `URI.Host` (port included) must equal the domain, *and* `https://<domain>/` must also be allow-listed |

Signing the real address would therefore mean a Rift server could only be reached over HTTPS,
at a dotted name, that its operator had also configured GoTrue to expect — no LAN IP, no
plain-http hostname, no testing across two machines.

Nothing is given up by the constant. Those two fields exist so a *wallet* can tell you which
site is asking; Rift has no wallet, the key is derived per `(host, server_id)`, and it is posted
only to the host it was derived for. GoTrue never redirects anywhere here either — email and
phone signup are off, there are no OAuth providers, and the web3 grant returns a token rather
than a redirect, so the allow list exists solely so the signature verifies.

**Setting `SITE_URL` to the server's own domain refuses every login**, with "message was signed
for another app" — a sentence naming neither SIWS nor the setting that caused it.
Keep `FUNCTIONS_VERIFY_JWT=false` — `login`, `register` and `resolve_invite` are invoked without
the runtime's own JWT gate (each self-validates).

### LiveKit

`get_channel_token` reads the credentials from `server_secrets`, so the `livekit_url` stored at
`create_server` time must be reachable **from the functions container as well as from clients** —
use a LAN IP (e.g. `ws://192.168.1.6:7880`), never `localhost`. When running
`livekit-server --dev` locally, start it with `--bind 0.0.0.0`.

**The address comes back with the token, and that is the point.** `get_channel_token` answers
with `livekit_url` alongside the JWT, and a client uses that in preference to the
`servers.livekit_url` it already holds — because *which* LiveKit a channel lives on is a
decision this function makes, not one compiled into every installed client.

Two other connections follow the same answer: a screen share and a sound share each open a
second connection into the call's own room, so they take the URL from their own token rather
than from the server row. A share that went to a different node than the call would join a room
of the same name with nobody in it.

Older clients ignore the field and read the server row, which is the same address on a server
with one region.

### More than one region

A server may hold calls on several LiveKits. `livekit_nodes` is the list, an admin writes the
labels, and `channels.livekit_node_id` pins a channel to one of them — NULL is automatic.

**A room lives on exactly one node.** LiveKit's open-source server binds a room to a single
node and cross-node media is a Cloud feature, so this is never "each person connects to their
nearest". It is one decision, made when the room is created, and everybody who joins afterwards
goes where it already is. What several nodes buy is a better choice of *where*, and a community
mostly in one place gets its calls near itself.

The order, in `app.claim_voice_node`:

1. **where the call already is** (`voice_rooms`) — absolute, because a live room cannot move;
2. **the channel's pin** (`channels.livekit_node_id`) — only ever one of the channel's own
   server's regions: a trigger refuses any other on write, and the claim ignores one on read,
   because a project holds many servers and a stranger's node would open the call on their box
   with their key;
3. **what the caller measured** — `preferred_node_id` on the request, checked against this
   server's own list before it counts for anything;
4. **the default node**, which mirrors `servers.livekit_url`.

That claim is a single statement ending in `ON CONFLICT DO NOTHING`: two people opening the
same call in the same moment must not open it in two regions, so the first writer wins and the
second reads their row.

`voice_roster` is the other half. Nothing announces that a room emptied, so the one thing
already asking every node who is in each room is the only thing that finds out — it releases
the channels it can see with nobody in them, and the next call on them is decided afresh.
Without that, "automatic" would decide once in a channel's lifetime rather than once per call.

The other functions that act on a room had one admin API per server, which was the same
assumption from the other side. Two shapes replace it: a known channel resolves through
`voice_rooms` to one node (`delete_channel`, `set_bot_voice_listen`, `set_bot_voice_summon`),
and a search across channels asks every node and merges (`kick_user`, `moderate_user`,
`move_user`, `delete_server`) — a node not holding a room answers empty, which is the same
answer as an empty room.

`move_user` needed nothing extra: it already sends a packet telling the client to rejoin, so
the destination resolves on that client's next token request. A move between two regions is the
reconnect it was always doing.

### Every region's own key

Every region a server adds holds its own LiveKit API key and secret, in
`livekit_node_secrets` — a table with no policy and no grant, like `server_secrets`, read only
by the edge functions on the service role. **It is required, not offered.** The default region
is the one exception and barely one: it *is* `servers.livekit_url`, so its pair is the server's
and it is refused a key of its own.

One pair per server was the first design, and the reasoning was that a LiveKit key is a line in
each box's own `livekit.yaml` anyway. What that missed is blast radius. The key is *on* every
box, so whoever takes the cheapest VPS in the list holds the key that mints tokens for the room
on any other node — including the one the server itself runs on. Calls are end-to-end
encrypted, so that buys metadata, impersonation and disruption rather than audio, and it is
still every room everywhere; rotating the answer meant changing every box at once. The operator
has to write *some* key into each box either way, so a distinct one is the same work — and an
optional safeguard is one most people skip.

A region is therefore added with `add_voice_region(p_label, p_url, p_api_key, p_secret)`, an
admin-checked `SECURITY DEFINER` function that writes the node and its key in one transaction;
`authenticated` has no INSERT on `livekit_nodes` at all. A deferred constraint trigger enforces
the same rule against the data rather than the API: at commit, a non-default node with no key
is refused, and the key cannot be deleted while its node is there. Rotation is
`set_voice_region_credentials(p_node, p_api_key, p_secret)`, both halves, one box at a time.

Everything that talks to a node reads that node's pair, and **a missing one is never the
server's**: `get_channel_token` mints the join token with the key of whichever node the claim
landed on (and again if the unreachable-pin fallback moves it), `move_call` signs for the
source and the target separately, and `livekitRoomServices` builds one admin client per node
from one query, leaving out any node it has no key for — which then behaves exactly like a
region that does not answer, because it is one. `claim_voice_node` and `move_voice_node` return
`is_default` alongside the address, since that is what decides which pair to reach for.

### When a region is offline

Nothing pretends otherwise, and the rule throughout is that a region which
does not answer must not be *recorded* as holding anything.

- **The probe never offers it.** A node that fails to answer `GET /` within
  three seconds cannot win the measurement, so automatic does not pick it.
- **`get_channel_token` releases the claim it just took.** The claim has to
  come before the room is opened — it is what stops two simultaneous joiners
  opening one call in two places — so a region that is down would otherwise
  leave a claim naming it, and a claim outranks both the pin and the probe.
  Released, an automatic channel is free to land on a region that is up; a
  pinned one claims it again and fails again, which is correct, because the
  operator said where those calls go.
- **`move_call` opens the room before it writes anything.** Opening it is how
  the region is asked whether it is there. A failed move changes nothing.
- **`voice_roster` answers without it.** A node that is down contributes an
  empty list rather than blanking the roster, so calls on the other regions
  still appear.
- **Moderation skips it.** `kick_user`, `moderate_user`, `move_user` and
  `delete_server` each ask every node and ignore the ones that fail, so a
  region being down does not stop a member being removed from the others.

A call already running on a region that goes down is between those clients
and LiveKit; nothing here can reconnect them, and the next join decides
afresh.
