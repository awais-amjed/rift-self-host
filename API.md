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
| `login` | none (self-authenticating via the signature) | Proxies GoTrue's `grant_type=web3` with the service key, so the client needs no anon key. Returns the session (`access_token`, `refresh_token`, …). `Chain ID: solana:mainnet`. Passes on `X-Rift-Client-IP` (Caddy's address for the caller, which replaces any a client sends) to Auth, whose per-address sign-in limits (`GOTRUE_RATE_LIMIT_HEADER`) count by it; before 1.9.1 it did not, and sign-in had no limit. An app that already holds the server's anon key (every joined server) posts the same body to `/auth/v1/token?grant_type=web3` itself, with the key as `apikey`; Caddy sets `X-Rift-Client-IP` on that request too. It asks this function on the first join, which has no key yet, and when the gateway refuses the key it holds (`401`) |
| `register` | Bearer (SIWS JWT) | Claims an invite and creates the profile row **before** the caller is a member of anything. `public_key` must be the key the caller signed in with (their `web3:solana:` subject), or the answer is `invalid_public_key`; before 1.9.1 that was asked only beside a pass. One atomic `register_user` RPC, so a failed register never burns an invite use. **`max_members` is enforced here**, last of the refusals and with the server row locked, so two invites racing cannot both be the last one through. Bots hold a seat; banned members do not. **A caller who is already a member** (they left, which is local to the device) is signed back in to that membership: the response is the same context plus `rejoined: true`, the typed username and display name are ignored, and the invite is not used up — but it must still be live and for this server. A banned member is refused with `user_banned`. **A kicked member is let back in** by a live invite of their own kind (a person's invite for a person, a bot invite for a bot): `register_user` answers `readmitted`, lifts the kick, grants the invite's role and counts a use (the member cap applies, since a kicked member holds no seat); the response is the same `rejoined: true` context. **A link that needs a Rift account** (`invites.needs_account`, which only an admin sets — on insert, or later with the `set_invite_needs_account` RPC) takes `pass`, central's signed pass for this server and this identity (`_shared/server_pass.ts`: Ed25519 over the payload bytes, checked against `RIFT_CENTRAL_PASS_KEY` or the key built in). The pass must name this server's own address (`SUPABASE_PUBLIC_URL`, as an origin), since central makes the tag from the address it is given and any other would be a tag nobody banned; and its key must be the `public_key` sent, which is the one the caller signed in with. Without a pass the answer is `account_required` — except for somebody already a member, who comes back as before; a pass that does not check out is `pass_invalid`. The pass's **tag** — one account on this server, different on every other, no email in it — is kept in `member_account_tags`, which no member role can read. Banning the member keeps the tag in `banned_tags` (a kick does not) and bans the account's other identities still here — none that `moderate_user` would refuse to ban (the owner, an admin, a holder of `BAN_MEMBERS`) — and a banned tag is refused `user_banned` through any link, whatever identity it brings. The same account arriving with a new identity takes its membership over: the old identity leaves as `leave_server` does, and keeps its tag, so banning it later still reaches the account. So does a kicked identity coming back with the account's pass, so one account is never in twice. Coming back with no pass, by the tag it kept, an identity is refused `account_moved` (code `account_in_use`) while another identity of its account is in: an old device's seed is not the account (1.9.1). A kept tag that is banned is refused `user_banned`. The owner's is never taken over (`account_in_use`). The identity a join took over is removed from every call it was in, channel and DM, on every node (`left` in `register_user`'s answer; `_shared/livekit.ts` `removeFromCalls`). Everybody arriving on a server waits for whoever came before (the server row, then every identity of the account, are locked), so two joins of one account, or a join and a ban of one of its identities, cannot both get through. **An invite's role** is given only while the link's maker could still give it — an unbanned administrator ranked at or above it (`app.may_hand_out`) — so a link made by an admin since demoted, or kicked, lets people in with no role (1.9.1). **`"context": false`** (1.9.1) answers `{server_id, supabase_key}` (plus `rejoined: true` for a returning member) instead of the context, for an app that reads `get_server_details` itself straight after: the context costs four reads, and the app has to ask the details anyway, since this one is built on the service role and cannot carry the caller's permission bits. Without the field the context comes as before |
| `resolve_invite` | none | Runs before the client has the server's anon key — it is what hands the key out. Maps an invite to `server_id` + `server_name` + `server_icon` (a path in the public `servers` bucket, which is public for this screen) **without consuming it**, so the per-`(host, server_id)` SIWS identity can be derived before login. `invite_invalid` covers a spent or expired invite as well as a mistyped one: `register_user` deletes an invite at its last use and `cleanup-expired-invites` sweeps expired ones, so all three are simply not found. An invite still on the table is spent when `uses` has reached `max_uses`, counted as `register_user` counts it: null is unlimited and 0 is spent (before 1.9.1 this read 0 as unlimited, and promised a join the database refused). Answers `needs_account`, so the app can say a link needs a Rift account before anybody signs in, and `public_url`, the address a pass for this server must name. Since 1.9.1 it also answers `supabase_key`, the anon key `register` hands every newcomer (public: the web app carries it), so the app's first sign-in goes to GoTrue directly, as every later one does, rather than through `login` |
| `create_server` | `service_key` in body | Writes the LiveKit API secret. Also seeds a `general` text channel and a `voice` voice channel — they differ in name because `(server_id, name)` is unique. It takes no icon: an icon is a path in the server's own folder, which an admin uploads to afterwards (`update_server`). Returns `server_id`, `name`, `supabase_url`, `supabase_key`, `invite_code` (single-use admin invite). A failure at any step deletes the server again, the invite included: a server nobody can join is one nobody can delete |
| `update_server` | Bearer + `is_server_admin`, asked before anything else | Writes the LiveKit API key/secret into `server_secrets`, which has no grant and no policy. **A new `livekit_url` comes with its own `livekit_api_key` and `livekit_secret_key`**, and must be a `ws://` or `wss://` address with no credentials in it (`livekit_url_invalid` otherwise): the functions sign admin tokens for whatever that column names with the pair in `server_secrets`, which on a stack with several servers is the bundled LiveKit's, shared by them all. The keys are written before the address, so a failure between the two leaves a call that does not open rather than the old keys sent to a new host. Name, icon and the operator limits — including the DM overrides `dm_retention_days` / `dm_history_cap`, where **null is a value** meaning "inherit the server-wide number" and an omitted key means "leave it alone" — ride along rather than splitting one dialog across two transports. `icon_url` is **not an address**: it is the path of an icon the admin has already uploaded to this server's folder of the `servers` bucket (`<serverId>/<hex>.img`), or null or empty to clear it, and anything else is refused (`icon_invalid`). Every member's app fetches what that column names, so an address there could send every member to a host that logs them. It does **not** touch storage: each server owns a `chat-<serverId>` bucket and a trigger moves that bucket's `file_size_limit` when the column changes, in the same statement. `max_attachment_bytes` may go up to `max_file_bytes()`, the machine's ceiling, and no further (`limit_invalid`, naming it). `max_voice_participants`, `max_share_mbps`, `max_members`, `max_storage_bytes` and `dm_openings_per_hour` ride along the same way; all are 0 = off |
| `sweep_attachments` | Bearer (any member) | Needs the **Storage API**, not a secret: `storage.protect_delete()` refuses a direct DELETE on `storage.objects`, so no database role can free an attachment blob. Removes what the `sweep_attachments` RPC (service-role only) lists: on every run the files of deleted messages (`attachment_trash`) that no other message names, and once a day, until a pass finds nothing, everything else nobody holds: files older than the oldest message left in their channel or conversation, and avatars, sounds and icons nothing names (`app.attachment_sweep_runs.whole_at`). The retention settings are applied by the hourly `rift-message-retention` job, not by the sweep: run inside it until 048, a pass on a big server took 23–31 s and failed at the API's 8-second limit, so nothing was swept there (measured Nov 25 2026 on 5 million messages). Safe for any member — it removes only unreferenced objects — and it runs at most once a minute whoever asks (`claim_attachment_sweep`); a call too soon answers `swept: 0`. Since 064 the console calls it every five minutes with the service key in the body (`service_key`, as `create_server` takes it), and an app that hears `server_start` say `sweeps_itself` no longer does; older apps still call it on server-ready |
| `get_channel_token` | Bearer | Mints a LiveKit JWT with the API secret, on the node this channel's call is held on (see **More than one region**). Identity is `<userId>~<deviceId>`, 1 h TTL, and **never `roomAdmin`**: RoomService admin lets its holder mute or remove anybody in the call, lift their own server mute, and send packets as the server, for the token's whole life past a demotion or a ban, and every moderation act is an edge function that asks the database first (channel managers held it before 1.9.1). Only a voice channel has a call (`channel_not_found` for any other). `CONNECT`, `SCREEN_SHARE` (for a share) and `SPEAK` are the channel's bits, as `user_has_channel_permission` answers them. Everything it decides from (membership, the door, those bits, a bot's key and grant, the server's LiveKit and limits, and the claimed region) is one database call, `voice_join_facts`, which refuses in the order the function always did (one call since 065, eleven before; a request missing `channel_id`, or asking to share and watch at once, is now refused before membership is asked); without `SPEAK` the token has no `microphone`, and the metadata does not call them muted. **What a connection may publish is named source by source** (`publishSources`): the camera always, the microphone as above, and `screen_share` / `screen_share_audio` only with the channel's `SCREEN_SHARE`, since phones and browsers share on the voice connection itself (before 1.9.1 the voice connection could publish every source, so a member the channel refused a share could still share from a phone or browser). The same list is pushed live, and `get_dm_call_token` names the screen only with the server's `SCREEN_SHARE`. **The soundboard is `canPublishData`**: a press is the only data packet a member sends, so the voice connection may send data only with the channel's `USE_SOUNDBOARD` and `SPEAK` (`_shared/call_rights.ts`) and LiveKit drops anyone else's presses; a share connection never may. **Moderation is enforced here at join time** — muted users get no `microphone` in `canPublishSources`, deafened users get `canSubscribe: false`. **A bot** gets `canSubscribe` only with a `bot_voice_grants` row, never `roomAdmin`, and is refused outright until a member has sealed it a media key (calls are E2E encrypted — BOTS.md §6b). **`max_voice_participants` is enforced here**: a new arrival past it is refused `voice_channel_full`, counted as *people* so a member's screen share does not use a place, and bots are exempt because a summoned bot is not what fills a call. The reply also carries `max_share_mbps`, which the client keeps — a LiveKit token has no bitrate field, so there is nothing here to clamp — and **`livekit_url`**, the address that token is good for. **`watch: true`** asks for the desktop's watch connection, `<userId>~<deviceId>_watch`, which only receives a stream the app is watching: `canSubscribe` as the member's own, no publish and no data, never `roomAdmin`, and **visible**: hidden, it would be a listener nobody sees, so the app folds it into its owner instead of drawing it twice. It is minted only while that device's voice connection is in the room (`user_not_in_voice` otherwise — `_shared/watch.ts` says why that is the condition), reads where the call is without claiming a region or opening a room, and is refused to a bot and alongside `screen_share` / `sound_share`. One whose voice connection has gone is removed when LiveKit says so (`livekit_webhook`), and also whenever anyone mints one in that room or reads the roster. A watch token joins for one minute (LiveKit allows about another minute of clock slack), so one cannot be kept and used after its device leaves. A server older than this ignores `watch` and answers with the voice identity, so the app checks the identity it gets back ends in `_watch` before connecting |
| `get_dm_call_token` | Bearer | The same answer as `get_channel_token` (`token`, `identity`, `livekit_url`, `max_share_mbps`, plus `room`) for a call between two members. The room is `dm-<callId>`, a name no channel id can be, so `voice_roster` and a moderator's mute never see it; a ban does reach it. Who may call whom was decided by `start_dm_call`; this asks `claim_dm_call_room` only whether the caller is on the call and may join yet — the caller from the first ring, the callee once they have answered — and claims a node on the first ask (the client's measured preference if it is one of this server's, else the default, falling back to the default once if the chosen node does not answer — only while nobody has answered the call, since afterwards somebody may be in it there, which moved half a call before 1.9.1). A `preferred_node_id` that is not a UUID is ignored. Voice moderation flags are not applied: they are about the server's channels. The voice connection may send data (press a soundboard clip) only with the server's `USE_SOUNDBOARD` and `SPEAK`, read at minting, so a role change takes effect at the next join (before 1.9.0 every DM call connection could); a share connection never may, as in a channel. Takes `watch: true` as `get_channel_token` does. `call_not_found` covers no such call, not yours, ended and a `call_id` that is not a UUID alike |
| `set_bot_voice_listen` | Bearer + `MANAGE_BOTS` (checked by the RPC) | Lets a bot hear a voice channel, or stops it. Calls `grant_bot_voice_listen` / `revoke_bot_voice_listen` with the caller's JWT, then pushes the new permission onto the bot's live connection with the API secret, its microphone held back where the channel does not give it `SPEAK` or a moderator muted it, its ears where one deafened it, and each connection given the set it was minted with (`livePermissionsFor`, as `moderate_user` pushes) — the row alone is half the job, exactly as with `moderate_user`, because a token is good for its hour whatever the table says. Names a bot of this server or is refused (`no_such_bot`), since revoking rewrites the named user's live permissions |
| `set_bot_voice_summon` | Bearer + `SUMMON_BOTS` in the channel to call a bot in; seeing the channel to send one away (checked by the RPC) | `bot_id`, `channel_id`, `summon`: calls `summon_bot_to_voice` / `dismiss_bot_from_voice` with the caller's JWT. Sending a bot away also removes its connections from that one room with the API secret, and answers `connections_updated` and `livekit_error` (the row is gone either way, so a client can say the bot is still connected until it leaves). Either names a bot of this server or is refused (`no_such_bot`): sending away removes the named user from the call. Since 080 the app summons through `summon_bot_to_voice` directly and comes here only to send a bot away |
| `moderate_user` | Bearer + `MANAGE_CHANNELS` to mute/deafen, `BAN_MEMBERS` to ban, `KICK_MEMBERS` to kick (checked by the RPC) | Mute/deafen/ban, or `kicked: true` alone to kick. Nobody bans an admin or another holder of `BAN_MEMBERS` (`cannot_ban_peer`). **A kick** (`kick_member`) is a ban that the member's next invite lifts (`register`): it sets `is_banned` and `kicked_at`, and takes their roles and private-channel seats. Never yourself, an admin, a holder of `KICK_MEMBERS` or `BAN_MEMBERS` (`cannot_kick_peer`), or somebody already banned (`user_banned`). A bot is kicked the same way and also loses its channel keys (with a line in each channel, as `revoke_bot_channel_key` leaves), what it may hear and the calls it was summoned to; a new **bot** invite brings it back, and a person's invite does not (nor a bot invite a person). Older servers refuse to kick a bot (`cannot_kick_bot`). Banning or unbanning a kicked member clears `kicked_at`. The response carries `kicked`; `get_server_details` and `member_directory` say `is_kicked`. Calls the `moderate_user` RPC with the caller's JWT — the rules stay in the database — then uses the LiveKit API secret to push the new permissions and metadata onto every live connection the target holds. A ban that reaches the account's other identities (they share its tag) removes their connections too, in channels and DM calls (1.9.1), counted in `connections_updated`. See below |
| `set_channel_override` | Bearer + managing the channel (checked by the RPC) | `channel_id`, `role_id`, `allow`, `deny`: calls the `set_channel_override` RPC with the caller's JWT and answers its `reason` as it came. After an `ok` on a voice channel it reads `SPEAK` and `USE_SOUNDBOARD` again for everyone in the call and pushes the microphone off (muting a published one) or back onto each connection where it no longer matches, and the soundboard (`canPublishData`, both bits) likewise (`reconcileConnections`, which `livekit_webhook` also runs on every join), with `connections_updated` and `livekit_error` as `moderate_user` reports them; a LiveKit failure does not fail the save. Only the microphone and the soundboard move live: `CONNECT`, `SCREEN_SHARE` and summoning are asked at the next join, share or summon (a reconnect included, which `livekit_webhook` checks), and nobody is put out of a call they stay in. Text channels may call the RPC directly |
| `delete_channel` | Bearer + `channel_manageable_by`, asked before anything is touched; `channels_delete_managers` still decides the row | Deletes the LiveKit room with the API secret, then the row with the caller's JWT. Rooms are named by channel id, so without the first half everyone carries on talking in a room whose channel is gone. Deleting a room disconnects its participants — that **is** the kick — which is why the permission is asked first: the room going before the policy had been consulted let any member end any call by asking to delete its channel and being refused. A text channel has no room, and the app deletes its row directly, under the same policy |
| `change_channel_members` | Bearer + the manage bit in the private channel for a change, nothing for leaving (checked by the RPCs) | `channel_id` with `add` and `remove` (lists of user ids) calls `change_channel_members`; `channel_id` with `leave: true` calls `leave_channel`; `leave` beside `add` or `remove` is refused (`missing_fields`). Either runs with the caller's JWT and answers its `reason` as it came; `not_authorized` is `permission_denied`. After an `ok` on a voice channel it asks `channel_joinable_by` for everyone in the call and removes every connection (shares included) of anybody who may no longer be there, and deletes the room, on every node, when the last seat took the channel with it, with `connections_removed` and `livekit_error`; a LiveKit failure does not fail the change. Without it a member taken out of a private voice channel kept hearing it until they hung up, since a seat is only checked when somebody joins. For a text channel, which has no call, the app calls the two RPCs itself |
| `delete_server` | Bearer + owner (checked by the `delete_server` RPC) | Runs the RPC with the caller's JWT, which marks the server (`servers.deleting_since`): from then on nobody is a member of it — `app.server_id()` answers nothing and every edge function answers `user_not_found`, as once the rows have gone — and its invites, webhooks and listing tokens are deleted, and a `channels` event on its topic sends every member's app to re-read it and forget it. Then, with the service role, it drops every voice channel's LiveKit room (with admin clients built before the RPC: before 1.9.1 no room was ever dropped), the `chat-<serverId>` bucket, the members' avatars and the server's icons, none of which a database role can reach, and runs `purge_deleted_servers` for 4 s. The rows go in pieces, by that function, every minute for up to 25 s (`rift-server-purge`): deleting them in the owner's request ran into its 8 s statement timeout past some 600 members, and the server could not be deleted at all. `pending` says whether any of the server's rows are still waiting for it (a small server's are not). Each step after the mark is best-effort and reported back in `errors` (`livekit`, `storage`, `purge`) rather than allowed to keep a server alive |
| `move_user` | Bearer + `is_server_admin` / `is_channel_manager`, and `channel_manageable_by` for both the call they are in and the destination (checked here — nothing is written down, so there is no RPC to defer to) | Pulls a member from the call they're in into another voice channel, by sending their connections a "join this channel" packet with the API secret. Never an administrator (`permission_denied`), as for a kick. A call the caller does not manage answers as though the member were not in voice (`user_not_in_voice`), and a destination they do not manage as `channel_not_found`. See below |
| `kick_user` | Bearer + `is_server_admin` / `is_channel_manager`, and `channel_manageable_by` for each call (checked here) | `target_user_id`: removes every connection (shares included) the member holds in a call the caller manages, on every node. Never an administrator or the caller. A call the caller does not manage is left alone and answers as though they were not in voice (`user_not_in_voice`): before 1.9.1 a channel manager reached into private calls they were not in, and learned from the answer who was there |
| `refresh_calls` | Bearer + `channel_manageable_by` with `channel_id`; `is_server_admin` or `MANAGE_ROLES` without | Brings running calls up to date with the roles (1.9.1), for one channel or every voice channel: removes every connection of anybody `channel_joinable_by` now refuses, and sets everybody else's microphone and soundboard as the channel now has them (`reconcileConnections`), both from one `call_rights_for` read per room (since 065, before which it was three questions per person), answering `connections_removed`, `connections_updated` and `livekit_error`. A role, a role's bits and `set_channel_role_access` are database writes and cannot reach LiveKit, so the app calls this after each. `CONNECT` is not asked: nobody is put out of a call they are already in for it |
| `move_call` | Bearer + `channel_manageable_by` (the channel's own managers when it is private, `MANAGE_CHANNELS` when it is not) | Moves a live call to another of this server's regions: opens the room there, re-points `voice_rooms`, and tells everybody in the old room to rejoin. A private channel answers to its own managers only, as everywhere else — a server-wide admin outside it gets the same refusal as a channel that does not exist. See **More than one region** |
| `note_clip` | Bearer + the caller's voice connection in that call (checked here, on LiveKit) | Tells a call that a member just kept its last stretch (1.9.0). `channel_id` or `call_id`, the `device_id` the clip was made on and `seconds` (held to 1–120). Sends `{v: 2, type: "clipped", identity, seconds}` on topic `rift.clip` through LiveKit's API to everybody else in the room, naming that device's voice identity, only while that connection is in the room (`user_not_in_voice` otherwise, `voice_server_unreachable` when the room does not answer). A packet from the API has no sender, which no member can fake, so the app believes only those — and a member without the soundboard right, whose own packets LiveKit drops, is announced too. At most one a minute per member (`note_clip_allowed`, migration 037): past it the answer is `noted: false` and nothing is sent |
| `voice_roster` | Bearer | Who is in which voice channel right now, `{userId: channelId}`, read off LiveKit: every visible room is asked who is in it, since a room's own count lags a join by about 5 s (before 1.9.0 a room reading empty was skipped, so a call just opened looked empty). The snapshot a client starts from before the `voice:<serverId>` broadcasts can tell it anything — see ARCHITECTURE.md §5. Also `started`, `{channelId: epochMs}`: when LiveKit created each visible, occupied call's room, which the sidebar counts up from. Also `sharing`: the user ids in those calls with a screen up (a `_screenshare` connection, or a phone's screen track on its own), so an app opening mid-stream can offer to watch it; after that, members say so in their own `here` broadcasts (`sharing: true`). Share and watch connections are never counted as people. What it reads from the database is one call, `voice_roster_facts` (since 065), and one sweep of the server's nodes answers every member who asks within 1.5 s of it, each told only the calls they can see: everybody opening the server at once, or everyone in a call reading the roster after somebody drops, asked LiveKit once each before. Reading the roster removes any watch connection whose own device's voice connection has left its room. Also `regions`: each region's `load` as `low` / `medium` / `high` (null with `reachable: false` when it did not answer), taken from forwarded streams across **every** room on the node. A level and never a count, because counts over rooms the caller cannot see told any member when a private call started and how many were in it; and no `idle`, which would announce the first one |
| `configure_push` | Bearer + `is_server_admin` | Writes `push_config`, a table with no grant and no policy — the secret in it is what proves a forward request came from this server, and nothing a client can read back may hold it. `{status:true}` answers whether push is on and with which relay id (never the secret); `{endpoint, relay_id, secret}` turns it on; `{disable:true}` turns it off and hands the relay id back so the admin's client can revoke it on central. Since 080 the app asks `push_status`, `set_push_config` and `clear_push_config` instead (below) |
| `webhook` | **none** | The one endpoint anybody may call. Deploy with `--no-verify-jwt`: the whole point of a webhook is that the caller cannot log in. `POST /functions/v1/webhook/<secret>` with `{text}` — or `{content}`, the field Discord's webhooks use, so anything already pointed at one works by changing the URL. A raw non-JSON body is taken as the text. Deliberately thin: the lookup, the rate check and the insert are one `post_webhook_message` statement in the database, and all that is left here is being reachable without a JWT and ringing the `chat:<channelId>` doorbell afterwards. See BOTS.md §7 |
| `livekit_webhook` | **LiveKit's signature** | Called by LiveKit, never by an app. Deploy with `--no-verify-jwt`: LiveKit holds no session, and signs each event instead with one of its API keys, over a hash of the body. The key named is looked up in `server_secrets` and `livekit_node_secrets`, so only a LiveKit of this project's servers is heard; anything unsigned, or signed with a key or secret it doesn't have, is answered `401`. A voice connection leaving, or a watch connection joining, sweeps that room's watch connections whose voice connection has gone (`_shared/watch.ts`). The sweep reads the room as it is now, so a repeated, late or replayed event can't remove one that should stay. **Any connection joining a channel's call is checked against the rules as they are now**, because a token is good for an hour and says only what was true when it was minted: an app that kept its first one could otherwise leave and rejoin unmuted after a moderator's mute, back to talking after the channel went Listen-only, pressing clips after losing the soundboard, or back in the call after a ban. A join `get_channel_token` would now refuse (`channel_joinable_by`, the channel's `CONNECT`, `SCREEN_SHARE` for a share; a banned member or another server's has no bits) is removed, and one it would mint differently is pushed what it would mint — microphone, `canPublishData`, `canSubscribe` and the moderation metadata (`reconcileConnections`, `_shared/call_rights.ts`), all from one `call_rights_for` read since 065. A worker keeps which node signs with a key for five minutes, asking again at once when a kept key no longer verifies, so a warm join check is that one read. A token minted a moment ago already agrees, so an honest join reads and changes nothing; a read that fails leaves the connection alone rather than emptying a call during a database hiccup. A join to a DM call's room (`dm-…`) is held to its call the way `get_dm_call_token` would answer now: removed unless the call is still on and the member is its caller, or its callee after answering, with `CONNECT` (and `SCREEN_SHARE` for a share); since 1.9.1, before which a token kept past a call's end brought the room back. Each of these, once verified, stamps `livekit_nodes.webhook_heard_at` on every node at that address (at most once in ten minutes, since 1.9.1), which is how the app's region list tells a node whose webhook never arrives from one that has held no calls. Every other event gets `200` and changes nothing. The bundled LiveKit posts to it inside the stack (`webhook:` in `livekit.yaml`, added on update to a stack from before Nov 2 2026); a region elsewhere posts to the server's public address (docs.joinrift.app/regions/). Verified Nov 2 2026 on the local stack: an orphaned watcher was gone 69 ms after its voice connection left, kept through a voice reconnect, and forged events were refused |
| `listing_token` | Bearer + `is_server_admin` (checked here **and** by the RPC) | The proof central cannot produce for itself. The public directory lives on central, which has never heard of this database and shares no identity with it — a member signs in here with a key derived on their device and to central with a Rift account, and nothing links the two. So `publish_server` there could only check that its caller was signed in, and every *member* of a server holds the URL, id and invite code that was all it took to list somebody else's server permanently. This mints a 256-bit single-use token, five-minute life, digest-only at rest. Since 080 the app asks `my_listing_token` instead (below) |
| `verify_listing_token` | **none** | Central redeems a token here before writing a listing. Deploy with `--no-verify-jwt`: central holds no session on this server and never will. The token *is* the credential, and the reply is deliberately almost empty — a valid one returns the server id the caller already named, and every failure returns one flat refusal, so there is no oracle for whether a server exists or a token was ever real. Burned in the same statement that checks it, so a replay is refused |
| `get_channel_key` | Bearer | Channel-key distribution (below). For a **voice** channel it also returns `bots_missing` — bots that may speak there and have no media key yet — and, for a bot caller, `my_voice_key`: the one key a bot is ever sealed. Since 063 the app asks `my_channel_key` instead (below), and so do the bot SDKs since Nov 26 2026 (falling back to this on `PGRST202`); this stays for older apps and older SDKs |
| `post_channel_keys` | Bearer | Channel-key distribution (below). With `store_channel_keys` (below), the only writer of `channel_keyring`: since 1.9.1 (migration 043) no member role holds INSERT on it. Since 077 the app asks `store_channel_keys` and `store_key_work` instead, and this stays for older apps |
| `sweep_channel_keys` | Bearer | Channel-key distribution (below). Covers **voice channels too** since calls became encrypted; it filtered to text, which was harmless while voice held no keys and a hole the moment it did — a banned member's voice key would never have rotated. Since 063 the app asks `my_key_work` instead (below), and this stays for older apps |

### Moderation has to reach the live room

A mute is two writes, and for a long time only the first one happened. The flag
went into `users`, and `get_channel_token` refused the `microphone` source *the
next time a token was minted*. Nothing touched the call that was already in
progress, so a moderator watched a muted member keep talking — and the client
caches LiveKit tokens for 55 minutes, so even leaving and rejoining handed back
the old grant. In practice the mute landed somewhere up to an hour later.

`moderate_user` therefore does three things after the row is written:

1. `updateParticipant` on **every** connection the target holds — each device,
   plus their share and watch connections — replacing permissions and metadata.
   Rooms are named by channel id, so the search is scoped to this server's
   channels rather than every room on a shared LiveKit deployment. Revoking the
   microphone source makes LiveKit unpublish the track outright. **Each kind
   keeps the shape it was minted with** (`livePermissionsFor`): a share never
   subscribes, a watch connection never publishes and stays visible, and a bot
   listens only where `bot_voice_grants` says. Until Nov 2 2026 every connection
   got a voice connection's set, so muting someone who was sharing let their
   hidden share connection listen, and muting a bot let it hear a call it was
   never granted.
2. `mutePublishedTrack` on a live microphone, so audio already flowing stops now
   rather than at their next publish. Un-muting deliberately does *not* unmute
   their track — it restores the permission and leaves the mic to them.
3. `removeParticipant` instead of the above, when the action is a ban or a kick.

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

The database rings `channels` and `members` on `server:<serverId>` itself
(`app.announce_channels`, `app.announce_member`), which is the authoritative
half: a rename, a deletion, a join or a ban lands whatever the actor did. Each
app with the server on its list hears it, on that server's private topic, and
the real read is the refetch it triggers. Since 062 a `members` ring names the
members it is about, `{"ids": [...]}` for up to 100 (no `ids`: anything may
have moved, as a role's name or colour), and rings only when something
`member_directory` shows moved; the app re-reads only those it holds, with
`members_refresh`, after a wait that grows with the server's size so its
members do not all ask in the same instant. It never says who made the change.
Since 069 a ring a role made (given, taken, made, deleted, renamed, recoloured,
moved or given bits) also carries `"roles": true`: no `users` row moved, so
the DM list, which draws no roles, lets it go.

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

**A removal rotates at most once an hour (014).** The sweep holds a rotation
whose only reason is somebody no longer entitled (a ban, a kick, a private
channel's member removed, a bot's grant revoked) until the current version is
an hour old (`app.key_rotation_spacing`), so removals in that hour share one.
A rotation for an addition — a bot's grant starting, a channel opening up —
is never held, and carries any waiting removal with it. A held rotation is
recorded in `app.key_rotations_due`, and `app.ring_due_rotations`, a pg_cron job
each minute, rings the server's `sweep` doorbell when it falls due.

**Members who joined since are sealed the old versions too.** Healing used to
cover only the current version, so a member who arrived after a rotation could
read nothing from before it, however many members were online who could have
opened it. The sweep now also lists, newest first, each older version the caller
holds and an eligible member lacks. Nothing at or below `rotate_from_key_version`
is offered (what a channel said while private stays with whoever had it), and a
bot is eligible only from its grant.

`post_channel_keys` also refuses a batch that seals to a **bot** with no
`bot_channel_keys` grant to that channel at that version — the same rule
`refuse_ineligible_keyring` puts on the insert, named here so one ineligible
recipient does not come back as a database error for every real member beside
it. It has to be the grant and not the bot flag: the sweep seals the next
version to everyone eligible, so a blanket refusal fails the **rotation**, and a
channel with a grant on it could then never rotate for any reason — a banned
member's included.

**The work is found in the database, in batches, one member at a time.**
`sweep_channel_keys` and `get_channel_key` used to read a server's whole keyring
and membership through PostgREST, which answers at most `PGRST_DB_MAX_ROWS`
(1000) rows and drops the rest without an error. A server past a thousand keyring
rows was swept from part of its table, and a member's own keys could be among the
rows dropped, so their channel showed locked while the server held every key.
They now call `channel_key_work` and `channel_key_state` (service role only),
which answer with one JSON value:

- **at most 500 entries to seal per answer**, `more: true` when some were held
  back. A rotation mints the next version with the first batch, the rotator
  first, and heals the rest from the next pass, because `post_channel_keys`
  takes 500 entries and a channel bigger than that could not rotate at all;
- **one member per channel**: whoever is handed a channel's work holds a lease
  on it (`app.channel_key_leases`) for a minute, and everyone else is told there
  is nothing to do there. Asking again keeps it but renews it only when the
  holder stored keyring entries since the last renewal, and never past ten
  minutes from taking it (017); a lease that ran out goes to somebody else
  asking before its last holder may take it back, a minute later. `get_channel_key` lists
  `members_missing` only to a caller who holds the current key and can take the
  lease;
- **only where something changed (047)**. A change that can make key work leaves
  a mark: one person in one channel (`app.key_due_members` — joining, publishing a
  chat key, a ban or unban, a seat, a role or a bot grant given or taken) or a
  whole channel (`app.key_due_channels` — a new channel, a change to who may read
  it, a rotation, whose new version everybody needs). `channel_key_work` looks only
  at marked channels the caller can see, and a mark goes once what it points at is
  settled for everybody, so a caller without the key cannot clear work only a
  holder can do. A whole channel is looked at only by a holder of its current key,
  a channel another call is looking at is skipped rather than waited on, and one
  call stops after a second and a half with `more: true`. A daily job
  (`rift-key-look`) marks every channel, so a change no trigger saw is found within
  a day. Measured Nov 25 2026 on 50,000 members and 300 channels: a call with
  nothing marked takes 3 ms where every call took 74 s before (and failed at the
  8-second timeout through the API), and 40 at once finish in 0.4 s.

**A rotation links the old key to the new one (013).** `post_channel_keys`
takes an optional `link` (`{ciphertext, nonce}`) with a mint: the outgoing
version sealed under the one just minted (format in the app's `ARCHITECTURE.md`
§4, *The key chain*). It is stored by `store_channel_key_link` only once the
version is won, only for the version just minted, only from somebody holding
both keys, and never across a channel's opening or into the version a bot's
grant starts at; the answer says `link_stored`. `get_channel_key` returns the
channel's `links`, newest first, and the sweep seals a newcomer only the current
version and the top of each linked stretch. `prune_channel_keys(p_channel,
p_versions)` is a member's own RPC: it drops their rows at those versions where
a chain of links reaches each from a newer row they keep. The client opens the
link and compares it with the row first; the server only checks the chain is
there.

`post_channel_keys` takes `mint`: `true` is a new version, which must be exactly
`current + 1` and is all-or-nothing, so the first writer wins it and a loser
gets `keyring_conflict`; `false` heals a version that exists, sealing only a key
the sender unwrapped from its own entry, and skips anybody already sealed. A
client that sends neither gets the old all-or-nothing insert.

Since 1.9.1 the sender must hold what they seal from: a heal is refused
(`permission_denied`) unless the sender has their own entry at that version, and
a mint of version 2 or later unless they have one at the version before — which
is who `channel_key_work` hands a rotation to. Before that a member who never
held a version could seal garbage to a newcomer first, and an entry is never
replaced. And members lost INSERT on `channel_keyring` (migration 043): every
rule above lived only here, and over PostgREST a member could insert version
2147483647, after which no rotation can be minted.

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
never rung for it — except by a mention. A channel message rings the members it
names whatever they have read, and everybody who can see the channel when it
names everyone (`app.channel_ring_targets`); before that, "@you" after somebody's
"hi" rang nobody.

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
  Past an hour central contributes nothing to a ring a server forwarded
  (`kind: wake`). Central's own ring says so (`kind: central`), and there an
  expired session is a Rift DM the phone cannot read, so the wake falls back to
  saying that something arrived. Before central's relay said which ring it was,
  that DM posted nothing (review, Nov 23).

Which servers this device is on comes from a small `push_wake.json` the app
writes beside its hydrated state — the isolate cannot ask the app, and reading
the app's own Hive box from a second isolate is a lock, not a read. A second
file remembers the newest message already announced per conversation, so a later
doorbell does not repeat it. One notification per conversation, posted under a
stable id derived from the scope, so it updates in place rather than stacking —
the same id the running app posts that conversation's notification under, and
the app writes the same marks when it announces something, so an app alive in
the background and a wake for the same message say it once. A press on one opens
its conversation, from a cold start too.

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
| *(new)* what is live in a channel | `channel_live_messages(p_channel)`: the rows the bar above a channel's message box holds — its open polls (`poll.closes_at` still ahead) and its bots' live panels (`blocks.live` the JSON boolean `true`), newest first, at most 25, whatever page the chat has loaded. Same two halves as `channel_messages`: ids off two partial indexes (`idx_messages_polls`, `idx_messages_live_panels`) in `app.channel_live_ids`, which checks only that the channel is open to you, then the rows by key under `messages_select`. A channel you cannot open answers with nothing. The app reads it on opening a channel and again on reconnecting; a server without it is read from the loaded page alone |
| *(new)* a call's players | `call_live_messages(p_call)`: the live panels whose `blocks.call` names this voice channel (`WIRE.md` §5), from whichever text channel each was posted in, newest first, at most 25 — the same two halves, off `idx_messages_call_panels`. Nothing without `can_see_channel(p_call)`. `messages_select` admits such a row to whoever can see its call, and `messages_insert` lets them press it (`app.can_press_call_panel`: an interaction into the panel's own channel, addressed to its bot); nothing else of the channel opens. `messages_panel_call` drops a `call` that is not a voice channel on the server the bot could join, or is on a panel that is not live or is for one member. A player's doorbells ring the call's topic as well when the channel or the call is private. Only a bot's row plays to a call, and only a bot changes `blocks` on a row, edits included (`messages_blocks_by_bot` refuses anybody else with `only_a_bot_draws_a_panel`): a member's own plain message, a command to a bot, would otherwise have become an interface in the whole call's bar. Older servers have no such function, and the app reads the channels alone |
| *(new)* a call's bar, in one read | `call_panels(p_call)`: `call_live_messages(p_call)` and the live panels (not polls) of every text channel the caller reads, newest first, in one read, the same two halves (`app.call_panel_ids`). Nothing without `can_see_channel(p_call)`. The app asks it when a call starts and when a bot in the call posts, in place of one `channel_live_messages` per text channel; on a server from before 065 it reads them as before |
| *(new)* opening a channel, in one read | `channel_open(p_channel, p_limit, p_bot_limit)`: what the app asked in five requests when a channel opens — the newest page (`channel_messages`), the bar (`app.channel_live_ids`), the caller's keys (`my_channel_key`, or `key_error` with its refusal, `channel_not_found`), the bots holding a key to it (`channel_bot_listeners`) and the bots a `/` there reaches (`list_members`) — as `{messages, live, key, key_error, listeners, bots}`, each row in the shape the app's own reads select (sender, reaction counts, pin). SECURITY INVOKER, so every part is decided by the policy and function it always was; a channel the caller cannot read answers empty parts and `channel_not_found`. On a server from before 066 the app asks the five apart. The app still asks again for the keys when this device published its chat key only that moment |
| `list_dms` | `dm_messages_page(p_peer, p_before, p_after, p_limit)`, with the sender embedded (`users!dm_messages_sender_id_fkey`): newest first, or oldest first from `p_after`, as `channel_messages` answers. It reads the conversation off `idx_dm_messages_pair`. Asked as a plain `select` ("sent by me to them, or by them to me"), and under `dm_messages_select`, Postgres gathered every message the caller had ever sent or received before picking the conversation out: 80 ms for a page of a 100,000-message conversation, 0.2 ms through the RPC (051). SECURITY DEFINER, and it reads only the caller's conversation with `p_peer`, which is what the policy allows; embeds selected on top are read as the caller. The app asks a server without it the old way, after its `PGRST202` |
| `send_message`, `send_dm` | `insert`; a BEFORE trigger stamps `sender_id = auth.uid()` and `created_at`, so a client can't post as someone else or backdate. `attachment_paths` lists the storage paths of the message's files (each attachment, a video's poster, a link card's picture), in the clear: each must be an object the sender uploaded to `chat-<server>` under this conversation's folder — the channel's id, or `dm_<low>_<high>` — or the insert is refused `attachment_not_yours`, and more than 64 is `too_many_attachments` (`app.check_attachment_paths`). Optional: a message without it keeps its files until the sweep's watermark passes them, as before console 1.9.0. A server before 1.9.0 answers PostgREST's `PGRST204` for the unknown column, and the app sends again without it |
| `edit_message`, `edit_dm`, `delete_message`, `delete_dm` | `update`/`delete` scoped by policy; the column grant limits an edit to the envelope, so `attachment_paths` never changes. A delete, by anyone and by any route (retention included), puts the message's `attachment_paths` in `attachment_trash` (`app.trash_message_files`), and `sweep_attachments` removes each one no other message still names. A file is deleted directly only by its uploader (`chat_attachments_delete`): before 1.9.0 whoever managed channels could delete any file in the server, so that a moderator's app could free a deleted message's files |
| `list_users`, `get_server_details` | `select` on `users` / `servers` / `channels`, all scoped to your server |
| `create_channel` | `insert` gated on `app.can_manage_channels()` |
| `rename_channel` | `update`; the column grant covers only `name`. A LiveKit room is named by the channel's **id**, so renaming a voice channel doesn't touch the call inside it |
| *(new)* file ceiling | `max_file_bytes()`: the largest file storage on this machine accepts, which the console sets (its `FILE_SIZE_LIMIT`) and records with `app.set_file_ceiling`, 50 MB until it has. `get_server_details` carries it as `max_file_bytes`, so the app offers no limit past it. No server's `max_attachment_bytes` may be changed above it, a new server is brought down to it, and lowering it lowers every server above it. Granted to `authenticated` and the service role; the table behind it to nobody |
| *(new)* channel order | `reorder_channels(p_channels)`: the channels in the order wanted, normally one section (text or voice) as the caller sees it. `MANAGE_CHANNELS` (`not_authorized`); every channel this server's and visible to the caller (`channel_not_found`), none twice (`duplicate_channel`). The channels given are dealt back into the places they held, so a private channel the caller cannot see keeps its own. `channels.position` has no column grant — this is its only writer — and a new channel goes last in its section. `get_server_details` lists by it, ties by name. Rings `channels` once, not once per row |
| *(new)* channels without encryption | `set_channel_encrypted(p_channel, p_on)`: turns a public text channel's encryption off, or back on, for whoever may manage it (`not_authorized`); a private or voice channel is `not_public_text`. Posts who did it as a system message. `channels.is_encrypted` has no column grant and a CHECK keeps it true on private and voice channels; making a channel private turns it back on. `get_server_details` carries it per channel. While it is off, `messages_insert` lets members post `key_version = 0` rows there (still signed, which clients check), polls included, and the key sweep never rotates the channel, though it goes on sealing the key so the history before the switch stays readable. Bots see what `messages_select` showed them before: nothing new |
| *(new)* changing a private channel's members | `change_channel_members(p_channel, p_add, p_remove)`: seats the people in `p_add` (this server's, never banned or a bot) and removes those in `p_remove`, touching nobody else. The manage bit in the channel (`not_authorized`); `{reason}` is `ok` or `no_such_channel` (not this server's, or not private). Added before removed, so a change never passes through an empty channel, which deletes it. `set_channel_members(p_channel, p_users)`, which replaces the whole list, stays for older apps: a list read wrong became members removed. The app calls it through the `change_channel_members` function, which also takes the removed out of a running call |
| `delete_channel` | still policy-gated, but back behind an edge function for a voice channel — it is the only thing that can drop the LiveKit room (above); a text channel's row is deleted directly |
| `create_invite` | `insert`; the code comes from a column default, and the policy refuses any permission the caller doesn't hold, and a role above the caller's own rank |
| *(new)* listing and revoking invites | `select` and `delete` on `invites`: a member reaches the links they made (`invites_select_own`, `invites_delete_own`), an administrator every link on the server (`invites_select_admin`, `invites_delete_admin`), one left by a member since kicked included — except a link carrying a role above their own rank, which they could not have made and do not see (1.9.1; before it, an admin could join a second identity through the owner's link for a higher role). Before Nov 22 2026 only the first held, so nobody could revoke somebody else's link |
| *(new)* webhooks | `create_webhook(p_channel_id, p_name)` mints one and returns its secret once; `select` and `delete` on `webhooks` list and revoke them. All three ask `app.can_manage_webhooks()`: `MANAGE_CHANNELS` and `MANAGE_WEBHOOKS` together, or an administrator (`forbidden`). Before Nov 22 2026 they asked only `MANAGE_CHANNELS` |
| *(new)* giving and taking roles | `insert` and `delete` on `member_roles`, an administrator's (`app.may_assign_role`), never `@everyone` or the owner's role. A role is given only if it sits at or below the giver's own rank (their highest role's `position`), so the only admin can make a second one, and taken off anybody only if it sits below it, so one admin cannot take Admin off another. Before Nov 22 2026 the rank was not asked of either, apart from taking a role off yourself |
| `update_profile`, `publish_chat_key` | `update` on your own row — the column grant covers only `display_name`, `chat_public_key`, `avatar_path` and `dm_policy` |
| `toggle_reaction`, `list_reactions` | `toggle_reaction(p_scope, p_message, p_emoji)` takes the caller's own reaction off, or puts it on if it was not there, and answers `{reacted, counts}` (`counts` as `reaction_counts` gives them). SECURITY INVOKER, so the row policies decide; taking one off is asked first, so a member the insert policy now turns away (timed out, without `ADD_REACTIONS`, blocked in a DM) can still take theirs off. A message holds at most twenty different emoji, however the row is written (`too_many_reactions`, checked after the insert policy). The ring (`reaction`, `dm_reaction`) names who reacted as `user_id`, which the reactor's app uses to skip reading counts it already holds. On a server from before 067 the app inserts the row and, on the duplicate-key error, deletes it. Counts come from `message_reaction_tallies(p_scope, p_ids)` and, with a page of messages, from the computed column `reaction_counts` |
| `moderate_user`, `set_user_permissions` | RPCs — RLS is row-level, so a policy allowing an admin to write another member's flags would also let them rewrite that member's identity. `moderate_user` kept the RPC but regained an edge function in front of it, which is the only thing that can reach LiveKit (above) |
| `list_dm_conversations` | `dm_conversations(p_limit, p_before)` — `DISTINCT ON` instead of a thousand rows grouped in TypeScript, and since 041 a page of them rather than every peer you have ever messaged |
| the `notifications` table | `unread_counts()` + `mark_read()` over `read_state`. `unread_counts()` answers `{channels, mentions, dms, prefs}`: per channel, how many messages are unread and how many of those name you or everyone (034; a server without `mentions` counts as though every unread message did); per conversation, how many messages from that person are unread, counted from your own conversation list (`dm_conversation_heads`) and, like a channel's, only up to `unread_cap()` (051). A request counts once it is accepted. A cursor that moves forward rings `read` on its owner's user topic, once per statement: `{scope, scope_id, last_read_id}` when one cursor moved, `{}` when several did (`mark_all_read`). A write that moved nothing rings nothing. The reader's other devices count again where they still show something unread there. The app writes one conversation's cursor at most once every 1.5 s while messages land in front of its reader (a burst of twenty was twenty writes and twenty `read`s), and at once when the reader moves on. A new member starts with a cursor at the newest message of every public channel; a private channel's is made when they are seated in it (`channel_members_seed_cursor`, 1.9.1). Before 1.9.1 every channel got one, so a new member could read every private channel's id from their own cursors |
| *(new)* pins | `set_pinned(p_scope, p_message, p_pinned)` for channels and DMs alike, then a `select` on `message_pins` / `dm_message_pins` with the message embedded to list them. A function rather than an insert because of the cap — fifty per conversation, and the fifty-first raises `pin_limit` — and because a channel pin takes `PIN_MESSAGES` (or managing a private channel) while a DM pin takes only being one of the two, and not being banned or blocked by the other (`dm_not_accepted`). Nobody timed out pins or unpins (`timed_out`). It rings `pin` on the channel, or `dm_pin` on both sides' user topics, with the message id. A pin names a message and never its words |
| *(new)* polls | posted as a message: the question and options in the sealed body (in the clear where the channel's encryption is off), and the rules the server enforces in `messages.poll` — `{options, multiple, closes_at}`, set once on insert and refused on an edit. Posting one takes `CREATE_POLLS`, which `@everyone` has by default. Then `vote_poll(p_message, p_options)` replaces the caller's ballot (an empty array takes it back), `poll_tallies(p_ids)` reads `{counts, voters, mine}`, and `close_poll(p_message)` lets the author end it early. **Members see counts, never ballots**: `poll_votes` shows each member only their own rows. The server can still read every row — it counts them |
| *(new)* reports | `report_message(p_message, p_reason, p_note)` and `report_member(p_target, p_reason, p_note)` file one; reasons are `spam`, `harassment`, `explicit`, `other`, the note is up to 1,000 characters. **A message report copies the sealed envelope server-side** — ciphertext, nonce, signature, key version, author — so the reporter supplies nothing that could be forged, the report outlives the message, and the database still never holds the words; a reviewer's client opens it with the channel key it holds and checks the signature. One report per message per reporter, one open report per member per reporter (`already_reported`), twenty open per reporter (`too_many_reports`). Reviewers (`REVIEW_REPORTS`, on `Moderator` by default) `select` from `reports`, never one about themselves; `resolve_report(p_report, p_outcome)` records `dismissed`, `deleted`, `timed_out`, `banned` or `kicked` after **checking it happened** (`outcome_not_done`; a kicked member is not recorded as banned, nor the other way round, and since 1.9.0 somebody who left (`users.left_at`) is not recorded as kicked), and closes every open report the action settles — all of a message's for a deletion, all of a person's for a ban or a kick. Rings `reports` on each reviewer's user topic. Closed reports are deleted after 90 days |
| *(new)* the member sidebar | `member_sidebar(p_limit)`: everything the sidebar's first frame needs, in one call and one JSON document: `bots` and `people` (each the first page `list_members` gives for that `p_limit`), `counts` (`member_counts`), `roles`, and `assignments` (`member_roles_for` the rows returned). It runs as the caller and adds no rule of its own. A client finding it missing (`PGRST202`, a server not updated yet) makes those requests itself. |
| *(new)* the members ring answered | `members_refresh(p_ids, p_limit)`: what the member list re-reads when `members` rings, in one call: `bots` (the first page, as `member_sidebar`), `members` (`members_by_ids(p_ids)`, up to 100), `counts`, `roles`, and `assignments` (`member_roles_for` the bots and members returned). It runs as the caller and adds no rule of its own. A client finding it missing (`PGRST202`) makes those requests itself. |
| *(new)* an app's first loads | `server_start(p_member_limit)`: `{unread, sidebar, sounds, listeners, summons, sweeps_itself}` — `unread_counts()`, `member_sidebar(p_member_limit)`, the soundboard, `voice_listeners` and `voice_summons`, as the app read them one by one. It runs as the caller and adds no rule of its own. The app's first loads for a server share one call, taken only while it is out or just back, and later reads are each part's own. A client finding it missing (`PGRST202`) makes those requests itself. |
| *(new)* the DM lists | `dm_lists()`: `{conversations, requests, blocks}` — `dm_conversations()`'s first page, `dm_requests()`, and the ids the caller has blocked (`member_blocks`), in one call. It runs as the caller. A client finding it missing (`PGRST202`) makes the three requests itself. |
| *(new)* reading a channel's keys | `my_channel_key(p_channel)` and `my_key_work()`: what `get_channel_key` and `sweep_channel_keys` answer, in the same shape, as one database call each. Definers that ask `channel_key_state` and `channel_key_work` about the caller and nobody else, and refuse whom the edge functions refused: `user_not_found` (no member row, or a server being deleted), `user_banned`, `channel_not_found` (another server's channel, or one the caller cannot see; a summoned bot gets its own sealed key, as from `get_channel_key`). Volatile: they take the leases that spread healing across members. A client finding them missing (`PGRST202`) asks the edge functions, and keeps doing so for that server until it restarts. Since 080 `my_channel_key` also answers, for a voice channel, `listening_bots`: the ids of the bots allowed to hear it (`voice_listeners`), read with the key, so a call learns which key each bot is registered under in the same request. |
| `set_bot_voice_summon` with `summon:true` | `summon_bot_to_voice(p_bot, p_channel)` directly (granted to `authenticated` from the start). Since 080 it answers, beside `reason`, `new` (the summon was not there before) and `needs_key` (the bot may speak here and holds no media key at the channel's current version), and the app rings `sweep` only when `needs_key` is true, or when an older server answers neither. The edge function stays for a dismiss, which must reach LiveKit |
| `configure_push` | `push_status()` → `{enabled, relay_id}`, `set_push_config(p_endpoint, p_relay_id, p_secret)` → `{enabled:true}` (`missing_fields` for an endpoint that is not https, or a secret under 16 characters), `clear_push_config()` → `{enabled:false, relay_id}`. Definers, admin only (`permission_denied`; `user_not_found` and `user_banned` as the key reads), since 080. `push_config` keeps no grant and no policy, and none of them hands the secret back |
| `listing_token` | `my_listing_token()` → `{token, server_id, expires_at}`: 32 random bytes made by pgcrypto, stored by `issue_listing_token` as a digest only. Admin only (`permission_denied`), since 080. `verify_listing_token` stays an edge function, since central calls it with no key |
| *(new)* storing sealed keys | `store_channel_keys(p_channel, p_version, p_entries, p_mint, p_link)` is `post_channel_keys` as one database call: the same checks in the same order (a member not banned on a server not being deleted, the channel on it and in the caller's sight, the batch's shape and its 500-entry cap, the version arithmetic, the hold, everyone sealed for on this server, a bot only under its grant), the same refusals by the same codes, and the same answer, `{channel_id, key_version, entries_stored, link_stored}`. One transaction, so a mint waits for any other mint of that channel and reads the version it left (`keyring_conflict` for the second, whether or not the two batches overlap). `store_key_work(p_jobs)` stores a sweep pass, each job `{channel_id, key_version, entries, mint, link}` as `store_channel_keys` would and on its own, so a lost race costs only its own channel: `{results}`, one per job in the order sent, each that answer with `success: true`, or `{channel_id, key_version, success: false, code}`. A pass holds at most 500 entries, what `my_key_work` hands out; the caller is refused once for the whole pass. A client finding them missing (`PGRST202`) posts each job to `post_channel_keys`, and keeps doing so for that server until it restarts. |
| *(new)* role counts | `role_counts()`: what the Roles page shows, in one call — `counts`, how many members hold each role of the caller's server (a role nobody holds is absent), and `mine`, the caller's own `member_role_list` rows, most senior first, which decide what they may edit. NULL for somebody who is no member. A client finding it missing (`PGRST202`) pages through `member_role_list` as before. |
| *(new)* moving a role | `swap_role_positions(p_a, p_b)`: exchanges two roles' positions in one statement, or neither (`not_swapped`), so the ladder is never left with two roles on one rung. SECURITY INVOKER: `roles_update` decides each row, so a role at or above the caller's own is left out (`not_swapped`) and a rung the caller could not put a role on is refused (42501); `@everyone` and the owner's role never move (`not_swapped`). A name, colour or place rings `members` once a statement (`roles_ring_drawing`), not once a row. A client finding it missing (`PGRST202`) writes the two rows itself and puts the first back if the second is refused. |
| *(new)* leaving | `leave_server()`: leave this server, a kick by your own hand. It locks you out the way `kick_member` does — `is_banned` and `kicked_at`, your roles and private-channel seats taken — and marks it yours with `users.left_at`; a new invite brings you back as yourself (`register_user` readmits you), and what you wrote, server DMs included, is still there. `member_directory` and `get_server_details` say `has_left`, so your other devices drop the server, and the banned page of `list_members` leaves out who left; a search still finds them. A ban outranks it both ways: somebody banned or kicked who leaves is told yes and nothing changes, and banning, unbanning or readmitting clears `left_at` (`users_clear_left_with_kick`). The owner cannot leave (`owner_cannot_leave`), nor a bot (`bot_cannot_leave`: a kick removes one). It does not reach LiveKit: the app hangs up its own call first, and a DM call ends with the ban (`users_ban_ends_calls`). Older servers have no such function (`PGRST202`), and the app only forgets the server there |
| *(new)* permissions per channel | `channel_overrides` holds, per channel and role (`@everyone` included), the bits it `allow`s and `deny`s on top of the server's; a member's bits in a channel are their server bits, then the `@everyone` row (denies off, allows on), then all their roles' rows together (denies off, then allows on, so allow wins between roles), and an administrator holds every bit (`app.channel_permissions_of`). Only a channel's own bits can be overridden: text `SEND_MESSAGES`, `ATTACH_FILES`, `ADD_REACTIONS`, `MENTION_ALL`, `MANAGE_MESSAGES`, `PIN_MESSAGES`, `CREATE_POLLS`; voice `CONNECT`, `SPEAK`, `SCREEN_SHARE`, `USE_SOUNDBOARD`, `SUMMON_BOTS` — never `VIEW_CHANNEL`, which is a private channel's member list. `set_channel_override(p_channel, p_role, p_allow, p_deny)` writes one role's whole row, both zero removing it, and answers `{reason}`: `ok`, `forbidden` (not a manager of the channel, a role at or above your own unless you are an administrator, or a bit you do not hold among those it changes), `no_such_channel`, `no_such_role` (not this server's), `invalid` (a bit outside the channel's kind, or one both allowed and denied). It rings `channels`. `select` on `channel_overrides` for whoever can see the channel. `get_server_details` carries the caller's bits per channel as `my_permissions`. The channel's bit is what posting, polls, presses on a bot's panel aside (`messages_insert`; since 1.9.1 a press past the bit must name a panel of that bot in that channel, `app.is_pressable_panel`, and a history cap ranks presses apart from messages so they never push one out), editing your own message, a bot's panel aside (`messages_update_own`), reactions, uploads named for the channel (`app.can_attach`, which since 1.9.1 also asks that the uploader can see the channel, or is one end of the DM a `dm_` name names — only as strong as the name: a file is sealed into a message the server cannot read, so one uploaded under another channel where the sender may attach can still be linked here by a message that leaves it out of `attachment_paths`; the bit is the app's to honour, like the row-level rules for what a sealed body says, and the app draws a file only from its own conversation's folder, `MessageBody.keptTo`), pins, deleting others' messages, `summon_bot_to_voice` and `get_channel_token` ask; `@all` (`mentions_all`) is dropped from a message whose sender the channel does not give `MENTION_ALL`. `user_has_channel_permission(p_user, p_channel, p_name)` is the service role's form. A change reaches a call on its next join, except `SPEAK` and `USE_SOUNDBOARD`, which the `set_channel_override` function pushes onto the call at once; `moderate_user` and `set_bot_voice_listen` read `SPEAK` when they push a microphone back, and both bits for the soundboard; `livekit_webhook` holds every join to the rules as they are now, so an old token kept and reused gets nothing back |
| *(new)* console update | `app.console_update()`: the newest release this server's console would be offered, as `{version, url, notes}`, for an admin of the server the console set up (`app.is_admin()`, and `app.console_server()`: the first server made on the database), null for anybody else — a database can hold other servers (`create_server`) whose admins do not run the console (1.9.1). The console (after 1.6.0) asks GitHub every six hours and keeps it in its own `rift_console.state` (`update_available`), out of every API role's reach, so this is SECURITY DEFINER; it clears it when there is none or an update lands, and a database the console never ran on (or a stored value it cannot read) answers null. After each change the console calls `app.announce_console_update()` (granted to nobody), which sends `me` to each of those admins' own topics, so an open app reads the details again at once. `get_server_details` carries it as `console_update`; older servers leave the key out. Telling only: nothing here updates anything |
| *(new)* time-outs | `time_out_member(p_target, p_minutes)` — text's mute: no messages, DMs, reactions, edits, pins or typing until `users.timed_out_until`. `MUTE_MEMBERS`; 0 lifts it; at most 28 days; never yourself, an admin, or another holder of the bit (`cannot_moderate_peer`) |
| *(new)* who may start a DM | `users.dm_policy` — `everyone`, `requests` or `nobody` — written by the member. Only a *first* message asks (`dm_links`, one row per pair that has ever talked, kept past retention). A first DM to `requests` becomes a request: no ring, no head for the recipient, no unread count, rung as `dm_requests` rather than `dm`, and the sender's second message is `dm_request_pending`. Since 1.9.0 every new DM, request or not, also rings `dm_sent` `{id, recipient_id}` on the sender's own `user:` topic, so their other devices list it (not `dm`, which an app counts as mail from `sender_id`), and an edit or a delete rings `dm_changed` on both people's topics rather than the recipient's alone. `dm_requests()` lists a member's waiting ones in the `dm_conversations` shape; `answer_dm_request(p_peer, p_accept)` accepts or ignores, and **replying accepts**. Accepting rings `dm_requests` on the sender's `user:` topic too, so their composer opens; ignoring rings only the answerer's own devices. `dm_link_state(p_peer)` is `none`, `open`, `waiting`, `asked` or `ignored` — `waiting` covers being ignored, which the sender is never told. A first DM to `nobody` is `dm_not_accepted`. Opening conversations is limited by `servers.dm_openings_per_hour` (default 10, admins exempt): `dm_rate_limited` |
| *(new)* DM calls | `dm_calls`, one row per call, no grant on the table. `start_dm_call(p_peer)` rings (only an open conversation — `call_needs_conversation`; a block either way is `call_not_accepted`; `timed_out`; `cannot_connect` without `CONNECT`, or from a bot; `call_rate_limited` after five unanswered calls to one person in an hour). If the pair already has a call ringing it is returned, and if that one is ringing the caller, it is answered — calling back is picking up. One already *answered* is ended where it went quiet and a new one rings: pressing Call means the presser is not in it, and rejoining a call both ends had left rang nobody. `answer_dm_call(p_call)` is the callee's, once (`call_not_ringing`, `call_ended` past the 45-second window). `end_dm_call(p_call)` from either end records `completed`, `declined`, `missed` (a caller giving up after 15 s) or `cancelled`. `end_dm_ring(p_call)` (1.9.0) is the same from either end but only while the call is unanswered: what Decline, a dismissed ring and the caller's timeout send, so one landing just after an answer leaves the call going and returns it answered. It takes the row lock `answer_dm_call` takes, so the two cannot cross. `dm_call_alive(p_call)` is the heartbeat, every twenty seconds; the `rift-dm-call-sweep` job ends a ring past its window as missed and an answered call silent for three minutes as completed, at the moment it went quiet. The job runs as `postgres`, which is granted `app.close_stale_dm_calls` by name in 008. `my_dm_calls(p_known)` lists the caller's calls still going, plus any named; `dm_call_log(p_peer, p_since)` is a conversation's ended calls. Every change of state rings `dm_calls` on both people's `user:` topics (empty); a ring, and the end of a ring, push the callee's phones, unless that conversation is muted to `none`. A ban hangs up, and so does a block (a ring the blocker was getting is `declined`, one they were making `cancelled`). Ended calls follow the DM retention age |
| *(new)* blocks | `insert`/`delete`/`select` on `member_blocks`, your own rows only. A blocked member's DM is `dm_not_accepted` — the same answer a `nobody` setting gives — and they cannot read that the block exists. Nor can they edit what they already sent you, react to or pin in the conversation, or send typing to your `user:` topic. Their waiting request leaves your list |
| *(new)* the soundboard | `select`/`insert`/`update`/`delete` on `soundboard_sounds`, gated on `MANAGE_SOUNDBOARD`; `server_id` and `created_by` have no column grant and are stamped. **Playing one is not here at all** — a press is a packet on the call's LiveKit data channel and every listener plays the clip locally, so the server neither carries the audio nor learns that it happened. Who may press is the server's, though: LiveKit drops data packets from a connection without `canPublishData`, which is minted and pushed from the channel's `USE_SOUNDBOARD` and `SPEAK` (`get_channel_token`) |

## Database schema

Defined by `migrations/`, run in order on a fresh instance. The central
project has its own set, in the `rift-central` repository.

The baseline, `001` to `008`, is split by *kind* rather than by feature, so an
object is defined in exactly one place and the order is a dependency order.
It is locked (`migrations/locked.sha256`): later changes are further numbered
files, each run once after it, and the list below grows with them.

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
   same accepted trade-off as reactions; since 070 read only by members of the same server), `soundboard` (5 MB a clip, unencrypted for the same
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
9. **009_region_key_check.sql** — `require_node_key` becomes `SECURITY DEFINER`. Its trigger
   is deferred, so it runs at commit as whoever called `add_voice_region`, who may not read
   `livekit_node_secrets`; adding or renaming a region failed until it could.
10. **010_channel_order.sql** — `channels.position`, numbered by name to begin with, and
   `reorder_channels`, its only writer. An update that changes only the position no longer
   rings `channels` per row.
11. **011_file_ceiling.sql** — the machine's largest file (`max_file_bytes`), set by the
   console; no server's `max_attachment_bytes` goes past it.
12. **012–014** — channel key work found in the database (`channel_key_work`, leases), key
   links (`store_channel_key_link`, `prune_channel_keys`), and one key change an hour for
   removals.
13. **015_plain_channels.sql** — `channels.is_encrypted` and `set_channel_encrypted`, for a
   public text channel only.
14. **016_attachment_scope.sql** — `chat_attachments_select` lets a member read a stored file
   only where they can read the conversation it is named for (a channel they can see, or a
   server DM they are one end of), plus their own uploads. Before it, any member could list
   and fetch every file in the bucket.
15. **017_key_lease_progress.sql** — a key lease is renewed only for work done (see
   `sweep_channel_keys` above).
16. **018_kick_bots.sql** — `kick_member` kicks a bot too, taking its channel keys, voice
   grants and summons with it; `register_user` lets a kicked bot back through a bot invite.
17. **019_plain_polls.sql** — a poll may be posted in the clear in a channel whose encryption is
   off; `messages_insert` keeps clear polls out of every other channel, and a webhook still
   posts none (`messages_poll_has_sender`).
18. **020_leave_server.sql** — `leave_server`, a kick by your own hand; `users.left_at` and
   `has_left`, so the banned list leaves out who left and your other devices drop the server.
19. **021_server_icons.sql** — an admin may write their own server's folder of `servers`
   (`server_icons_insert`, `server_icons_delete`); the bucket takes a PNG of up to 2 MB, holds
   `app.server_icons_per_server()` objects a server, and the sweep collects an icon no server
   names. `servers.icon_url` holds that path, never an address.
20. **022_live_messages.sql** — what is live in a channel: its open polls and a bot's current
   player, asked for directly, since one page of chat may not hold them.
21. **023_call_players.sql** — a bot's player belongs to the call it plays to (`"call"` beside
   the live mark), so everyone in that call can see and press it.
22. **024_panels_are_bots.sql** — only a bot writes `blocks`, on an edit as well as an insert
   (`messages_blocks_by_bot`).
23. **025_member_sidebar.sql** — `member_sidebar`, the sidebar's first five requests in one.
24. **026_read_announce.sql** — a read cursor that moves forward rings `read` on its owner's
   user topic, so the reader's other devices clear the badge (`app.announce_read`).
25. **027–043** — permissions per channel (`channel_overrides`), no edits where you cannot
   post, the console update notice, links that need a Rift account and one live identity per
   account, rank on assigning roles and webhooks by their own bit, mention rings and counts,
   stopping a DM ring, clip names and notices, reports of somebody who left, a DM ringing its
   sender's devices, a message's own files (`attachment_paths`), bot voice targets,
   `change_channel_members`, and the keyring written only through `post_channel_keys`. Each
   file's header says what it changes and why.
26. **044_schema_review.sql** — what the review of 026–043 found: a press needs a panel to
   press and is capped apart from messages; an invite's role is its maker's to give when it is
   used, and an admin sees links only up to their rank; a returning identity takes the account
   over only with its pass, and joins and bans of one account wait for each other; a private
   channel's cursor comes with its seat; locks for `set_channel_override` and
   `set_channel_members`; a call's region claim renews its time; uploads named for a
   conversation the uploader is in; the console notice to the console's own server; the
   retention pass deletes DMs without ringing.
27. **047_key_work_marks.sql** — the key sweep looks only where a change left a mark (see
   `sweep_channel_keys` above), and each key version's mint time is kept
   (`app.channel_key_minted`) so a removal's wait is not a scan of the version's rows.
28. **048_sweep_cost.sql** — the attachment sweep no longer runs the retention pass, and
   reads every file only once a day; the retention pass, now hourly, reads the old end of the
   tables through BRIN indexes on `created_at` and finds each channel's and conversation's
   history-cap edge by walking its index, rather than numbering every row; a retention delete
   rings nobody in channels too. Measured Nov 25 2026 on 5 million messages: a sweep 2.2 s →
   0.5 s for the daily whole pass and a few ms between, retention with nothing to do 14 ms.
29. **049_role_edit_cost.sql** — editing a role writes only the members' rows whose
   permission flags (`is_server_admin`, `is_channel_manager`, `can_create_tokens`, `is_owner`)
   it moves, worked out in one statement (`app.sync_permission_caches`), and rings `members`
   once rather than once per holder; a change to its permissions tells each holder `me`
   once. Roles handed out or taken away, a deleted role's included, are handled a statement
   at a time the same way. Measured Nov 25 2026 on 50,000 members: recolouring a role 40,000
   hold 5.1 s → 6 ms, `@everyone` 6.4 s → 2 ms, with 100,000 messages sent → 1. A permission
   that moves every member's flag still takes 2–3 s: the cost of writing that many `users`
   rows, which 52 foreign keys point at.
30. **050_reaction_counts.sql** — a message row has a computed column, `reaction_counts`
   (`[{emoji, count, mine}]`, ordered by emoji; null for a message the caller may not see),
   which the app selects with a page (`reactions:reaction_counts`) instead of embedding every
   reaction row. The check of who may see the message is made once per message
   (`app.reaction_counts_of`), and `message_reaction_tallies` uses the same. Measured Nov 25
   2026 on a page of fifty messages with 2,600 reactions each: 220 ms and 3.3 MB → 22 ms and
   45 KB; the tally for those fifty 455 → 17 ms. The app asks a server without the column the
   old way, after its `42703`.
31. **051_dm_reads.sql** — a conversation is read off its own index, `idx_dm_messages_pair`:
   the DM page (`dm_messages_page`, which the app now asks), the DM half of `unread_counts`
   (from the caller's `dm_conversation_heads`, skipping a conversation read up to its newest
   message, and capped at `unread_cap()`), `mark_all_read` (the conversations in that list
   and the requests waiting on the caller, which it marked before too), `mark_read` without
   an id, and `has_unread_before`. `mark_read` no longer writes a cursor that would not move.
   Measured Nov 26 2026 on a member with 300 conversations and 45,000 DMs: `unread_counts`
   417 → 10 ms, `mark_all_read` 377 → 11 ms, `mark_read` on a conversation 43 → 1 ms; a page
   of a 100,000-message conversation 80 → 0.2 ms. The app asks a server without
   `dm_messages_page` the old way, after its `PGRST202`.
32. **052_member_search.sql** — `search_members`, which the composer's @ menu asks, gathers a
   private channel's audience once (`app.channel_audience`, as `list_members` does) instead of
   asking `app.member_in_scope` of each member it walks past. Same members in the same order.
   Measured Nov 26 2026 on 50,000 members, in a private channel of 201: the menu opening
   with nothing typed 534 → 6 ms through PostgREST, "a" 904 → 35 ms (what it costs in a
   public channel too). A private channel opened to a role of 38,000 pays about 10 ms more
   for gathering that list.
33. **053_unread_channels.sql** — `unread_counts` runs as the server and works out the
   caller's readable channels once (`app.visible_channels`), instead of `messages_select`
   building them again for each of the few hundred statements its channel-by-channel count
   makes. Each count asks of a row what that policy asks: not somebody else's ephemeral
   reply, and for a bot only what was sent to it or sealed under a key version it was given.
   Same counts. Measured Nov 26 2026 on 300 channels, for a member behind in 93: 157 → 17 ms
   through PostgREST.
34. **054_ring_targets.sql** — `app.channel_ring_targets`, which picks the phones a new
   channel message rings, reads `read_state` from the newest message for everybody and finds
   the last sender's own cursor by the primary key. Before, in a channel only one person
   writes in, the bound was 0 and every member's cursor was read and checked. Same people
   rung. Measured Nov 26 2026 with 2,475 of 47,981 members caught up: 45,506 cursors read
   and dropped → none, 11 → 8.5 ms.
35. **055_member_counts_index.sql** — `idx_users_counted`, the members who are not banned by
   server and bot, so `member_counts` (the sidebar header) is an index-only scan rather than a
   read of every user. Measured Nov 26 2026 on 50,000 members: 7.4 → 3.4 ms through
   PostgREST.
36. **056_member_fk_indexes.sql** — an index behind each reference to a member from a table
   that grows with the members or what they write (who wrapped a keyring row, who sent a
   message, whose reaction or vote, …), so the cascade from `delete_server` finds a member's
   rows rather than reading each table whole. Measured Nov 26 2026 on 5,000,000 messages and
   12,800,000 keyring rows: 3.5 s → 13 ms a member, for 125 MB of index.
37. **057_server_purge.sql** — deleting a server marks it (`servers.deleting_since`), and
   `purge_deleted_servers` deletes its rows afterwards, a channel's messages and then a few
   hundred members at a time, for a set time, quietly (`app.realtime_ready()` is false while it
   runs). Every minute for up to 25 s, and once for 4 s from the `delete_server` edge function.
   A marked server has no members: `app.server_id()` and a member's own row (`users_select_self`)
   answer nothing for it. Measured Nov 26 2026 on 50,000 members and 5,000,000 messages: 37,000
   messages a second, 2.2 ms a member, so some four minutes of work in all.
38. **058_server_details_overrides.sql** — `get_server_details` reads the caller's channel
   overrides for the whole server in one grouped pass (`app.my_channel_overrides`) rather than
   two lookups per channel, and applies them by the same rule as `app.apply_channel_overrides`
   (`app.override_bits`). Same answers. Measured Nov 26 2026 on 320 channels, 60 with
   overrides: 9.5 → 5 ms for a member.
39. **059_role_counts.sql** — `role_counts`, the Roles page's counts and the viewer's own
   roles in one call, in place of reading `member_role_list` whole a thousand rows at a time.
   Measured Nov 26 2026 on 50,000 members holding 49,000 roles: 49 requests and 657 ms → one
   request and 7 ms through PostgREST.
40. **060_poll_tallies.sql** — `poll_tallies` counts each option and the voters in one walk
   of a poll's votes along the primary key, rather than reading them twice. Same answers.
   Measured Nov 26 2026 on 20 polls of 5,000 voters each: 1.5 → 1.2 ms a poll.
41. **061_bot_voice_key_version.sql** — a bot's voice key is taken only at the room's current
   key version, from a member who holds it (`bot_voice_keys_insert`, `app.holds_room_key`): a
   bot speaks with its newest row, so a row sealed ahead of the room left it inaudible.
42. **062_member_rings.sql** — a `members` ring names who moved (`app.members_ring`) and rings
   only for what `member_directory` shows; `members_refresh` answers it in one call. Measured
   Nov 26 2026 on 50,000 members: 200 apps answering one ring through PostgREST, 865 → 185 ms
   (5 requests each → 1).
43. **063_my_keys.sql** — `my_channel_key` and `my_key_work` answer a member's key reads in the
   database, in place of the `get_channel_key` and `sweep_channel_keys` edge functions, which
   stay for older apps and older bot SDKs. Measured Nov 26 2026 on 50,000 members, counting the
   database requests only (the functions runtime's own cost is on top): a channel's keys
   5.8 → 1.8 ms, 200 at once 613 → 102 ms; key work 2.2 → 1.3 ms, 200 at once 143 → 40 ms.
44. **064_server_start.sql** — `server_start` answers an app's first loads on a server in one
   call (unread counts, the member sidebar, the soundboard, voice listeners and summons), and
   `dm_lists` the three DM lists; the console sweeps attachments on a timer. Measured Nov 26 2026
   on 50,000 members: 200 apps' first loads at once 1.2–1.4 s → 0.57–0.73 s (5 requests each → 1);
   the DM lists 222–331 → 52–102 ms (3 → 1). One app alone is a few milliseconds slower (19 → 23 ms),
   since the parts run one after another rather than side by side.
45. **065_voice_join.sql** — a call's questions in one database call each: `voice_join_facts`
   for `get_channel_token` (11 → 1), `call_rights_for` for the webhook's join check,
   `refresh_calls` and the other functions that push rights into a call, `voice_roster_facts`
   for `voice_roster` (7 → 1), and `call_panels` for a call's bar (one read for every text
   channel). A claim made in the last 30 seconds is read, not written again. Measured Nov 26 2026
   on 50,000 members, database requests only: a join 16.9 → 3.3 ms, 200 at once 1.96 → 0.12 s;
   the webhook's join check 7.8 → 2.8 ms, 200 at once 325 → 109 ms; the roster's reads
   12 → 2.1 ms, 200 at once 606 → 71 ms; a call's bar with 300 text channels 209 → 40 ms
   (301 requests → 1). Rights for a room of 40 are one request instead of 122, at about the same
   time (29 → 27 ms).
46. **066_channel_open.sql** — `channel_open` answers what a channel needs when it opens (the
   page, the bar, the caller's keys, the bots holding one and the bots a `/` reaches) in one
   call instead of five. Measured Nov 26 2026 on 50,000 members through PostgREST: 200 apps
   opening a channel at once 0.4–1.0 s → 0.27–0.58 s; one app alone 7.5 → 10 ms, since the parts
   run one after another rather than side by side.
47. **067_toggle_reaction.sql** — `toggle_reaction` puts a reaction on or takes it off in one call
   and answers the counts; the rings name who reacted; a message holds at most twenty different
   emoji. Measured Nov 26 2026 on 50,000 members through PostgREST: one app putting a reaction on
   and taking it off 28.6 → 20.3 ms; 200 apps at once 260–560 → 130–180 ms. The cap's count costs
   0.7 ms on a message with 2,600 reactions.
48. **068_swap_role_positions.sql** — `swap_role_positions` moves a role in one statement, both
   or neither, and a role's name, colour or place rings `members` once a statement. Measured
   Nov 26 2026 through PostgREST: a move with the reads after it 67.7 → 46.7 ms (six requests →
   four), and one ring instead of two.
49. **069_role_rings_marked.sql** — a `members` ring about roles carries `"roles": true`
   (`app.roles_ring`), so an app's DM list, which draws no roles, does not read its
   conversations again: on a server of 50,000, one role renamed was 50,000 such reads.
50. **070_banned_reach.sql** — three paths a ban (or a server marked deleted) never closed,
   found in the security re-review of Nov 26 2026: a banned bot kept reading its channels and
   their keys through its grants, and was still told of each new message (`app.bot_channels`
   and `app.announce_to_channel` now ask that it is still in; its grants are kept, so lifting
   the ban gives them back); a banned or kicked member could still edit every DM they had sent
   (`dm_messages_update_own` now asks `app.server_id()`, as every other DM write did); and the
   `avatars` bucket took uploads from anyone signed in and let them list every picture: writing
   now takes a member, and reading a member of the same server (`app.avatar_owner`).
51. **071_helpers_keep_plans.sql** — the definer helpers every policy, trigger and RPC asks
   (`app.server_id`, `app.visible_channels`, `app.has_perm`, …) are PL/pgSQL rather than SQL,
   bodies unchanged: Postgres 17 planned a definer SQL function again in every statement that
   asked it, and PL/pgSQL keeps the plan for the connection. `app.visible_channels` asks for
   its private channels in one statement. Measured Nov 26 2026 on 50,000 members, warm, in psql:
   a page 2.95 → 0.75 ms, a send 1.8 → 1.3, a reaction 2.6 → 0.6, `channel_open` 8.9 → 3.6,
   `get_server_details` 7.7 → 5.5, `server_start` 20 → 16; the same answers for five members.
52. **072_push_ring_holders.sql** — with push set up, a message works out the devices to wake
   from the members holding one (`app.channel_ring_tokens`), not from everyone caught up in
   the channel (`app.channel_ring_targets`, kept, and held to the same answer by the suite).
   `ring_channel_members` and `ring_devices` post through `app.push_tokens`. Measured Nov 26
   2026 on 50,000 members, 48,000 caught up in the channel: 116 ms → 8 ms with 3,000 members
   holding a device; 135 ms with 25,000.
53. **073_keyring_key_and_check.sql** — `channel_keyring` loses its primary key on `id`, a random
   UUID nothing reads, whose index every sealed key went into at a random place; the unique
   `(channel_id, key_version, user_id)` stays the key, and `id` stays as a column.
   `refuse_ineligible_keyring` runs once a statement over the rows written, with the same three
   refusals; a row an upsert skips is no longer asked about. Measured Nov 26 2026 on 12.8 M
   keyring rows: a 500-key batch 106 ms → 11 ms (median of ten).
54. **074_reads_that_move_nothing.sql** — `mark_read` reads the cursor first and answers from it
   when there is nowhere to move, so the common call (a channel opened with nothing new, a
   window focused) locks no row and takes no transaction id; `mark_all_read` writes only the
   cursors behind. The suite checks that neither locks nor rewrites a cursor already in place.
   Neither looks for a channel's newest message where the caller sees none of it (a private
   channel they are not in, a ban, a bot): under their row security that search read the whole
   of `messages` to find nothing. Measured Nov 26 2026 on 5 M messages: a bot's `mark_read`
   with no id 12 s → 0.03 ms, its `mark_all_read` ~100 s → 0.5 ms; a member's `mark_all_read`
   with nothing new 8.9 → 4.8 ms.
55. **075_member_search_matches_first.sql** — `search_members` gathers what a prefix matches
   (three name indexes, ids and sort key only) before sorting it, rather than walking the
   members in name order and testing each one; and what a name merely contains is looked for
   from the third letter, where the trigram index can, so "ab" no longer offers Gabriel and
   "abr" does. Below three letters the answer is the prefix matches alone; from three it is
   unchanged (compared over 672 calls on the test server). Measured Nov 26 2026 on 50,000
   members: "a" 31 → 4.9 ms, a two-letter prefix nobody has 39 → 0.5 ms.
56. **076_member_count_kept.sql** — `server_member_counts` holds each server's members who are
   not banned, people and bots apart, kept by triggers on `users` (`users_tally_*`) in the
   transaction that moves them, and `member_counts` reads it for the whole server or a public
   channel; a private channel's audience is still counted. A join already waits on the server's
   row in `register_user`, so the count's row holds up no join that was not already held. The
   suite checks the kept counts against a real count after everything it does. Measured Nov 26
   2026 on 50,000 members: `member_counts()` 1.5 → 0.03 ms, `members_refresh` of one id 2.4 →
   0.9 ms; a ban costs what it did.
57. **077_key_writes_in_database.sql** — `store_channel_keys` is `post_channel_keys` as one
   database call, with its checks, refusals and answer, in one transaction; two mints of a
   channel take turns, so the second is told the version exists whether or not the batches
   overlap. `store_key_work` stores a whole sweep pass, each job in its own savepoint, one
   answer a job. A newcomer who can see C channels cost C edge invocations and some 8 × C
   round trips in series; now one request.
58. **078_voice_token_names_the_screen.sql** — `voice_join_facts` answers `screen_share`, so a
   voice token names the sources it may publish and the screen only with `SCREEN_SHARE`.
59. **079_region_moves_with_its_key.sql** — a voice region's address changes only through
   `move_voice_region`, with its key, and no path takes an address that points inside the
   server (`app.livekit_url_refused`).
60. **080_small_calls_in_database.sql** — `summon_bot_to_voice` answers `new` and `needs_key`,
   so the app calls it directly and rings `sweep` only for a bot owed a key; `my_channel_key`
   names a voice channel's `listening_bots`; `push_status`, `set_push_config`,
   `clear_push_config` and `my_listing_token` do what `configure_push` and `listing_token` did.
61. **081_policies_ask_once.sql** — the last policies that called a helper once a row ask once a
   statement: `app.server_id()` and `auth.uid()` as scalar subqueries, and a row's channel tested
   against `app.visible_channels()`, in `soundboard_select`, `livekit_nodes_read`, both invite
   policies, `webhooks_select`, `voice_rooms_read`, `bot_voice_grants_select`,
   `bot_voice_summons_select`, `bot_channel_keys_select` and `channel_overrides_select`. Who
   sees what is unchanged. `idx_users_server` is dropped: the whole-table indexes leading with
   `server_id` cover it.

Central's set is smaller and has no edge functions behind it at all. Its RPCs are `claim_handle`,
`send_dm`, `dm_quota`, `unread_counts`, `mark_read` and `dm_conversations`. A read cursor that
moves rings `read` on `user:<id>` there too, in the same shape. Two of those exist
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
#### The message's time

GoTrue also refuses a message whose `Issued At` is more than ten minutes from its own clock
(`GOTRUE_EXTERNAL_WEB3_SOLANA_MAXIMUM_VALIDITY_DURATION`), with "Solana message was issued too
far in the future" or "…too long ago". `login` passes that through, and the client signs again
once at the time in the response's `Date` header. A device whose clock is wrong could otherwise
sign in to no server. Every function exposes `Date` to other origins (`_shared/cors.ts`) so the
web client can read it too.

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
second reads their row. A claim made in the last 30 seconds is only read (since 065): the upsert
changed nothing there but still locked the row, a write each join waited to flush, so everybody
joining a call that had just started paid for it one after another.

`voice_roster` is the other half. Nothing announces that a room emptied, so the one thing
already asking every node who is in each room is the only thing that finds out — it releases
the channels it can see with no room on any node, and the next call on them is decided afresh.
Only when the node the call was claimed on answered, and never a row claimed in the last
30 seconds (`release_idle_voice_node`): a node that did not answer may hold the call, and a room
claimed a moment ago may not exist yet. Before 1.9.1 either read as ended, and the next
person in could open the same call on another node. A claim that fails is refused
(`voice_server_unreachable`) rather than read as "no node", and a `preferred_node_id` that
is not a UUID is dropped before it can fail one.
Without that, "automatic" would decide once in a channel's lifetime rather than once per call.

The other functions that act on a room had one admin API per server, which was the same
assumption from the other side. Two shapes replace it: a known channel resolves through
`voice_rooms` to one node (`delete_channel`, `set_bot_voice_listen`, `set_bot_voice_summon`,
`set_channel_override`),
and a search across channels asks every node and merges (`kick_user`, `moderate_user`,
`move_user`, `delete_server`) — a node not holding a room answers empty, which is the same
answer as an empty room. A room with people on two nodes comes back once for each, so a ban
reaches both halves of a call that split.

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

**A region's address moves only with its key**: `move_voice_region(p_node, p_url, p_api_key,
p_secret)`, admin-checked, never the default (which follows `servers.livekit_url`, and
`update_server` asks for its key the same way). Before 1.9.1 the address was a column an admin
could update alone, and the functions then signed RoomService requests with the region's key for
the new host: an admin never given that key could collect admin tokens for the real region.
`authenticated` holds `UPDATE (label)` only. On every path, the default's included, an address
pointing inside the server is refused (`app.livekit_url_refused`): loopback, link-local (where a
cloud keeps its metadata), a name with no dot (a Docker service), a login in the address and the
odd spellings of an IP. A LAN address is allowed, since a local install runs on one.

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
  operator said where those calls go. Either token function then refuses
  `voice_server_unreachable`, which says the voice server is down and nothing
  about the caller's access (before 1.9.0 it was `unexpected_error`, which the
  app read as "you may have lost access").
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
